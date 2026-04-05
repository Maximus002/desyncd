//! Probing: test whether a domain is accessible with a given strategy.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use desyncd_desync::PayloadContext;
use desyncd_strategy::Strategy;
use desyncd_types::DesyncAction;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// Result of a single probe attempt.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Whether the connection succeeded (got a TLS ServerHello or HTTP response).
    pub success: bool,
    /// Round-trip latency for the handshake.
    pub latency: Duration,
    /// Error message if the probe failed.
    pub error: Option<String>,
}

/// Probe a domain by attempting a TLS handshake with the given strategy applied.
///
/// This does NOT perform a full TLS handshake (no certificate validation).
/// It sends a ClientHello, applies the strategy to desync it, and checks
/// if we get a ServerHello back (or any response at all).
///
/// When `secure_dns` is true, resolves the domain via public DNS
/// (Cloudflare/Google) instead of system DNS to bypass DNS poisoning.
pub async fn probe_domain(
    domain: &str,
    port: u16,
    strategy: Option<&Strategy>,
    timeout: Duration,
) -> ProbeResult {
    probe_domain_ex(domain, port, strategy, timeout, true).await
}

/// Extended probe with explicit secure_dns flag.
pub async fn probe_domain_ex(
    domain: &str,
    port: u16,
    strategy: Option<&Strategy>,
    timeout: Duration,
    secure_dns: bool,
) -> ProbeResult {
    let start = Instant::now();

    let result = tokio::time::timeout(
        timeout,
        probe_inner(domain, port, strategy, secure_dns),
    )
    .await;

    let latency = start.elapsed();

    match result {
        Ok(Ok(true)) => {
            debug!(%domain, ?latency, "probe succeeded");
            ProbeResult {
                success: true,
                latency,
                error: None,
            }
        }
        Ok(Ok(false)) => {
            debug!(%domain, ?latency, "probe failed: no response");
            ProbeResult {
                success: false,
                latency,
                error: Some("no valid response received".into()),
            }
        }
        Ok(Err(e)) => {
            debug!(%domain, ?latency, error = %e, "probe error");
            ProbeResult {
                success: false,
                latency,
                error: Some(e.to_string()),
            }
        }
        Err(_) => {
            debug!(%domain, "probe timed out");
            ProbeResult {
                success: false,
                latency: timeout,
                error: Some("timeout".into()),
            }
        }
    }
}

/// Inner probe logic: connect, send ClientHello, apply strategy, check response.
async fn probe_inner(
    domain: &str,
    port: u16,
    strategy: Option<&Strategy>,
    secure_dns: bool,
) -> anyhow::Result<bool> {
    let mut stream = if secure_dns {
        // Resolve via public DNS to bypass ISP DNS poisoning.
        match desyncd_dns::resolve_secure(domain).await {
            Ok(ips) => {
                let mut last_err = None;
                let mut connected = None;
                for ip in &ips {
                    let addr = SocketAddr::new(*ip, port);
                    match TcpStream::connect(addr).await {
                        Ok(s) => {
                            debug!(%domain, ip = %ip, "probe connected via secure DNS");
                            connected = Some(s);
                            break;
                        }
                        Err(e) => {
                            debug!(%domain, ip = %ip, error = %e, "secure DNS IP failed");
                            last_err = Some(e);
                        }
                    }
                }
                match connected {
                    Some(s) => s,
                    None => return Err(last_err
                        .map(|e| e.into())
                        .unwrap_or_else(|| anyhow::anyhow!("no IPs from secure DNS"))),
                }
            }
            Err(e) => {
                // Secure DNS failed, fall back to system DNS.
                debug!(%domain, error = %e, "secure DNS failed, using system DNS");
                let addr = format!("{}:{}", domain, port);
                TcpStream::connect(&addr).await?
            }
        }
    } else {
        let addr = format!("{}:{}", domain, port);
        TcpStream::connect(&addr).await?
    };

    let peer = stream.peer_addr().ok();
    debug!(%domain, ?peer, "probe connected");
    stream.set_nodelay(true)?;

    // Build a minimal TLS ClientHello.
    let client_hello = build_probe_client_hello(domain);

    if let Some(strategy) = strategy {
        // Move `client_hello` into the context so we don't clone it just to
        // pass the original bytes to `execute_action` — `ctx.payload` is the
        // same slice and `execute_action` only needs a `&[u8]`.
        let ctx = PayloadContext::new(client_hello);
        let action = strategy.apply(&ctx).unwrap_or(DesyncAction::PassThrough);
        desyncd_proxy::action::execute_action(&action, &ctx.payload, &mut stream, None).await?;
    } else {
        // No strategy — baseline test.
        stream.write_all(&client_hello).await?;
    }

    stream.flush().await?;

    // Wait for a response (ServerHello or RST/FIN).
    // Use the remaining time from the outer timeout (capped at 10s).
    let read_timeout = Duration::from_secs(10);
    let mut buf = [0u8; 6]; // TLS record header (5) + handshake type (1).
    match tokio::time::timeout(read_timeout, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            // A real ServerHello: content_type=0x16 (Handshake), then
            // after the 5-byte record header, handshake_type=0x02 (ServerHello).
            let is_server_hello = buf[0] == 0x16 && buf[5] == 0x02;
            // TLS Alert (0x15) means data reached the server but
            // it rejected our handshake — technique is NOT usable.
            trace!(
                content_type = buf[0],
                handshake_type = buf[5],
                is_server_hello,
                "got response"
            );
            Ok(is_server_hello)
        }
        Ok(Err(e)) => {
            // Connection reset or other error — likely blocked.
            Err(e.into())
        }
        Err(_) => {
            // Timeout — could be slowdown DPI.
            Ok(false)
        }
    }
}

/// Build a realistic TLS 1.2/1.3 ClientHello with the given SNI.
///
/// Includes all extensions required by modern servers:
/// SNI, supported_groups, signature_algorithms, ec_point_formats,
/// and supported_versions.
fn build_probe_client_hello(domain: &str) -> Vec<u8> {
    let sni_bytes = domain.as_bytes();

    // We'll build extensions into a temporary buffer first, then compute lengths.
    let mut extensions = Vec::with_capacity(256);

    // 1. SNI extension (0x0000).
    {
        let sni_list_len = 1 + 2 + sni_bytes.len(); // type(1) + len(2) + name
        let ext_data_len = 2 + sni_list_len;         // list_len(2) + list
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        extensions.push(0x00); // host_name type
        extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni_bytes);
    }

    // 2. EC point formats (0x000b).
    {
        extensions.extend_from_slice(&0x000bu16.to_be_bytes());
        extensions.extend_from_slice(&2u16.to_be_bytes()); // ext data len
        extensions.push(1); // formats length
        extensions.push(0); // uncompressed
    }

    // 3. Supported groups (0x000a) — required for ECDHE ciphers.
    {
        let groups: &[u16] = &[
            0x001d, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
            0x0019, // secp521r1
        ];
        let list_len = (groups.len() * 2) as u16;
        extensions.extend_from_slice(&0x000au16.to_be_bytes());
        extensions.extend_from_slice(&(list_len + 2).to_be_bytes()); // ext data len
        extensions.extend_from_slice(&list_len.to_be_bytes());
        for g in groups {
            extensions.extend_from_slice(&g.to_be_bytes());
        }
    }

    // 4. Signature algorithms (0x000d) — required for certificate verification.
    {
        let sig_algs: &[u16] = &[
            0x0403, // ecdsa_secp256r1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0804, // rsa_pss_rsae_sha256
            0x0805, // rsa_pss_rsae_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0401, // rsa_pkcs1_sha256
            0x0501, // rsa_pkcs1_sha384
            0x0601, // rsa_pkcs1_sha512
        ];
        let list_len = (sig_algs.len() * 2) as u16;
        extensions.extend_from_slice(&0x000du16.to_be_bytes());
        extensions.extend_from_slice(&(list_len + 2).to_be_bytes());
        extensions.extend_from_slice(&list_len.to_be_bytes());
        for sa in sig_algs {
            extensions.extend_from_slice(&sa.to_be_bytes());
        }
    }

    // 5. Supported versions (0x002b) — TLS 1.3 + 1.2.
    {
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&5u16.to_be_bytes());
        extensions.push(4); // list length in bytes
        extensions.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
        extensions.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
    }

    // 6. ALPN extension (0x0010) — required by many modern servers.
    {
        // Advertise h2 and http/1.1.
        let protocols: &[&[u8]] = &[b"h2", b"http/1.1"];
        let mut alpn_data = Vec::new();
        for proto in protocols {
            alpn_data.push(proto.len() as u8);
            alpn_data.extend_from_slice(proto);
        }
        extensions.extend_from_slice(&0x0010u16.to_be_bytes());
        extensions.extend_from_slice(&((alpn_data.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&alpn_data);
    }

    // 7. Key share (0x0033) — x25519 with dummy public key (probe only).
    {
        let mut x25519_key = [0u8; 32];
        for b in &mut x25519_key {
            *b = fastrand::u8(..);
        }
        // key_share entry: group(2) + key_len(2) + key(32) = 36
        let entry_len = 2 + 2 + 32;
        let ext_data_len = 2 + entry_len; // client_shares_len(2) + entry
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(entry_len as u16).to_be_bytes());
        extensions.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
        extensions.extend_from_slice(&32u16.to_be_bytes());
        extensions.extend_from_slice(&x25519_key);
    }

    let extensions_len = extensions.len();

    // Cipher suites.
    let cipher_suites: &[u16] = &[
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
    let cipher_suites_len = cipher_suites.len() * 2;

    // Session ID (32 random bytes for TLS 1.3 middlebox compat).
    let mut session_id = [0u8; 32];
    for b in &mut session_id {
        *b = fastrand::u8(..);
    }

    let ch_body_len = 2      // client_version
        + 32                  // random
        + 1 + 32              // session_id_len + session_id
        + 2 + cipher_suites_len // cipher_suites
        + 1 + 1               // compression
        + 2 + extensions_len; // extensions

    let hs_len = 4 + ch_body_len; // handshake header + body

    let mut buf = Vec::with_capacity(5 + hs_len);

    // TLS record header.
    buf.push(0x16); // Handshake
    buf.extend_from_slice(&0x0301u16.to_be_bytes()); // TLS 1.0 (compat)
    buf.extend_from_slice(&(hs_len as u16).to_be_bytes());

    // Handshake header.
    buf.push(0x01); // ClientHello
    buf.push(0x00);
    buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());

    // ClientHello body.
    buf.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2

    // Random (32 bytes).
    for _ in 0..32 {
        buf.push(fastrand::u8(..));
    }

    // Session ID (32 bytes for middlebox compatibility).
    buf.push(32);
    buf.extend_from_slice(&session_id);

    // Cipher suites.
    buf.extend_from_slice(&(cipher_suites_len as u16).to_be_bytes());
    for cs in cipher_suites {
        buf.extend_from_slice(&cs.to_be_bytes());
    }

    buf.push(1); // compression_methods_len
    buf.push(0); // null compression

    // Extensions.
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    buf.extend_from_slice(&extensions);

    buf
}
