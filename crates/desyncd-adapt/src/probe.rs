//! Probing: test whether a domain is accessible with a given strategy.

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
pub async fn probe_domain(
    domain: &str,
    port: u16,
    strategy: Option<&Strategy>,
    timeout: Duration,
) -> ProbeResult {
    let start = Instant::now();

    let result = tokio::time::timeout(timeout, probe_inner(domain, port, strategy)).await;

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
) -> anyhow::Result<bool> {
    let addr = format!("{}:{}", domain, port);
    let mut stream = TcpStream::connect(&addr).await?;
    stream.set_nodelay(true)?;

    // Build a minimal TLS ClientHello.
    let client_hello = build_probe_client_hello(domain);

    if let Some(strategy) = strategy {
        let ctx = PayloadContext::new(client_hello.clone());
        let action = strategy.apply(&ctx).unwrap_or(DesyncAction::PassThrough);

        match action {
            DesyncAction::PassThrough => {
                stream.write_all(&client_hello).await?;
            }
            DesyncAction::Replace(data) => {
                stream.write_all(&data).await?;
            }
            DesyncAction::Split(chunks) => {
                for chunk in &chunks {
                    stream.write_all(chunk).await?;
                    stream.flush().await?;
                }
            }
            DesyncAction::InjectBefore(fakes) => {
                for fake in &fakes {
                    stream.write_all(fake).await?;
                    stream.flush().await?;
                }
                stream.write_all(&client_hello).await?;
            }
        }
    } else {
        // No strategy — baseline test.
        stream.write_all(&client_hello).await?;
    }

    stream.flush().await?;

    // Wait for a response (ServerHello or RST/FIN).
    let mut buf = [0u8; 5]; // TLS record header: type + version + length.
    match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            // Check if it looks like a TLS record.
            let is_tls = buf[0] == 0x16 // Handshake
                || buf[0] == 0x15 // Alert (still means DPI didn't block)
                || buf[0] == 0x14; // ChangeCipherSpec
            trace!(first_byte = buf[0], is_tls, "got response");
            Ok(is_tls)
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

/// Build a minimal TLS 1.2 ClientHello with the given SNI.
fn build_probe_client_hello(domain: &str) -> Vec<u8> {
    let sni_bytes = domain.as_bytes();

    // SNI extension.
    let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
    let sni_ext_len = 4 + sni_ext_data_len;

    // Supported versions extension (TLS 1.3 + 1.2).
    let sv_ext_len = 4 + 1 + 4; // type(2) + len(2) + list_len(1) + 2 versions

    let extensions_len = sni_ext_len + sv_ext_len;

    // Cipher suites: common ones.
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

    let ch_body_len = 2 + 32 + 1 + 2 + cipher_suites_len + 1 + 1 + 2 + extensions_len;
    let hs_len = 4 + ch_body_len;

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

    buf.push(0); // session_id_len = 0

    // Cipher suites.
    buf.extend_from_slice(&(cipher_suites_len as u16).to_be_bytes());
    for cs in cipher_suites {
        buf.extend_from_slice(&cs.to_be_bytes());
    }

    buf.push(1); // compression_methods_len
    buf.push(0); // null compression

    // Extensions.
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());

    // SNI extension (type 0x0000).
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    let sni_list_len = 1 + 2 + sni_bytes.len();
    buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    buf.push(0x00); // host_name type
    buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);

    // Supported versions extension (type 0x002b).
    buf.extend_from_slice(&0x002bu16.to_be_bytes());
    buf.extend_from_slice(&5u16.to_be_bytes()); // ext data len
    buf.push(4); // list length
    buf.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
    buf.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2

    buf
}
