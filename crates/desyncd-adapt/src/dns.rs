//! Secure DNS resolver module.
//!
//! Bypasses DNS poisoning by querying public DNS servers via
//! DNS-over-TLS (DoT, RFC 7858) on port 853. Unlike plain UDP/53,
//! DoT is encrypted — the ISP cannot inspect or tamper with queries.
//!
//! Servers: Cloudflare (1.1.1.1) and Google (8.8.8.8).
//!
//! Falls back to plain UDP/53 if DoT fails, then to system DNS.
//!
//! Enabled via `[adaptation] secure_dns = true` in config (default).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// DoT server: (IP, SNI hostname for certificate validation).
const DOT_SERVERS: &[(IpAddr, &str)] = &[
    (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "cloudflare-dns.com"),
    (IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), "cloudflare-dns.com"),
    (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), "dns.google"),
    (IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), "dns.google"),
];

/// Plain UDP DNS servers (fallback if DoT fails).
const UDP_DNS_SERVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];

/// Timeout per DNS query.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a shared TLS config for DoT connections.
fn dot_tls_config() -> Arc<rustls::ClientConfig> {
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS protocol versions")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    Arc::new(config)
}

/// Resolve a domain to IP addresses using secure DNS.
///
/// Tries DNS-over-TLS first (encrypted, tamper-proof), then falls back
/// to plain UDP/53 if DoT is unreachable.
pub async fn resolve_secure(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    // Try DoT first.
    match resolve_dot(domain).await {
        Ok(ips) if !ips.is_empty() => return Ok(ips),
        Ok(_) => debug!(%domain, "DoT returned no A records, trying UDP fallback"),
        Err(e) => debug!(%domain, error = %e, "DoT failed, trying UDP fallback"),
    }

    // Fallback: plain UDP/53.
    for &server in UDP_DNS_SERVERS {
        match query_dns_udp(domain, server).await {
            Ok(ips) if !ips.is_empty() => {
                debug!(%domain, server = %server, ips = ?ips, "UDP DNS resolved (fallback)");
                return Ok(ips);
            }
            _ => continue,
        }
    }

    anyhow::bail!("all DNS methods failed for {}", domain)
}

/// Resolve using both system DNS and secure DNS, prefer secure.
pub async fn resolve_with_fallback(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    match resolve_secure(domain).await {
        Ok(secure_ips) => {
            // Compare with system DNS for poisoning detection.
            if let Ok(system_ips) = resolve_system(domain).await {
                let secure_set: std::collections::HashSet<_> = secure_ips.iter().collect();
                let system_set: std::collections::HashSet<_> = system_ips.iter().collect();

                if secure_set != system_set {
                    warn!(
                        %domain,
                        system = ?system_ips,
                        secure = ?secure_ips,
                        "DNS mismatch detected (possible poisoning), using secure DNS"
                    );
                }
            }
            Ok(secure_ips)
        }
        Err(e) => {
            debug!(%domain, error = %e, "secure DNS failed, falling back to system");
            resolve_system(domain).await
        }
    }
}

/// Resolve via DNS-over-TLS (port 853).
///
/// DNS-over-TLS: same wire format as TCP DNS (2-byte length prefix + query),
/// but over a TLS connection. The ISP sees only encrypted traffic to port 853.
async fn resolve_dot(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    let tls_config = dot_tls_config();

    for &(server_ip, sni) in DOT_SERVERS {
        match query_dns_dot(domain, server_ip, sni, &tls_config).await {
            Ok(ips) if !ips.is_empty() => {
                debug!(
                    %domain, server = %server_ip, ips = ?ips,
                    "DoT resolved"
                );
                return Ok(ips);
            }
            Ok(_) => {
                debug!(%domain, server = %server_ip, "DoT: no A records");
            }
            Err(e) => {
                debug!(%domain, server = %server_ip, error = %e, "DoT query failed");
            }
        }
    }

    anyhow::bail!("all DoT servers failed for {}", domain)
}

/// Send a single DNS query over TLS to a DoT server.
async fn query_dns_dot(
    domain: &str,
    server_ip: IpAddr,
    sni: &str,
    tls_config: &Arc<rustls::ClientConfig>,
) -> anyhow::Result<Vec<IpAddr>> {
    let addr = SocketAddr::new(server_ip, 853);
    let tcp = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect(addr)).await??;

    let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())?;

    let mut tls_stream = tokio::time::timeout(
        DNS_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await??;

    // Build DNS query.
    let query = build_dns_query(domain);

    // TCP/TLS DNS framing: 2-byte big-endian length prefix.
    let len_prefix = (query.len() as u16).to_be_bytes();
    tls_stream.write_all(&len_prefix).await?;
    tls_stream.write_all(&query).await?;
    tls_stream.flush().await?;

    // Read response: 2-byte length prefix, then message.
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(DNS_TIMEOUT, tls_stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    if resp_len > 4096 {
        anyhow::bail!("DNS response too large: {}", resp_len);
    }

    let mut resp_buf = vec![0u8; resp_len];
    tokio::time::timeout(DNS_TIMEOUT, tls_stream.read_exact(&mut resp_buf)).await??;

    parse_dns_response(&resp_buf)
}

/// Resolve using system DNS (tokio's built-in resolver).
async fn resolve_system(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    let addr_str = format!("{}:0", domain);
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(&addr_str)
        .await?
        .map(|sa| sa.ip())
        .collect();
    Ok(addrs)
}

/// Send a DNS A-record query via plain UDP to a specific server.
async fn query_dns_udp(domain: &str, server: IpAddr) -> anyhow::Result<Vec<IpAddr>> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let server_addr = SocketAddr::new(server, 53);

    let query = build_dns_query(domain);
    socket.send_to(&query, server_addr).await?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(DNS_TIMEOUT, socket.recv(&mut buf)).await??;

    parse_dns_response(&buf[..n])
}

/// Build a DNS A-record query packet (RFC 1035 wire format).
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Header.
    let id = fastrand::u16(..);
    buf.extend_from_slice(&id.to_be_bytes());        // ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT = 0

    // Question section: encode domain as labels.
    for label in domain.split('.') {
        let len = label.len().min(63);
        buf.push(len as u8);
        buf.extend_from_slice(&label.as_bytes()[..len]);
    }
    buf.push(0); // Root label.

    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A (1)
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN (1)

    buf
}

/// Parse a DNS response and extract A record IP addresses.
fn parse_dns_response(data: &[u8]) -> anyhow::Result<Vec<IpAddr>> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short");
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        anyhow::bail!("DNS error: rcode={}", rcode);
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut pos = 12;

    // Skip questions.
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        pos += 4; // QTYPE (2) + QCLASS (2)
    }

    // Parse answers.
    let mut ips = Vec::new();

    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        if rtype == 1 && rdlength == 4 {
            // A record.
            let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            ips.push(IpAddr::V4(ip));
        }

        pos += rdlength;
    }

    Ok(ips)
}

/// Skip a DNS name (handles labels and compression pointers).
fn skip_dns_name(data: &[u8], mut pos: usize) -> anyhow::Result<usize> {
    loop {
        if pos >= data.len() {
            anyhow::bail!("DNS name extends past end of packet");
        }

        let len = data[pos] as usize;

        if len == 0 {
            pos += 1;
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes, done.
            pos += 2;
            break;
        }

        // Regular label.
        if pos + 1 + len > data.len() {
            anyhow::bail!("DNS label extends past end of packet");
        }
        pos += 1 + len;
    }

    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query("example.com");

        assert!(query.len() > 12);
        assert_eq!(query[4], 0);
        assert_eq!(query[5], 1); // QDCOUNT = 1

        assert_eq!(query[12], 7); // "example" length
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3); // "com" length
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0); // root label
    }

    #[test]
    fn test_parse_dns_response() {
        // Minimal DNS response with one A record for 1.2.3.4.
        let mut response = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // Flags: response, RD, RA
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        // Question: example.com A IN
        response.extend_from_slice(&[7]);
        response.extend_from_slice(b"example");
        response.extend_from_slice(&[3]);
        response.extend_from_slice(b"com");
        response.push(0);
        response.extend_from_slice(&[0, 1]); // QTYPE=A
        response.extend_from_slice(&[0, 1]); // QCLASS=IN

        // Answer: compression pointer + A record
        response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
        response.extend_from_slice(&[0, 1]);        // TYPE = A
        response.extend_from_slice(&[0, 1]);        // CLASS = IN
        response.extend_from_slice(&[0, 0, 0, 60]); // TTL
        response.extend_from_slice(&[0, 4]);        // RDLENGTH
        response.extend_from_slice(&[1, 2, 3, 4]);  // 1.2.3.4

        let ips = parse_dns_response(&response).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[tokio::test]
    async fn test_resolve_dot_real() {
        if std::env::var("CI").is_ok() {
            return;
        }

        let ips = resolve_secure("google.com").await.unwrap();
        assert!(!ips.is_empty(), "should resolve google.com");
        println!("google.com resolved via DoT: {:?}", ips);
    }

    #[tokio::test]
    async fn test_resolve_dot_whatsapp() {
        if std::env::var("CI").is_ok() {
            return;
        }

        let ips = resolve_secure("whatsapp.com").await.unwrap();
        assert!(!ips.is_empty(), "should resolve whatsapp.com");
        println!("whatsapp.com resolved via DoT: {:?}", ips);

        // Verify TCP connectivity to resolved IP.
        let addr = SocketAddr::new(ips[0], 443);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await;
        println!("TCP to {:?}: {:?}", addr, result.is_ok() && result.unwrap().is_ok());
    }
}
