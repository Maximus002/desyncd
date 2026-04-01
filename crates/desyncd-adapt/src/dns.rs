//! Secure DNS resolver module.
//!
//! Bypasses DNS poisoning by querying public DNS servers directly
//! (Cloudflare 1.1.1.1, Google 8.8.8.8) via UDP instead of the
//! system/ISP resolver.
//!
//! Enabled via `[dns] secure_dns = true` in config.
//! Falls back to system DNS if all public resolvers fail.
//!
//! Future: can be extended to support DNS-over-HTTPS (DoH) for
//! ISPs that intercept port 53.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Public DNS servers to query, in order of preference.
const DNS_SERVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),       // Cloudflare
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),       // Cloudflare secondary
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),       // Google
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),       // Google secondary
];

/// Timeout per DNS query.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolve a domain to IP addresses using public DNS servers.
///
/// Returns a list of IPs (A records). Tries each server in order,
/// returns first successful response.
pub async fn resolve_secure(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    for &server in DNS_SERVERS {
        match query_dns(domain, server).await {
            Ok(ips) if !ips.is_empty() => {
                debug!(
                    %domain,
                    server = %server,
                    ips = ?ips,
                    "secure DNS resolved"
                );
                return Ok(ips);
            }
            Ok(_) => {
                debug!(%domain, server = %server, "no A records returned");
            }
            Err(e) => {
                debug!(%domain, server = %server, error = %e, "DNS query failed");
            }
        }
    }

    anyhow::bail!("all public DNS servers failed for {}", domain)
}

/// Resolve using both system DNS and public DNS, prefer public.
///
/// If public DNS returns different IPs than system DNS, log a warning
/// (likely DNS poisoning) and use the public DNS result.
pub async fn resolve_with_fallback(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    // Try public DNS first.
    match resolve_secure(domain).await {
        Ok(secure_ips) => {
            // Also resolve via system for comparison.
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

/// Resolve using system DNS (tokio's built-in resolver).
async fn resolve_system(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    let addr_str = format!("{}:0", domain);
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(&addr_str)
        .await?
        .map(|sa| sa.ip())
        .collect();
    Ok(addrs)
}

/// Send a DNS A-record query to a specific server and parse the response.
async fn query_dns(domain: &str, server: IpAddr) -> anyhow::Result<Vec<IpAddr>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let server_addr = SocketAddr::new(server, 53);

    // Build DNS query packet.
    let query = build_dns_query(domain);
    socket.send_to(&query, server_addr).await?;

    // Read response.
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(DNS_TIMEOUT, socket.recv(&mut buf)).await??;

    parse_dns_response(&buf[..n])
}

/// Build a DNS A-record query packet.
///
/// DNS wire format (RFC 1035):
/// - Header (12 bytes): ID, flags, counts
/// - Question: QNAME + QTYPE(A) + QCLASS(IN)
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Header.
    let id = fastrand::u16(..);
    buf.extend_from_slice(&id.to_be_bytes());     // ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes());    // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes());    // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());    // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());    // ARCOUNT = 0

    // Question section: encode domain as labels.
    for label in domain.split('.') {
        let len = label.len();
        if len > 63 {
            // Invalid label, truncate.
            buf.push(63);
            buf.extend_from_slice(&label.as_bytes()[..63]);
        } else {
            buf.push(len as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // Root label (end of QNAME).

    buf.extend_from_slice(&1u16.to_be_bytes());  // QTYPE = A (1)
    buf.extend_from_slice(&1u16.to_be_bytes());  // QCLASS = IN (1)

    buf
}

/// Parse a DNS response and extract A record IP addresses.
fn parse_dns_response(data: &[u8]) -> anyhow::Result<Vec<IpAddr>> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short");
    }

    // Check response flags.
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        anyhow::bail!("DNS error: rcode={}", rcode);
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    // Skip past the header and question section.
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

        // Skip NAME (may use compression).
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        // let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        // let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        if rtype == 1 && rdlength == 4 {
            // A record — 4 bytes for IPv4.
            let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            ips.push(IpAddr::V4(ip));
        }

        pos += rdlength;
    }

    Ok(ips)
}

/// Skip a DNS name (handles both labels and compression pointers).
fn skip_dns_name(data: &[u8], mut pos: usize) -> anyhow::Result<usize> {
    let jumped = false;

    loop {
        if pos >= data.len() {
            anyhow::bail!("DNS name extends past end of packet");
        }

        let len = data[pos] as usize;

        if len == 0 {
            // End of name.
            if !jumped {
                pos += 1;
            }
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes).
            if !jumped {
                pos += 2; // After pointer, we're done with this name in the original position.
            }
            // We don't need to follow the pointer since we're just skipping.
            break;
        }

        // Regular label.
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

        // Header is 12 bytes.
        assert!(query.len() > 12);
        // QDCOUNT = 1.
        assert_eq!(query[4], 0);
        assert_eq!(query[5], 1);

        // Question starts at byte 12.
        // "example" = 7 bytes label.
        assert_eq!(query[12], 7);
        assert_eq!(&query[13..20], b"example");
        // "com" = 3 bytes label.
        assert_eq!(query[20], 3);
        assert_eq!(&query[21..24], b"com");
        // Root label.
        assert_eq!(query[24], 0);
        // QTYPE=A(1), QCLASS=IN(1).
        assert_eq!(&query[25..27], &[0, 1]);
        assert_eq!(&query[27..29], &[0, 1]);
    }

    #[test]
    fn test_parse_dns_response() {
        // Minimal DNS response with one A record for 1.2.3.4.
        let mut response = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // Flags: response, RD, RA, no error
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];

        // Question: example.com A IN
        response.extend_from_slice(&[7]); // "example"
        response.extend_from_slice(b"example");
        response.extend_from_slice(&[3]); // "com"
        response.extend_from_slice(b"com");
        response.push(0); // root
        response.extend_from_slice(&[0, 1]); // QTYPE=A
        response.extend_from_slice(&[0, 1]); // QCLASS=IN

        // Answer: compression pointer to question name + A record.
        response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        response.extend_from_slice(&[0, 1]);        // TYPE = A
        response.extend_from_slice(&[0, 1]);        // CLASS = IN
        response.extend_from_slice(&[0, 0, 0, 60]); // TTL = 60
        response.extend_from_slice(&[0, 4]);        // RDLENGTH = 4
        response.extend_from_slice(&[1, 2, 3, 4]);  // RDATA = 1.2.3.4

        let ips = parse_dns_response(&response).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[tokio::test]
    async fn test_resolve_secure_real() {
        // This test makes real network calls — skip in CI.
        if std::env::var("CI").is_ok() {
            return;
        }

        let ips = resolve_secure("google.com").await.unwrap();
        assert!(!ips.is_empty(), "should resolve google.com");
        println!("google.com resolved to: {:?}", ips);
    }
}
