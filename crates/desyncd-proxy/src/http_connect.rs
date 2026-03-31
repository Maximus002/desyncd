//! HTTP CONNECT proxy protocol handler.
//!
//! Parses `CONNECT host:port HTTP/1.x` requests and tunnels the
//! connection with DPI desync applied to the first outbound data.

use desyncd_strategy::Selector;
use desyncd_types::StealthConfig;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::relay;

/// Handle an HTTP CONNECT request.
///
/// The first line has already been partially read (the caller peeked the
/// first byte to detect the protocol). We receive the stream with the
/// full request still pending.
pub async fn handle_connect(
    mut client: TcpStream,
    peer_addr: std::net::SocketAddr,
    first_bytes: &[u8],
    selector: &Selector,
    stealth: Option<&StealthConfig>,
) -> anyhow::Result<()> {
    debug!(%peer_addr, "HTTP CONNECT connection");

    // Read the full first line (we already have `first_bytes`, read the rest).
    let mut reader = BufReader::new(&mut client);

    // We need to parse the CONNECT line. Since we've already peeked,
    // read the full request header.
    let mut request_line = String::from_utf8_lossy(first_bytes).to_string();
    reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim().to_string();

    debug!(%request_line, "HTTP CONNECT request line");

    // Parse: "CONNECT host:port HTTP/1.x"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        anyhow::bail!("invalid CONNECT request: {}", request_line);
    }

    let target = parts[1];

    // Consume remaining headers (until empty line).
    let mut header_line = String::new();
    loop {
        header_line.clear();
        reader.read_line(&mut header_line).await?;
        if header_line.trim().is_empty() {
            break;
        }
    }

    // Parse host:port.
    let (host, port) = parse_host_port(target)?;

    info!(
        %peer_addr,
        %host,
        port,
        "HTTP CONNECT"
    );

    // Resolve and connect to target.
    let addr_str = format!("{}:{}", host, port);
    let upstream = match TcpStream::connect(&addr_str).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%addr_str, error = %e, "failed to connect to target");
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Err(e.into());
        }
    };

    // Send 200 Connection Established.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Relay with desync.
    relay::relay_with_desync(client, upstream, Some(&host), selector, stealth).await?;

    Ok(())
}

/// Parse "host:port" string, defaulting to port 443 if not specified.
fn parse_host_port(target: &str) -> anyhow::Result<(String, u16)> {
    if let Some(colon_pos) = target.rfind(':') {
        let host = &target[..colon_pos];
        let port_str = &target[colon_pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid port in CONNECT target: {}", target))?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        let (host, port) = parse_host_port("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        let (host, port) = parse_host_port("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);

        let (host, port) = parse_host_port("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }
}
