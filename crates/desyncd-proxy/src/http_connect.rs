//! HTTP proxy protocol handler.
//!
//! Supports two modes:
//! - `CONNECT host:port HTTP/1.x` — tunnel mode for HTTPS
//! - `GET/POST/... http://host/path HTTP/1.x` — forward proxy for plain HTTP

use desyncd_strategy::Selector;
use desyncd_types::StealthConfig;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::relay;

/// Handle any HTTP proxy request (CONNECT or forward).
///
/// The first bytes have been read by the caller. We parse the request
/// line to determine if it's CONNECT (tunnel) or a regular HTTP method
/// (forward proxy).
pub async fn handle_http_proxy(
    mut client: TcpStream,
    peer_addr: std::net::SocketAddr,
    first_bytes: &[u8],
    selector: &Selector,
    stealth: Option<&StealthConfig>,
) -> anyhow::Result<()> {
    // Reconstruct the full request line from first_bytes + remainder.
    let mut reader = BufReader::new(&mut client);
    let mut request_line = String::from_utf8_lossy(first_bytes).to_string();

    // If the first_bytes don't contain a newline, keep reading.
    if !request_line.contains('\n') {
        reader.read_line(&mut request_line).await?;
    }

    // Extract just the first line.
    let first_line = request_line.lines().next().unwrap_or("").trim().to_string();
    debug!(%first_line, "HTTP proxy request");

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        anyhow::bail!("malformed HTTP request: {}", first_line);
    }

    let method = parts[0].to_uppercase();

    if method == "CONNECT" {
        // Consume remaining headers.
        let mut header_line = String::new();
        // We may have already read some headers in request_line.
        // Read lines from `reader` until we find an empty line.
        // But first check if request_line already contains the full header block.
        let remaining = &request_line[first_line.len()..];
        let headers_complete = remaining.contains("\r\n\r\n") || remaining.contains("\n\n");

        if !headers_complete {
            loop {
                header_line.clear();
                reader.read_line(&mut header_line).await?;
                if header_line.trim().is_empty() {
                    break;
                }
            }
        }

        handle_connect_tunnel(client, peer_addr, parts[1], selector, stealth).await
    } else {
        // Forward proxy for plain HTTP (GET, POST, etc.)
        // Collect remaining headers.
        let mut headers = Vec::new();

        // Parse headers already in request_line (after first line).
        let remaining = &request_line[first_line.len()..];
        let mut headers_complete = false;
        for line in remaining.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                headers_complete = true;
                break;
            }
            if trimmed.contains(':') {
                headers.push(trimmed.to_string());
            }
        }

        // Read more headers if needed.
        if !headers_complete {
            let mut header_line = String::new();
            loop {
                header_line.clear();
                reader.read_line(&mut header_line).await?;
                let trimmed = header_line.trim().to_string();
                if trimmed.is_empty() {
                    break;
                }
                headers.push(trimmed);
            }
        }

        handle_forward_proxy(client, peer_addr, &method, parts[1], parts[2], &headers, selector, stealth).await
    }
}

/// Handle CONNECT tunnel (for HTTPS).
async fn handle_connect_tunnel(
    mut client: TcpStream,
    peer_addr: std::net::SocketAddr,
    target: &str,
    selector: &Selector,
    stealth: Option<&StealthConfig>,
) -> anyhow::Result<()> {
    let (host, port) = parse_host_port(target)?;

    info!(%peer_addr, %host, port, "HTTP CONNECT");

    let addr_str = format!("{}:{}", host, port);
    let upstream = match TcpStream::connect(&addr_str).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%addr_str, error = %e, "failed to connect to target");
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            return Err(e.into());
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    relay::relay_with_desync(client, upstream, Some(&host), selector, stealth).await?;
    Ok(())
}

/// Handle forward HTTP proxy (GET http://host/path, POST, etc.)
///
/// For plain HTTP requests, we connect to the target, rewrite the request
/// to use a relative path (as the upstream server expects), and relay.
async fn handle_forward_proxy(
    mut client: TcpStream,
    peer_addr: std::net::SocketAddr,
    method: &str,
    url: &str,
    http_version: &str,
    headers: &[String],
    _selector: &Selector,
    _stealth: Option<&StealthConfig>,
) -> anyhow::Result<()> {
    // Parse the absolute URL: http://host[:port]/path
    // Note: desync is not applied for plain HTTP — DPI bypass is only
    // meaningful for TLS (HTTPS) connections via CONNECT tunnel.
    let (host, port, path) = parse_absolute_url(url)?;

    info!(%peer_addr, %host, port, %path, %method, "HTTP forward proxy");

    let addr_str = format!("{}:{}", host, port);
    let mut upstream = match TcpStream::connect(&addr_str).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%addr_str, error = %e, "failed to connect to target");
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            return Err(e.into());
        }
    };

    // Rewrite request with relative path and forward to upstream.
    let mut request = format!("{} {} {}\r\n", method, path, http_version);

    // Forward headers, filtering out proxy-specific ones.
    let mut has_host = false;
    for header in headers {
        let lower = header.to_lowercase();
        if lower.starts_with("proxy-connection")
            || lower.starts_with("proxy-authorization")
        {
            continue;
        }
        if lower.starts_with("host:") {
            has_host = true;
        }
        request.push_str(header);
        request.push_str("\r\n");
    }

    if !has_host {
        if port == 80 {
            request.push_str(&format!("Host: {}\r\n", host));
        } else {
            request.push_str(&format!("Host: {}:{}\r\n", host, port));
        }
    }

    // Replace keep-alive with close for simpler handling.
    request.push_str("Connection: close\r\n");
    request.push_str("\r\n");

    // Send the rewritten request to upstream.
    upstream.write_all(request.as_bytes()).await?;

    // Relay response back to client and any remaining request body.
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    let client_to_upstream = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut client_reader, &mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if tokio::io::AsyncWriteExt::write_all(&mut upstream_writer, &buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut upstream_writer).await;
        Ok::<_, std::io::Error>(())
    };

    let upstream_to_client = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut upstream_reader, &mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if tokio::io::AsyncWriteExt::write_all(&mut client_writer, &buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut client_writer).await;
        Ok::<_, std::io::Error>(())
    };

    tokio::select! {
        _ = client_to_upstream => {}
        _ = upstream_to_client => {}
    }

    Ok(())
}

/// Parse "host:port" string, defaulting to port 443 if not specified.
fn parse_host_port(target: &str) -> anyhow::Result<(String, u16)> {
    if let Some(colon_pos) = target.rfind(':') {
        let host = &target[..colon_pos];
        let port_str = &target[colon_pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid port in target: {}", target))?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

/// Parse an absolute URL like `http://host[:port]/path` into components.
fn parse_absolute_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    // Strip the scheme.
    let without_scheme = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        // No scheme — might be just host:port/path or /path.
        url
    };

    // Split host[:port] from path.
    let (host_port, path) = match without_scheme.find('/') {
        Some(pos) => (&without_scheme[..pos], &without_scheme[pos..]),
        None => (without_scheme, "/"),
    };

    // Parse host and port.
    let (host, port) = if let Some(colon_pos) = host_port.rfind(':') {
        let host = &host_port[..colon_pos];
        let port: u16 = host_port[colon_pos + 1..]
            .parse()
            .unwrap_or(80);
        (host.to_string(), port)
    } else {
        (host_port.to_string(), 80)
    };

    Ok((host, port, path.to_string()))
}

// Keep the old function name as a public alias for backwards compat.
pub use handle_http_proxy as handle_connect;

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

    #[test]
    fn test_parse_absolute_url() {
        let (host, port, path) = parse_absolute_url("http://example.com/foo/bar").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/foo/bar");

        let (host, port, path) = parse_absolute_url("http://example.com:8080/test").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/test");

        let (host, port, path) = parse_absolute_url("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }
}
