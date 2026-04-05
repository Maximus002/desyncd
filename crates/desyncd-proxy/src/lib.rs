pub mod action;
pub mod socks5;
pub mod http_connect;
pub mod relay;
pub mod connstate;
pub mod transparent;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use desyncd_dns::DnsCache;
use desyncd_strategy::Selector;
use desyncd_types::StealthConfig;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

/// Default TTL for the in-process DNS cache. 60s balances freshness with
/// the goal of taking DNS out of the per-connection hot path.
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Run the proxy server with auto-detection of protocol.
///
/// Peeks at the first bytes to determine the protocol:
/// - `0x05` → SOCKS5
/// - `0x04` → SOCKS4/4a
/// - ASCII letter → HTTP proxy (CONNECT, GET, POST, etc.)
pub async fn run_socks_proxy(
    listen_addr: SocketAddr,
    selector: Arc<Selector>,
    stealth: Option<StealthConfig>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let stealth = Arc::new(stealth);
    // Shared DNS cache lives for the lifetime of the proxy — entries are
    // reused across every connection from every client.
    let dns_cache = Arc::new(DnsCache::new(DNS_CACHE_TTL));
    info!(%listen_addr, "proxy listening (SOCKS5 + SOCKS4 + HTTP proxy auto-detect)");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // Transient errors (fd exhaustion, etc.) should not crash the proxy.
                // Log and retry after a brief pause to let fds get freed.
                error!(error = %e, "accept error (retrying in 50ms)");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let selector = selector.clone();
        let stealth = stealth.clone();
        let dns_cache = dns_cache.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, &selector, stealth.as_ref().as_ref(), &dns_cache).await {
                error!(%peer_addr, error = %e, "connection error");
            }
        });
    }
}

/// Handle a single connection, auto-detecting protocol.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    selector: &Selector,
    stealth: Option<&StealthConfig>,
    dns_cache: &Arc<DnsCache>,
) -> anyhow::Result<()> {
    // Peek the first byte to determine protocol.
    let mut peek_buf = [0u8; 1];
    stream.peek(&mut peek_buf).await?;

    match peek_buf[0] {
        0x05 => {
            // SOCKS5.
            debug!(%peer_addr, "detected SOCKS5 protocol");
            socks5::handle_client(stream, peer_addr, selector, stealth, dns_cache).await
        }
        0x04 => {
            // SOCKS4/4a.
            debug!(%peer_addr, "detected SOCKS4 protocol");
            socks5::handle_socks4(stream, peer_addr, selector, stealth, dns_cache).await
        }
        // Any ASCII letter → HTTP proxy request.
        // CONNECT (0x43), GET (0x47), POST (0x50), PUT (0x50),
        // HEAD (0x48), DELETE (0x44), OPTIONS (0x4F), PATCH (0x50)
        b if b.is_ascii_alphabetic() => {
            debug!(%peer_addr, first_byte = b, "detected HTTP proxy protocol");
            let mut first_buf = vec![0u8; 8192];
            let n = stream.read(&mut first_buf).await?;
            first_buf.truncate(n);
            http_connect::handle_http_proxy(stream, peer_addr, &first_buf, selector, stealth, dns_cache).await
        }
        other => {
            debug!(%peer_addr, first_byte = other, "unknown protocol byte, trying SOCKS5");
            socks5::handle_client(stream, peer_addr, selector, stealth, dns_cache).await
        }
    }
}
