pub mod action;
pub mod socks5;
pub mod http_connect;
pub mod relay;
pub mod connstate;
pub mod transparent;

use std::net::SocketAddr;
use std::sync::Arc;

use desyncd_strategy::Selector;
use desyncd_types::StealthConfig;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

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
    info!(%listen_addr, "proxy listening (SOCKS5 + SOCKS4 + HTTP proxy auto-detect)");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let selector = selector.clone();
        let stealth = stealth.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, &selector, stealth.as_ref().as_ref()).await {
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
) -> anyhow::Result<()> {
    // Peek the first byte to determine protocol.
    let mut peek_buf = [0u8; 1];
    stream.peek(&mut peek_buf).await?;

    match peek_buf[0] {
        0x05 => {
            // SOCKS5.
            debug!(%peer_addr, "detected SOCKS5 protocol");
            socks5::handle_client(stream, peer_addr, selector, stealth).await
        }
        0x04 => {
            // SOCKS4/4a.
            debug!(%peer_addr, "detected SOCKS4 protocol");
            socks5::handle_socks4(stream, peer_addr, selector, stealth).await
        }
        // Any ASCII letter → HTTP proxy request.
        // CONNECT (0x43), GET (0x47), POST (0x50), PUT (0x50),
        // HEAD (0x48), DELETE (0x44), OPTIONS (0x4F), PATCH (0x50)
        b if b.is_ascii_alphabetic() => {
            debug!(%peer_addr, first_byte = b, "detected HTTP proxy protocol");
            let mut first_buf = vec![0u8; 8192];
            let n = stream.read(&mut first_buf).await?;
            first_buf.truncate(n);
            http_connect::handle_http_proxy(stream, peer_addr, &first_buf, selector, stealth).await
        }
        other => {
            debug!(%peer_addr, first_byte = other, "unknown protocol byte, trying SOCKS5");
            socks5::handle_client(stream, peer_addr, selector, stealth).await
        }
    }
}
