//! Transparent proxy mode (Linux only).
//!
//! Uses `iptables -t nat ... -j REDIRECT` to intercept connections without
//! requiring the client to be configured for SOCKS/HTTP CONNECT. The
//! original destination is recovered via `SO_ORIGINAL_DST` getsockopt.
//!
//! After recovering the original destination, the connection is handled
//! identically to SOCKS mode — the same relay and desync logic applies.
//!
//! # Setup
//!
//! ```sh
//! # Redirect outbound port 443 traffic to the proxy on port 1080:
//! iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 1080
//! ```
//!
//! # Limitations
//!
//! - Linux only (requires `SO_ORIGINAL_DST` / `IP_TRANSPARENT`)
//! - Domain name unknown until first data (SNI/Host extraction)
//! - Requires root or `CAP_NET_ADMIN` for iptables rules

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::unix::io::AsRawFd;
    use std::sync::Arc;

    use desyncd_strategy::Selector;
    use desyncd_types::StealthConfig;
    use tokio::net::{TcpListener, TcpStream};
    use tracing::{debug, error, info};

    use crate::relay;

    /// SO_ORIGINAL_DST constant (not always in libc).
    const SO_ORIGINAL_DST: libc::c_int = 80;

    /// Run a transparent proxy that recovers the original destination
    /// via `SO_ORIGINAL_DST` and applies DPI desync.
    pub async fn run_transparent_proxy(
        listen_addr: SocketAddr,
        selector: Arc<Selector>,
        stealth: Option<StealthConfig>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        let stealth = Arc::new(stealth);
        info!(%listen_addr, "transparent proxy listening");

        loop {
            let (client, peer_addr) = listener.accept().await?;
            let selector = selector.clone();
            let stealth = stealth.clone();

            tokio::spawn(async move {
                match handle_transparent(client, peer_addr, &selector, stealth.as_ref().as_ref()).await {
                    Ok(()) => debug!(%peer_addr, "transparent connection completed"),
                    Err(e) => error!(%peer_addr, error = %e, "transparent connection error"),
                }
            });
        }
    }

    async fn handle_transparent(
        client: TcpStream,
        peer_addr: SocketAddr,
        selector: &Selector,
        stealth: Option<&StealthConfig>,
    ) -> anyhow::Result<()> {
        let original_dst = get_original_dst(&client)?;
        debug!(%peer_addr, %original_dst, "transparent: recovered original destination");

        let upstream = TcpStream::connect(original_dst).await?;

        // Domain is unknown in transparent mode — will be extracted from
        // the first data (TLS SNI or HTTP Host header) by PayloadContext.
        relay::relay_with_desync(client, upstream, original_dst, None, selector, stealth).await
    }

    /// Recover the original destination address using `SO_ORIGINAL_DST`.
    ///
    /// This works when the connection was redirected by iptables REDIRECT
    /// or TPROXY. The kernel stores the original destination in the socket.
    fn get_original_dst(stream: &TcpStream) -> anyhow::Result<SocketAddr> {
        let fd = stream.as_raw_fd();
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("getsockopt SO_ORIGINAL_DST failed: {}", err);
        }

        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);

        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}

// Re-export for Linux.
#[cfg(target_os = "linux")]
pub use linux::run_transparent_proxy;

// Stub for non-Linux platforms — compile-time gate in CLI.
#[cfg(not(target_os = "linux"))]
pub async fn run_transparent_proxy(
    _listen_addr: std::net::SocketAddr,
    _selector: std::sync::Arc<desyncd_strategy::Selector>,
    _stealth: Option<desyncd_types::StealthConfig>,
) -> anyhow::Result<()> {
    anyhow::bail!("transparent mode is only supported on Linux")
}
