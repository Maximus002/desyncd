//! SOCKS4/4a and SOCKS5 protocol implementation.
//!
//! Implements the SOCKS5 handshake (RFC 1928) and SOCKS4/4a for the
//! CONNECT command. After the handshake, the connection is passed to
//! the relay module which applies DPI bypass techniques.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use desyncd_strategy::Selector;
use desyncd_types::StealthConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tracing::{debug, info, warn};

use crate::relay;

// SOCKS5 constants.
const SOCKS_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REPLY_SUCCESS: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Handle a single SOCKS5 client connection.
pub async fn handle_client(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    selector: &Selector,
    stealth: Option<&StealthConfig>,
) -> anyhow::Result<()> {
    debug!(%peer_addr, "new SOCKS5 connection");

    // --- Phase 1: Authentication negotiation ---
    let version = client.read_u8().await?;
    if version != SOCKS_VERSION {
        anyhow::bail!("unsupported SOCKS version: {}", version);
    }

    let nmethods = client.read_u8().await? as usize;
    // RFC 1928: NMETHODS is a u8, so max 255 — stack buffer avoids heap alloc.
    let mut methods = [0u8; 255];
    client.read_exact(&mut methods[..nmethods]).await?;

    // We only support "no authentication".
    if !methods[..nmethods].contains(&AUTH_NONE) {
        client.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        anyhow::bail!("no acceptable auth method from client");
    }

    client.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;

    // --- Phase 2: Connection request ---
    let ver = client.read_u8().await?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("bad version in request: {}", ver);
    }

    let cmd = client.read_u8().await?;
    let _rsv = client.read_u8().await?;
    let atyp = client.read_u8().await?;

    if cmd != CMD_CONNECT {
        send_reply(&mut client, REPLY_CMD_NOT_SUPPORTED, atyp).await?;
        anyhow::bail!("unsupported command: {}", cmd);
    }

    // Parse target address.
    let (target_addr, domain) = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            let port = client.read_u16().await?;
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port));
            (addr, None)
        }
        ATYP_DOMAIN => {
            let len = client.read_u8().await? as usize;
            if len == 0 {
                send_reply(&mut client, REPLY_GENERAL_FAILURE, atyp).await?;
                anyhow::bail!("SOCKS5 domain length is zero");
            }
            // RFC 1928: domain length is u8, max 255 — stack buffer avoids heap alloc.
            let mut domain_buf = [0u8; 255];
            client.read_exact(&mut domain_buf[..len]).await?;
            let port = client.read_u16().await?;
            let domain = std::str::from_utf8(&domain_buf[..len])
                .map_err(|e| anyhow::anyhow!("SOCKS5 domain is not valid UTF-8: {}", e))?
                .to_string();

            // Resolve domain, preferring IPv4, without collecting into a Vec.
            let addr = resolve_preferring_v4(&domain, port).await?;

            (addr, Some(domain))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip).await?;
            let port = client.read_u16().await?;
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
            (addr, None)
        }
        _ => {
            send_reply(&mut client, REPLY_ATYP_NOT_SUPPORTED, ATYP_IPV4).await?;
            anyhow::bail!("unsupported address type: {}", atyp);
        }
    };

    info!(
        %peer_addr,
        target = %target_addr,
        domain = ?domain,
        "SOCKS5 CONNECT"
    );

    // --- Phase 3: Connect to target ---
    let upstream = match TcpStream::connect(target_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%target_addr, error = %e, "failed to connect to target");
            send_reply(&mut client, REPLY_GENERAL_FAILURE, atyp).await?;
            return Err(e.into());
        }
    };

    // Send success reply.
    send_reply(&mut client, REPLY_SUCCESS, atyp).await?;

    // --- Phase 4: Relay with desync ---
    relay::relay_with_desync(client, upstream, target_addr, domain.as_deref(), selector, stealth).await?;

    Ok(())
}

/// Send a SOCKS5 reply to the client.
///
/// Allocation-free for the IPv4 case (which covers IPv4, domain, and fallback).
/// IPv6 replies use a 22-byte stack buffer.
async fn send_reply(client: &mut TcpStream, reply: u8, atyp: u8) -> anyhow::Result<()> {
    if atyp == ATYP_IPV6 {
        // VER REP RSV ATYP BND.ADDR(16) BND.PORT(2) = 22 bytes
        let response = [
            SOCKS_VERSION, reply, 0x00, ATYP_IPV6,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // BND.ADDR
            0, 0, // BND.PORT
        ];
        client.write_all(&response).await?;
    } else {
        // VER REP RSV ATYP BND.ADDR(4) BND.PORT(2) = 10 bytes
        let response = [
            SOCKS_VERSION, reply, 0x00, ATYP_IPV4,
            0, 0, 0, 0, // BND.ADDR
            0, 0, // BND.PORT
        ];
        client.write_all(&response).await?;
    }
    Ok(())
}

/// Resolve a domain to a SocketAddr, preferring IPv4, without collecting into a Vec.
///
/// This is a hot-path helper: on every SOCKS5/4a connection with a domain target
/// we need to look up the address. The previous implementation called
/// `format!("{}:{}", domain, port)` to build a &str, then `.collect::<Vec>()`ed the
/// iterator, then searched it twice (once for v4, once for any). We now use the
/// tuple form of `lookup_host` (no format!) and short-circuit on the first v4.
async fn resolve_preferring_v4(domain: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let mut first: Option<SocketAddr> = None;
    let iter = lookup_host((domain, port)).await?;
    for a in iter {
        if a.is_ipv4() {
            return Ok(a);
        }
        if first.is_none() {
            first = Some(a);
        }
    }
    first.ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}", domain))
}

/// Handle a SOCKS4/4a client connection.
///
/// SOCKS4 format:
///   VER(1) CMD(1) DSTPORT(2) DSTIP(4) USERID(variable, null-terminated)
///
/// SOCKS4a extension: if DSTIP is 0.0.0.x (x != 0), a domain name follows
/// the null-terminated userid.
pub async fn handle_socks4(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    selector: &Selector,
    stealth: Option<&StealthConfig>,
) -> anyhow::Result<()> {
    debug!(%peer_addr, "new SOCKS4 connection");

    // Read version byte (already peeked as 0x04).
    let version = client.read_u8().await?;
    if version != 0x04 {
        anyhow::bail!("expected SOCKS4, got version: {}", version);
    }

    let cmd = client.read_u8().await?;
    if cmd != 0x01 {
        // Only CONNECT (0x01) is supported, not BIND (0x02).
        let reply = [0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // rejected
        client.write_all(&reply).await?;
        anyhow::bail!("SOCKS4 unsupported command: {}", cmd);
    }

    let port = client.read_u16().await?;

    let mut ip_bytes = [0u8; 4];
    client.read_exact(&mut ip_bytes).await?;

    // Read userid (null-terminated). Max 256 bytes; we discard the content.
    let mut userid_buf = [0u8; 256];
    let mut userid_len = 0usize;
    loop {
        let b = client.read_u8().await?;
        if b == 0x00 {
            break;
        }
        if userid_len >= userid_buf.len() {
            anyhow::bail!("SOCKS4 userid too long");
        }
        userid_buf[userid_len] = b;
        userid_len += 1;
    }

    // SOCKS4a: if IP is 0.0.0.x (x != 0), read domain after userid.
    let is_socks4a = ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0;

    let (target_addr, domain) = if is_socks4a {
        // Read domain name (null-terminated) into a stack buffer.
        let mut domain_buf = [0u8; 256];
        let mut domain_len = 0usize;
        loop {
            let b = client.read_u8().await?;
            if b == 0x00 {
                break;
            }
            if domain_len >= domain_buf.len() {
                anyhow::bail!("SOCKS4a domain too long");
            }
            domain_buf[domain_len] = b;
            domain_len += 1;
        }
        let domain = std::str::from_utf8(&domain_buf[..domain_len])
            .map_err(|e| anyhow::anyhow!("SOCKS4a domain is not valid UTF-8: {}", e))?
            .to_string();
        let addr = resolve_preferring_v4(&domain, port).await?;
        (addr, Some(domain))
    } else {
        let ip = Ipv4Addr::from(ip_bytes);
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        (addr, None)
    };

    info!(
        %peer_addr,
        target = %target_addr,
        domain = ?domain,
        "SOCKS4 CONNECT"
    );

    // Connect to target.
    let upstream = match TcpStream::connect(target_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%target_addr, error = %e, "SOCKS4 failed to connect");
            // SOCKS4 rejected reply.
            let reply = [0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            client.write_all(&reply).await?;
            return Err(e.into());
        }
    };

    // SOCKS4 success reply: VN=0x00 CD=0x5A DSTPORT(2) DSTIP(4).
    let mut reply = vec![0x00, 0x5A];
    reply.extend_from_slice(&port.to_be_bytes());
    reply.extend_from_slice(&ip_bytes);
    client.write_all(&reply).await?;

    // Relay with desync.
    relay::relay_with_desync(client, upstream, target_addr, domain.as_deref(), selector, stealth).await?;
    Ok(())
}
