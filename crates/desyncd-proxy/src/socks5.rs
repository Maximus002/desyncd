//! SOCKS4/4a and SOCKS5 protocol implementation.
//!
//! Implements the SOCKS5 handshake (RFC 1928) and SOCKS4/4a for the
//! CONNECT command. After the handshake, the connection is passed to
//! the relay module which applies DPI bypass techniques.
//!
//! # Hot-path notes
//!
//! The SOCKS5 handshake is on every proxy connection, so we go out of our
//! way to avoid per-byte reads: each logical unit is read with a single
//! `read_exact` call. A naive implementation has ~8 `read_u8` await points
//! which is ~8 scheduler trips + 8 syscalls; byedpi makes 1 recv. We merge
//! the fixed-length header reads into bulk `[u8; N]` buffers to match that.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use desyncd_dns::DnsCache;
use desyncd_strategy::Selector;
use desyncd_types::StealthConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
    dns_cache: &Arc<DnsCache>,
) -> anyhow::Result<()> {
    debug!(%peer_addr, "new SOCKS5 connection");

    // --- Phase 1: Authentication negotiation ---
    //
    // Wire format: VER(1) NMETHODS(1) METHODS(NMETHODS)
    // We read VER+NMETHODS in a single bulk read, then METHODS in a second
    // read. That's 2 syscalls instead of 2 read_u8 + 1 read_exact = 3.
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS_VERSION {
        anyhow::bail!("unsupported SOCKS version: {}", hdr[0]);
    }
    let nmethods = hdr[1] as usize;

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
    //
    // Wire format: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
    // We read the fixed 4-byte header in a single bulk call instead of
    // four read_u8 awaits.
    let mut req_hdr = [0u8; 4];
    client.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != SOCKS_VERSION {
        anyhow::bail!("bad version in request: {}", req_hdr[0]);
    }
    let cmd = req_hdr[1];
    // req_hdr[2] is RSV, ignored
    let atyp = req_hdr[3];

    if cmd != CMD_CONNECT {
        send_reply(&mut client, REPLY_CMD_NOT_SUPPORTED, atyp).await?;
        anyhow::bail!("unsupported command: {}", cmd);
    }

    // Parse target address.
    //
    // For each address family we bulk-read the addr + port together (no
    // separate read_u16 call for the port). The Domain branch still needs
    // a one-byte read for the length prefix, but everything after that is
    // one bulk read.
    let (target_addr, domain) = match atyp {
        ATYP_IPV4 => {
            // 4 bytes IP + 2 bytes port = 6 bytes, one read.
            let mut ip_port = [0u8; 6];
            client.read_exact(&mut ip_port).await?;
            let ip = Ipv4Addr::new(ip_port[0], ip_port[1], ip_port[2], ip_port[3]);
            let port = u16::from_be_bytes([ip_port[4], ip_port[5]]);
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            (addr, None)
        }
        ATYP_DOMAIN => {
            // One byte length, then domain + 2-byte port in a single read.
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            if len == 0 {
                send_reply(&mut client, REPLY_GENERAL_FAILURE, atyp).await?;
                anyhow::bail!("SOCKS5 domain length is zero");
            }

            // RFC 1928: max domain length is 255, so +2 for port fits in 257.
            let mut tail = [0u8; 257];
            client.read_exact(&mut tail[..len + 2]).await?;

            let domain_bytes = &tail[..len];
            let domain = std::str::from_utf8(domain_bytes)
                .map_err(|e| anyhow::anyhow!("SOCKS5 domain is not valid UTF-8: {}", e))?
                .to_string();
            let port = u16::from_be_bytes([tail[len], tail[len + 1]]);

            // Hot-path DNS: look the domain up through the TTL cache.
            // First hit per (domain,port) goes to DoT+system resolver;
            // subsequent hits return in microseconds.
            let addr = dns_cache.resolve(&domain, port).await?;

            (addr, Some(domain))
        }
        ATYP_IPV6 => {
            // 16 bytes IP + 2 bytes port = 18 bytes, one read.
            let mut ip_port = [0u8; 18];
            client.read_exact(&mut ip_port).await?;
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&ip_port[..16]);
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([ip_port[16], ip_port[17]]);
            let addr = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));
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
    dns_cache: &Arc<DnsCache>,
) -> anyhow::Result<()> {
    debug!(%peer_addr, "new SOCKS4 connection");

    // Fixed 8-byte header: VER(1) CMD(1) DSTPORT(2) DSTIP(4). Bulk read.
    let mut hdr = [0u8; 8];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != 0x04 {
        anyhow::bail!("expected SOCKS4, got version: {}", hdr[0]);
    }
    let cmd = hdr[1];
    if cmd != 0x01 {
        // Only CONNECT (0x01) is supported, not BIND (0x02).
        let reply = [0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // rejected
        client.write_all(&reply).await?;
        anyhow::bail!("SOCKS4 unsupported command: {}", cmd);
    }
    let port = u16::from_be_bytes([hdr[2], hdr[3]]);
    let ip_bytes: [u8; 4] = [hdr[4], hdr[5], hdr[6], hdr[7]];

    // Read userid (null-terminated). Max 256 bytes; we discard the content.
    // This is still byte-by-byte but the userid is typically empty (just a
    // 0x00 terminator), so it's a single read in practice.
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
        let addr = dns_cache.resolve(&domain, port).await?;
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

    // SOCKS4 success reply: VN=0x00 CD=0x5A DSTPORT(2) DSTIP(4) = 8 bytes, stack buf.
    let mut reply = [0u8; 8];
    reply[0] = 0x00;
    reply[1] = 0x5A;
    reply[2..4].copy_from_slice(&port.to_be_bytes());
    reply[4..8].copy_from_slice(&ip_bytes);
    client.write_all(&reply).await?;

    // Relay with desync.
    relay::relay_with_desync(client, upstream, target_addr, domain.as_deref(), selector, stealth).await?;
    Ok(())
}
