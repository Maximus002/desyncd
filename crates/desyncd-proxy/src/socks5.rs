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

    let nmethods = client.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    client.read_exact(&mut methods).await?;

    // We only support "no authentication".
    if !methods.contains(&AUTH_NONE) {
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
            let mut domain_bytes = vec![0u8; len];
            client.read_exact(&mut domain_bytes).await?;
            let port = client.read_u16().await?;
            let domain = String::from_utf8(domain_bytes)?;

            // Resolve domain, preferring IPv4 over IPv6.
            let addr_str = format!("{}:{}", domain, port);
            let addrs: Vec<SocketAddr> = lookup_host(&addr_str).await?.collect();
            let addr = addrs
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| addrs.first())
                .copied()
                .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}", domain))?;

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
    relay::relay_with_desync(client, upstream, domain.as_deref(), selector, stealth).await?;

    Ok(())
}

/// Send a SOCKS5 reply to the client.
async fn send_reply(client: &mut TcpStream, reply: u8, atyp: u8) -> anyhow::Result<()> {
    let mut response = vec![SOCKS_VERSION, reply, 0x00];

    match atyp {
        ATYP_IPV4 | ATYP_DOMAIN => {
            response.push(ATYP_IPV4);
            response.extend_from_slice(&[0, 0, 0, 0]); // BND.ADDR
            response.extend_from_slice(&[0, 0]); // BND.PORT
        }
        ATYP_IPV6 => {
            response.push(ATYP_IPV6);
            response.extend_from_slice(&[0u8; 16]); // BND.ADDR
            response.extend_from_slice(&[0, 0]); // BND.PORT
        }
        _ => {
            response.push(ATYP_IPV4);
            response.extend_from_slice(&[0, 0, 0, 0]);
            response.extend_from_slice(&[0, 0]);
        }
    }

    client.write_all(&response).await?;
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

    // Read userid (null-terminated).
    let mut userid = Vec::new();
    loop {
        let b = client.read_u8().await?;
        if b == 0x00 {
            break;
        }
        userid.push(b);
        if userid.len() > 255 {
            anyhow::bail!("SOCKS4 userid too long");
        }
    }

    // SOCKS4a: if IP is 0.0.0.x (x != 0), read domain after userid.
    let is_socks4a = ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0;

    let (target_addr, domain) = if is_socks4a {
        // Read domain name (null-terminated).
        let mut domain_bytes = Vec::new();
        loop {
            let b = client.read_u8().await?;
            if b == 0x00 {
                break;
            }
            domain_bytes.push(b);
            if domain_bytes.len() > 255 {
                anyhow::bail!("SOCKS4a domain too long");
            }
        }
        let domain = String::from_utf8(domain_bytes)?;
        let addr_str = format!("{}:{}", domain, port);
        let addrs: Vec<SocketAddr> = lookup_host(&addr_str).await?.collect();
        let addr = addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}", domain))?;
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
    relay::relay_with_desync(client, upstream, domain.as_deref(), selector, stealth).await?;
    Ok(())
}
