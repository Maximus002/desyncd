//! Raw IP/TCP and IP/UDP packet parsing and construction.
//!
//! Provides helpers for parsing intercepted packets and rebuilding them
//! after payload modification. TCP is the main path (used by all desync
//! techniques); UDP parsing exists so the NFQ loop can recognise and drop
//! QUIC Initial packets to force HTTP/3 fallback to TCP+TLS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Parsed TCP packet info (extracted from raw IP packet).
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    /// Offset of the TCP payload within the original packet data.
    pub payload_offset: usize,
    /// The TCP payload (application data).
    pub payload: &'a [u8],
    /// IP header length.
    pub ip_header_len: usize,
    /// TCP header length.
    pub tcp_header_len: usize,
    /// Raw TCP sequence number.
    pub seq: u32,
    /// Raw TCP acknowledgment number.
    pub ack: u32,
}

/// Parsed UDP packet info (extracted from raw IP packet).
#[derive(Debug)]
pub struct ParsedUdpPacket<'a> {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    /// The UDP payload (application data — e.g. a QUIC Initial packet).
    pub payload: &'a [u8],
}

impl<'a> ParsedPacket<'a> {
    /// Get the TCP sequence number.
    pub fn tcp_seq(&self) -> u32 {
        self.seq
    }
}

/// Parse an IPv4+TCP packet, returning header info and payload reference.
pub fn parse_ip_tcp(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 20 {
        return None; // Too short for IP header.
    }

    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return None; // Only IPv4 for now.
    }

    let ip_header_len = ((data[0] & 0xF) as usize) * 4;
    if ip_header_len < 20 || data.len() < ip_header_len {
        return None;
    }

    let protocol = data[9];
    if protocol != 6 {
        return None; // Not TCP.
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let tcp_start = ip_header_len;
    if data.len() < tcp_start + 20 {
        return None; // Too short for TCP header.
    }

    let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);

    // TCP sequence and acknowledgment numbers.
    let seq = u32::from_be_bytes([
        data[tcp_start + 4],
        data[tcp_start + 5],
        data[tcp_start + 6],
        data[tcp_start + 7],
    ]);
    let ack = u32::from_be_bytes([
        data[tcp_start + 8],
        data[tcp_start + 9],
        data[tcp_start + 10],
        data[tcp_start + 11],
    ]);

    let tcp_data_offset = ((data[tcp_start + 12] >> 4) & 0xF) as usize * 4;

    if tcp_data_offset < 20 {
        return None;
    }

    let payload_offset = tcp_start + tcp_data_offset;
    let payload = if payload_offset < data.len() {
        &data[payload_offset..]
    } else {
        &[]
    };

    Some(ParsedPacket {
        src_addr: SocketAddr::new(IpAddr::V4(src_ip), src_port),
        dst_addr: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
        payload_offset,
        payload,
        ip_header_len,
        tcp_header_len: tcp_data_offset,
        seq,
        ack,
    })
}

/// Parse an IPv4+UDP packet, returning endpoints and the UDP payload.
///
/// Returns `None` if the packet is not a well-formed IPv4+UDP packet. Used
/// by the NFQ loop to recognise outbound QUIC Initial packets so they can
/// be dropped to force HTTP/3 fallback to TCP+TLS (where our desync
/// techniques apply).
pub fn parse_ip_udp(data: &[u8]) -> Option<ParsedUdpPacket<'_>> {
    // IP header: at least 20 bytes.
    if data.len() < 20 {
        return None;
    }

    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return None;
    }

    let ip_header_len = ((data[0] & 0xF) as usize) * 4;
    if ip_header_len < 20 || data.len() < ip_header_len {
        return None;
    }

    // Protocol 17 = UDP.
    if data[9] != 17 {
        return None;
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    // UDP header is a flat 8 bytes: src port(2) dst port(2) length(2) checksum(2).
    let udp_start = ip_header_len;
    if data.len() < udp_start + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);

    let payload_start = udp_start + 8;
    let payload = if payload_start < data.len() {
        &data[payload_start..]
    } else {
        &[]
    };

    Some(ParsedUdpPacket {
        src_addr: SocketAddr::new(IpAddr::V4(src_ip), src_port),
        dst_addr: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
        payload,
    })
}

/// Rebuild a raw IP+TCP packet with a new payload.
///
/// Recalculates IP total length and both IP and TCP checksums.
pub fn rebuild_packet(
    original: &[u8],
    parsed: &ParsedPacket<'_>,
    new_payload: &[u8],
) -> Option<Vec<u8>> {
    let header_len = parsed.payload_offset;
    if original.len() < header_len {
        return None;
    }

    let mut packet = Vec::with_capacity(header_len + new_payload.len());
    packet.extend_from_slice(&original[..header_len]);
    packet.extend_from_slice(new_payload);

    // Update IP total length.
    let total_len = packet.len() as u16;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = total_len as u8;

    // Recalculate IP header checksum.
    packet[10] = 0;
    packet[11] = 0;
    let ip_checksum = compute_checksum(&packet[..parsed.ip_header_len]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = ip_checksum as u8;

    // Recalculate TCP checksum.
    let tcp_start = parsed.ip_header_len;
    packet[tcp_start + 16] = 0;
    packet[tcp_start + 17] = 0;
    let tcp_checksum = compute_tcp_checksum(&packet, parsed.ip_header_len);
    packet[tcp_start + 16] = (tcp_checksum >> 8) as u8;
    packet[tcp_start + 17] = tcp_checksum as u8;

    Some(packet)
}

/// Compute Internet checksum (RFC 1071).
fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute TCP checksum including pseudo-header.
///
/// Expects `packet` to be a full IPv4 + TCP packet with at least 20 bytes
/// of IP header (which contains src/dst IPs at offsets 12..20) followed by
/// the TCP segment starting at `ip_header_len`. Callers currently guarantee
/// this via `rebuild_packet`, but we bounds-check defensively so a truncated
/// packet returns `0` instead of panicking.
fn compute_tcp_checksum(packet: &[u8], ip_header_len: usize) -> u16 {
    // Need: IP header (≥20 bytes) for src/dst IPs, plus at least 20 bytes
    // of TCP header starting at `ip_header_len`.
    if packet.len() < 20 || packet.len() < ip_header_len + 20 {
        return 0;
    }

    let tcp_start = ip_header_len;
    let tcp_len = packet.len() - tcp_start;

    let mut sum: u32 = 0;

    // Pseudo-header: src IP, dst IP, zero, protocol(6), TCP length.
    sum += u16::from_be_bytes([packet[12], packet[13]]) as u32;
    sum += u16::from_be_bytes([packet[14], packet[15]]) as u32;
    sum += u16::from_be_bytes([packet[16], packet[17]]) as u32;
    sum += u16::from_be_bytes([packet[18], packet[19]]) as u32;
    sum += 6u32; // Protocol: TCP
    sum += tcp_len as u32;

    // TCP segment.
    let tcp_data = &packet[tcp_start..];
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        // Simple test: checksum of all zeros should be 0xFFFF.
        let data = [0u8; 20];
        assert_eq!(compute_checksum(&data), 0xFFFF);
    }

    #[test]
    fn test_parse_non_ip() {
        assert!(parse_ip_tcp(&[0x60, 0, 0, 0]).is_none()); // IPv6
        assert!(parse_ip_tcp(&[0x45]).is_none()); // Too short
    }

    /// Build a minimal IPv4 + UDP packet with the given payload.
    /// Returns the full packet buffer. No checksums are computed — the
    /// parser doesn't verify them.
    fn build_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let ip_header_len = 20;
        let udp_header_len = 8;
        let total_len = ip_header_len + udp_header_len + payload.len();
        let mut buf = vec![0u8; total_len];
        // IP version + IHL
        buf[0] = 0x45;
        // Total length (big-endian)
        buf[2] = (total_len >> 8) as u8;
        buf[3] = total_len as u8;
        // TTL
        buf[8] = 64;
        // Protocol: UDP = 17
        buf[9] = 17;
        // src IP: 10.0.0.1
        buf[12..16].copy_from_slice(&[10, 0, 0, 1]);
        // dst IP: 10.0.0.2
        buf[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // UDP header
        buf[20..22].copy_from_slice(&src_port.to_be_bytes());
        buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = (udp_header_len + payload.len()) as u16;
        buf[24..26].copy_from_slice(&udp_len.to_be_bytes());
        // checksum = 0 (optional on IPv4)
        buf[26..28].copy_from_slice(&[0, 0]);
        // payload
        buf[28..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn parse_udp_extracts_payload() {
        let payload = b"hello quic";
        let pkt = build_ipv4_udp(54321, 443, payload);
        let parsed = parse_ip_udp(&pkt).expect("should parse");
        assert_eq!(parsed.src_addr.port(), 54321);
        assert_eq!(parsed.dst_addr.port(), 443);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_udp_rejects_tcp_packet() {
        // Build an IP packet with protocol = 6 (TCP) and check UDP parser declines.
        let mut pkt = build_ipv4_udp(1234, 443, b"x");
        pkt[9] = 6; // TCP
        assert!(parse_ip_udp(&pkt).is_none());
    }

    #[test]
    fn parse_udp_too_short() {
        assert!(parse_ip_udp(&[]).is_none());
        assert!(parse_ip_udp(&[0x45; 19]).is_none());
        // Has IP header but no UDP header.
        let mut short = vec![0u8; 20];
        short[0] = 0x45;
        short[9] = 17;
        assert!(parse_ip_udp(&short).is_none());
    }
}
