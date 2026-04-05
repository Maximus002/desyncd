//! Raw IP/TCP packet parsing and construction.
//!
//! Provides helpers for parsing intercepted packets and rebuilding them
//! after payload modification.

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
}
