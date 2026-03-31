//! Platform abstraction layer for packet interception.
//!
//! Provides traits for intercepting network packets at the OS level
//! (Linux nfqueue, Windows WinDivert, macOS pf/divert) and managing
//! firewall rules.

pub mod firewall;

use desyncd_types::Direction;

/// A packet intercepted from the network stack.
#[derive(Debug, Clone)]
pub struct InterceptedPacket {
    /// Unique ID for this packet (used to send verdict).
    pub id: u32,
    /// Raw packet data (IP header + payload).
    pub data: Vec<u8>,
    /// Direction of the packet.
    pub direction: Direction,
}

/// Verdict to apply to an intercepted packet.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Accept the packet unchanged.
    Accept,
    /// Drop the packet.
    Drop,
    /// Replace the packet data with new content.
    Modify(Vec<u8>),
}

/// Trait for platform-specific packet interception.
///
/// Implementations receive packets from the kernel, allow inspection
/// and modification, then send a verdict back.
#[async_trait::async_trait]
pub trait PacketInterceptor: Send + Sync {
    /// Start intercepting packets (bind to queue, install hooks, etc.).
    async fn start(&mut self) -> anyhow::Result<()>;

    /// Receive the next intercepted packet. Blocks until one is available.
    async fn recv_packet(&mut self) -> anyhow::Result<InterceptedPacket>;

    /// Send a verdict for a previously received packet.
    async fn send_verdict(
        &mut self,
        id: u32,
        verdict: Verdict,
        data: Option<&[u8]>,
    ) -> anyhow::Result<()>;

    /// Stop intercepting and clean up.
    async fn stop(&mut self) -> anyhow::Result<()>;
}
