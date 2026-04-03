use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Direction of intercepted packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Outbound,
    Inbound,
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportProto {
    Tcp,
    Udp,
}

/// Application-layer protocol detected in a packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProtocol {
    /// TLS ClientHello with optional SNI.
    TlsClientHello {
        sni: Option<String>,
        /// Byte offset of the SNI value within the TLS payload.
        sni_offset: usize,
        /// Length of the SNI value.
        sni_len: usize,
    },
    /// HTTP/1.x request.
    HttpRequest {
        method: String,
        host: Option<String>,
        /// Byte offset of the Host header value within the HTTP payload.
        host_offset: usize,
    },
    /// QUIC Initial packet.
    QuicInitial {
        dcid: Vec<u8>,
        scid: Vec<u8>,
    },
    /// Protocol not recognized or not relevant.
    Unknown,
}

/// Uniquely identifies a network connection (5-tuple).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub proto: TransportProto,
}

/// Operating mode for the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Mode {
    /// SOCKS5 proxy mode (no elevated privileges needed).
    #[default]
    Socks,
    /// Netfilter queue mode (Linux, requires root).
    Nfq,
    /// Transparent proxy mode (requires firewall rules).
    Transparent,
    /// Hybrid: SOCKS + NFQ for critical domains.
    Hybrid,
}


/// Position within a packet/payload where a split should occur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum SplitPosition {
    /// Absolute byte offset from the start of the application payload.
    Absolute(usize),
    /// Split right before the SNI value in TLS ClientHello.
    #[default]
    Sni,
    /// Split at SNI offset + N (can be negative via wrapping).
    SniOffset(i32),
    /// Random offset within the given range.
    Random { min: usize, max: usize },
}


/// Stealth configuration for anti-detection and anti-ML features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub struct StealthConfig {
    /// Jitter ±N bytes applied to split position (0 = disabled).
    #[serde(default)]
    pub split_jitter: u8,
    /// Delay between segments in microseconds (0 = disabled).
    #[serde(default)]
    pub timing_jitter_us: u32,
    /// Range for fake TLS record size randomization (None = fixed 64 bytes).
    #[serde(default)]
    pub fake_size_range: Option<(usize, usize)>,
    /// Add random TLS padding extension to vary packet size.
    #[serde(default)]
    pub randomize_tls_padding: bool,
}


/// How to make a fake packet undeliverable to the real server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FakeType {
    /// Corrupt TCP checksum.
    BadChecksum,
    /// Set TTL so packet expires before reaching server.
    BadTtl,
    /// Add TCP MD5 signature option (Linux servers drop these).
    BadMd5Sig,
    /// Use incorrect TCP sequence number.
    BadSeq,
}

/// Result of applying a desync technique.
#[derive(Debug, Clone)]
pub enum DesyncAction {
    /// Do not modify the data.
    PassThrough,
    /// Replace the original data with this.
    Replace(Vec<u8>),
    /// Split into multiple chunks to be sent separately.
    Split(Vec<Vec<u8>>),
    /// Inject these chunks before sending the original data.
    InjectBefore(Vec<Vec<u8>>),
}

/// Error types for the desyncd project.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("packet parse error: {0}")]
    PacketParse(String),

    #[error("technique not applicable: {0}")]
    NotApplicable(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Resolved target for a proxied connection.
#[derive(Debug, Clone)]
pub struct ProxyTarget {
    pub domain: Option<String>,
    pub addr: SocketAddr,
}

impl std::fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref domain) = self.domain {
            write!(f, "{}:{}", domain, self.addr.port())
        } else {
            write!(f, "{}", self.addr)
        }
    }
}
