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
    /// Split at the start of the SNI extension header (the `extension_type`
    /// field, 9 bytes before the SNI value). Equivalent to byedpi/zapret's
    /// `sniext+0` marker.
    SniExtStart,
    /// Split at the end of the second-level domain in the SNI value. For
    /// `www.twitter.com` this is the byte between `twitter` and `.com`.
    /// Equivalent to byedpi/zapret's `endsld+0` marker.
    EndSld,
    /// Split in the middle of the second-level domain in the SNI value.
    /// For `www.twitter.com` this falls inside `twitter`. Equivalent to
    /// byedpi/zapret's `midsld+0` marker. Useful for defeating DPI that
    /// pattern-matches on the SLD string.
    MidSld,
    /// Same as the named marker variants but with an additional signed
    /// byte offset ("tamper-start"). Lets operators nudge the split by a
    /// few bytes without re-building the enum externally.
    ///
    /// `OffsetFrom { marker: EndSld, delta: -2 }` picks a position two
    /// bytes before the end of the SLD.
    OffsetFrom {
        marker: Box<SplitPosition>,
        delta: i32,
    },
}


/// L7 (application-layer) filter for a single technique. When set, the
/// technique is only applied if the detected protocol matches.
///
/// Inspired by byedpi's `--filter-l7 {tls,http,any}`. Lets operators build
/// chains that apply different techniques to different protocols in one
/// strategy, e.g. `tls_record_frag` for HTTPS but `http_host` for plain HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L7Filter {
    /// Only apply if the payload is a TLS ClientHello.
    Tls,
    /// Only apply if the payload is an HTTP/1.x request.
    Http,
    /// Only apply if the payload is a QUIC Initial packet.
    Quic,
    /// Apply regardless of detected protocol.
    Any,
}

impl L7Filter {
    /// Check whether this filter matches the detected protocol.
    pub fn matches(&self, proto: &AppProtocol) -> bool {
        matches!(
            (self, proto),
            (L7Filter::Any, _)
                | (L7Filter::Tls, AppProtocol::TlsClientHello { .. })
                | (L7Filter::Http, AppProtocol::HttpRequest { .. })
                | (L7Filter::Quic, AppProtocol::QuicInitial { .. })
        )
    }
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
