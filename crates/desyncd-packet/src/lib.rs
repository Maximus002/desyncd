pub mod tls;
pub mod http;
pub mod quic;

use desyncd_types::AppProtocol;

// Re-export for consumers that need incremental parsing.
pub use tls::ParseStatus;

/// Attempt to detect the application-layer protocol from a raw payload.
///
/// This examines the first bytes of the payload (the TCP/UDP payload,
/// not including IP or transport headers) and returns the detected protocol.
///
/// Note: This assumes the payload is complete. For handling partial reads,
/// use `tls::try_parse_client_hello()` directly.
pub fn detect_protocol(payload: &[u8]) -> AppProtocol {
    // Try TLS ClientHello first (most common for HTTPS).
    if let Some(proto) = tls::parse_client_hello(payload) {
        return proto;
    }

    // Try HTTP request.
    if let Some(proto) = http::parse_http_request(payload) {
        return proto;
    }

    // Try QUIC Initial.
    if let Some(proto) = quic::parse_quic_initial(payload) {
        return proto;
    }

    AppProtocol::Unknown
}

/// Find the appropriate split position for a given protocol detection result.
pub fn default_split_offset(proto: &AppProtocol) -> Option<usize> {
    match proto {
        AppProtocol::TlsClientHello {
            sni_offset, sni: Some(_), ..
        } => {
            Some(*sni_offset)
        }
        AppProtocol::HttpRequest {
            host_offset, host: Some(_), ..
        } => {
            Some(*host_offset)
        }
        _ => None,
    }
}
