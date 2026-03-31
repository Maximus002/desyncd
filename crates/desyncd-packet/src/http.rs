//! HTTP/1.x request parser.
//!
//! Extracts the Host header and its byte offset for DPI bypass techniques.

use desyncd_types::AppProtocol;

/// HTTP methods we recognize.
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
];

/// Attempt to parse an HTTP/1.x request from the given payload.
///
/// Returns `Some(AppProtocol::HttpRequest { ... })` if the payload starts
/// with a known HTTP method and contains headers. Returns `None` otherwise.
pub fn parse_http_request(data: &[u8]) -> Option<AppProtocol> {
    // Check if data starts with a known HTTP method.
    let method = HTTP_METHODS
        .iter()
        .find(|m| data.starts_with(m))?;

    let method_str = std::str::from_utf8(&method[..method.len() - 1])
        .ok()?
        .to_string();

    // Find the Host header.
    let (host, host_offset) = find_host_header(data);

    Some(AppProtocol::HttpRequest {
        method: method_str,
        host,
        host_offset,
    })
}

/// Search for the `Host:` header in HTTP data.
///
/// Returns `(Some(host_value), offset)` where offset is the byte position
/// of the host value within the data. Case-insensitive header name search.
fn find_host_header(data: &[u8]) -> (Option<String>, usize) {
    // Find \r\n to skip the request line.
    let mut pos = 0;
    while pos + 1 < data.len() {
        if data[pos] == b'\r' && data[pos + 1] == b'\n' {
            pos += 2;
            break;
        }
        pos += 1;
    }

    // Walk headers looking for Host.
    while pos + 1 < data.len() {
        // End of headers?
        if data[pos] == b'\r' && data[pos + 1] == b'\n' {
            break;
        }

        // Find the colon.
        let header_start = pos;
        let mut colon_pos = None;
        while pos < data.len() && data[pos] != b'\r' {
            if data[pos] == b':' && colon_pos.is_none() {
                colon_pos = Some(pos);
            }
            pos += 1;
        }

        if let Some(cp) = colon_pos {
            let name = &data[header_start..cp];
            if name.eq_ignore_ascii_case(b"Host") {
                // Skip colon and optional whitespace.
                let mut value_start = cp + 1;
                while value_start < pos && data[value_start] == b' ' {
                    value_start += 1;
                }
                let value_end = pos;
                let host = std::str::from_utf8(&data[value_start..value_end])
                    .ok()
                    .map(|s| s.trim().to_string());
                return (host, value_start);
            }
        }

        // Skip \r\n.
        if pos + 1 < data.len() && data[pos] == b'\r' && data[pos + 1] == b'\n' {
            pos += 2;
        } else {
            break;
        }
    }

    (None, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_request() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let result = parse_http_request(data);
        match result {
            Some(AppProtocol::HttpRequest { method, host, host_offset }) => {
                assert_eq!(method, "GET");
                assert_eq!(host.as_deref(), Some("example.com"));
                assert!(host_offset > 0);
                let extracted = &data[host_offset..host_offset + "example.com".len()];
                assert_eq!(extracted, b"example.com");
            }
            other => panic!("expected HttpRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_non_http_data() {
        let data = &[0x16, 0x03, 0x01, 0x00, 0x05];
        assert!(parse_http_request(data).is_none());
    }

    #[test]
    fn test_post_request_no_host() {
        let data = b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
        let result = parse_http_request(data);
        match result {
            Some(AppProtocol::HttpRequest { method, host, .. }) => {
                assert_eq!(method, "POST");
                assert!(host.is_none());
            }
            other => panic!("expected HttpRequest, got {:?}", other),
        }
    }
}
