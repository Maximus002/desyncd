//! HTTP Host Header manipulation technique.
//!
//! Modifies the Host header in HTTP/1.x requests to confuse DPI:
//!
//! - `MixedCase`: Randomize the case of "Host" header name (e.g., "hOsT:")
//! - `ExtraSpace`: Add extra whitespace after the colon ("Host:  value")
//! - `Tab`: Replace space with tab character ("Host:\tvalue")
//! - `LineWrapping`: Use HTTP line folding (deprecated in HTTP/1.1 but often accepted)
//! - `DuplicateHeader`: Add a second Host header with garbage
//!
//! These techniques exploit differences between DPI signature matching
//! and actual HTTP server parsing.

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Technique trait implementation for HTTP Host manipulation.
pub struct HttpHostTechnique;

impl Technique for HttpHostTechnique {
    fn name(&self) -> &'static str {
        "http_host"
    }

    fn apply(
        &self,
        ctx: &PayloadContext,
        _split_pos: &SplitPosition,
        config: &TechniqueConfig,
        _stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction> {
        let mode = config
            .host_mode
            .as_deref()
            .and_then(HostMode::from_str_opt)
            .unwrap_or_default();
        apply(ctx, mode)
    }
}

/// HTTP Host manipulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[derive(Default)]
pub enum HostMode {
    /// Randomize case of "Host" header name.
    #[default]
    MixedCase,
    /// Add extra spaces after the colon.
    ExtraSpace,
    /// Use tab character instead of space.
    Tab,
    /// Use obsolete HTTP line folding.
    LineWrapping,
    /// Add a duplicate Host header with garbage value.
    DuplicateHeader,
}

impl HostMode {
    /// Parse a mode from a string (case-insensitive).
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mixed_case" | "mixedcase" | "mixed" => Some(Self::MixedCase),
            "extra_space" | "extraspace" | "space" => Some(Self::ExtraSpace),
            "tab" => Some(Self::Tab),
            "line_wrapping" | "linewrapping" | "wrap" => Some(Self::LineWrapping),
            "duplicate_header" | "duplicateheader" | "duplicate" => Some(Self::DuplicateHeader),
            _ => None,
        }
    }
}


/// Apply HTTP Host header manipulation.
pub fn apply(ctx: &PayloadContext, mode: HostMode) -> Result<DesyncAction> {
    match &ctx.protocol {
        AppProtocol::HttpRequest { host: Some(_), .. } => {}
        _ => {
            return Err(desyncd_types::Error::NotApplicable(
                "http_host requires HTTP request with Host header".into(),
            ));
        }
    }

    let payload_str = match std::str::from_utf8(&ctx.payload) {
        Ok(s) => s,
        Err(_) => {
            return Err(desyncd_types::Error::NotApplicable(
                "HTTP payload is not valid UTF-8".into(),
            ));
        }
    };

    let new_payload = match mode {
        HostMode::MixedCase => apply_mixed_case_header(payload_str),
        HostMode::ExtraSpace => apply_extra_space(payload_str),
        HostMode::Tab => apply_tab(payload_str),
        HostMode::LineWrapping => apply_line_wrapping(payload_str),
        HostMode::DuplicateHeader => apply_duplicate_header(payload_str),
    };

    debug!(mode = ?mode, "http_host: applied host header manipulation");

    Ok(DesyncAction::Replace(new_payload.into_bytes()))
}

/// Randomize case of the "Host" header name.
fn apply_mixed_case_header(payload: &str) -> String {
    // Find "Host:" (case-insensitive) and replace with mixed case.
    let variants = ["hOsT", "HOST", "HoSt", "hoST", "HOst", "hosT"];
    let idx = fastrand::usize(..variants.len());
    let replacement = variants[idx];

    replace_header_name(payload, "host", replacement)
}

/// Add extra whitespace after the Host colon.
fn apply_extra_space(payload: &str) -> String {
    replace_host_line(payload, |name, value| {
        format!("{}:   {}", name, value)
    })
}

/// Use tab character after the Host colon.
fn apply_tab(payload: &str) -> String {
    replace_host_line(payload, |name, value| {
        format!("{}:\t{}", name, value)
    })
}

/// Use HTTP line folding (obs-fold): split Host value onto next line with leading whitespace.
fn apply_line_wrapping(payload: &str) -> String {
    replace_host_line(payload, |name, value| {
        format!("{}:\r\n {}", name, value)
    })
}

/// Add a duplicate Host header with garbage value after the real one.
fn apply_duplicate_header(payload: &str) -> String {
    replace_host_line(payload, |name, value| {
        format!("{}: {}\r\nHost: decoy.invalid", name, value)
    })
}

/// Replace the "Host" header name with a given replacement (case variation).
fn replace_header_name(payload: &str, search: &str, replacement: &str) -> String {
    let mut result = String::with_capacity(payload.len());
    let lower = payload.to_lowercase();

    if let Some(pos) = lower.find(&format!("\n{}:", search)) {
        result.push_str(&payload[..pos + 1]); // Include \n
        result.push_str(replacement);
        result.push_str(&payload[pos + 1 + search.len()..]);
    } else {
        result.push_str(payload);
    }

    result
}

/// Find and replace the entire Host header line using a formatting function.
fn replace_host_line<F>(payload: &str, format_fn: F) -> String
where
    F: Fn(&str, &str) -> String,
{
    let lines: Vec<&str> = payload.split("\r\n").collect();
    let mut result = Vec::new();

    let mut found = false;
    for line in &lines {
        if !found {
            if let Some(colon_pos) = line.find(':') {
                let name = &line[..colon_pos];
                if name.eq_ignore_ascii_case("Host") {
                    let value = line[colon_pos + 1..].trim();
                    result.push(format_fn(name, value));
                    found = true;
                    continue;
                }
            }
        }
        result.push(line.to_string());
    }

    result.join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_http_ctx(host: &str) -> PayloadContext {
        let payload = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\n\r\n",
            host
        );
        PayloadContext::new(payload.into_bytes())
    }

    #[test]
    fn test_mixed_case_header() {
        let ctx = make_http_ctx("example.com");
        let result = apply(&ctx, HostMode::MixedCase).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                let s = String::from_utf8(new_payload).unwrap();
                // Should contain the host value.
                assert!(s.contains("example.com"));
                // Header name should not be exactly "Host".
                assert!(!s.contains("\nHost:") || s.contains("HOST") || s.contains("hOsT"));
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_extra_space() {
        let ctx = make_http_ctx("example.com");
        let result = apply(&ctx, HostMode::ExtraSpace).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                let s = String::from_utf8(new_payload).unwrap();
                assert!(s.contains(":   example.com"));
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_tab() {
        let ctx = make_http_ctx("example.com");
        let result = apply(&ctx, HostMode::Tab).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                let s = String::from_utf8(new_payload).unwrap();
                assert!(s.contains(":\texample.com"));
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_duplicate_header() {
        let ctx = make_http_ctx("example.com");
        let result = apply(&ctx, HostMode::DuplicateHeader).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                let s = String::from_utf8(new_payload).unwrap();
                assert!(s.contains("decoy.invalid"));
                assert!(s.contains("example.com"));
            }
            _ => panic!("expected Replace"),
        }
    }
}
