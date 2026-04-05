//! Per-connection state tracking for SOCKS proxy mode.
//!
//! In SOCKS mode, we operate on application-layer sockets and the OS
//! handles TCP seq/ack/retransmit. Our state tracking focuses on:
//!
//! - Whether desync has been applied to this connection
//! - Whether the connection succeeded after desync (for logging/telemetry)
//! - Bytes transferred (for detecting stalls that may indicate DPI slowdown)
//!
//! Shared via `Arc` between the two relay directions, so all mutators
//! take `&self` and use atomics.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// State of a single proxied connection.
#[derive(Debug)]
pub struct ConnState {
    /// Whether we've applied desync techniques to the first outbound data.
    pub desync_applied: AtomicBool,
    /// When the connection was established.
    pub started_at: Instant,
    /// Whether the upstream connection succeeded (got response data).
    pub upstream_responded: AtomicBool,
    /// Total bytes sent to upstream.
    pub bytes_sent: AtomicU64,
    /// Total bytes received from upstream.
    pub bytes_received: AtomicU64,
}

impl Default for ConnState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnState {
    /// Create a new connection state.
    pub fn new() -> Self {
        Self {
            desync_applied: AtomicBool::new(false),
            started_at: Instant::now(),
            upstream_responded: AtomicBool::new(false),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// Record that desync was applied.
    pub fn mark_desync_applied(&self) {
        self.desync_applied.store(true, Ordering::Relaxed);
    }

    /// Record that we got a response from upstream.
    pub fn mark_upstream_responded(&self) {
        self.upstream_responded.store(true, Ordering::Relaxed);
    }

    /// Add to bytes sent counter.
    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Add to bytes received counter.
    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Whether the connection appears successful.
    ///
    /// Returns true if either no desync was applied (passthrough — always "ok"),
    /// or desync was applied AND upstream responded (desync didn't break it).
    /// Returns false only when desync was applied but upstream never responded,
    /// suggesting the technique broke the connection.
    pub fn is_success(&self) -> bool {
        !self.desync_applied.load(Ordering::Relaxed)
            || self.upstream_responded.load(Ordering::Relaxed)
    }

    /// Connection duration so far.
    pub fn elapsed(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}
