//! Per-connection state tracking for NFQ mode.
//!
//! In NFQ mode we intercept raw packets, so we need to track TCP state:
//! - Sequence/ACK numbers to detect retransmits
//! - Whether we've already modified this connection's first data packet
//! - What we injected, so we don't re-inject on retransmit
//!
//! This is NOT a full TCP reassembly engine — we only track enough
//! to make correct desync decisions on the first data packet.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

/// Key for identifying a TCP connection (4-tuple, direction implied by src/dst order).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// State of a tracked connection in NFQ mode.
#[derive(Debug)]
pub struct NfqConnState {
    /// TCP sequence number of the first data packet we modified.
    pub first_data_seq: Option<u32>,
    /// Whether we've already applied desync to this connection.
    pub desync_applied: bool,
    /// The desync action we took, so retransmits get the same treatment.
    pub applied_action: AppliedAction,
    /// When this connection was first seen.
    pub first_seen: Instant,
    /// Last packet timestamp (for expiry).
    pub last_seen: Instant,
}

/// What action we applied (stored to handle retransmits consistently).
#[derive(Debug, Clone)]
pub enum AppliedAction {
    /// Haven't applied anything yet.
    None,
    /// Passed through without modification.
    PassThrough,
    /// Replaced the payload. Store the modified packet so retransmits match.
    Replaced,
    /// Applied split/inject. On retransmit, just accept the original
    /// since the first segments already went out.
    SplitOrInject,
}

/// Connection tracker for NFQ mode.
pub struct ConnTracker {
    connections: HashMap<ConnKey, NfqConnState>,
    /// Maximum tracked connections before LRU eviction.
    max_connections: usize,
}

impl ConnTracker {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
        }
    }

    /// Get or create state for a connection.
    pub fn get_or_create(&mut self, key: &ConnKey) -> &mut NfqConnState {
        // Evict old entries if we're at capacity.
        if !self.connections.contains_key(key) && self.connections.len() >= self.max_connections {
            self.evict_oldest();
        }

        self.connections
            .entry(key.clone())
            .or_insert_with(|| NfqConnState {
                first_data_seq: None,
                desync_applied: false,
                applied_action: AppliedAction::None,
                first_seen: Instant::now(),
                last_seen: Instant::now(),
            })
    }

    /// Check if a packet is a retransmit of a packet we already processed.
    ///
    /// A retransmit has the same sequence number as the first data packet.
    pub fn is_retransmit(&self, key: &ConnKey, seq: u32) -> bool {
        if let Some(state) = self.connections.get(key) {
            if let Some(first_seq) = state.first_data_seq {
                return state.desync_applied && seq == first_seq;
            }
        }
        false
    }

    /// Record that we applied desync to a connection.
    pub fn mark_applied(&mut self, key: &ConnKey, seq: u32, action: AppliedAction) {
        if let Some(state) = self.connections.get_mut(key) {
            state.first_data_seq = Some(seq);
            state.desync_applied = true;
            state.applied_action = action;
            state.last_seen = Instant::now();
        }
    }

    /// Remove expired connections (older than 5 minutes with no activity).
    pub fn cleanup_expired(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(300);
        self.connections.retain(|_, state| state.last_seen > cutoff);
    }

    /// Evict the oldest connection to make room.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .connections
            .iter()
            .min_by_key(|(_, state)| state.last_seen)
            .map(|(key, _)| key.clone())
        {
            self.connections.remove(&oldest_key);
        }
    }

    /// Number of tracked connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether the tracker has no connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn make_key(src_port: u16, dst_port: u16) -> ConnKey {
        ConnKey {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), src_port)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), dst_port)),
        }
    }

    #[test]
    fn test_new_connection() {
        let mut tracker = ConnTracker::new(100);
        let key = make_key(12345, 443);

        let state = tracker.get_or_create(&key);
        assert!(!state.desync_applied);
        assert!(state.first_data_seq.is_none());
    }

    #[test]
    fn test_retransmit_detection() {
        let mut tracker = ConnTracker::new(100);
        let key = make_key(12345, 443);

        tracker.get_or_create(&key);
        assert!(!tracker.is_retransmit(&key, 1000));

        tracker.mark_applied(&key, 1000, AppliedAction::SplitOrInject);
        assert!(tracker.is_retransmit(&key, 1000));
        assert!(!tracker.is_retransmit(&key, 2000)); // Different seq.
    }

    #[test]
    fn test_eviction() {
        let mut tracker = ConnTracker::new(3);

        for port in 1..=3 {
            tracker.get_or_create(&make_key(port, 443));
        }
        assert_eq!(tracker.len(), 3);

        // Adding a 4th should evict one.
        tracker.get_or_create(&make_key(4, 443));
        assert_eq!(tracker.len(), 3);
    }
}
