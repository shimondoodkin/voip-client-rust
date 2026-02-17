/// Adaptive jitter buffer for RTP audio.
///
/// Uses a BTreeMap keyed by RTP sequence number to reorder packets.
/// Adapts target buffer depth based on RFC 3550 jitter estimation.

use std::collections::BTreeMap;

/// A buffered RTP packet.
pub struct JitterPacket {
    pub seq: u16,
    pub timestamp: u32,
    pub payload: Vec<u8>,
}

/// Adaptive jitter buffer.
pub struct JitterBuffer {
    packets: BTreeMap<u16, JitterPacket>,
    /// Next expected sequence number to play out.
    playout_seq: u16,
    /// Whether playout_seq has been initialized.
    started: bool,
    /// Target buffer depth in packets.
    target_depth: usize,
    /// Maximum buffer depth in packets.
    max_depth: usize,
    /// RFC 3550 interarrival jitter estimate (in timestamp units).
    jitter_estimate: f64,
    /// Last received RTP timestamp (for jitter calculation).
    last_rx_ts: u32,
    /// Last receive time in ms (monotonic).
    last_rx_time: Option<std::time::Instant>,
    /// Packets received since last adaptation.
    adapt_counter: u32,
    /// Total packets received.
    pub stats_received: u64,
    /// Packets lost (gaps in sequence).
    pub stats_lost: u64,
    /// Packets dropped (too old / duplicate).
    pub stats_dropped: u64,
    /// Clock rate for timestamp->ms conversion.
    clock_rate: u32,
}

impl JitterBuffer {
    /// Create a new jitter buffer.
    ///
    /// `clock_rate`: RTP clock rate (e.g., 8000 for G.722/G.711, 48000 for Opus)
    pub fn new(clock_rate: u32) -> Self {
        Self {
            packets: BTreeMap::new(),
            playout_seq: 0,
            started: false,
            target_depth: 3,  // 3 packets = 60ms at 20ms ptime
            max_depth: 10,    // 10 packets = 200ms
            jitter_estimate: 0.0,
            last_rx_ts: 0,
            last_rx_time: None,
            adapt_counter: 0,
            stats_received: 0,
            stats_lost: 0,
            stats_dropped: 0,
            clock_rate,
        }
    }

    /// Push a received RTP packet into the buffer.
    pub fn push(&mut self, seq: u16, timestamp: u32, payload: Vec<u8>) {
        self.stats_received += 1;

        // Update jitter estimate (RFC 3550 A.8)
        let now = std::time::Instant::now();
        if let Some(last_time) = self.last_rx_time {
            let arrival_diff_ms = now.duration_since(last_time).as_secs_f64() * 1000.0;
            let ts_diff = timestamp.wrapping_sub(self.last_rx_ts) as f64
                / self.clock_rate as f64 * 1000.0;
            let d = (arrival_diff_ms - ts_diff).abs();
            self.jitter_estimate += (d - self.jitter_estimate) / 16.0;
        }
        self.last_rx_ts = timestamp;
        self.last_rx_time = Some(now);

        if !self.started {
            self.playout_seq = seq;
            self.started = true;
        }

        // Drop if too old (behind playout pointer with wrapping)
        let age = seq.wrapping_sub(self.playout_seq) as i16;
        if age < 0 {
            self.stats_dropped += 1;
            return;
        }

        // Drop if buffer is too full
        if self.packets.len() >= self.max_depth {
            self.stats_dropped += 1;
            return;
        }

        self.packets.insert(seq, JitterPacket { seq, timestamp, payload });

        // Adaptation
        self.adapt_counter += 1;
        if self.adapt_counter >= 50 {
            self.adapt();
            self.adapt_counter = 0;
        }
    }

    /// Pop the next in-sequence packet for playout.
    ///
    /// Returns `None` if no packet available (PLC opportunity).
    /// The caller should send silence/PLC when None is returned.
    pub fn pop(&mut self) -> Option<JitterPacket> {
        if !self.started {
            return None;
        }

        // Wait until we have enough packets buffered
        if self.packets.len() < self.target_depth.min(2) && self.stats_received < self.target_depth as u64 {
            return None;
        }

        let pkt = self.packets.remove(&self.playout_seq);
        if pkt.is_none() {
            self.stats_lost += 1;
        }
        self.playout_seq = self.playout_seq.wrapping_add(1);
        pkt
    }

    /// Adapt target buffer depth based on jitter estimate.
    fn adapt(&mut self) {
        // Convert jitter from ms to packets (at 20ms per packet)
        let jitter_packets = (self.jitter_estimate / 20.0).ceil() as usize;
        let new_depth = (jitter_packets + 1).clamp(2, self.max_depth);

        if new_depth != self.target_depth {
            tracing::debug!(
                "Jitter buffer adapt: depth {} -> {}, jitter={:.1}ms",
                self.target_depth, new_depth, self.jitter_estimate
            );
            self.target_depth = new_depth;
        }
    }

    /// Get current jitter estimate in milliseconds.
    pub fn jitter_ms(&self) -> f64 {
        self.jitter_estimate
    }

    /// Get current buffer depth (number of packets).
    pub fn depth(&self) -> usize {
        self.packets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_buffer_in_order() {
        let mut jb = JitterBuffer::new(8000);

        // Push 5 packets in order
        for i in 0u16..5 {
            jb.push(i, i as u32 * 160, vec![i as u8; 160]);
        }

        assert_eq!(jb.depth(), 5);

        // Pop should return them in order
        for i in 0u16..5 {
            let pkt = jb.pop().unwrap();
            assert_eq!(pkt.seq, i);
        }

        // No more packets
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_out_of_order() {
        let mut jb = JitterBuffer::new(8000);

        // Push out of order: 0, 2, 1, 3
        jb.push(0, 0, vec![0; 160]);
        jb.push(2, 320, vec![2; 160]);
        jb.push(1, 160, vec![1; 160]);
        jb.push(3, 480, vec![3; 160]);

        // Should pop in order
        assert_eq!(jb.pop().unwrap().seq, 0);
        assert_eq!(jb.pop().unwrap().seq, 1);
        assert_eq!(jb.pop().unwrap().seq, 2);
        assert_eq!(jb.pop().unwrap().seq, 3);
    }

    #[test]
    fn test_jitter_buffer_missing_packet() {
        let mut jb = JitterBuffer::new(8000);

        // Push 0, 2 (skip 1)
        jb.push(0, 0, vec![0; 160]);
        jb.push(2, 320, vec![2; 160]);
        jb.push(3, 480, vec![3; 160]);

        assert_eq!(jb.pop().unwrap().seq, 0);
        // Seq 1 is missing
        assert!(jb.pop().is_none());
        assert_eq!(jb.stats_lost, 1);
        // Seq 2 should be next
        assert_eq!(jb.pop().unwrap().seq, 2);
    }

    #[test]
    fn test_jitter_buffer_duplicate() {
        let mut jb = JitterBuffer::new(8000);

        jb.push(0, 0, vec![0; 160]);
        jb.push(0, 0, vec![0; 160]); // duplicate
        jb.push(1, 160, vec![1; 160]);

        // Buffer should only have 2 unique packets
        assert_eq!(jb.depth(), 2);
    }

    #[test]
    fn test_jitter_buffer_late_packet() {
        let mut jb = JitterBuffer::new(8000);

        jb.push(0, 0, vec![0; 160]);
        jb.push(1, 160, vec![1; 160]);
        let _ = jb.pop(); // pop seq 0
        let _ = jb.pop(); // pop seq 1

        // Late packet (seq 0 arrives after playout)
        jb.push(0, 0, vec![0; 160]);
        assert_eq!(jb.stats_dropped, 1);
    }
}
