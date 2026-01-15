use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};
use std::os::unix::io::AsRawFd;
use std::os::fd::AsFd;
use anyhow::Result;

const MAX_WINDOW_SIZE: u32 = 1048576;
const MIN_WINDOW_SIZE: u32 = 8192;
const WINDOW_SCALE_FACTOR: u8 = 7;
const RETRANSMIT_TIMEOUT_MS: u64 = 200;
const MAX_RETRANSMITS: u8 = 3;

#[derive(Debug, Clone)]
pub struct TcpWindowManager {
    current_window: u32,
    advertised_window: u32,
    scale_factor: u8,
    last_update: Instant,
    rtt_samples: VecDeque<Duration>,
    bandwidth_estimate: f64,
}

impl TcpWindowManager {
    pub fn new(initial_window: u32) -> Self {
        Self {
            current_window: initial_window,
            advertised_window: initial_window,
            scale_factor: WINDOW_SCALE_FACTOR,
            last_update: Instant::now(),
            rtt_samples: VecDeque::with_capacity(10),
            bandwidth_estimate: 0.0,
        }
    }

    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > 10 {
            self.rtt_samples.pop_front();
        }
    }

    pub fn get_average_rtt(&self) -> Duration {
        if self.rtt_samples.is_empty() {
            return Duration::from_millis(100);
        }
        
        let sum: Duration = self.rtt_samples.iter().sum();
        sum / self.rtt_samples.len() as u32
    }

    pub fn calculate_optimal_window(&mut self, bytes_in_flight: u32) -> u32 {
        let rtt = self.get_average_rtt();
        let rtt_secs = rtt.as_secs_f64();
        
        if rtt_secs > 0.0 && self.bandwidth_estimate > 0.0 {
            let bdp = (self.bandwidth_estimate * rtt_secs) as u32;
            let target = bdp.max(MIN_WINDOW_SIZE).min(MAX_WINDOW_SIZE);
            
            let adjustment = if bytes_in_flight > target {
                ((target as f64 * 0.95) as u32).max(MIN_WINDOW_SIZE)
            } else if bytes_in_flight < target / 2 {
                ((target as f64 * 1.05) as u32).min(MAX_WINDOW_SIZE)
            } else {
                target
            };
            
            adjustment
        } else {
            self.current_window
        }
    }

    pub fn update_window(&mut self, bytes_in_flight: u32) -> u32 {
        let optimal = self.calculate_optimal_window(bytes_in_flight);
        
        let delta = optimal as i64 - self.current_window as i64;
        let adjustment = (delta / 10).max(-4096).min(4096) as i32;
        
        self.current_window = ((self.current_window as i32 + adjustment) as u32)
            .max(MIN_WINDOW_SIZE)
            .min(MAX_WINDOW_SIZE);
        
        self.advertised_window = self.current_window << self.scale_factor;
        self.last_update = Instant::now();
        
        self.current_window
    }

    pub fn update_bandwidth(&mut self, bytes: u64, duration: Duration) {
        let duration_secs = duration.as_secs_f64();
        if duration_secs > 0.0 {
            let current_bw = bytes as f64 / duration_secs;
            
            if self.bandwidth_estimate == 0.0 {
                self.bandwidth_estimate = current_bw;
            } else {
                self.bandwidth_estimate = self.bandwidth_estimate * 0.8 + current_bw * 0.2;
            }
        }
    }

    pub fn get_current_window(&self) -> u32 {
        self.current_window
    }

    pub fn get_advertised_window(&self) -> u32 {
        self.advertised_window
    }
}

#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub timestamp: Instant,
    pub retransmit_count: u8,
}

impl TcpSegment {
    pub fn new(seq: u32, data: Vec<u8>) -> Self {
        Self {
            seq,
            data,
            timestamp: Instant::now(),
            retransmit_count: 0,
        }
    }

    pub fn should_retransmit(&self, timeout: Duration) -> bool {
        self.timestamp.elapsed() > timeout && self.retransmit_count < MAX_RETRANSMITS
    }

    pub fn mark_retransmit(&mut self) {
        self.retransmit_count += 1;
        self.timestamp = Instant::now();
    }
}

pub struct OutOfOrderBuffer {
    segments: BTreeMap<u32, Vec<u8>>,
    expected_seq: u32,
    max_size: usize,
}

impl OutOfOrderBuffer {
    pub fn new(initial_seq: u32, max_size: usize) -> Self {
        Self {
            segments: BTreeMap::new(),
            expected_seq: initial_seq,
            max_size,
        }
    }

    pub fn insert(&mut self, seq: u32, data: Vec<u8>) -> bool {
        if self.segments.len() >= self.max_size {
            return false;
        }

        if seq < self.expected_seq {
            return false;
        }

        self.segments.insert(seq, data);
        true
    }

    pub fn get_contiguous_data(&mut self) -> Option<Vec<u8>> {
        let mut result = Vec::new();
        let mut current_seq = self.expected_seq;

        loop {
            if let Some(data) = self.segments.remove(&current_seq) {
                current_seq += data.len() as u32;
                result.extend_from_slice(&data);
            } else {
                break;
            }
        }

        if result.is_empty() {
            None
        } else {
            self.expected_seq = current_seq;
            Some(result)
        }
    }

    pub fn has_data(&self) -> bool {
        !self.segments.is_empty()
    }

    pub fn update_expected_seq(&mut self, seq: u32) {
        self.expected_seq = seq;
    }
}

pub struct RetransmissionQueue {
    segments: VecDeque<TcpSegment>,
    timeout: Duration,
}

impl RetransmissionQueue {
    pub fn new() -> Self {
        Self {
            segments: VecDeque::new(),
            timeout: Duration::from_millis(RETRANSMIT_TIMEOUT_MS),
        }
    }

    pub fn add(&mut self, seq: u32, data: Vec<u8>) {
        let segment = TcpSegment::new(seq, data);
        self.segments.push_back(segment);
    }

    pub fn acknowledge(&mut self, ack_seq: u32) {
        self.segments.retain(|seg| {
            let end_seq = seg.seq.wrapping_add(seg.data.len() as u32);
            ack_seq < end_seq
        });
    }

    pub fn get_retransmits(&mut self) -> Vec<TcpSegment> {
        let mut retransmits = Vec::new();

        for segment in self.segments.iter_mut() {
            if segment.should_retransmit(self.timeout) {
                segment.mark_retransmit();
                retransmits.push(segment.clone());
            }
        }

        retransmits
    }

    pub fn update_timeout(&mut self, rtt: Duration) {
        let rto = rtt * 2;
        self.timeout = rto.max(Duration::from_millis(100)).min(Duration::from_secs(60));
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }
}

#[derive(Debug, Clone)]
pub struct SackBlock {
    pub left_edge: u32,
    pub right_edge: u32,
}

impl SackBlock {
    pub fn new(left: u32, right: u32) -> Self {
        Self {
            left_edge: left,
            right_edge: right,
        }
    }

    pub fn contains(&self, seq: u32) -> bool {
        seq >= self.left_edge && seq < self.right_edge
    }

    pub fn len(&self) -> u32 {
        self.right_edge.wrapping_sub(self.left_edge)
    }
}

pub struct SackManager {
    blocks: Vec<SackBlock>,
    max_blocks: usize,
}

impl SackManager {
    pub fn new(max_blocks: usize) -> Self {
        Self {
            blocks: Vec::with_capacity(max_blocks),
            max_blocks,
        }
    }

    pub fn add_block(&mut self, left: u32, right: u32) {
        let new_block = SackBlock::new(left, right);
        
        self.blocks.retain(|block| {
            !(new_block.left_edge <= block.left_edge && new_block.right_edge >= block.right_edge)
        });

        if self.blocks.len() < self.max_blocks {
            self.blocks.push(new_block);
            self.merge_adjacent_blocks();
        }
    }

    fn merge_adjacent_blocks(&mut self) {
        self.blocks.sort_by_key(|b| b.left_edge);
        
        let mut i = 0;
        while i + 1 < self.blocks.len() {
            if self.blocks[i].right_edge >= self.blocks[i + 1].left_edge {
                let right = self.blocks[i + 1].right_edge;
                self.blocks[i].right_edge = right;
                self.blocks.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    pub fn is_sacked(&self, seq: u32) -> bool {
        self.blocks.iter().any(|block| block.contains(seq))
    }

    pub fn get_blocks(&self) -> &[SackBlock] {
        &self.blocks
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }
}

pub fn configure_tcp_socket<F: AsRawFd + AsFd>(socket: &F) -> Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};
    
    setsockopt(socket, sockopt::TcpNoDelay, &true)?;
    setsockopt(socket, sockopt::ReuseAddr, &true)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_manager() {
        let mut wm = TcpWindowManager::new(65536);
        
        wm.update_rtt(Duration::from_millis(50));
        wm.update_bandwidth(1024 * 1024, Duration::from_secs(1));
        
        let new_window = wm.update_window(32768);
        assert!(new_window >= MIN_WINDOW_SIZE);
        assert!(new_window <= MAX_WINDOW_SIZE);
    }

    #[test]
    fn test_out_of_order_buffer() {
        let mut buffer = OutOfOrderBuffer::new(1000, 10);
        
        assert!(buffer.insert(1010, vec![1, 2, 3]));
        assert!(buffer.insert(1000, vec![4, 5, 6]));
        
        let data = buffer.get_contiguous_data().unwrap();
        assert_eq!(data, vec![4, 5, 6]);
        assert_eq!(buffer.expected_seq, 1003);
    }

    #[test]
    fn test_retransmission_queue() {
        let mut queue = RetransmissionQueue::new();
        
        queue.add(1000, vec![1, 2, 3]);
        queue.add(1003, vec![4, 5, 6]);
        
        assert_eq!(queue.len(), 2);
        
        queue.acknowledge(1003);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_sack_manager() {
        let mut sack = SackManager::new(4);
        
        sack.add_block(1000, 1010);
        sack.add_block(1020, 1030);
        
        assert!(sack.is_sacked(1005));
        assert!(!sack.is_sacked(1015));
        assert!(sack.is_sacked(1025));
    }
}