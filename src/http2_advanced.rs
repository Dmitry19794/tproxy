use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use anyhow::Result;

const INITIAL_WINDOW_SIZE: u32 = 1048576;
const WINDOW_UPDATE_THRESHOLD: u32 = 524288;
const MAX_FRAME_SIZE: u32 = 16384;
const HEADER_TABLE_SIZE: u32 = 65536;

#[derive(Debug, Clone, Copy)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Default for Http2Settings {
    fn default() -> Self {
        Self {
            header_table_size: HEADER_TABLE_SIZE,
            enable_push: false,
            max_concurrent_streams: 100,
            initial_window_size: INITIAL_WINDOW_SIZE,
            max_frame_size: MAX_FRAME_SIZE,
            max_header_list_size: 0,
        }
    }
}

impl Http2Settings {
    pub fn ios_safari() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: false,
            max_concurrent_streams: 100,
            initial_window_size: 1048576,
            max_frame_size: 16384,
            max_header_list_size: 0,
        }
    }

    pub fn to_frame(&self) -> Vec<u8> {
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&[0, 0, 0]);
        frame.push(0x04);
        frame.push(0x00);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        
        let mut settings = Vec::new();
        
        settings.extend_from_slice(&self.header_table_size.to_be_bytes()[2..4]);
        settings.extend_from_slice(&self.header_table_size.to_be_bytes());
        
        settings.extend_from_slice(&[0x00, 0x04]);
        settings.extend_from_slice(&self.initial_window_size.to_be_bytes());
        
        settings.extend_from_slice(&[0x00, 0x05]);
        settings.extend_from_slice(&self.max_frame_size.to_be_bytes());
        
        let length = settings.len() as u32;
        frame[0..3].copy_from_slice(&length.to_be_bytes()[1..4]);
        frame.extend_from_slice(&settings);
        
        frame
    }
}

#[derive(Debug)]
pub struct StreamState {
    pub id: u32,
    pub window_size: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_update: Instant,
    pub priority: StreamPriority,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamPriority {
    pub depends_on: u32,
    pub weight: u8,
    pub exclusive: bool,
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self {
            depends_on: 0,
            weight: 16,
            exclusive: false,
        }
    }
}

impl StreamState {
    pub fn new(id: u32, initial_window: u32) -> Self {
        Self {
            id,
            window_size: initial_window,
            bytes_sent: 0,
            bytes_received: 0,
            last_update: Instant::now(),
            priority: StreamPriority::default(),
        }
    }

    pub fn consume_window(&mut self, bytes: u32) -> bool {
        if self.window_size >= bytes {
            self.window_size -= bytes;
            self.bytes_sent += bytes as u64;
            true
        } else {
            false
        }
    }

    pub fn add_window(&mut self, bytes: u32) {
        self.window_size = self.window_size.saturating_add(bytes);
    }

    pub fn should_send_window_update(&self) -> bool {
        self.window_size < WINDOW_UPDATE_THRESHOLD
    }

    pub fn update_received(&mut self, bytes: u32) {
        self.bytes_received += bytes as u64;
        self.last_update = Instant::now();
    }
}

pub struct FlowController {
    connection_window: u32,
    streams: HashMap<u32, StreamState>,
    window_updates: VecDeque<(u32, u32)>,
    last_update_time: Instant,
}

impl FlowController {
    pub fn new(initial_window: u32) -> Self {
        Self {
            connection_window: initial_window,
            streams: HashMap::new(),
            window_updates: VecDeque::new(),
            last_update_time: Instant::now(),
        }
    }

    pub fn create_stream(&mut self, stream_id: u32, initial_window: u32) {
        let state = StreamState::new(stream_id, initial_window);
        self.streams.insert(stream_id, state);
    }

    pub fn remove_stream(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    pub fn consume_window(&mut self, stream_id: u32, bytes: u32) -> Result<bool> {
        if self.connection_window < bytes {
            return Ok(false);
        }

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if stream.consume_window(bytes) {
                self.connection_window -= bytes;
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn update_window(&mut self, stream_id: u32, increment: u32) {
        if stream_id == 0 {
            self.connection_window = self.connection_window.saturating_add(increment);
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.add_window(increment);
        }
    }

    pub fn check_and_queue_updates(&mut self) {
        let now = Instant::now();
        
        if self.connection_window < WINDOW_UPDATE_THRESHOLD {
            let increment = INITIAL_WINDOW_SIZE - self.connection_window;
            self.window_updates.push_back((0, increment));
            self.connection_window = INITIAL_WINDOW_SIZE;
        }

        let mut stream_updates = Vec::new();
        for (id, stream) in self.streams.iter_mut() {
            if stream.should_send_window_update() {
                let increment = INITIAL_WINDOW_SIZE - stream.window_size;
                stream_updates.push((*id, increment));
                stream.add_window(increment);
            }
        }

        for (id, increment) in stream_updates {
            self.window_updates.push_back((id, increment));
        }

        self.last_update_time = now;
    }

    pub fn pop_window_update(&mut self) -> Option<(u32, u32)> {
        self.window_updates.pop_front()
    }

    pub fn natural_update_interval(&self) -> Duration {
        Duration::from_millis(100)
    }

    pub fn should_send_updates(&self) -> bool {
        self.last_update_time.elapsed() >= self.natural_update_interval()
    }
}

pub struct PriorityTree {
    streams: HashMap<u32, StreamPriority>,
}

impl PriorityTree {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn ios_safari_defaults() -> Self {
        let mut tree = Self::new();
        
        tree.add_stream(3, StreamPriority {
            depends_on: 0,
            weight: 200,
            exclusive: false,
        });
        
        tree.add_stream(5, StreamPriority {
            depends_on: 0,
            weight: 100,
            exclusive: false,
        });
        
        tree.add_stream(7, StreamPriority {
            depends_on: 0,
            weight: 0,
            exclusive: false,
        });
        
        tree
    }

    pub fn add_stream(&mut self, stream_id: u32, priority: StreamPriority) {
        self.streams.insert(stream_id, priority);
    }

    pub fn update_priority(&mut self, stream_id: u32, priority: StreamPriority) {
        self.streams.insert(stream_id, priority);
    }

    pub fn get_priority(&self, stream_id: u32) -> Option<&StreamPriority> {
        self.streams.get(&stream_id)
    }

    pub fn to_priority_frame(&self, stream_id: u32) -> Option<Vec<u8>> {
        let priority = self.streams.get(&stream_id)?;
        
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&[0, 0, 5]);
        frame.push(0x02);
        frame.push(0x00);
        
        frame.extend_from_slice(&stream_id.to_be_bytes());
        
        let mut depends = priority.depends_on;
        if priority.exclusive {
            depends |= 0x80000000;
        }
        frame.extend_from_slice(&depends.to_be_bytes());
        
        frame.push(priority.weight);
        
        Some(frame)
    }
}

pub struct HeaderOrderPreserver {
    order: Vec<String>,
}

impl HeaderOrderPreserver {
    pub fn ios_safari() -> Self {
        Self {
            order: vec![
                ":method".to_string(),
                ":scheme".to_string(),
                ":path".to_string(),
                ":authority".to_string(),
                "accept".to_string(),
                "accept-encoding".to_string(),
                "accept-language".to_string(),
                "user-agent".to_string(),
            ],
        }
    }

    pub fn sort_headers(&self, headers: &mut Vec<(String, String)>) {
        headers.sort_by(|a, b| {
            let pos_a = self.order.iter().position(|h| h == &a.0);
            let pos_b = self.order.iter().position(|h| h == &b.0);
            
            match (pos_a, pos_b) {
                (Some(a), Some(b)) => a.cmp(&b),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.0.cmp(&b.0),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_frame() {
        let settings = Http2Settings::ios_safari();
        let frame = settings.to_frame();
        
        assert_eq!(frame[3], 0x04);
        assert!(frame.len() > 9);
    }

    #[test]
    fn test_flow_controller() {
        let mut fc = FlowController::new(INITIAL_WINDOW_SIZE);
        fc.create_stream(1, INITIAL_WINDOW_SIZE);
        
        assert!(fc.consume_window(1, 1000).unwrap());
        assert_eq!(fc.connection_window, INITIAL_WINDOW_SIZE - 1000);
    }

    #[test]
    fn test_priority_tree() {
        let tree = PriorityTree::ios_safari_defaults();
        
        let priority = tree.get_priority(3).unwrap();
        assert_eq!(priority.weight, 200);
    }

    #[test]
    fn test_header_order() {
        let preserver = HeaderOrderPreserver::ios_safari();
        
        let mut headers = vec![
            ("user-agent".to_string(), "Safari".to_string()),
            (":method".to_string(), "GET".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ];
        
        preserver.sort_headers(&mut headers);
        
        assert_eq!(headers[0].0, ":method");
        assert_eq!(headers[1].0, "accept");
    }
}
