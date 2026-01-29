use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use anyhow::Result;

const INITIAL_WINDOW_SIZE: u32 = 1048576; // 1MB - iOS Safari
const WINDOW_UPDATE_THRESHOLD: u32 = 524288; // 512KB
const MAX_FRAME_SIZE: u32 = 16384; // 16KB - iOS Safari
const HEADER_TABLE_SIZE: u32 = 65536; // 64KB - iOS Safari

// iOS Safari SETTINGS frame точные значения (критично для Akamai)
const IOS_HEADER_TABLE_SIZE: u32 = 65536;
const IOS_ENABLE_PUSH: bool = false;
const IOS_MAX_CONCURRENT_STREAMS: u32 = 100;
const IOS_INITIAL_WINDOW_SIZE: u32 = 1048576; // 1MB
const IOS_MAX_FRAME_SIZE: u32 = 16384; // 16KB
const IOS_MAX_HEADER_LIST_SIZE: u32 = 0; // Не устанавливается

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
    /// Точные настройки iOS Safari для Akamai fingerprinting
    pub fn ios_safari() -> Self {
        Self {
            header_table_size: IOS_HEADER_TABLE_SIZE,
            enable_push: IOS_ENABLE_PUSH,
            max_concurrent_streams: IOS_MAX_CONCURRENT_STREAMS,
            initial_window_size: IOS_INITIAL_WINDOW_SIZE,
            max_frame_size: IOS_MAX_FRAME_SIZE,
            max_header_list_size: IOS_MAX_HEADER_LIST_SIZE,
        }
    }

    /// Генерирует SETTINGS frame в точном формате iOS Safari
    pub fn to_frame(&self) -> Vec<u8> {
        let mut frame = Vec::new();
        
        // Frame header: length (3 bytes) + type (1) + flags (1) + stream_id (4)
        frame.extend_from_slice(&[0, 0, 0]); // length - заполним позже
        frame.push(0x04); // SETTINGS type
        frame.push(0x00); // flags (no ACK)
        frame.extend_from_slice(&[0, 0, 0, 0]); // stream_id = 0
        
        let mut settings = Vec::new();
        
        // iOS Safari отправляет настройки в СТРОГО определенном порядке:
        
        // 1. SETTINGS_HEADER_TABLE_SIZE (0x01)
        settings.extend_from_slice(&[0x00, 0x01]);
        settings.extend_from_slice(&self.header_table_size.to_be_bytes());
        
        // 2. SETTINGS_ENABLE_PUSH (0x02) - iOS Safari НЕ отправляет
        // (отсутствие этой настройки - часть fingerprint)
        
        // 3. SETTINGS_MAX_CONCURRENT_STREAMS (0x03) - iOS Safari НЕ отправляет
        // (также часть fingerprint)
        
        // 4. SETTINGS_INITIAL_WINDOW_SIZE (0x04)
        settings.extend_from_slice(&[0x00, 0x04]);
        settings.extend_from_slice(&self.initial_window_size.to_be_bytes());
        
        // 5. SETTINGS_MAX_FRAME_SIZE (0x05)
        settings.extend_from_slice(&[0x00, 0x05]);
        settings.extend_from_slice(&self.max_frame_size.to_be_bytes());
        
        // 6. SETTINGS_MAX_HEADER_LIST_SIZE (0x06) - iOS Safari НЕ отправляет
        
        // Обновляем длину в header
        let length = settings.len() as u32;
        frame[0..3].copy_from_slice(&length.to_be_bytes()[1..4]);
        frame.extend_from_slice(&settings);
        
        frame
    }

    /// Создает WINDOW_UPDATE для connection после SETTINGS
    /// iOS Safari отправляет WINDOW_UPDATE сразу после SETTINGS
    pub fn initial_window_update(&self) -> Vec<u8> {
        let mut frame = Vec::new();
        
        // iOS Safari увеличивает connection window до 15663105 (0xEF0001)
        let window_increment = 15663105u32 - 65535; // начальный window 65535
        
        frame.extend_from_slice(&[0, 0, 4]); // length = 4
        frame.push(0x08); // WINDOW_UPDATE type
        frame.push(0x00); // flags
        frame.extend_from_slice(&[0, 0, 0, 0]); // stream_id = 0 (connection)
        frame.extend_from_slice(&window_increment.to_be_bytes());
        
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
        // iOS Safari отправляет WINDOW_UPDATE когда окно упало ниже 50%
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
    natural_delay: Duration,
}

impl FlowController {
    pub fn new(initial_window: u32) -> Self {
        Self {
            connection_window: initial_window,
            streams: HashMap::new(),
            window_updates: VecDeque::new(),
            last_update_time: Instant::now(),
            // iOS Safari отправляет WINDOW_UPDATE с естественными интервалами
            natural_delay: Duration::from_millis(50),
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

    /// Проверяет нужно ли отправить WINDOW_UPDATE и добавляет в очередь
    /// iOS Safari не агрессивно обновляет окна - делает это естественно
    pub fn check_and_queue_updates(&mut self) {
        let now = Instant::now();
        
        // Обновляем connection window если нужно (не слишком часто)
        if self.connection_window < WINDOW_UPDATE_THRESHOLD 
            && now.duration_since(self.last_update_time) >= self.natural_delay {
            let increment = INITIAL_WINDOW_SIZE - self.connection_window;
            self.window_updates.push_back((0, increment));
            self.connection_window = INITIAL_WINDOW_SIZE;
        }

        // Обновляем stream windows с естественной задержкой
        let mut stream_updates = Vec::new();
        for (id, stream) in self.streams.iter_mut() {
            if stream.should_send_window_update() 
                && now.duration_since(stream.last_update) >= self.natural_delay {
                let increment = INITIAL_WINDOW_SIZE - stream.window_size;
                stream_updates.push((*id, increment));
                stream.add_window(increment);
                stream.last_update = now;
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
        self.natural_delay
    }

    pub fn should_send_updates(&self) -> bool {
        self.last_update_time.elapsed() >= self.natural_delay
    }
}

/// iOS Safari Priority Tree - точная эмуляция stream dependencies
pub struct PriorityTree {
    streams: HashMap<u32, StreamPriority>,
}

impl PriorityTree {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Дефолтное priority tree iOS Safari
    /// Streams 3, 5, 7, 9, 11 - специальные приоритеты
    pub fn ios_safari_defaults() -> Self {
        let mut tree = Self::new();
        
        // iOS Safari создает priority tree с определенными зависимостями
        // Stream 3: images, зависит от 0, weight=200 (высокий приоритет)
        tree.add_stream(3, StreamPriority {
            depends_on: 0,
            weight: 200,
            exclusive: false,
        });
        
        // Stream 5: stylesheets, зависит от 0, weight=100
        tree.add_stream(5, StreamPriority {
            depends_on: 0,
            weight: 100,
            exclusive: false,
        });
        
        // Stream 7: scripts, зависит от 0, weight=0 (низкий приоритет)
        tree.add_stream(7, StreamPriority {
            depends_on: 0,
            weight: 0,
            exclusive: false,
        });
        
        // Stream 9: fonts, зависит от 0, weight=42
        tree.add_stream(9, StreamPriority {
            depends_on: 0,
            weight: 42,
            exclusive: false,
        });
        
        // Stream 11: async resources, зависит от 0, weight=16
        tree.add_stream(11, StreamPriority {
            depends_on: 0,
            weight: 16,
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

    /// Создает PRIORITY frame для stream
    pub fn to_priority_frame(&self, stream_id: u32) -> Option<Vec<u8>> {
        let priority = self.streams.get(&stream_id)?;
        
        let mut frame = Vec::new();
        
        // Frame header
        frame.extend_from_slice(&[0, 0, 5]); // length = 5
        frame.push(0x02); // PRIORITY type
        frame.push(0x00); // flags
        frame.extend_from_slice(&stream_id.to_be_bytes());
        
        // Priority data
        let mut depends = priority.depends_on;
        if priority.exclusive {
            depends |= 0x80000000; // Set exclusive bit
        }
        frame.extend_from_slice(&depends.to_be_bytes());
        frame.push(priority.weight);
        
        Some(frame)
    }
}

/// Header order preservation - критично для Akamai
pub struct HeaderOrderPreserver {
    order: Vec<String>,
}

impl HeaderOrderPreserver {
    /// iOS Safari header order (ТОЧНЫЙ порядок для Akamai)
    pub fn ios_safari() -> Self {
        Self {
            order: vec![
                ":method".to_string(),
                ":scheme".to_string(),
                ":path".to_string(),
                ":authority".to_string(),
                "accept".to_string(),
                "accept-language".to_string(),
                "accept-encoding".to_string(),
                "user-agent".to_string(),
                "cache-control".to_string(),
                "referer".to_string(),
                "cookie".to_string(),
            ],
        }
    }

    /// Сортирует headers в правильном порядке для iOS Safari
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

/// Timing controller для естественных интервалов отправки frames
pub struct FrameTimingController {
    last_frame_time: Instant,
    frame_intervals: VecDeque<Duration>,
    max_history: usize,
}

impl FrameTimingController {
    pub fn new() -> Self {
        Self {
            last_frame_time: Instant::now(),
            frame_intervals: VecDeque::with_capacity(50),
            max_history: 50,
        }
    }

    pub fn record_frame(&mut self) {
        let now = Instant::now();
        let interval = now.duration_since(self.last_frame_time);
        
        self.frame_intervals.push_back(interval);
        if self.frame_intervals.len() > self.max_history {
            self.frame_intervals.pop_front();
        }
        
        self.last_frame_time = now;
    }

    /// Получить естественный интервал для следующего frame
    pub fn get_natural_delay(&self) -> Duration {
        if self.frame_intervals.is_empty() {
            return Duration::from_millis(10);
        }
        
        let sum: Duration = self.frame_intervals.iter().sum();
        sum / self.frame_intervals.len() as u32
    }

    /// iOS Safari не отправляет frames агрессивно
    pub fn should_wait(&self) -> bool {
        self.last_frame_time.elapsed() < Duration::from_millis(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ios_safari_settings() {
        let settings = Http2Settings::ios_safari();
        assert_eq!(settings.header_table_size, 65536);
        assert_eq!(settings.initial_window_size, 1048576);
        assert_eq!(settings.max_frame_size, 16384);
        assert_eq!(settings.enable_push, false);
    }

    #[test]
    fn test_settings_frame_format() {
        let settings = Http2Settings::ios_safari();
        let frame = settings.to_frame();
        
        // Проверяем формат frame
        assert_eq!(frame[3], 0x04); // SETTINGS type
        assert_eq!(frame[5..9], [0, 0, 0, 0]); // stream_id = 0
        
        // Frame должен содержать только 3 настройки (header_table, initial_window, max_frame)
        // Каждая настройка = 6 bytes (2 id + 4 value)
        let settings_length = u32::from_be_bytes([0, frame[0], frame[1], frame[2]]);
        assert_eq!(settings_length, 18); // 3 * 6 = 18
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
        assert_eq!(priority.depends_on, 0);
    }

    #[test]
    fn test_header_order() {
        let preserver = HeaderOrderPreserver::ios_safari();
        
        let mut headers = vec![
            ("user-agent".to_string(), "Safari".to_string()),
            (":method".to_string(), "GET".to_string()),
            ("accept".to_string(), "*/*".to_string()),
            (":path".to_string(), "/".to_string()),
        ];
        
        preserver.sort_headers(&mut headers);
        
        assert_eq!(headers[0].0, ":method");
        assert_eq!(headers[1].0, ":path");
        assert_eq!(headers[2].0, "accept");
        assert_eq!(headers[3].0, "user-agent");
    }

    #[test]
    fn test_frame_timing() {
        let mut timing = FrameTimingController::new();
        
        timing.record_frame();
        std::thread::sleep(Duration::from_millis(10));
        timing.record_frame();
        
        let delay = timing.get_natural_delay();
        assert!(delay >= Duration::from_millis(9));
        assert!(delay <= Duration::from_millis(11));
    }
}