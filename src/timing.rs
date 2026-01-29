use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::time::sleep;
use rand::Rng;

const HISTORY_SIZE: usize = 100;
const MIN_DELAY_MS: u64 = 1;
const MAX_DELAY_MS: u64 = 5000;

// iOS Safari timing характеристики (естественное поведение)
const IOS_BASE_DELAY_MS: u64 = 10;          // Базовая задержка между пакетами
const IOS_JITTER_PERCENT: f64 = 0.15;       // 15% jitter (естественные вариации)
const IOS_BURST_THRESHOLD: usize = 5;       // После 5 пакетов - небольшая пауза
const IOS_BURST_PAUSE_MS: u64 = 50;         // Пауза после burst
const IOS_THINK_TIME_MIN_MS: u64 = 100;     // Минимальное "время размышления"
const IOS_THINK_TIME_MAX_MS: u64 = 500;     // Максимальное "время размышления"

pub struct TimingPreserver {
    last_send: Option<Instant>,
    intervals: VecDeque<Duration>,
    jitter_percent: f64,
    packet_count: usize,
    last_burst_pause: Instant,
}

impl TimingPreserver {
    pub fn new(jitter_percent: f64) -> Self {
        Self {
            last_send: None,
            intervals: VecDeque::with_capacity(HISTORY_SIZE),
            jitter_percent: jitter_percent.max(0.0).min(1.0),
            packet_count: 0,
            last_burst_pause: Instant::now(),
        }
    }

    /// Создать TimingPreserver с iOS Safari параметрами
    pub fn ios_safari() -> Self {
        Self::new(IOS_JITTER_PERCENT)
    }

    pub fn record_send(&mut self) {
        let now = Instant::now();
        
        if let Some(last) = self.last_send {
            let interval = now.duration_since(last);
            self.intervals.push_back(interval);
            
            if self.intervals.len() > HISTORY_SIZE {
                self.intervals.pop_front();
            }
        }
        
        self.last_send = Some(now);
        self.packet_count += 1;
    }

    pub fn get_average_interval(&self) -> Duration {
        if self.intervals.is_empty() {
            return Duration::from_millis(IOS_BASE_DELAY_MS);
        }

        let sum: Duration = self.intervals.iter().sum();
        sum / self.intervals.len() as u32
    }

    /// Получить естественную задержку с учетом iOS Safari поведения
    pub async fn wait_natural_delay(&mut self) {
        let mut delay = self.calculate_natural_delay();
        
        // iOS Safari имеет естественные паузы после burst'ов пакетов
        if self.should_pause_after_burst() {
            delay += Duration::from_millis(IOS_BURST_PAUSE_MS);
            self.last_burst_pause = Instant::now();
            log::trace!("Natural burst pause: {}ms", IOS_BURST_PAUSE_MS);
        }
        
        // Иногда добавляем "think time" (имитация обработки на клиенте)
        if self.should_add_think_time() {
            let think_time = self.generate_think_time();
            delay += think_time;
            log::trace!("Think time added: {}ms", think_time.as_millis());
        }
        
        if delay > Duration::from_millis(MIN_DELAY_MS) 
            && delay < Duration::from_millis(MAX_DELAY_MS) {
            sleep(delay).await;
        }
    }

    /// Вычисляет естественную задержку с jitter
    fn calculate_natural_delay(&mut self) -> Duration {
        let base_delay = if self.intervals.is_empty() {
            Duration::from_millis(IOS_BASE_DELAY_MS)
        } else {
            self.get_average_interval()
        };
        
        self.apply_jitter(base_delay)
    }

    /// Применяет jitter к задержке (iOS Safari имеет естественные вариации)
    fn apply_jitter(&mut self, base: Duration) -> Duration {
        let mut rng = rand::thread_rng();
        
        // Генерируем jitter в пределах ±jitter_percent
        let jitter_range = 2.0 * self.jitter_percent;
        let jitter_factor = 1.0 + (rng.gen::<f64>() * jitter_range - self.jitter_percent);
        
        let base_ms = base.as_millis() as f64;
        let jittered_ms = (base_ms * jitter_factor).max(MIN_DELAY_MS as f64);
        
        Duration::from_millis(jittered_ms as u64)
    }

    /// Проверяет нужна ли пауза после burst
    fn should_pause_after_burst(&self) -> bool {
        // iOS Safari делает паузу после нескольких пакетов подряд
        self.packet_count % IOS_BURST_THRESHOLD == 0 
            && self.packet_count > 0
            && self.last_burst_pause.elapsed() > Duration::from_millis(100)
    }

    /// Проверяет нужно ли добавить "think time"
    fn should_add_think_time(&self) -> bool {
        let mut rng = rand::thread_rng();
        // 5% вероятность добавить think time (имитация обработки)
        rng.gen::<f64>() < 0.05
    }

    /// Генерирует think time (случайное время "обдумывания")
    fn generate_think_time(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let think_ms = rng.gen_range(IOS_THINK_TIME_MIN_MS..=IOS_THINK_TIME_MAX_MS);
        Duration::from_millis(think_ms)
    }

    pub fn should_send(&self, min_interval: Duration) -> bool {
        match self.last_send {
            None => true,
            Some(last) => last.elapsed() >= min_interval,
        }
    }

    pub fn reset(&mut self) {
        self.last_send = None;
        self.intervals.clear();
        self.packet_count = 0;
    }

    /// Получить статистику по timing
    pub fn get_stats(&self) -> TimingStats {
        TimingStats {
            packet_count: self.packet_count,
            average_interval: self.get_average_interval(),
            jitter_percent: self.jitter_percent,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimingStats {
    pub packet_count: usize,
    pub average_interval: Duration,
    pub jitter_percent: f64,
}

/// Анализатор packet timing для детекции аномалий
pub struct PacketTimingAnalyzer {
    packet_times: VecDeque<Instant>,
    window_size: usize,
    anomaly_threshold: f64,
}

impl PacketTimingAnalyzer {
    pub fn new(window_size: usize) -> Self {
        Self {
            packet_times: VecDeque::with_capacity(window_size),
            window_size,
            anomaly_threshold: 10.0, // 10x средняя скорость считается аномалией
        }
    }

    pub fn record_packet(&mut self) {
        let now = Instant::now();
        self.packet_times.push_back(now);
        
        if self.packet_times.len() > self.window_size {
            self.packet_times.pop_front();
        }
    }

    pub fn get_packet_rate(&self) -> f64 {
        if self.packet_times.len() < 2 {
            return 0.0;
        }

        let first = self.packet_times.front().unwrap();
        let last = self.packet_times.back().unwrap();
        let duration = last.duration_since(*first);

        if duration.as_secs_f64() > 0.0 {
            self.packet_times.len() as f64 / duration.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Проверяет является ли текущая скорость burst'ом
    pub fn is_burst(&self, threshold: f64) -> bool {
        self.get_packet_rate() > threshold
    }

    /// Детектирует аномальное поведение (слишком быстро или слишком медленно)
    pub fn detect_anomaly(&self) -> bool {
        if self.packet_times.len() < self.window_size / 2 {
            return false;
        }

        let rate = self.get_packet_rate();
        let average_rate = self.calculate_average_rate();

        // Аномалия если скорость в anomaly_threshold раз отличается от средней
        rate > average_rate * self.anomaly_threshold || rate < average_rate / self.anomaly_threshold
    }

    fn calculate_average_rate(&self) -> f64 {
        if self.packet_times.len() < 2 {
            return 1.0;
        }

        // Вычисляем среднюю скорость за весь window
        let mut intervals = Vec::new();
        for i in 1..self.packet_times.len() {
            let interval = self.packet_times[i].duration_since(self.packet_times[i - 1]);
            intervals.push(interval);
        }

        if intervals.is_empty() {
            return 1.0;
        }

        let avg_interval: Duration = intervals.iter().sum::<Duration>() / intervals.len() as u32;
        if avg_interval.as_secs_f64() > 0.0 {
            1.0 / avg_interval.as_secs_f64()
        } else {
            1.0
        }
    }
}

/// Request timing - имитирует естественное поведение пользователя между запросами
pub struct RequestTiming {
    last_request: Option<Instant>,
    user_think_times: VecDeque<Duration>,
    max_history: usize,
}

impl RequestTiming {
    pub fn new() -> Self {
        Self {
            last_request: None,
            user_think_times: VecDeque::with_capacity(20),
            max_history: 20,
        }
    }

    /// Ожидает естественное время перед следующим запросом (имитация пользователя)
    pub async fn wait_before_next_request(&mut self) {
        if let Some(last) = self.last_request {
            let elapsed = last.elapsed();
            
            // Минимальное время между запросами (реальный пользователь)
            let min_wait = Duration::from_millis(50);
            
            if elapsed < min_wait {
                sleep(min_wait - elapsed).await;
            }
            
            // Дополнительное "думание" пользователя
            let think_time = self.generate_user_think_time();
            sleep(think_time).await;
            
            self.user_think_times.push_back(think_time);
            if self.user_think_times.len() > self.max_history {
                self.user_think_times.pop_front();
            }
        }
        
        self.last_request = Some(Instant::now());
    }

    /// Генерирует естественное время "размышления" пользователя
    fn generate_user_think_time(&self) -> Duration {
        let mut rng = rand::thread_rng();
        
        // Большинство пользователей думают 100-2000ms между действиями
        // Используем log-normal distribution для более реалистичного поведения
        let base_ms = 200.0;
        let variance = 1.5;
        
        let random_factor = (rng.gen::<f64>() * variance).exp();
        let think_ms = (base_ms * random_factor).min(2000.0).max(50.0);
        
        Duration::from_millis(think_ms as u64)
    }

    pub fn get_average_think_time(&self) -> Duration {
        if self.user_think_times.is_empty() {
            return Duration::from_millis(500);
        }

        let sum: Duration = self.user_think_times.iter().sum();
        sum / self.user_think_times.len() as u32
    }
}

/// Adaptive timing - адаптируется к сети и серверу
pub struct AdaptiveTiming {
    rtt_samples: VecDeque<Duration>,
    server_response_times: VecDeque<Duration>,
    max_samples: usize,
}

impl AdaptiveTiming {
    pub fn new() -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(50),
            server_response_times: VecDeque::with_capacity(50),
            max_samples: 50,
        }
    }

    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > self.max_samples {
            self.rtt_samples.pop_front();
        }
    }

    pub fn record_server_response(&mut self, response_time: Duration) {
        self.server_response_times.push_back(response_time);
        if self.server_response_times.len() > self.max_samples {
            self.server_response_times.pop_front();
        }
    }

    /// Вычисляет оптимальную задержку на основе сетевых условий
    pub fn get_adaptive_delay(&self) -> Duration {
        let avg_rtt = self.get_average_rtt();
        let avg_response = self.get_average_response_time();
        
        // Задержка должна быть пропорциональна RTT и времени ответа сервера
        let base_delay = (avg_rtt + avg_response) / 4;
        
        // Минимум 5ms, максимум 100ms
        base_delay.max(Duration::from_millis(5)).min(Duration::from_millis(100))
    }

    fn get_average_rtt(&self) -> Duration {
        if self.rtt_samples.is_empty() {
            return Duration::from_millis(50);
        }
        
        let sum: Duration = self.rtt_samples.iter().sum();
        sum / self.rtt_samples.len() as u32
    }

    fn get_average_response_time(&self) -> Duration {
        if self.server_response_times.is_empty() {
            return Duration::from_millis(100);
        }
        
        let sum: Duration = self.server_response_times.iter().sum();
        sum / self.server_response_times.len() as u32
    }

    pub fn get_stats(&self) -> AdaptiveTimingStats {
        AdaptiveTimingStats {
            average_rtt: self.get_average_rtt(),
            average_response_time: self.get_average_response_time(),
            adaptive_delay: self.get_adaptive_delay(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdaptiveTimingStats {
    pub average_rtt: Duration,
    pub average_response_time: Duration,
    pub adaptive_delay: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timing_preserver() {
        let mut tp = TimingPreserver::ios_safari();
        
        tp.record_send();
        sleep(Duration::from_millis(10)).await;
        tp.record_send();
        
        let avg = tp.get_average_interval();
        assert!(avg >= Duration::from_millis(9));
        assert!(avg <= Duration::from_millis(11));
    }

    #[tokio::test]
    async fn test_natural_delay() {
        let mut tp = TimingPreserver::ios_safari();
        
        let start = Instant::now();
        tp.wait_natural_delay().await;
        let elapsed = start.elapsed();
        
        // Задержка должна быть в разумных пределах
        assert!(elapsed >= Duration::from_millis(8));
        assert!(elapsed <= Duration::from_millis(50));
    }

    #[test]
    fn test_packet_timing_analyzer() {
        let mut analyzer = PacketTimingAnalyzer::new(10);
        
        for _ in 0..5 {
            analyzer.record_packet();
        }
        
        assert!(analyzer.get_packet_rate() >= 0.0);
        assert!(!analyzer.detect_anomaly()); // Не должно быть аномалий при нормальной работе
    }

    #[tokio::test]
    async fn test_request_timing() {
        let mut rt = RequestTiming::new();
        
        let start = Instant::now();
        rt.wait_before_next_request().await;
        let elapsed = start.elapsed();
        
        // Первый запрос - быстрый
        assert!(elapsed < Duration::from_millis(100));
        
        let start = Instant::now();
        rt.wait_before_next_request().await;
        let elapsed = start.elapsed();
        
        // Последующие запросы - с think time
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[test]
    fn test_adaptive_timing() {
        let mut at = AdaptiveTiming::new();
        
        at.record_rtt(Duration::from_millis(30));
        at.record_rtt(Duration::from_millis(40));
        at.record_server_response(Duration::from_millis(100));
        
        let delay = at.get_adaptive_delay();
        assert!(delay >= Duration::from_millis(5));
        assert!(delay <= Duration::from_millis(100));
    }

    #[test]
    fn test_burst_detection() {
        let mut analyzer = PacketTimingAnalyzer::new(20);
        
        // Симулируем burst
        for _ in 0..10 {
            analyzer.record_packet();
        }
        
        let rate = analyzer.get_packet_rate();
        assert!(rate > 100.0); // Очень высокая скорость = burst
    }
}