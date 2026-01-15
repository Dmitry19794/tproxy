use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::time::sleep;
use rand::rng;
use rand_distr::{Distribution, Normal};

const HISTORY_SIZE: usize = 100;
const MIN_DELAY_MS: u64 = 1;
const MAX_DELAY_MS: u64 = 5000;

pub struct TimingPreserver {
    last_send: Option<Instant>,
    intervals: VecDeque<Duration>,
    jitter_dist: Normal<f64>,
}

impl TimingPreserver {
    pub fn new(jitter_stddev: f64) -> Self {
        let jitter_dist = Normal::new(0.0, jitter_stddev).unwrap_or_else(|_| {
            Normal::new(0.0, 1.0).unwrap()
        });

        Self {
            last_send: None,
            intervals: VecDeque::with_capacity(HISTORY_SIZE),
            jitter_dist,
        }
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
    }

    pub fn get_average_interval(&self) -> Duration {
        if self.intervals.is_empty() {
            return Duration::from_millis(10);
        }

        let sum: Duration = self.intervals.iter().sum();
        sum / self.intervals.len() as u32
    }

    pub async fn wait_natural_delay(&mut self) {
        let base_delay = self.get_average_interval();
        let delay = self.apply_jitter(base_delay);
        
        if delay > Duration::from_millis(MIN_DELAY_MS) 
            && delay < Duration::from_millis(MAX_DELAY_MS) {
            sleep(delay).await;
        }
    }

    fn apply_jitter(&mut self, base: Duration) -> Duration {
        let mut rng = rng();
        let jitter: f64 = self.jitter_dist.sample(&mut rng);
        
        let base_ms = base.as_millis() as f64;
        let jittered_ms = (base_ms * (1.0 + jitter)).max(0.0);
        
        Duration::from_millis(jittered_ms as u64)
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
    }
}

pub struct PacketTimingAnalyzer {
    packet_times: VecDeque<Instant>,
    window_size: usize,
}

impl PacketTimingAnalyzer {
    pub fn new(window_size: usize) -> Self {
        Self {
            packet_times: VecDeque::with_capacity(window_size),
            window_size,
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

    pub fn is_burst(&self, threshold: f64) -> bool {
        self.get_packet_rate() > threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timing_preserver() {
        let mut tp = TimingPreserver::new(0.1);
        
        tp.record_send();
        sleep(Duration::from_millis(10)).await;
        tp.record_send();
        
        let avg = tp.get_average_interval();
        assert!(avg >= Duration::from_millis(9));
        assert!(avg <= Duration::from_millis(11));
    }

    #[test]
    fn test_packet_timing_analyzer() {
        let mut analyzer = PacketTimingAnalyzer::new(10);
        
        for _ in 0..5 {
            analyzer.record_packet();
        }
        
        assert!(analyzer.get_packet_rate() >= 0.0);
    }
}