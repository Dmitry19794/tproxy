// src/timing.rs - Natural Timing Engine для реалистичных задержек
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use rand::Rng;
use rand_distr::{Distribution, Normal};

/// Timing Engine для сохранения оригинальных интервалов
pub struct TimingEngine {
    /// История межпакетных задержек
    inter_packet_delays: VecDeque<Duration>,
    /// Максимальный размер истории
    max_history: usize,
    /// Jitter distribution
    jitter_dist: Normal<f64>,
    /// Последний timestamp
    last_packet: Option<Instant>,
}

impl TimingEngine {
    pub fn new(jitter_percent: f64, max_history: usize) -> Self {
        let jitter_dist = Normal::new(0.0, jitter_percent / 100.0)
            .unwrap_or_else(|_| Normal::new(0.0, 0.1).unwrap());
        
        Self {
            inter_packet_delays: VecDeque::with_capacity(max_history),
            max_history,
            jitter_dist,
            last_packet: None,
        }
    }
    
    /// Записать задержку между пакетами
    pub fn record_packet(&mut self) {
        let now = Instant::now();
        
        if let Some(last) = self.last_packet {
            let delay = now.duration_since(last);
            
            self.inter_packet_delays.push_back(delay);
            
            // Ограничиваем размер истории
            if self.inter_packet_delays.len() > self.max_history {
                self.inter_packet_delays.pop_front();
            }
        }
        
        self.last_packet = Some(now);
    }
    
    /// Получить естественную задержку (median из истории)
    pub fn get_natural_delay(&self) -> Duration {
        if self.inter_packet_delays.is_empty() {
            return Duration::from_micros(100); // Default 100μs
        }
        
        let mut sorted: Vec<Duration> = self.inter_packet_delays.iter().copied().collect();
        sorted.sort();
        
        // Median
        sorted[sorted.len() / 2]
    }
    
    /// Получить задержку с jitter
    pub fn get_delay_with_jitter(&self, base: Duration) -> Duration {
        let mut rng = rand::thread_rng();
        let jitter: f64 = self.jitter_dist.sample(&mut rng);
        
        let micros = base.as_micros() as f64;
        let jittered_micros = (micros * (1.0 + jitter)).max(0.0);
        
        Duration::from_micros(jittered_micros as u64)
    }
    
    /// Применить естественную задержку с jitter
    pub async fn apply_natural_delay(&self) {
        let base_delay = self.get_natural_delay();
        let delay = self.get_delay_with_jitter(base_delay);
        
        tokio::time::sleep(delay).await;
    }
    
    /// Применить конкретную задержку с jitter
    pub async fn apply_delay(&self, base: Duration) {
        let delay = self.get_delay_with_jitter(base);
        tokio::time::sleep(delay).await;
    }
    
    /// Получить статистику задержек
    pub fn get_stats(&self) -> TimingStats {
        if self.inter_packet_delays.is_empty() {
            return TimingStats {
                min: Duration::ZERO,
                max: Duration::ZERO,
                avg: Duration::ZERO,
                median: Duration::ZERO,
                count: 0,
            };
        }
        
        let mut sorted: Vec<Duration> = self.inter_packet_delays.iter().copied().collect();
        sorted.sort();
        
        let min = sorted[0];
        let max = sorted[sorted.len() - 1];
        let median = sorted[sorted.len() / 2];
        
        let sum: Duration = sorted.iter().sum();
        let avg = sum / sorted.len() as u32;
        
        TimingStats {
            min,
            max,
            avg,
            median,
            count: sorted.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimingStats {
    pub min: Duration,
    pub max: Duration,
    pub avg: Duration,
    pub median: Duration,
    pub count: usize,
}

/// Специализированные таймеры для разных типов операций
pub struct SpecializedTimers {
    /// TLS handshake delay (имитация генерации ключей)
    pub tls_handshake: Duration,
    /// HTTP/2 SETTINGS delay
    pub http2_settings: Duration,
    /// Challenge response delay
    pub challenge_delay: Duration,
}

impl Default for SpecializedTimers {
    fn default() -> Self {
        Self {
            tls_handshake: Duration::from_millis(2),  // 2ms для ECDH
            http2_settings: Duration::from_millis(1),  // 1ms после TLS
            challenge_delay: Duration::from_millis(50), // 50ms для JS challenge
        }
    }
}

impl SpecializedTimers {
    /// Применить TLS handshake delay с jitter
    pub async fn apply_tls_delay(&self, engine: &TimingEngine) {
        engine.apply_delay(self.tls_handshake).await;
    }
    
    /// Применить HTTP/2 SETTINGS delay с jitter
    pub async fn apply_http2_delay(&self, engine: &TimingEngine) {
        engine.apply_delay(self.http2_settings).await;
    }
    
    /// Применить Challenge delay с jitter
    pub async fn apply_challenge_delay(&self, engine: &TimingEngine) {
        engine.apply_delay(self.challenge_delay).await;
    }
}

/// Timing Normalizer для минимизации девиации
pub struct TimingNormalizer {
    /// Целевой интервал
    target_interval: Duration,
    /// Допустимая девиация (процент)
    max_deviation_percent: f64,
}

impl TimingNormalizer {
    pub fn new(target_interval: Duration, max_deviation_percent: f64) -> Self {
        Self {
            target_interval,
            max_deviation_percent,
        }
    }
    
    /// Нормализовать измеренную задержку
    pub fn normalize(&self, measured: Duration) -> Duration {
        let target_micros = self.target_interval.as_micros() as f64;
        let measured_micros = measured.as_micros() as f64;
        
        let deviation = ((measured_micros - target_micros).abs() / target_micros) * 100.0;
        
        // Если девиация больше допустимой - используем target
        if deviation > self.max_deviation_percent {
            self.target_interval
        } else {
            measured
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timing_engine() {
        let mut engine = TimingEngine::new(10.0, 100);
        
        // Записываем несколько задержек
        engine.record_packet();
        std::thread::sleep(Duration::from_millis(10));
        engine.record_packet();
        std::thread::sleep(Duration::from_millis(20));
        engine.record_packet();
        
        let stats = engine.get_stats();
        assert_eq!(stats.count, 2);
        assert!(stats.avg > Duration::ZERO);
    }
    
    #[test]
    fn test_timing_normalizer() {
        let normalizer = TimingNormalizer::new(
            Duration::from_millis(10),
            10.0 // 10% max deviation
        );
        
        // В пределах допустимого
        let measured = Duration::from_millis(11);
        let normalized = normalizer.normalize(measured);
        assert_eq!(normalized, measured);
        
        // Превышает допустимое
        let measured = Duration::from_millis(20);
        let normalized = normalizer.normalize(measured);
        assert_eq!(normalized, Duration::from_millis(10));
    }
}
