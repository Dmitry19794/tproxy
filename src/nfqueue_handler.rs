// src/nfqueue_handler.rs
use anyhow::Result;
use std::sync::Arc;
use tracing::{info, error, debug};
use nfq_updated::{Queue, Message, Verdict};  // <-- ИЗМЕНЕНО
use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::config::Config;
use crate::packet::PacketInterceptor;

// Глобальный interceptor
static INTERCEPTOR: Lazy<Mutex<Option<Arc<PacketInterceptor>>>> = Lazy::new(|| Mutex::new(None));

pub struct NfqueueHandler {
    queue_num: u16,
    config: Arc<Config>,
}

impl NfqueueHandler {
    pub fn new(queue_num: u16, config: Arc<Config>) -> Result<Self> {
        Ok(Self {
            queue_num,
            config,
        })
    }
    
    pub fn run(&mut self) -> Result<()> {
        info!("Opening NFQUEUE {} with nfq library", self.queue_num);
        
        // Инициализируем interceptor
        let interceptor = Arc::new(PacketInterceptor::new(self.config.clone()));
        *INTERCEPTOR.lock().unwrap() = Some(interceptor.clone());
        
        // Создаём queue через nfq
        let mut queue = Queue::open()?;
        
        info!("Binding to queue {}", self.queue_num);
        queue.bind(self.queue_num)?;
        
        info!("✓ NFQUEUE {} ready, processing packets...", self.queue_num);
        
        // Обрабатываем пакеты
        loop {
            let mut msg = match queue.recv() {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to receive packet: {}", e);
                    continue;
                }
            };
            
            let packet_data = msg.get_payload();
            
            match interceptor.process_packet(packet_data) {
                Ok(modified) => {
                    if modified.len() != packet_data.len() || modified != packet_data {
                        debug!("Packet modified, size: {} -> {}", packet_data.len(), modified.len());
                        
                        // Для модифицированных пакетов: Drop оригинал и inject новый
                        msg.set_verdict(Verdict::Drop);
                        
                        // TODO: Нужно inject модифицированный пакет через raw socket
                        // Пока просто Accept оригинал (не ломаем соединение)
                        msg.set_verdict(Verdict::Accept);
                    } else {
                        msg.set_verdict(Verdict::Accept);
                    }
                }
                Err(e) => {
                    error!("Packet processing error: {}, accepting", e);
                    msg.set_verdict(Verdict::Accept);
                }
            }
        }
    }
}

/// Cleanup iptables rules
pub fn cleanup_iptables() -> Result<()> {
    info!("Cleaning up iptables rules...");
    
    let _ = std::process::Command::new("iptables")
        .args(&["-t", "mangle", "-F"])
        .output();
    
    info!("✓ iptables rules cleaned");
    
    Ok(())
}
