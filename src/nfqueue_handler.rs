// src/nfqueue_handler.rs
use anyhow::Result;
use std::sync::Arc;
use tracing::{info, error, debug};
use nfqueue::{Queue, Verdict, Message};
use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::config::Config;
use crate::packet::PacketInterceptor;

// Глобальный interceptor (нужен для callback функции)
static INTERCEPTOR: Lazy<Mutex<Option<Arc<PacketInterceptor>>>> = Lazy::new(|| Mutex::new(None));

// Callback функция для nfqueue
fn packet_callback(msg: &Message, _data: &mut ()) {
    let interceptor = INTERCEPTOR.lock().unwrap();
    let interceptor = match interceptor.as_ref() {
        Some(i) => i,
        None => {
            error!("Interceptor not initialized");
            msg.set_verdict(Verdict::Accept);
            return;
        }
    };
    
    let packet_data = msg.get_payload();
    
    // Обрабатываем через interceptor
    match interceptor.process_packet(packet_data) {
        Ok(modified) => {
            if modified.len() != packet_data.len() || modified != packet_data {
                // Пакет был модифицирован
                debug!("Packet modified, size: {} -> {}", packet_data.len(), modified.len());
                msg.set_verdict_full(Verdict::Drop, 0, &modified);
            } else {
                // Пакет не изменился
                msg.set_verdict(Verdict::Accept);
            }
        }
        Err(e) => {
            error!("Packet processing error: {}, accepting", e);
            msg.set_verdict(Verdict::Accept);
        }
    }
}

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
    
    /// Запуск обработки пакетов из NFQUEUE
    pub fn run(&mut self) -> Result<()> {
        info!("Opening NFQUEUE {}", self.queue_num);
        
        // Инициализируем глобальный interceptor
        let interceptor = Arc::new(PacketInterceptor::new(self.config.clone()));
        *INTERCEPTOR.lock().unwrap() = Some(interceptor);
        
        let mut queue = Queue::new(());
        queue.open();
        queue.bind(libc::AF_INET);
        queue.create_queue(self.queue_num, packet_callback);
        queue.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);
        
        info!("✓ NFQUEUE {} ready, processing packets...", self.queue_num);
        
        queue.run_loop();
        
        Ok(())
    }
}

/// Setup iptables rules для NFQUEUE
pub fn setup_iptables(queue_num: u16) -> Result<()> {
    info!("Setting up iptables rules...");
    
    // Очистка старых правил
    let _ = std::process::Command::new("iptables")
        .args(&["-t", "mangle", "-F"])
        .output();
    
    // NFQUEUE для HTTPS трафика (port 443)
    let output = std::process::Command::new("iptables")
        .args(&[
            "-t", "mangle",
            "-A", "PREROUTING",
            "-p", "tcp",
            "--dport", "443",
            "-j", "NFQUEUE",
            "--queue-num", &queue_num.to_string()
        ])
        .output()?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to setup iptables: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }
    
    info!("✓ iptables rule added: HTTPS -> NFQUEUE {}", queue_num);
    
    Ok(())
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
