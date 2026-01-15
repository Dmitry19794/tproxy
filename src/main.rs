// src/main.rs
#![allow(dead_code, unused_imports)]

#[cfg(all(unix, not(target_env = "musl")))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use anyhow::Result;
use tracing::info;
use std::sync::Arc;

mod config;
mod tcp;
mod tls;
mod http2;
mod udp;
mod proxy;
mod challenge;
mod packet;
mod nfqueue_handler;
mod state;
mod timing;

use config::Config;
use nfqueue_handler::{NfqueueHandler, cleanup_iptables};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("🚀 TPROXY Production v2.0 - Full Mode");

    // Load config
    let config = match Config::load("config.json") {
        Ok(cfg) => {
            info!("✓ Config loaded: {} profiles", cfg.profiles.len());
            Arc::new(cfg)
        }
        Err(_) => {
            info!("Using default config");
            Arc::new(Config::default())
        }
    };

    let profile = config.default_profile();
    info!("Profile: {}", profile.name);
    info!("Cipher suites: {}", profile.cipher_suites.len());
    info!("Extensions: {}", profile.extensions.len());

    // Cleanup on exit
    ctrlc::set_handler(move || {
        info!("Cleaning up...");
        let _ = cleanup_iptables();
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    // Start NFQUEUE handler
    info!("Starting NFQUEUE packet processing...");
    let mut handler = NfqueueHandler::new(0, config.clone())?;
    
    info!("✅ System ready - intercepting HTTPS traffic");
    info!("Press Ctrl+C to stop");
    
    // Run packet processing (blocking)
    tokio::task::spawn_blocking(move || {
        if let Err(e) = handler.run() {
            tracing::error!("NFQUEUE handler error: {}", e);
        }
    }).await?;

    Ok(())
}
