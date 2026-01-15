use tokio::net::TcpListener;
use std::sync::Arc;
use anyhow::Result;

mod config;
mod proxy;
mod tls;
mod tcp;
mod udp;
mod http2;
mod packet;
mod state;
mod challenge;
mod timing;
mod nfqueue_handler;
mod zerocopy;
mod graceful;
mod http2_advanced;
mod tcp_advanced;

use config::Config;
use proxy::ProxyHandler;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Поддержка выбора конфига через аргумент
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "config.json"
    };

    let config = Config::load(config_path).unwrap_or_else(|e| {
        log::warn!("Failed to load {}: {}, using defaults", config_path, e);
        Config::default()
    });
    
    log::info!("Configuration loaded from: {}", config_path);
    log::info!("Default profile: {}", config.default_profile);
    
    if config.proxy_settings.is_direct() {
        log::info!("Proxy: DIRECT MODE (no upstream proxy)");
    } else {
        log::info!("Proxy: {}:{} ({})", 
            config.proxy_settings.proxy_host,
            config.proxy_settings.proxy_port,
            config.proxy_settings.proxy_type
        );
    }

    let proxy_handler = Arc::new(ProxyHandler::new(config));

    // Запускаем задачу очистки
    let cleanup_handler = proxy_handler.clone();
    tokio::spawn(async move {
        cleanup_handler.cleanup_task().await;
    });

    let listen_addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(listen_addr).await?;
    log::info!("TPROXY listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                log::debug!("New connection from {}", addr);
                
                let handler = proxy_handler.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = handler.handle_connection(stream).await {
                        log::error!("Connection error from {}: {}", addr, e);
                    } else {
                        log::debug!("Connection from {} closed successfully", addr);
                    }
                });
            }
            Err(e) => {
                log::error!("Accept error: {}", e);
            }
        }
    }
}