use tokio::net::TcpListener;
use std::sync::Arc;
use anyhow::Result;
use tokio::signal;

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
mod socks5;

use config::Config;
use proxy::ProxyHandler;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

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
    
    log::info!("=================================================");
    log::info!("TPROXY v2.0 - Transparent Proxy with Fingerprinting");
    log::info!("=================================================");
    log::info!("Configuration: {}", config_path);
    log::info!("Profile: {}", config.default_profile);
    
    if config.proxy_settings.is_direct() {
        log::info!("Mode: DIRECT (no upstream proxy)");
    } else {
        log::info!("Mode: {} proxy", config.proxy_settings.proxy_type.to_uppercase());
        log::info!("Upstream: {}:{}", 
            config.proxy_settings.proxy_host,
            config.proxy_settings.proxy_port
        );
        if config.proxy_settings.username.is_some() {
            log::info!("Authentication: enabled");
        }
    }
    log::info!("=================================================");

    let proxy_handler = Arc::new(ProxyHandler::new(config));

    // Cleanup task
    let cleanup_handler = proxy_handler.clone();
    tokio::spawn(async move {
        cleanup_handler.cleanup_task().await;
    });

    // Graceful shutdown handler
    let shutdown_handler = proxy_handler.clone();
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                log::info!("Received SIGINT, initiating graceful shutdown...");
                // Можно добавить логику shutdown
            }
            Err(err) => {
                log::error!("Failed to listen for SIGINT: {}", err);
            }
        }
    });

    let listen_addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(listen_addr).await?;
    log::info!("✓ Listening on {}", listen_addr);
    log::info!("Ready to accept connections");

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