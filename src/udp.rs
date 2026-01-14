// src/udp.rs
use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct UdpForwarder {
    listen_addr: SocketAddr,
}

impl UdpForwarder {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }
    
    pub async fn run(self) -> Result<()> {
        let socket = UdpSocket::bind(self.listen_addr).await?;
        let mut buf = vec![0u8; 65535];
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    // Прозрачная передача
                    let _ = socket.send_to(&buf[..len], src).await;
                }
                Err(_) => break,
            }
        }
        
        Ok(())
    }
}
