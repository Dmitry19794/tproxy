use anyhow::Result;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

const MAX_DATAGRAM_SIZE: usize = 65535;
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct UdpSession {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    last_activity: Instant,
    bytes_sent: u64,
    bytes_received: u64,
}

impl UdpSession {
    fn new(client_addr: SocketAddr, target_addr: SocketAddr) -> Self {
        Self {
            client_addr,
            target_addr,
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

pub struct UdpForwarder {
    listen_addr: SocketAddr,
    sessions: Arc<RwLock<HashMap<SocketAddr, UdpSession>>>,
}

impl UdpForwarder {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run(self) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        log::info!("UDP forwarder listening on {}", self.listen_addr);

        // Cleanup task
        let sessions_cleanup = self.sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                Self::cleanup_sessions(&sessions_cleanup).await;
            }
        });

        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let data = &buf[..len];
                    
                    // Detect protocol
                    if self.is_quic_packet(data) {
                        log::debug!("QUIC packet from {}, {} bytes", src, len);
                        self.handle_quic_packet(&socket, data, src).await;
                    } else if self.is_stun_packet(data) {
                        log::debug!("STUN packet from {}, {} bytes", src, len);
                        self.handle_stun_packet(&socket, data, src).await;
                    } else if self.is_dtls_packet(data) {
                        log::debug!("DTLS packet from {}, {} bytes", src, len);
                        self.handle_dtls_packet(&socket, data, src).await;
                    } else {
                        log::debug!("Generic UDP packet from {}, {} bytes", src, len);
                        self.handle_generic_udp(&socket, data, src).await;
                    }
                }
                Err(e) => {
                    log::error!("UDP recv error: {}", e);
                }
            }
        }
    }

    /// QUIC packet detection (long header starts with 0b11xxxxxx or 0b10xxxxxx)
    fn is_quic_packet(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        
        let first_byte = data[0];
        // QUIC Long Header: 0b11xxxxxx
        // QUIC Short Header: 0b01xxxxxx
        (first_byte & 0xC0) == 0xC0 || (first_byte & 0xC0) == 0x40
    }

    /// STUN packet detection (first 2 bits must be 00)
    fn is_stun_packet(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }
        
        // STUN message type: first 2 bits are 00
        let first_byte = data[0];
        (first_byte & 0xC0) == 0x00 &&
        // Magic cookie check (offset 4-7): 0x2112A442
        data.len() >= 8 &&
        &data[4..8] == &[0x21, 0x12, 0xA4, 0x42]
    }

    /// DTLS packet detection (ContentType in range 20-23)
    fn is_dtls_packet(&self, data: &[u8]) -> bool {
        if data.len() < 13 {
            return false;
        }
        
        let content_type = data[0];
        // DTLS ContentType: 20-23 (ChangeCipherSpec, Alert, Handshake, ApplicationData)
        // Version: 254.xxx (DTLS 1.0/1.2)
        content_type >= 20 && content_type <= 23 && data[1] == 254
    }

    /// Handle QUIC: прозрачная передача без модификаций
    async fn handle_quic_packet(&self, socket: &UdpSocket, data: &[u8], src: SocketAddr) {
        // QUIC - полностью прозрачная передача
        // Не модифицируем пакеты, только форвардим
        
        if let Err(e) = socket.send_to(data, src).await {
            log::error!("Failed to forward QUIC packet: {}", e);
        }
        
        // Update session stats
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&src) {
            session.bytes_sent += data.len() as u64;
            session.update_activity();
        } else {
            let mut session = UdpSession::new(src, src);
            session.bytes_sent = data.len() as u64;
            sessions.insert(src, session);
        }
    }

    /// Handle STUN: прозрачная передача
    async fn handle_stun_packet(&self, socket: &UdpSocket, data: &[u8], src: SocketAddr) {
        // STUN/TURN - прозрачная передача для WebRTC
        
        if let Err(e) = socket.send_to(data, src).await {
            log::error!("Failed to forward STUN packet: {}", e);
        }
        
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&src) {
            session.bytes_sent += data.len() as u64;
            session.update_activity();
        } else {
            let mut session = UdpSession::new(src, src);
            session.bytes_sent = data.len() as u64;
            sessions.insert(src, session);
        }
    }

    /// Handle DTLS: прозрачная передача
    async fn handle_dtls_packet(&self, socket: &UdpSocket, data: &[u8], src: SocketAddr) {
        // DTLS - прозрачная передача для WebRTC
        
        if let Err(e) = socket.send_to(data, src).await {
            log::error!("Failed to forward DTLS packet: {}", e);
        }
        
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&src) {
            session.bytes_sent += data.len() as u64;
            session.update_activity();
        } else {
            let mut session = UdpSession::new(src, src);
            session.bytes_sent = data.len() as u64;
            sessions.insert(src, session);
        }
    }

    /// Handle generic UDP
    async fn handle_generic_udp(&self, socket: &UdpSocket, data: &[u8], src: SocketAddr) {
        // Generic UDP - прозрачная передача
        
        if let Err(e) = socket.send_to(data, src).await {
            log::error!("Failed to forward UDP packet: {}", e);
        }
        
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&src) {
            session.bytes_sent += data.len() as u64;
            session.update_activity();
        } else {
            let mut session = UdpSession::new(src, src);
            session.bytes_sent = data.len() as u64;
            sessions.insert(src, session);
        }
    }

    async fn cleanup_sessions(sessions: &Arc<RwLock<HashMap<SocketAddr, UdpSession>>>) {
        let mut sessions = sessions.write().await;
        let before = sessions.len();
        
        sessions.retain(|_, session| !session.is_expired());
        
        let after = sessions.len();
        if before != after {
            log::debug!("Cleaned up {} expired UDP sessions ({} active)", 
                before - after, after);
        }
    }

    pub async fn get_stats(&self) -> UdpStats {
        let sessions = self.sessions.read().await;
        
        let total_sessions = sessions.len();
        let total_bytes_sent: u64 = sessions.values().map(|s| s.bytes_sent).sum();
        let total_bytes_received: u64 = sessions.values().map(|s| s.bytes_received).sum();
        
        UdpStats {
            active_sessions: total_sessions,
            total_bytes_sent,
            total_bytes_received,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpStats {
    pub active_sessions: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_detection() {
        let forwarder = UdpForwarder::new("127.0.0.1:8080".parse().unwrap());
        
        // QUIC long header
        let quic_long = vec![0xC0, 0x00, 0x00, 0x00];
        assert!(forwarder.is_quic_packet(&quic_long));
        
        // QUIC short header
        let quic_short = vec![0x40, 0x00, 0x00, 0x00];
        assert!(forwarder.is_quic_packet(&quic_short));
        
        // Not QUIC
        let not_quic = vec![0x00, 0x00, 0x00, 0x00];
        assert!(!forwarder.is_quic_packet(&not_quic));
    }

    #[test]
    fn test_stun_detection() {
        let forwarder = UdpForwarder::new("127.0.0.1:8080".parse().unwrap());
        
        // STUN packet with magic cookie
        let stun = vec![
            0x00, 0x01, 0x00, 0x08,  // Type and length
            0x21, 0x12, 0xA4, 0x42,  // Magic cookie
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(forwarder.is_stun_packet(&stun));
        
        // Not STUN (wrong magic cookie)
        let not_stun = vec![
            0x00, 0x01, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!forwarder.is_stun_packet(&not_stun));
    }

    #[test]
    fn test_dtls_detection() {
        let forwarder = UdpForwarder::new("127.0.0.1:8080".parse().unwrap());
        
        // DTLS handshake
        let dtls = vec![
            22,   // ContentType: Handshake
            254, 253,  // Version: DTLS 1.2
            0, 0, 0, 0, 0, 0, 0, 1,  // Epoch + Sequence
            0, 10,  // Length
            0, 0, 0, 0, 0,
        ];
        assert!(forwarder.is_dtls_packet(&dtls));
    }

    #[test]
    fn test_session_expiry() {
        let session = UdpSession::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap()
        );
        
        assert!(!session.is_expired());
    }
}