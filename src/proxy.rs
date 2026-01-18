use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::Result;
use std::os::unix::io::AsRawFd;

use crate::config::Config;
use crate::tls::{TlsClientHello, SessionTicketCache};
use crate::challenge::ChallengeHandler;
use crate::http2::Http2Handler;
use crate::state::ConnectionStateManager;
use crate::graceful::{GracefulShutdown, ConnectionRecovery};
use crate::tcp_advanced::{configure_tcp_socket, apply_tcp_options};
use crate::timing::TimingPreserver;
use crate::socks5::{Socks5Connector, HttpsProxyConnector};

const BUFFER_SIZE: usize = 65536;

pub struct ProxyHandler {
    config: Arc<Config>,
    session_cache: Arc<SessionTicketCache>,
    challenge_handler: Arc<parking_lot::RwLock<ChallengeHandler>>,
    state_manager: Arc<ConnectionStateManager>,
    graceful_shutdown: Arc<GracefulShutdown>,
}

impl ProxyHandler {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            session_cache: Arc::new(SessionTicketCache::new()),
            challenge_handler: Arc::new(parking_lot::RwLock::new(ChallengeHandler::new())),
            state_manager: Arc::new(ConnectionStateManager::new()),
            graceful_shutdown: Arc::new(GracefulShutdown::new()),
        }
    }

    pub async fn handle_connection(&self, mut client_stream: TcpStream) -> Result<()> {
        let conn_id = self.state_manager.create_connection();
        self.graceful_shutdown.register_connection(conn_id).await;

        let result = self.process_connection(&mut client_stream, conn_id).await;

        self.graceful_shutdown.unregister_connection(conn_id).await;
        self.state_manager.remove_connection(conn_id);

        result
    }

    async fn process_connection(&self, client_stream: &mut TcpStream, conn_id: u64) -> Result<()> {
        configure_tcp_socket(client_stream)?;
        
        // Apply iOS Safari TCP options
        if let Err(e) = apply_tcp_options(client_stream, true) {
            log::warn!("Failed to apply TCP options: {}", e);
        }

        let mut buffer = vec![0u8; BUFFER_SIZE];
        let n = client_stream.read(&mut buffer).await?;

        if n == 0 {
            return Ok(());
        }

        let request_data = &buffer[..n];

        if self.is_connect_method(request_data) {
            self.handle_connect_method(client_stream, request_data, conn_id).await
        } else if self.is_tls_handshake(request_data) {
            self.handle_tls_connection(client_stream, request_data, conn_id).await
        } else if self.is_http_request(request_data) {
            self.handle_http_connection(client_stream, request_data, conn_id).await
        } else {
            self.handle_tcp_passthrough(client_stream, request_data, conn_id).await
        }
    }

    async fn handle_connect_method(
        &self,
        client_stream: &mut TcpStream,
        initial_data: &[u8],
        conn_id: u64,
    ) -> Result<()> {
        let request = String::from_utf8_lossy(initial_data);
        let target = self.extract_connect_target(&request)?;
        
        log::debug!("CONNECT method to: {}", target);

        let mut server_stream = self.connect_to_target(&target).await?;
        
        // Apply TCP options to server connection
        if let Err(e) = apply_tcp_options(&server_stream, false) {
            log::warn!("Failed to apply server TCP options: {}", e);
        }

        let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        client_stream.write_all(response).await?;
        log::debug!("Sent 200 Connection Established to client");

        let mut first_packet = vec![0u8; BUFFER_SIZE];
        let n = client_stream.read(&mut first_packet).await?;

        if n == 0 {
            return Ok(());
        }

        let first_packet = &first_packet[..n];

        if self.is_tls_handshake(first_packet) {
            log::debug!("Detected TLS ClientHello, applying iOS Safari fingerprint");

            let domain = target.split(':').next().unwrap_or(&target).to_string();

            match TlsClientHello::parse(first_packet) {
                Ok(client_hello) => {
                    match client_hello.to_ios_safari(Some(&self.session_cache), &domain) {
                        Ok(modified_hello) => {
                            log::info!("✓ TLS fingerprint applied: {} ({}→{} bytes)", 
                                domain, first_packet.len(), modified_hello.len());
                            server_stream.write_all(&modified_hello).await?;
                        }
                        Err(e) => {
                            log::warn!("Failed to generate iOS ClientHello: {}, using original", e);
                            server_stream.write_all(first_packet).await?;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to parse ClientHello: {}, using original", e);
                    server_stream.write_all(first_packet).await?;
                }
            }
        } else {
            log::debug!("Non-TLS data, forwarding as-is");
            server_stream.write_all(first_packet).await?;
        }

        self.proxy_bidirectional(client_stream, &mut server_stream, conn_id).await
    }

    fn extract_connect_target(&self, request: &str) -> Result<String> {
        for line in request.lines() {
            if line.to_uppercase().starts_with("CONNECT ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Ok(parts[1].to_string());
                }
            }
        }
        Err(anyhow::anyhow!("Could not extract CONNECT target"))
    }

    fn is_connect_method(&self, data: &[u8]) -> bool {
        data.len() >= 7 && data[..7].eq_ignore_ascii_case(b"CONNECT")
    }

    fn is_tls_handshake(&self, data: &[u8]) -> bool {
        data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03
    }

    fn is_http_request(&self, data: &[u8]) -> bool {
        data.starts_with(b"GET ") || 
        data.starts_with(b"POST ") || 
        data.starts_with(b"PUT ") ||
        data.starts_with(b"HEAD ") ||
        data.starts_with(b"DELETE ")
    }

    async fn handle_tls_connection(
        &self,
        client_stream: &mut TcpStream,
        initial_data: &[u8],
        conn_id: u64,
    ) -> Result<()> {
        let domain = self.extract_sni(initial_data).unwrap_or_default();

        let client_hello = TlsClientHello::parse(initial_data)?;
        let modified_hello = client_hello.to_ios_safari(Some(&self.session_cache), &domain)?;

        let target = if !domain.is_empty() {
            format!("{}:443", domain)
        } else {
            "unknown:443".to_string()
        };

        let mut server_stream = self.connect_to_target(&target).await?;
        apply_tcp_options(&server_stream, false)?;

        server_stream.write_all(&modified_hello).await?;

        self.proxy_bidirectional(client_stream, &mut server_stream, conn_id).await
    }

    async fn handle_http_connection(
        &self,
        client_stream: &mut TcpStream,
        initial_data: &[u8],
        conn_id: u64,
    ) -> Result<()> {
        let request = String::from_utf8_lossy(initial_data);
        let is_http2 = request.contains("HTTP/2");

        let target_host = self.extract_http_host(&request);
        log::debug!("Extracted target host: {}", target_host);

        let mut server_stream = self.connect_to_target(&target_host).await?;
        apply_tcp_options(&server_stream, false)?;

        let modified_request = if self.config.proxy_settings.is_direct() {
            self.rewrite_http_request(&request)
        } else {
            initial_data.to_vec()
        };

        if is_http2 {
            self.handle_http2_connection(client_stream, &mut server_stream, &modified_request, conn_id).await
        } else {
            server_stream.write_all(&modified_request).await?;
            
            // Read response and check for challenges
            let mut response_buffer = vec![0u8; BUFFER_SIZE];
            let n = server_stream.read(&mut response_buffer).await?;
            
            if n > 0 {
                let response_data = &response_buffer[..n];
                let response_str = String::from_utf8_lossy(response_data);
                
                // Check for challenge/redirect
                if self.detect_challenge_in_response(&response_str) {
                    log::info!("Challenge detected, handling...");
                    self.handle_challenge_response(
                        client_stream, 
                        &mut server_stream, 
                        response_data, 
                        &target_host,
                        conn_id
                    ).await?;
                } else {
                    // Normal response
                    client_stream.write_all(response_data).await?;
                    self.proxy_bidirectional(client_stream, &mut server_stream, conn_id).await?;
                }
            }
            
            Ok(())
        }
    }

    fn detect_challenge_in_response(&self, response: &str) -> bool {
        let mut headers = std::collections::HashMap::new();
        
        for line in response.lines() {
            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_lowercase();
                let value = line[pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        let handler = self.challenge_handler.read();
        handler.detect_challenge(response, &headers)
    }

    async fn handle_challenge_response(
        &self,
        client_stream: &mut TcpStream,
        server_stream: &mut TcpStream,
        response_data: &[u8],
        url: &str,
        conn_id: u64,
    ) -> Result<()> {
        let response_str = String::from_utf8_lossy(response_data);
        
        // Extract status code
        let status_code = response_str.lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(200);

        // Extract cookies
        let mut cookies = Vec::new();
        for line in response_str.lines() {
            if line.to_lowercase().starts_with("set-cookie:") {
                if let Some(cookie) = line.split(':').nth(1) {
                    cookies.push(cookie.trim().to_string());
                }
            }
        }

        // Store challenge state
        {
            let mut handler = self.challenge_handler.write();
            handler.register_challenge(url.to_string(), cookies.clone());
            
            if handler.is_redirect(status_code) {
                handler.start_redirect_chain(url.to_string());
                
                // Extract redirect location
                for line in response_str.lines() {
                    if line.to_lowercase().starts_with("location:") {
                        if let Some(location) = line.split(':').nth(1) {
                            let _ = handler.add_redirect(
                                url,
                                url.to_string(),
                                location.trim().to_string(),
                                status_code,
                            );
                        }
                    }
                }
            }
        }

        // Pass response to client (important: don't modify challenge responses)
        client_stream.write_all(response_data).await?;
        
        // Continue proxying
        self.proxy_bidirectional(client_stream, server_stream, conn_id).await
    }

    fn rewrite_http_request(&self, request: &str) -> Vec<u8> {
        let parts: Vec<&str> = request.split("\r\n\r\n").collect();
        let headers_part = parts[0];
        let body = if parts.len() > 1 { parts[1] } else { "" };
        
        let lines: Vec<&str> = headers_part.split("\r\n").collect();
        
        if lines.is_empty() {
            return request.as_bytes().to_vec();
        }

        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        
        if parts.len() >= 2 {
            let method = parts[0];
            let url = parts[1];
            let version = if parts.len() >= 3 { parts[2] } else { "HTTP/1.1" };
            
            let path = if url.starts_with("http://") {
                if let Some(host_end) = url[7..].find('/') {
                    &url[7 + host_end..]
                } else {
                    "/"
                }
            } else {
                url
            };
            
            let new_first_line = format!("{} {} {}", method, path, version);
            let mut new_lines = vec![new_first_line];
            
            for line in &lines[1..] {
                if !line.is_empty() && !line.to_lowercase().starts_with("proxy-connection:") {
                    new_lines.push(line.to_string());
                }
            }
            
            let rewritten = if body.is_empty() {
                format!("{}\r\n\r\n", new_lines.join("\r\n"))
            } else {
                format!("{}\r\n\r\n{}", new_lines.join("\r\n"), body)
            };
            
            return rewritten.as_bytes().to_vec();
        }
        
        request.as_bytes().to_vec()
    }

    async fn handle_http2_connection(
        &self,
        client_stream: &mut TcpStream,
        server_stream: &mut TcpStream,
        initial_data: &[u8],
        conn_id: u64,
    ) -> Result<()> {
        let mut http2_handler = Http2Handler::new_ios_safari();

        let preface = http2_handler.build_connection_preface();
        server_stream.write_all(&preface).await?;

        server_stream.write_all(initial_data).await?;

        self.proxy_http2_bidirectional(
            client_stream,
            server_stream,
            &mut http2_handler,
            conn_id,
        ).await
    }

    async fn proxy_http2_bidirectional(
        &self,
        client_stream: &mut TcpStream,
        server_stream: &mut TcpStream,
        http2_handler: &mut Http2Handler,
        conn_id: u64,
    ) -> Result<()> {
        let mut client_buffer = vec![0u8; BUFFER_SIZE];
        let mut server_buffer = vec![0u8; BUFFER_SIZE];
        let mut timing = TimingPreserver::new(0.05);

        loop {
            if self.graceful_shutdown.is_shutting_down().await {
                break;
            }

            tokio::select! {
                result = client_stream.read(&mut client_buffer) => {
                    let n = result?;
                    if n == 0 {
                        break;
                    }

                    timing.wait_natural_delay().await;
                    server_stream.write_all(&client_buffer[..n]).await?;
                    timing.record_send();
                    self.graceful_shutdown.mark_activity(conn_id).await;
                }
                result = server_stream.read(&mut server_buffer) => {
                    let n = result?;
                    if n == 0 {
                        break;
                    }

                    // Process HTTP/2 frame and get response frames
                    let response_frames = http2_handler.handle_incoming_frame(&server_buffer[..n])?;
                    if !response_frames.is_empty() {
                        server_stream.write_all(&response_frames).await?;
                    }

                    // Check and send window updates
                    let window_updates = http2_handler.check_and_send_window_updates();
                    for frame in window_updates {
                        server_stream.write_all(&frame).await?;
                    }

                    timing.wait_natural_delay().await;
                    client_stream.write_all(&server_buffer[..n]).await?;
                    timing.record_send();
                    self.graceful_shutdown.mark_activity(conn_id).await;
                }
            }
        }

        Ok(())
    }

    async fn handle_tcp_passthrough(
        &self,
        client_stream: &mut TcpStream,
        initial_data: &[u8],
        conn_id: u64,
    ) -> Result<()> {
        let mut server_stream = self.connect_to_upstream().await?;
        apply_tcp_options(&server_stream, false)?;

        server_stream.write_all(initial_data).await?;

        self.proxy_bidirectional(client_stream, &mut server_stream, conn_id).await
    }

    async fn proxy_bidirectional(
        &self,
        client_stream: &mut TcpStream,
        server_stream: &mut TcpStream,
        conn_id: u64,
    ) -> Result<()> {
        log::debug!("Starting bidirectional proxy for connection {}", conn_id);
        
        let mut client_buffer = vec![0u8; BUFFER_SIZE];
        let mut server_buffer = vec![0u8; BUFFER_SIZE];
        let mut timing = TimingPreserver::new(0.05);

        loop {
            if self.graceful_shutdown.is_shutting_down().await {
                log::debug!("Shutdown detected for connection {}", conn_id);
                break;
            }

            tokio::select! {
                result = client_stream.read(&mut client_buffer) => {
                    match result {
                        Ok(0) => {
                            log::debug!("Client closed connection {}", conn_id);
                            break;
                        }
                        Ok(n) => {
                            timing.wait_natural_delay().await;
                            
                            if let Err(e) = server_stream.write_all(&client_buffer[..n]).await {
                                log::error!("Failed to write to server: {}", e);
                                break;
                            }

                            timing.record_send();
                            self.graceful_shutdown.mark_activity(conn_id).await;
                        }
                        Err(e) => {
                            log::error!("Client read error: {}", e);
                            break;
                        }
                    }
                }
                result = server_stream.read(&mut server_buffer) => {
                    match result {
                        Ok(0) => {
                            log::debug!("Server closed connection {}", conn_id);
                            break;
                        }
                        Ok(n) => {
                            timing.wait_natural_delay().await;
                            
                            if let Err(e) = client_stream.write_all(&server_buffer[..n]).await {
                                log::error!("Failed to write to client: {}", e);
                                break;
                            }

                            timing.record_send();
                            self.graceful_shutdown.mark_activity(conn_id).await;
                        }
                        Err(e) => {
                            log::error!("Server read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        log::debug!("Bidirectional proxy ended for connection {}", conn_id);
        Ok(())
    }

    async fn connect_to_upstream(&self) -> Result<TcpStream> {
        let proxy = &self.config.proxy_settings;
        let addr = format!("{}:{}", proxy.proxy_host, proxy.proxy_port);
        
        let recovery = ConnectionRecovery::new();
        
        recovery.retry_with_backoff(|| async {
            TcpStream::connect(&addr).await.map_err(|e| e.into())
        }).await
    }

    async fn connect_to_target(&self, target: &str) -> Result<TcpStream> {
        let proxy = &self.config.proxy_settings;
        
        if proxy.is_direct() {
            log::debug!("Direct mode: connecting to {}", target);
            
            let recovery = ConnectionRecovery::new();
            return recovery.retry_with_backoff(|| async {
                TcpStream::connect(target).await.map_err(|e| e.into())
            }).await;
        }
        
        // Parse target
        let (host, port) = if let Some(pos) = target.rfind(':') {
            (&target[..pos], target[pos + 1..].parse::<u16>().unwrap_or(443))
        } else {
            (target, 443)
        };

        match proxy.proxy_type.to_lowercase().as_str() {
            "socks5" => {
                let connector = Socks5Connector::new(
                    proxy.proxy_host.clone(),
                    proxy.proxy_port,
                    proxy.username.clone(),
                    proxy.password.clone(),
                );
                connector.connect(host, port).await
            }
            "http" | "https" => {
                let connector = HttpsProxyConnector::new(
                    proxy.proxy_host.clone(),
                    proxy.proxy_port,
                    proxy.username.clone(),
                    proxy.password.clone(),
                );
                connector.connect(host, port).await
            }
            _ => {
                Err(anyhow::anyhow!("Unsupported proxy type: {}", proxy.proxy_type))
            }
        }
    }

    fn extract_http_host(&self, request: &str) -> String {
        for line in request.lines() {
            if line.to_lowercase().starts_with("host:") {
                let host = line[5..].trim();
                
                if host.contains(':') {
                    return host.to_string();
                } else {
                    if request.starts_with("CONNECT") {
                        return format!("{}:443", host);
                    } else {
                        return format!("{}:80", host);
                    }
                }
            }
        }
        
        if let Some(first_line) = request.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let url = parts[1];
                if url.starts_with("http://") {
                    if let Some(host_part) = url.strip_prefix("http://") {
                        if let Some(host_end) = host_part.find('/') {
                            let host = &host_part[..host_end];
                            return if host.contains(':') {
                                host.to_string()
                            } else {
                                format!("{}:80", host)
                            };
                        }
                    }
                }
            }
        }
        
        log::warn!("Could not extract host from request, using default");
        "httpbin.org:80".to_string()
    }

    fn extract_sni(&self, data: &[u8]) -> Option<String> {
        if data.len() < 43 {
            return None;
        }

        let handshake_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + handshake_len {
            return None;
        }

        let mut offset = 43;
        
        if offset >= data.len() {
            return None;
        }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > data.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;

        if offset >= data.len() {
            return None;
        }
        let compression_len = data[offset] as usize;
        offset += 1 + compression_len;

        if offset + 2 > data.len() {
            return None;
        }
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let extensions_end = offset + extensions_len;
        while offset + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if ext_type == 0 && offset + ext_len <= data.len() {
                let mut sni_offset = offset + 2;
                if sni_offset + 3 <= offset + ext_len {
                    let name_len = u16::from_be_bytes([data[sni_offset + 1], data[sni_offset + 2]]) as usize;
                    sni_offset += 3;
                    if sni_offset + name_len <= offset + ext_len {
                        return Some(String::from_utf8_lossy(&data[sni_offset..sni_offset + name_len]).to_string());
                    }
                }
            }

            offset += ext_len;
        }

        None
    }

    pub async fn cleanup_task(&self) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            self.session_cache.cleanup_expired();
            self.challenge_handler.write().cleanup_expired();
            self.state_manager.cleanup();
            self.graceful_shutdown.cleanup_idle_connections(
                tokio::time::Duration::from_secs(300)
            ).await;
            
            log::debug!("Cleanup completed");
        }
    }
}