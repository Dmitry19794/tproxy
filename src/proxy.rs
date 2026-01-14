// src/proxy.rs
use anyhow::Result;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug, Clone)]
pub enum ProxyType {
    Direct,
    Http(ProxyConfig),
    Socks5(ProxyConfig),
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub struct ProxyConnector;

impl ProxyConnector {
    pub async fn connect(
        proxy: &ProxyType,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream> {
        match proxy {
            ProxyType::Direct => {
                Self::connect_direct(target_host, target_port).await
            }
            ProxyType::Http(config) => {
                Self::connect_http(config, target_host, target_port).await
            }
            ProxyType::Socks5(config) => {
                Self::connect_socks5(config, target_host, target_port).await
            }
        }
    }
    
    async fn connect_direct(host: &str, port: u16) -> Result<TcpStream> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).await?;
        Ok(stream)
    }
    
    async fn connect_http(
        config: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream> {
        let proxy_addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect(&proxy_addr).await?;
        
        let mut request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            target_host, target_port, target_host, target_port
        );
        
        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            let auth = general_purpose::STANDARD.encode(format!("{}:{}", username, password));
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", auth));
        }
        
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        
        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("HTTP/1.1 200") && !response_str.starts_with("HTTP/1.0 200") {
            return Err(anyhow::anyhow!("Proxy CONNECT failed"));
        }
        
        Ok(stream)
    }
    
    async fn connect_socks5(
        config: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream> {
        let proxy_addr = format!("{}:{}", config.host, config.port);
        let mut stream = TcpStream::connect(&proxy_addr).await?;
        
        let has_auth = config.username.is_some() && config.password.is_some();
        
        let methods = if has_auth {
            vec![0x05, 0x02, 0x00, 0x02]
        } else {
            vec![0x05, 0x01, 0x00]
        };
        
        stream.write_all(&methods).await?;
        
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version"));
        }
        
        match response[1] {
            0x00 => {},
            0x02 => {
                if let (Some(username), Some(password)) = (&config.username, &config.password) {
                    Self::socks5_auth(&mut stream, username, password).await?;
                }
            }
            _ => {
                return Err(anyhow::anyhow!("SOCKS5 auth failed"));
            }
        }
        
        let mut request = vec![0x05, 0x01, 0x00, 0x03];
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
        request.extend_from_slice(&target_port.to_be_bytes());
        
        stream.write_all(&request).await?;
        
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await?;
        
        if response[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 CONNECT failed"));
        }
        
        match response[3] {
            0x01 => {
                let mut addr = [0u8; 6];
                stream.read_exact(&mut addr).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut domain).await?;
            }
            0x04 => {
                let mut addr = [0u8; 18];
                stream.read_exact(&mut addr).await?;
            }
            _ => {}
        }
        
        Ok(stream)
    }
    
    async fn socks5_auth(
        stream: &mut TcpStream,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let mut request = vec![0x01];
        request.push(username.len() as u8);
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        
        stream.write_all(&request).await?;
        
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        
        if response[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 authentication failed"));
        }
        
        Ok(())
    }
}
