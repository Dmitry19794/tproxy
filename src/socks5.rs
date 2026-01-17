use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result, Context};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use base64::Engine;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_PASSWORD: u8 = 0x02;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;

pub struct Socks5Connector {
    proxy_host: String,
    proxy_port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Connector {
    pub fn new(
        proxy_host: String,
        proxy_port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            proxy_host,
            proxy_port,
            username,
            password,
        }
    }

    pub async fn connect(&self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        let proxy_addr = format!("{}:{}", self.proxy_host, self.proxy_port);
        let mut stream = TcpStream::connect(&proxy_addr).await
            .context("Failed to connect to SOCKS5 proxy")?;

        log::debug!("Connected to SOCKS5 proxy at {}", proxy_addr);

        self.handshake(&mut stream).await?;
        self.authenticate(&mut stream).await?;
        self.send_connect_request(&mut stream, target_host, target_port).await?;

        log::info!("✓ SOCKS5 connection established to {}:{} via {}", 
            target_host, target_port, proxy_addr);

        Ok(stream)
    }

    async fn handshake(&self, stream: &mut TcpStream) -> Result<()> {
        let mut auth_methods = vec![SOCKS5_AUTH_NONE];
        if self.username.is_some() && self.password.is_some() {
            auth_methods.push(SOCKS5_AUTH_PASSWORD);
        }

        let mut request = vec![SOCKS5_VERSION, auth_methods.len() as u8];
        request.extend_from_slice(&auth_methods);

        stream.write_all(&request).await
            .context("Failed to send SOCKS5 handshake")?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await
            .context("Failed to read SOCKS5 handshake response")?;

        if response[0] != SOCKS5_VERSION {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version in response: {}", response[0]));
        }

        if response[1] == 0xFF {
            return Err(anyhow::anyhow!("No acceptable authentication method"));
        }

        log::debug!("SOCKS5 handshake complete, auth method: {}", response[1]);
        Ok(())
    }

    async fn authenticate(&self, stream: &mut TcpStream) -> Result<()> {
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            let mut auth_request = vec![0x01]; // Auth version
            auth_request.push(username.len() as u8);
            auth_request.extend_from_slice(username.as_bytes());
            auth_request.push(password.len() as u8);
            auth_request.extend_from_slice(password.as_bytes());

            stream.write_all(&auth_request).await
                .context("Failed to send SOCKS5 authentication")?;

            let mut auth_response = [0u8; 2];
            stream.read_exact(&mut auth_response).await
                .context("Failed to read SOCKS5 authentication response")?;

            if auth_response[1] != 0x00 {
                return Err(anyhow::anyhow!("SOCKS5 authentication failed"));
            }

            log::debug!("SOCKS5 authentication successful");
        }

        Ok(())
    }

    async fn send_connect_request(
        &self,
        stream: &mut TcpStream,
        target_host: &str,
        target_port: u16,
    ) -> Result<()> {
        let mut request = vec![
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00, // Reserved
        ];

        if let Ok(ip) = target_host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ipv4) => {
                    request.push(SOCKS5_ATYP_IPV4);
                    request.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    request.push(SOCKS5_ATYP_IPV6);
                    request.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            request.push(SOCKS5_ATYP_DOMAIN);
            request.push(target_host.len() as u8);
            request.extend_from_slice(target_host.as_bytes());
        }

        request.extend_from_slice(&target_port.to_be_bytes());

        stream.write_all(&request).await
            .context("Failed to send SOCKS5 connect request")?;

        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await
            .context("Failed to read SOCKS5 connect response")?;

        if response[0] != SOCKS5_VERSION {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version in connect response"));
        }

        if response[1] != SOCKS5_REP_SUCCESS {
            return Err(anyhow::anyhow!("SOCKS5 connect failed with code: {}", response[1]));
        }

        let atyp = response[3];
        let skip_bytes = match atyp {
            SOCKS5_ATYP_IPV4 => 4 + 2,
            SOCKS5_ATYP_IPV6 => 16 + 2,
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                len_buf[0] as usize + 2
            }
            _ => return Err(anyhow::anyhow!("Invalid address type: {}", atyp)),
        };

        let mut skip_buffer = vec![0u8; skip_bytes];
        stream.read_exact(&mut skip_buffer).await
            .context("Failed to read SOCKS5 bind address")?;

        log::debug!("SOCKS5 CONNECT successful to {}:{}", target_host, target_port);
        Ok(())
    }
}

pub struct HttpsProxyConnector {
    proxy_host: String,
    proxy_port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl HttpsProxyConnector {
    pub fn new(
        proxy_host: String,
        proxy_port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            proxy_host,
            proxy_port,
            username,
            password,
        }
    }

    pub async fn connect(&self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        let proxy_addr = format!("{}:{}", self.proxy_host, self.proxy_port);
        let mut stream = TcpStream::connect(&proxy_addr).await
            .context("Failed to connect to HTTPS proxy")?;

        log::debug!("Connected to HTTPS proxy at {}", proxy_addr);

        let mut connect_request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            target_host, target_port, target_host, target_port
        );

        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            use base64::Engine;
            let credentials = format!("{}:{}", username, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
            connect_request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        connect_request.push_str("\r\n");

        stream.write_all(connect_request.as_bytes()).await
            .context("Failed to send CONNECT request")?;

        let mut response = Vec::new();
        let mut buffer = [0u8; 1];
        let mut headers_end = false;

        while !headers_end {
            stream.read_exact(&mut buffer).await?;
            response.push(buffer[0]);

            if response.len() >= 4 
                && &response[response.len() - 4..] == b"\r\n\r\n" {
                headers_end = true;
            }

            if response.len() > 8192 {
                return Err(anyhow::anyhow!("HTTPS proxy response too large"));
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        
        if !response_str.contains("200") && !response_str.contains("Connection established") {
            return Err(anyhow::anyhow!("HTTPS proxy CONNECT failed: {}", 
                response_str.lines().next().unwrap_or("Unknown error")));
        }

        log::info!("✓ HTTPS proxy connection established to {}:{} via {}", 
            target_host, target_port, proxy_addr);

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_connector_creation() {
        let connector = Socks5Connector::new(
            "127.0.0.1".to_string(),
            1080,
            None,
            None,
        );
        assert_eq!(connector.proxy_host, "127.0.0.1");
        assert_eq!(connector.proxy_port, 1080);
    }

    #[test]
    fn test_https_connector_creation() {
        let connector = HttpsProxyConnector::new(
            "proxy.example.com".to_string(),
            8080,
            Some("user".to_string()),
            Some("pass".to_string()),
        );
        assert_eq!(connector.proxy_host, "proxy.example.com");
    }
}