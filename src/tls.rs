use bytes::{BytesMut, BufMut};
use anyhow::Result;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];
const CLIENT_HELLO: u8 = 0x01;
const SESSION_TICKET_LIFETIME: u64 = 7200; // 2 hours

#[derive(Debug, Clone)]
pub struct TlsClientHello {
    pub version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
}

#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub ticket: Vec<u8>,
    pub timestamp: u64,
    pub domain: String,
}

impl SessionTicket {
    pub fn new(ticket: Vec<u8>, domain: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            ticket,
            timestamp,
            domain,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.timestamp > SESSION_TICKET_LIFETIME
    }
}

pub struct SessionTicketCache {
    tickets: Arc<RwLock<HashMap<String, SessionTicket>>>,
}

impl SessionTicketCache {
    pub fn new() -> Self {
        Self {
            tickets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn store(&self, domain: String, ticket: Vec<u8>) {
        let session_ticket = SessionTicket::new(ticket, domain.clone());
        self.tickets.write().insert(domain, session_ticket);
    }

    pub fn get(&self, domain: &str) -> Option<Vec<u8>> {
        let tickets = self.tickets.read();
        if let Some(ticket) = tickets.get(domain) {
            if !ticket.is_expired() {
                return Some(ticket.ticket.clone());
            }
        }
        None
    }

    pub fn cleanup_expired(&self) {
        let mut tickets = self.tickets.write();
        tickets.retain(|_, ticket| !ticket.is_expired());
    }

    pub fn clear(&self) {
        self.tickets.write().clear();
    }
}

impl TlsClientHello {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(anyhow::anyhow!("Data too short for TLS record"));
        }

        if data[0] != TLS_HANDSHAKE {
            return Err(anyhow::anyhow!("Not a TLS handshake"));
        }

        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + record_length {
            return Err(anyhow::anyhow!("Incomplete TLS record"));
        }

        let handshake_data = &data[5..];
        
        if handshake_data[0] != CLIENT_HELLO {
            return Err(anyhow::anyhow!("Not a ClientHello"));
        }

        let mut offset = 4;
        
        let version = [handshake_data[offset], handshake_data[offset + 1]];
        offset += 2;

        let mut random = [0u8; 32];
        random.copy_from_slice(&handshake_data[offset..offset + 32]);
        offset += 32;

        let session_id_len = handshake_data[offset] as usize;
        offset += 1;
        let session_id = handshake_data[offset..offset + session_id_len].to_vec();
        offset += session_id_len;

        let cipher_suites_len = u16::from_be_bytes([
            handshake_data[offset],
            handshake_data[offset + 1],
        ]) as usize;
        offset += 2;

        let mut cipher_suites = Vec::new();
        for i in (0..cipher_suites_len).step_by(2) {
            let suite = u16::from_be_bytes([
                handshake_data[offset + i],
                handshake_data[offset + i + 1],
            ]);
            cipher_suites.push(suite);
        }
        offset += cipher_suites_len;

        let compression_len = handshake_data[offset] as usize;
        offset += 1;
        let compression_methods = handshake_data[offset..offset + compression_len].to_vec();
        offset += compression_len;

        let mut extensions = Vec::new();
        if offset < handshake_data.len() {
            let extensions_len = u16::from_be_bytes([
                handshake_data[offset],
                handshake_data[offset + 1],
            ]) as usize;
            offset += 2;

            let extensions_end = offset + extensions_len;
            while offset < extensions_end {
                let ext_type = u16::from_be_bytes([
                    handshake_data[offset],
                    handshake_data[offset + 1],
                ]);
                offset += 2;

                let ext_len = u16::from_be_bytes([
                    handshake_data[offset],
                    handshake_data[offset + 1],
                ]) as usize;
                offset += 2;

                let ext_data = handshake_data[offset..offset + ext_len].to_vec();
                offset += ext_len;

                extensions.push(TlsExtension {
                    extension_type: ext_type,
                    data: ext_data,
                });
            }
        }

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    pub fn to_ios_safari(&self, ticket_cache: Option<&SessionTicketCache>, domain: &str) -> Result<Vec<u8>> {
        let mut result = BytesMut::new();
        
        result.put_u8(TLS_HANDSHAKE);
        result.put_slice(&TLS_VERSION_1_2);
        
        let mut handshake = BytesMut::new();
        handshake.put_u8(CLIENT_HELLO);
        
        let mut client_hello = BytesMut::new();
        
        client_hello.put_slice(&TLS_VERSION_1_2);
        
        let mut rng = rand::rng();
        for _ in 0..32 {
            client_hello.put_u8(rng.random_range(0..=255));
        }
        
        client_hello.put_u8(0);
        
        let safari_ciphers = get_ios_safari_cipher_suites();
        client_hello.put_u16(safari_ciphers.len() as u16 * 2);
        for cipher in safari_ciphers {
            client_hello.put_u16(cipher);
        }
        
        client_hello.put_u8(1);
        client_hello.put_u8(0);
        
        let extensions = self.build_ios_extensions(ticket_cache, domain);
        let extensions_bytes = Self::serialize_extensions(&extensions);
        client_hello.put_u16(extensions_bytes.len() as u16);
        client_hello.put_slice(&extensions_bytes);
        
        let ch_len = client_hello.len();
        handshake.put_u8((ch_len >> 16) as u8);
        handshake.put_u8((ch_len >> 8) as u8);
        handshake.put_u8(ch_len as u8);
        handshake.put_slice(&client_hello);
        
        result.put_u16(handshake.len() as u16);
        result.put_slice(&handshake);
        
        Ok(result.to_vec())
    }

    fn build_ios_extensions(&self, ticket_cache: Option<&SessionTicketCache>, domain: &str) -> Vec<TlsExtension> {
        let mut extensions = Vec::new();
        
        let grease_values = get_grease_values();
        let mut rng = rand::rng();
        let grease_idx = rng.random_range(0..grease_values.len());
        let grease = grease_values[grease_idx];
        
        extensions.push(TlsExtension {
            extension_type: grease,
            data: vec![],
        });
        
        extensions.push(TlsExtension {
            extension_type: 0,
            data: self.find_extension_data(0).unwrap_or_default(),
        });
        
        extensions.push(TlsExtension {
            extension_type: 23,
            data: vec![],
        });
        
        extensions.push(TlsExtension {
            extension_type: 65281,
            data: vec![0x00],
        });
        
        extensions.push(TlsExtension {
            extension_type: 10,
            data: vec![
                0x00, 0x0a,
                0x00, 0x1d,
                0x00, 0x17,
                0x00, 0x18,
                0x00, 0x19,
            ],
        });
        
        extensions.push(TlsExtension {
            extension_type: 11,
            data: vec![0x01, 0x00],
        });
        
        // Session Ticket Extension (35)
        if let Some(cache) = ticket_cache {
            if let Some(ticket) = cache.get(domain) {
                extensions.push(TlsExtension {
                    extension_type: 35,
                    data: ticket,
                });
            } else {
                extensions.push(TlsExtension {
                    extension_type: 35,
                    data: vec![],
                });
            }
        } else {
            extensions.push(TlsExtension {
                extension_type: 35,
                data: vec![],
            });
        }
        
        extensions.push(TlsExtension {
            extension_type: 16,
            data: self.find_extension_data(16).unwrap_or_else(|| {
                vec![0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]
            }),
        });
        
        extensions.push(TlsExtension {
            extension_type: 5,
            data: vec![0x01, 0x00, 0x00, 0x00, 0x00],
        });
        
        extensions.push(TlsExtension {
            extension_type: 13,
            data: vec![
                0x00, 0x14,
                0x04, 0x03,
                0x08, 0x04,
                0x04, 0x01,
                0x05, 0x03,
                0x08, 0x05,
                0x05, 0x01,
                0x08, 0x06,
                0x06, 0x01,
                0x02, 0x01,
            ],
        });
        
        extensions.push(TlsExtension {
            extension_type: 51,
            data: vec![
                0x00, 0x1d,
                0x00, 0x20,
            ].into_iter().chain((0..32).map(|_| rng.random_range(0..=255))).collect(),
        });
        
        extensions.push(TlsExtension {
            extension_type: 43,
            data: vec![0x03, 0x04, 0x03, 0x03],
        });
        
        extensions.push(TlsExtension {
            extension_type: 27,
            data: vec![0x02, 0x00, 0x02],
        });
        
        extensions.push(TlsExtension {
            extension_type: 21,
            data: vec![0x00],
        });
        
        extensions
    }

    fn find_extension_data(&self, ext_type: u16) -> Option<Vec<u8>> {
        self.extensions
            .iter()
            .find(|e| e.extension_type == ext_type)
            .map(|e| e.data.clone())
    }

    fn serialize_extensions(extensions: &[TlsExtension]) -> Vec<u8> {
        let mut result = Vec::new();
        
        for ext in extensions {
            result.extend_from_slice(&ext.extension_type.to_be_bytes());
            result.extend_from_slice(&(ext.data.len() as u16).to_be_bytes());
            result.extend_from_slice(&ext.data);
        }
        
        result
    }

    pub fn extract_session_ticket(&self) -> Option<Vec<u8>> {
        for ext in &self.extensions {
            if ext.extension_type == 35 && !ext.data.is_empty() {
                return Some(ext.data.clone());
            }
        }
        None
    }
}

pub fn parse_server_hello_for_ticket(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 5 || data[0] != TLS_HANDSHAKE {
        return None;
    }

    let handshake_data = &data[5..];
    
    if handshake_data.is_empty() || handshake_data[0] != 0x02 {
        return None;
    }

    let mut offset = 38;
    
    if offset >= handshake_data.len() {
        return None;
    }
    
    let session_id_len = handshake_data[offset] as usize;
    offset += 1 + session_id_len;
    
    if offset + 3 >= handshake_data.len() {
        return None;
    }
    
    offset += 2;
    offset += 1;
    
    if offset + 2 > handshake_data.len() {
        return None;
    }
    
    let extensions_len = u16::from_be_bytes([
        handshake_data[offset],
        handshake_data[offset + 1],
    ]) as usize;
    offset += 2;
    
    let extensions_end = offset + extensions_len;
    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([
            handshake_data[offset],
            handshake_data[offset + 1],
        ]);
        offset += 2;
        
        let ext_len = u16::from_be_bytes([
            handshake_data[offset],
            handshake_data[offset + 1],
        ]) as usize;
        offset += 2;
        
        if ext_type == 35 && offset + ext_len <= handshake_data.len() {
            return Some(handshake_data[offset..offset + ext_len].to_vec());
        }
        
        offset += ext_len;
    }
    
    None
}

fn get_ios_safari_cipher_suites() -> Vec<u16> {
    vec![
        0x1301,
        0x1302,
        0x1303,
        0xc02c,
        0xc02b,
        0xcca9,
        0xcca8,
        0xc030,
        0xc02f,
        0xc024,
        0xc023,
        0xc028,
        0xc027,
        0xc00a,
        0xc009,
        0xc014,
        0xc013,
    ]
}

fn get_grease_values() -> Vec<u16> {
    vec![
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
        0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
        0xcaca, 0xdada, 0xeaea, 0xfafa,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_values() {
        let grease = get_grease_values();
        assert!(grease.len() > 0);
        assert!(grease.contains(&0x0a0a));
    }

    #[test]
    fn test_cipher_suites() {
        let ciphers = get_ios_safari_cipher_suites();
        assert!(ciphers.len() > 0);
        assert_eq!(ciphers[0], 0x1301);
    }

    #[test]
    fn test_session_ticket_cache() {
        let cache = SessionTicketCache::new();
        
        cache.store("example.com".to_string(), vec![1, 2, 3, 4]);
        
        let ticket = cache.get("example.com");
        assert!(ticket.is_some());
        assert_eq!(ticket.unwrap(), vec![1, 2, 3, 4]);
        
        let no_ticket = cache.get("other.com");
        assert!(no_ticket.is_none());
    }

    #[test]
    fn test_session_ticket_expiry() {
        let mut ticket = SessionTicket::new(vec![1, 2, 3], "test.com".to_string());
        assert!(!ticket.is_expired());
        
        ticket.timestamp = 0;
        assert!(ticket.is_expired());
    }
}