use bytes::{BytesMut, BufMut};
use anyhow::Result;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_1_0: [u8; 2] = [0x03, 0x01]; // Legacy version in record
const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03]; // Legacy version in handshake
const CLIENT_HELLO: u8 = 0x01;
const SESSION_TICKET_LIFETIME: u64 = 7200;

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
        if data.len() < 43 {
            return Err(anyhow::anyhow!("Data too short for TLS ClientHello"));
        }

        if data[0] != TLS_HANDSHAKE {
            return Err(anyhow::anyhow!("Not a TLS handshake"));
        }

        let handshake_data = &data[5..];
        
        if handshake_data[0] != CLIENT_HELLO {
            return Err(anyhow::anyhow!("Not a ClientHello"));
        }

        let mut offset = 6; // Skip handshake type (1) + length (3) + version (2)
        
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
            if offset + i + 1 < handshake_data.len() {
                let suite = u16::from_be_bytes([
                    handshake_data[offset + i],
                    handshake_data[offset + i + 1],
                ]);
                cipher_suites.push(suite);
            }
        }
        offset += cipher_suites_len;

        let compression_len = handshake_data[offset] as usize;
        offset += 1;
        let compression_methods = handshake_data[offset..offset + compression_len].to_vec();
        offset += compression_len;

        let mut extensions = Vec::new();
        if offset + 2 <= handshake_data.len() {
            let extensions_len = u16::from_be_bytes([
                handshake_data[offset],
                handshake_data[offset + 1],
            ]) as usize;
            offset += 2;

            let extensions_end = (offset + extensions_len).min(handshake_data.len());
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

                if offset + ext_len <= handshake_data.len() {
                    let ext_data = handshake_data[offset..offset + ext_len].to_vec();
                    extensions.push(TlsExtension {
                        extension_type: ext_type,
                        data: ext_data,
                    });
                    offset += ext_len;
                }
            }
        }

        Ok(Self {
            version: TLS_VERSION_1_2,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    pub fn to_ios_safari(&self, _ticket_cache: Option<&SessionTicketCache>, domain: &str) -> Result<Vec<u8>> {
        let mut rng = rand::rng();
        
        // TLS Record Header
        let mut result = BytesMut::new();
        result.put_u8(TLS_HANDSHAKE);
        result.put_slice(&TLS_VERSION_1_0);
        
        let mut handshake = BytesMut::new();
        handshake.put_u8(CLIENT_HELLO);
        
        let mut client_hello = BytesMut::new();
        
        // Legacy version
        client_hello.put_slice(&TLS_VERSION_1_2);
        
        // Random - используем оригинальный для сохранения сессии
        client_hello.put_slice(&self.random);
        
        // Session ID - используем оригинальный
        client_hello.put_u8(self.session_id.len() as u8);
        client_hello.put_slice(&self.session_id);
        
        // Cipher Suites - подменяем на iOS Safari порядок
        let ciphers = vec![
            0x1301, 0x1302, 0x1303, // TLS 1.3 ciphers
            0xc02c, 0xc02b, 0xc030, 0xc02f, // ECDHE
            0xcca9, 0xcca8, // ChaCha20
            0x00ff, // Renegotiation
        ];
        
        client_hello.put_u16(ciphers.len() as u16 * 2);
        for cipher in ciphers {
            client_hello.put_u16(cipher);
        }
        
        // Compression - используем оригинальный
        client_hello.put_u8(self.compression_methods.len() as u8);
        client_hello.put_slice(&self.compression_methods);
        
        // Extensions - используем оригинальные критичные, подменяем порядок
        let extensions = self.reorder_extensions_ios_safari(domain);
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

    fn reorder_extensions_ios_safari(&self, domain: &str) -> Vec<TlsExtension> {
        let mut extensions = Vec::new();
        
        // 1. SNI - подменяем на правильный домен
        let mut sni_data = BytesMut::new();
        sni_data.put_u16((domain.len() + 3) as u16);
        sni_data.put_u8(0);
        sni_data.put_u16(domain.len() as u16);
        sni_data.put_slice(domain.as_bytes());
        
        extensions.push(TlsExtension {
            extension_type: 0,
            data: sni_data.to_vec(),
        });
        
        // 2-5. Берём оригинальные extensions в правильном порядке iOS Safari
        let ios_order = [
            23,    // extended_master_secret
            65281, // renegotiation_info
            10,    // supported_groups
            11,    // ec_point_formats
            16,    // ALPN
            13,    // signature_algorithms  
            43,    // supported_versions (критично!)
            51,    // key_share (критично!)
            45,    // psk_key_exchange_modes
        ];
        
        for &ext_type in &ios_order {
            if let Some(original) = self.find_extension(ext_type) {
                extensions.push(original.clone());
            }
        }
        
        extensions
    }

    fn find_extension(&self, ext_type: u16) -> Option<&TlsExtension> {
        self.extensions.iter().find(|e| e.extension_type == ext_type)
    }

    fn build_ios_safari_extensions(&self, domain: &str) -> Vec<TlsExtension> {
        let mut extensions = Vec::new();
        let mut rng = rand::rng();
        
        // Extension 0: server_name (SNI)
        let mut sni_data = BytesMut::new();
        sni_data.put_u16((domain.len() + 3) as u16); // list length
        sni_data.put_u8(0); // name type: hostname
        sni_data.put_u16(domain.len() as u16);
        sni_data.put_slice(domain.as_bytes());
        
        extensions.push(TlsExtension {
            extension_type: 0,
            data: sni_data.to_vec(),
        });
        
        // Extension 23: extended_master_secret
        extensions.push(TlsExtension {
            extension_type: 23,
            data: vec![],
        });
        
        // Extension 65281: renegotiation_info
        extensions.push(TlsExtension {
            extension_type: 65281,
            data: vec![0x00],
        });
        
        // Extension 10: supported_groups
        extensions.push(TlsExtension {
            extension_type: 10,
            data: vec![
                0x00, 0x08, // length: 8 bytes
                0x00, 0x1d, // x25519
                0x00, 0x17, // secp256r1
                0x00, 0x18, // secp384r1
                0x00, 0x19, // secp521r1
            ],
        });
        
        // Extension 11: ec_point_formats
        extensions.push(TlsExtension {
            extension_type: 11,
            data: vec![0x01, 0x00], // uncompressed
        });
        
        // Extension 16: application_layer_protocol_negotiation (ALPN)
        extensions.push(TlsExtension {
            extension_type: 16,
            data: vec![
                0x00, 0x0c, // length: 12
                0x02, 0x68, 0x32, // h2
                0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
            ],
        });
        
        // Extension 13: signature_algorithms
        extensions.push(TlsExtension {
            extension_type: 13,
            data: vec![
                0x00, 0x14, // length: 20 bytes
                0x04, 0x03, // ecdsa_secp256r1_sha256
                0x08, 0x04, // rsa_pss_rsae_sha256
                0x04, 0x01, // rsa_pkcs1_sha256
                0x05, 0x03, // ecdsa_secp384r1_sha384
                0x08, 0x05, // rsa_pss_rsae_sha384
                0x05, 0x01, // rsa_pkcs1_sha384
                0x08, 0x06, // rsa_pss_rsae_sha512
                0x06, 0x01, // rsa_pkcs1_sha512
                0x02, 0x01, // rsa_pkcs1_sha1
            ],
        });
        
        // Extension 43: supported_versions (КРИТИЧНО для TLS 1.3!)
        extensions.push(TlsExtension {
            extension_type: 43,
            data: vec![
                0x04, // length: 4 bytes
                0x03, 0x04, // TLS 1.3
                0x03, 0x03, // TLS 1.2
            ],
        });
        
        // Extension 51: key_share (КРИТИЧНО для TLS 1.3!)
        let mut key_share = BytesMut::new();
        key_share.put_u16(0x0024); // length: 36 bytes
        key_share.put_u16(0x001d); // group: x25519
        key_share.put_u16(0x0020); // key_exchange length: 32 bytes
        // Генерируем случайный public key (32 bytes для x25519)
        for _ in 0..32 {
            key_share.put_u8(rng.random_range(0..=255));
        }
        
        extensions.push(TlsExtension {
            extension_type: 51,
            data: key_share.to_vec(),
        });
        
        // Extension 45: psk_key_exchange_modes
        extensions.push(TlsExtension {
            extension_type: 45,
            data: vec![0x01, 0x01], // psk_dhe_ke
        });
        
        extensions
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_ticket_cache() {
        let cache = SessionTicketCache::new();
        
        cache.store("example.com".to_string(), vec![1, 2, 3, 4]);
        
        let ticket = cache.get("example.com");
        assert!(ticket.is_some());
        assert_eq!(ticket.unwrap(), vec![1, 2, 3, 4]);
    }
}