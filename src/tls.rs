use bytes::{BytesMut, BufMut};
use anyhow::Result;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_1_0: [u8; 2] = [0x03, 0x01];
const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];
const CLIENT_HELLO: u8 = 0x01;
const SESSION_TICKET_LIFETIME: u64 = 7200;

// GREASE values (RFC 8701) - используются для предотвращения ossification
const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

// iOS Safari 17+ TLS 1.3 cipher suites (точный порядок)
const IOS_CIPHER_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
];

// iOS Safari extension order (критично важно!)
const IOS_EXTENSION_ORDER: &[u16] = &[
    0,     // server_name
    5,     // status_request (OCSP stapling)
    10,    // supported_groups
    11,    // ec_point_formats
    13,    // signature_algorithms
    16,    // application_layer_protocol_negotiation
    18,    // signed_certificate_timestamp
    43,    // supported_versions
    45,    // psk_key_exchange_modes
    51,    // key_share
    27,    // compress_certificate
    35,    // session_ticket
    23,    // extended_master_secret
    65281, // renegotiation_info
];

// Supported groups для iOS Safari (порядок важен)
const IOS_SUPPORTED_GROUPS: &[u16] = &[
    0x001d, // x25519
    0x0017, // secp256r1
    0x0018, // secp384r1
    0x001e, // x448
];

// Signature algorithms (iOS Safari порядок)
const IOS_SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
    0x0203, // ecdsa_sha1
    0x0201, // rsa_pkcs1_sha1
];

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

        let mut offset = 6;
        
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

    /// Passthrough режим - НЕ модифицирует ClientHello, только обновляет SNI если нужно
    pub fn passthrough(&self, domain: &str) -> Result<Vec<u8>> {
        let mut result = BytesMut::new();
        result.put_u8(TLS_HANDSHAKE);
        result.put_slice(&TLS_VERSION_1_0);
        
        let mut handshake = BytesMut::new();
        handshake.put_u8(CLIENT_HELLO);
        
        let mut client_hello = BytesMut::new();
        
        // Копируем всё из оригинального ClientHello
        client_hello.put_slice(&self.version);
        client_hello.put_slice(&self.random);
        
        // Session ID
        client_hello.put_u8(self.session_id.len() as u8);
        if !self.session_id.is_empty() {
            client_hello.put_slice(&self.session_id);
        }
        
        // Cipher Suites - БЕЗ ИЗМЕНЕНИЙ
        client_hello.put_u16(self.cipher_suites.len() as u16 * 2);
        for cipher in &self.cipher_suites {
            client_hello.put_u16(*cipher);
        }
        
        // Compression - БЕЗ ИЗМЕНЕНИЙ
        client_hello.put_u8(self.compression_methods.len() as u8);
        client_hello.put_slice(&self.compression_methods);
        
        // Extensions - только обновляем SNI
        let extensions = self.update_sni_only(domain);
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

    /// Обновляет только SNI extension, всё остальное без изменений
    fn update_sni_only(&self, domain: &str) -> Vec<TlsExtension> {
        let mut extensions = Vec::new();
        let mut sni_updated = false;
        
        for ext in &self.extensions {
            if ext.extension_type == 0 {
                // Обновляем SNI
                let mut sni_data = BytesMut::new();
                sni_data.put_u16((domain.len() + 3) as u16);
                sni_data.put_u8(0);
                sni_data.put_u16(domain.len() as u16);
                sni_data.put_slice(domain.as_bytes());
                extensions.push(TlsExtension {
                    extension_type: 0,
                    data: sni_data.to_vec(),
                });
                sni_updated = true;
            } else {
                // Всё остальное - КАК ЕСТЬ
                extensions.push(ext.clone());
            }
        }
        
        // Если SNI не было - добавляем
        if !sni_updated {
            let mut sni_data = BytesMut::new();
            sni_data.put_u16((domain.len() + 3) as u16);
            sni_data.put_u8(0);
            sni_data.put_u16(domain.len() as u16);
            sni_data.put_slice(domain.as_bytes());
            extensions.insert(0, TlsExtension {
                extension_type: 0,
                data: sni_data.to_vec(),
            });
        }
        
        extensions
    }

    /// Совместимая iOS Safari подмена с GREASE (hybrid mode)
    /// Сохраняет больше от оригинального ClientHello для совместимости
    pub fn to_ios_safari(&self, ticket_cache: Option<&SessionTicketCache>, domain: &str) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        
        // Генерируем GREASE значения
        let grease_cipher = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
        let grease_group = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
        let grease_version = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
        let grease_extension = GREASE_VALUES[rng.gen_range(0..GREASE_VALUES.len())];
        
        let mut result = BytesMut::new();
        result.put_u8(TLS_HANDSHAKE);
        result.put_slice(&TLS_VERSION_1_0);
        
        let mut handshake = BytesMut::new();
        handshake.put_u8(CLIENT_HELLO);
        
        let mut client_hello = BytesMut::new();
        
        // Version: TLS 1.2 (0x0303) - iOS Safari использует это даже для TLS 1.3
        client_hello.put_slice(&TLS_VERSION_1_2);
        
        // Random: 32 байта (первые 4 - Unix timestamp, остальные - случайные)
        let mut random = [0u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        random[0..4].copy_from_slice(&timestamp.to_be_bytes());
        rng.fill(&mut random[4..]);
        client_hello.put_slice(&random);
        
        // Session ID: используем пустой или из кэша
        let session_id = if let Some(cache) = ticket_cache {
            cache.get(domain).unwrap_or_default()
        } else {
            Vec::new()
        };
        
        if session_id.is_empty() {
            client_hello.put_u8(0);
        } else {
            client_hello.put_u8(session_id.len().min(32) as u8);
            client_hello.put_slice(&session_id[..session_id.len().min(32)]);
        }
        
        // Cipher Suites: ГИБРИДНЫЙ режим - добавляем TLS 1.3 + сохраняем оригинальные
        let mut ciphers = Vec::new();
        ciphers.push(grease_cipher); // GREASE в начале
        
        // Добавляем TLS 1.3 ciphers если их нет
        for cipher in &[0x1301, 0x1302, 0x1303] {
            if !self.cipher_suites.contains(cipher) {
                ciphers.push(*cipher);
            }
        }
        
        // ВАЖНО: Сохраняем ВСЕ оригинальные cipher suites для совместимости
        ciphers.extend_from_slice(&self.cipher_suites);
        
        client_hello.put_u16(ciphers.len() as u16 * 2);
        for cipher in ciphers {
            client_hello.put_u16(cipher);
        }
        
        // Compression: только NULL (0x00)
        client_hello.put_u8(1);
        client_hello.put_u8(0);
        
        // Extensions: ГИБРИДНЫЙ режим - обновляем SNI + добавляем GREASE + сохраняем оригинальные
        let extensions = Self::build_hybrid_extensions(
            domain,
            ticket_cache,
            &self.extensions, // Передаем оригинальные extensions
            grease_extension,
            grease_group,
            grease_version,
        );
        
        let extensions_bytes = Self::serialize_extensions(&extensions);
        client_hello.put_u16(extensions_bytes.len() as u16);
        client_hello.put_slice(&extensions_bytes);
        
        // Собираем handshake
        let ch_len = client_hello.len();
        handshake.put_u8((ch_len >> 16) as u8);
        handshake.put_u8((ch_len >> 8) as u8);
        handshake.put_u8(ch_len as u8);
        handshake.put_slice(&client_hello);
        
        // Собираем финальный пакет
        result.put_u16(handshake.len() as u16);
        result.put_slice(&handshake);
        
        Ok(result.to_vec())
    }

    /// ГИБРИДНЫЙ режим: сохраняем оригинальные extensions + добавляем iOS Safari улучшения
    fn build_hybrid_extensions(
        domain: &str,
        ticket_cache: Option<&SessionTicketCache>,
        original_extensions: &[TlsExtension],
        grease_extension: u16,
        grease_group: u16,
        grease_version: u16,
    ) -> Vec<TlsExtension> {
        let mut extensions = Vec::new();
        let mut has_sni = false;
        let mut has_supported_groups = false;
        let mut has_supported_versions = false;
        let mut has_key_share = false;
        
        // Добавляем GREASE extension в начало
        extensions.push(TlsExtension {
            extension_type: grease_extension,
            data: vec![0],
        });
        
        // Проходим по оригинальным extensions и улучшаем их
        for ext in original_extensions {
            match ext.extension_type {
                // 0: server_name - обновляем на правильный домен
                0 => {
                    let mut sni_data = BytesMut::new();
                    sni_data.put_u16((domain.len() + 3) as u16);
                    sni_data.put_u8(0);
                    sni_data.put_u16(domain.len() as u16);
                    sni_data.put_slice(domain.as_bytes());
                    extensions.push(TlsExtension {
                        extension_type: 0,
                        data: sni_data.to_vec(),
                    });
                    has_sni = true;
                }
                
                // 10: supported_groups - добавляем GREASE
                10 => {
                    let mut groups = BytesMut::new();
                    let mut group_list = vec![grease_group];
                    
                    // Парсим оригинальные группы
                    if ext.data.len() >= 2 {
                        let count = u16::from_be_bytes([ext.data[0], ext.data[1]]) as usize / 2;
                        for i in 0..count {
                            let offset = 2 + i * 2;
                            if offset + 1 < ext.data.len() {
                                let group = u16::from_be_bytes([ext.data[offset], ext.data[offset + 1]]);
                                if !group_list.contains(&group) {
                                    group_list.push(group);
                                }
                            }
                        }
                    }
                    
                    groups.put_u16((group_list.len() * 2) as u16);
                    for group in group_list {
                        groups.put_u16(group);
                    }
                    extensions.push(TlsExtension {
                        extension_type: 10,
                        data: groups.to_vec(),
                    });
                    has_supported_groups = true;
                }
                
                // 43: supported_versions - добавляем GREASE + TLS 1.3
                43 => {
                    let mut versions = BytesMut::new();
                    versions.put_u8(5);
                    versions.put_u16(grease_version);
                    versions.put_u16(0x0304); // TLS 1.3
                    versions.put_u16(0x0303); // TLS 1.2
                    extensions.push(TlsExtension {
                        extension_type: 43,
                        data: versions.to_vec(),
                    });
                    has_supported_versions = true;
                }
                
                // 51: key_share - генерируем новый для x25519
                51 => {
                    let mut key_share = BytesMut::new();
                    let mut shares = BytesMut::new();
                    
                    shares.put_u16(0x001d); // x25519
                    shares.put_u16(32);
                    let mut x25519_key = [0u8; 32];
                    rand::thread_rng().fill(&mut x25519_key);
                    shares.put_slice(&x25519_key);
                    
                    key_share.put_u16(shares.len() as u16);
                    key_share.put_slice(&shares);
                    extensions.push(TlsExtension {
                        extension_type: 51,
                        data: key_share.to_vec(),
                    });
                    has_key_share = true;
                }
                
                // Все остальные extensions - сохраняем КАК ЕСТЬ
                _ => {
                    extensions.push(ext.clone());
                }
            }
        }
        
        // Если каких-то критичных extensions нет - добавляем минимальные
        if !has_sni {
            let mut sni_data = BytesMut::new();
            sni_data.put_u16((domain.len() + 3) as u16);
            sni_data.put_u8(0);
            sni_data.put_u16(domain.len() as u16);
            sni_data.put_slice(domain.as_bytes());
            extensions.insert(1, TlsExtension {
                extension_type: 0,
                data: sni_data.to_vec(),
            });
        }
        
        if !has_supported_groups {
            let mut groups = BytesMut::new();
            groups.put_u16(4);
            groups.put_u16(grease_group);
            groups.put_u16(0x001d); // x25519
            extensions.push(TlsExtension {
                extension_type: 10,
                data: groups.to_vec(),
            });
        }
        
        if !has_supported_versions {
            let mut versions = BytesMut::new();
            versions.put_u8(5);
            versions.put_u16(grease_version);
            versions.put_u16(0x0304);
            versions.put_u16(0x0303);
            extensions.push(TlsExtension {
                extension_type: 43,
                data: versions.to_vec(),
            });
        }
        
        extensions
    }

    fn build_ios_safari_extensions(
        domain: &str,
        ticket_cache: Option<&SessionTicketCache>,
        grease_extension: u16,
        grease_group: u16,
        grease_version: u16,
    ) -> Vec<TlsExtension> {
        let mut extensions = Vec::new();
        
        // Добавляем GREASE extension в случайную позицию (обычно в начало)
        extensions.push(TlsExtension {
            extension_type: grease_extension,
            data: vec![0], // GREASE extension с минимальными данными
        });
        
        // 0: server_name (SNI)
        let mut sni_data = BytesMut::new();
        sni_data.put_u16((domain.len() + 3) as u16);
        sni_data.put_u8(0); // name_type: host_name
        sni_data.put_u16(domain.len() as u16);
        sni_data.put_slice(domain.as_bytes());
        extensions.push(TlsExtension {
            extension_type: 0,
            data: sni_data.to_vec(),
        });
        
        // 5: status_request (OCSP stapling)
        let mut status_req = BytesMut::new();
        status_req.put_u8(1); // CertificateStatusType: ocsp
        status_req.put_u16(0); // ResponderID list length
        status_req.put_u16(0); // Extensions length
        extensions.push(TlsExtension {
            extension_type: 5,
            data: status_req.to_vec(),
        });
        
        // 10: supported_groups (с GREASE)
        let mut groups = BytesMut::new();
        let mut group_list = vec![grease_group]; // GREASE в начале
        group_list.extend_from_slice(IOS_SUPPORTED_GROUPS);
        groups.put_u16((group_list.len() * 2) as u16);
        for group in group_list {
            groups.put_u16(group);
        }
        extensions.push(TlsExtension {
            extension_type: 10,
            data: groups.to_vec(),
        });
        
        // 11: ec_point_formats
        extensions.push(TlsExtension {
            extension_type: 11,
            data: vec![1, 0], // uncompressed
        });
        
        // 13: signature_algorithms
        let mut sig_algs = BytesMut::new();
        sig_algs.put_u16((IOS_SIGNATURE_ALGORITHMS.len() * 2) as u16);
        for alg in IOS_SIGNATURE_ALGORITHMS {
            sig_algs.put_u16(*alg);
        }
        extensions.push(TlsExtension {
            extension_type: 13,
            data: sig_algs.to_vec(),
        });
        
        // 16: application_layer_protocol_negotiation (ALPN)
        let mut alpn = BytesMut::new();
        alpn.put_u16(5); // Total length
        alpn.put_u8(2); // h2 length
        alpn.put_slice(b"h2");
        alpn.put_u8(8); // http/1.1 length
        alpn.put_slice(b"http/1.1");
        extensions.push(TlsExtension {
            extension_type: 16,
            data: alpn.to_vec(),
        });
        
        // 18: signed_certificate_timestamp
        extensions.push(TlsExtension {
            extension_type: 18,
            data: vec![],
        });
        
        // 43: supported_versions (TLS 1.3, TLS 1.2 + GREASE)
        let mut versions = BytesMut::new();
        versions.put_u8(5); // Length
        versions.put_u16(grease_version); // GREASE
        versions.put_u16(0x0304); // TLS 1.3
        versions.put_u16(0x0303); // TLS 1.2
        extensions.push(TlsExtension {
            extension_type: 43,
            data: versions.to_vec(),
        });
        
        // 45: psk_key_exchange_modes
        extensions.push(TlsExtension {
            extension_type: 45,
            data: vec![1, 1], // psk_dhe_ke
        });
        
        // 51: key_share (только для первых групп)
        let mut key_share = BytesMut::new();
        let mut shares = BytesMut::new();
        
        // x25519 key share (32 байта случайных данных)
        shares.put_u16(0x001d); // x25519
        shares.put_u16(32); // length
        let mut x25519_key = [0u8; 32];
        rand::thread_rng().fill(&mut x25519_key);
        shares.put_slice(&x25519_key);
        
        key_share.put_u16(shares.len() as u16);
        key_share.put_slice(&shares);
        extensions.push(TlsExtension {
            extension_type: 51,
            data: key_share.to_vec(),
        });
        
        // 27: compress_certificate (brotli)
        let mut compress = BytesMut::new();
        compress.put_u8(2); // Length
        compress.put_u16(0x0002); // brotli
        extensions.push(TlsExtension {
            extension_type: 27,
            data: compress.to_vec(),
        });
        
        // 35: session_ticket (пустой или из кэша)
        let ticket = if let Some(cache) = ticket_cache {
            cache.get(domain).unwrap_or_default()
        } else {
            Vec::new()
        };
        extensions.push(TlsExtension {
            extension_type: 35,
            data: ticket,
        });
        
        // 23: extended_master_secret
        extensions.push(TlsExtension {
            extension_type: 23,
            data: vec![],
        });
        
        // 65281: renegotiation_info
        extensions.push(TlsExtension {
            extension_type: 65281,
            data: vec![0],
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
    fn test_grease_values() {
        // GREASE значения должны иметь формат 0x?a?a
        for val in GREASE_VALUES {
            assert_eq!(val & 0x0f0f, 0x0a0a);
        }
    }

    #[test]
    fn test_ios_safari_generation() {
        let cache = SessionTicketCache::new();
        let hello = TlsClientHello {
            version: TLS_VERSION_1_2,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suites: vec![],
            compression_methods: vec![0],
            extensions: vec![],
        };
        
        let result = hello.to_ios_safari(Some(&cache), "example.com");
        assert!(result.is_ok());
        
        let data = result.unwrap();
        assert!(data.len() > 200); // iOS Safari ClientHello обычно ~300-500 байт
        assert_eq!(data[0], TLS_HANDSHAKE);
    }

    #[test]
    fn test_session_ticket_cache() {
        let cache = SessionTicketCache::new();
        
        cache.store("example.com".to_string(), vec![1, 2, 3, 4]);
        
        let ticket = cache.get("example.com");
        assert!(ticket.is_some());
        assert_eq!(ticket.unwrap(), vec![1, 2, 3, 4]);
    }
}