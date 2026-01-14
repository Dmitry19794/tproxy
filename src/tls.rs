// src/tls.rs
use anyhow::Result;
use bytes::{BufMut, BytesMut};
use std::sync::Arc;
use rand::Rng;
use crate::config::{Config, FingerprintProfile};

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;

pub struct TlsModifier {
    config: Arc<Config>,
}

impl TlsModifier {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
    
    pub fn is_client_hello(data: &[u8]) -> bool {
        data.len() >= 6 
            && data[0] == TLS_HANDSHAKE 
            && data[5] == TLS_CLIENT_HELLO
    }
    
    pub fn modify_client_hello(&self, data: &mut Vec<u8>) -> Result<()> {
        if !Self::is_client_hello(data) {
            return Ok(());
        }
        
        let profile = self.config.default_profile();
        let modified = self.build_modified_hello(data, profile)?;
        *data = modified;
        Ok(())
    }
    
    fn build_modified_hello(&self, _original: &[u8], profile: &FingerprintProfile) -> Result<Vec<u8>> {
        let mut result = BytesMut::new();
        
        // TLS Record header
        result.put_u8(TLS_HANDSHAKE);
        result.put_u8(0x03);
        result.put_u8(0x01);
        result.put_u16(0); // Length - будет обновлено
        
        // Handshake header
        result.put_u8(TLS_CLIENT_HELLO);
        result.put_u8(0);
        result.put_u8(0);
        result.put_u8(0); // Length - будет обновлено
        
        // Version
        result.put_u16(0x0303);
        
        // Random (32 bytes)
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            result.put_u8(rng.gen());
        }
        
        // Session ID (empty)
        result.put_u8(0);
        
        // Cipher Suites
        let cs_len = profile.cipher_suites.len() * 2;
        result.put_u16(cs_len as u16);
        for &cipher in &profile.cipher_suites {
            result.put_u16(cipher);
        }
        
        // Compression (null)
        result.put_u8(1);
        result.put_u8(0);
        
        // Extensions
        let extensions = self.build_extensions(profile)?;
        result.put_u16(extensions.len() as u16);
        result.put_slice(&extensions);
        
        // Update lengths
        let mut final_result = result.to_vec();
        let total_len = final_result.len() - 5;
        final_result[3] = (total_len >> 8) as u8;
        final_result[4] = (total_len & 0xFF) as u8;
        
        let hs_len = final_result.len() - 9;
        final_result[6] = ((hs_len >> 16) & 0xFF) as u8;
        final_result[7] = ((hs_len >> 8) & 0xFF) as u8;
        final_result[8] = (hs_len & 0xFF) as u8;
        
        Ok(final_result)
    }
    
    fn build_extensions(&self, profile: &FingerprintProfile) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        for &ext_type in &profile.extensions {
            match ext_type {
                0 => result.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]),
                23 => result.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]),
                35 => result.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]),
                13 => {
                    result.extend_from_slice(&[0x00, 0x0d]);
                    let algos_len = (profile.signature_algorithms.len() * 2) as u16;
                    result.extend_from_slice(&(algos_len + 2).to_be_bytes());
                    result.extend_from_slice(&algos_len.to_be_bytes());
                    for &algo in &profile.signature_algorithms {
                        result.extend_from_slice(&algo.to_be_bytes());
                    }
                }
                10 => {
                    result.extend_from_slice(&[0x00, 0x0a]);
                    let groups_len = (profile.supported_groups.len() * 2) as u16;
                    result.extend_from_slice(&(groups_len + 2).to_be_bytes());
                    result.extend_from_slice(&groups_len.to_be_bytes());
                    for &group in &profile.supported_groups {
                        result.extend_from_slice(&group.to_be_bytes());
                    }
                }
                16 => {
                    result.extend_from_slice(&[0x00, 0x10]);
                    let mut alpn_data = Vec::new();
                    for proto in &profile.alpn {
                        alpn_data.push(proto.len() as u8);
                        alpn_data.extend_from_slice(proto.as_bytes());
                    }
                    result.extend_from_slice(&((alpn_data.len() + 2) as u16).to_be_bytes());
                    result.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
                    result.extend_from_slice(&alpn_data);
                }
                _ => {}
            }
        }
        
        Ok(result)
    }
}
