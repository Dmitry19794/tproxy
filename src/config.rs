// src/config.rs
use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub profiles: Vec<FingerprintProfile>,
    pub default_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintProfile {
    pub name: String,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<String>,
    pub grease: Vec<u16>,
    pub http2_settings: Http2Settings,
    pub signature_algorithms: Vec<u16>,
    pub supported_groups: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: u32,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub window_update: u32,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }
    
    pub fn default_profile(&self) -> &FingerprintProfile {
        self.profiles.iter()
            .find(|p| p.name == self.default_profile)
            .expect("Default profile must exist")
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            profiles: vec![
                FingerprintProfile {
                    name: "ios_safari_17".to_string(),
                    cipher_suites: vec![4865, 4866, 4867],
                    extensions: vec![0, 23, 35, 13],
                    supported_versions: vec![772, 771],
                    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                    grease: vec![2570, 6682, 10794],
                    http2_settings: Http2Settings {
                        header_table_size: 65536,
                        enable_push: 0,
                        max_concurrent_streams: 0,
                        initial_window_size: 1048576,
                        max_frame_size: 16384,
                        max_header_list_size: 0,
                        window_update: 15663105,
                    },
                    signature_algorithms: vec![1027, 1283, 1539],
                    supported_groups: vec![29, 23, 30],
                },
            ],
            default_profile: "ios_safari_17".to_string(),
        }
    }
}
