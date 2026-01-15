use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub profiles: Vec<FingerprintProfile>,
    pub default_profile: String,
    #[serde(default)]
    pub proxy_settings: ProxySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_type: String, // "socks5", "http", "https", "direct"
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 1080,
            proxy_type: "socks5".to_string(),
            username: None,
            password: None,
        }
    }
}

impl ProxySettings {
    pub fn is_direct(&self) -> bool {
        self.proxy_type.to_lowercase() == "direct"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintProfile {
    pub name: String,
    pub cipher_suites: Vec<String>,
    pub extensions: Vec<String>,
    pub supported_versions: Vec<String>,
    pub alpn: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub key_share_groups: Vec<String>,
    pub psk_key_exchange_modes: Vec<String>,
    pub compress_certificate: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: vec![Self::default_ios_safari_profile()],
            default_profile: "ios_safari".to_string(),
            proxy_settings: ProxySettings::default(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn get_profile(&self, name: &str) -> Option<&FingerprintProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    pub fn get_default_profile(&self) -> Option<&FingerprintProfile> {
        self.get_profile(&self.default_profile)
    }

    fn default_ios_safari_profile() -> FingerprintProfile {
        FingerprintProfile {
            name: "ios_safari".to_string(),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
            ],
            extensions: vec![
                "server_name".to_string(),
                "status_request".to_string(),
                "supported_groups".to_string(),
                "ec_point_formats".to_string(),
                "signature_algorithms".to_string(),
                "application_layer_protocol_negotiation".to_string(),
                "signed_certificate_timestamp".to_string(),
                "key_share".to_string(),
                "psk_key_exchange_modes".to_string(),
                "supported_versions".to_string(),
                "compress_certificate".to_string(),
                "session_ticket".to_string(),
            ],
            supported_versions: vec![
                "TLS 1.3".to_string(),
                "TLS 1.2".to_string(),
            ],
            alpn: vec![
                "h2".to_string(),
                "http/1.1".to_string(),
            ],
            signature_algorithms: vec![
                "ecdsa_secp256r1_sha256".to_string(),
                "rsa_pss_rsae_sha256".to_string(),
                "rsa_pkcs1_sha256".to_string(),
                "ecdsa_secp384r1_sha384".to_string(),
                "ecdsa_sha1".to_string(),
                "rsa_pkcs1_sha1".to_string(),
            ],
            key_share_groups: vec![
                "x25519".to_string(),
                "secp256r1".to_string(),
            ],
            psk_key_exchange_modes: vec![
                "psk_dhe_ke".to_string(),
            ],
            compress_certificate: vec![
                "brotli".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.default_profile, "ios_safari");
        assert_eq!(config.profiles.len(), 1);
        assert_eq!(config.proxy_settings.proxy_host, "127.0.0.1");
    }

    #[test]
    fn test_get_profile() {
        let config = Config::default();
        let profile = config.get_profile("ios_safari");
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().name, "ios_safari");
    }

    #[test]
    fn test_proxy_settings() {
        let settings = ProxySettings::default();
        assert_eq!(settings.proxy_type, "socks5");
        assert_eq!(settings.proxy_port, 1080);
        assert!(!settings.is_direct());
    }

    #[test]
    fn test_direct_mode() {
        let mut settings = ProxySettings::default();
        settings.proxy_type = "direct".to_string();
        assert!(settings.is_direct());
        
        settings.proxy_type = "DIRECT".to_string();
        assert!(settings.is_direct());
    }
}