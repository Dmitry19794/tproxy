// src/http2.rs
use anyhow::Result;
use std::sync::Arc;
use crate::config::Config;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub struct Http2Modifier {
    config: Arc<Config>,
}

impl Http2Modifier {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
    
    pub fn is_http2(&self, data: &[u8]) -> bool {
        data.starts_with(HTTP2_PREFACE)
    }
    
    pub fn modify(&self, data: &mut Vec<u8>) -> Result<()> {
        if !self.is_http2(data) {
            return Ok(());
        }
        
        // HTTP/2 modification будет здесь
        Ok(())
    }
}
