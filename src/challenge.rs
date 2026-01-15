use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use cookie::Cookie;

const MAX_REDIRECTS: u32 = 10;
const CHALLENGE_TIMEOUT: u64 = 300; // 5 minutes

pub struct ChallengeHandler {
    pending_challenges: HashMap<String, ChallengeState>,
    redirect_chains: HashMap<String, RedirectChain>,
}

#[derive(Debug, Clone)]
pub struct ChallengeState {
    pub url: String,
    pub timestamp: u64,
    pub cookies: Vec<String>,
    pub redirects: u32,
}

#[derive(Debug, Clone)]
pub struct RedirectChain {
    pub original_url: String,
    pub redirects: Vec<RedirectEntry>,
    pub cookies: HashMap<String, String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct RedirectEntry {
    pub from_url: String,
    pub to_url: String,
    pub status_code: u16,
    pub timestamp: u64,
}

impl RedirectChain {
    pub fn new(original_url: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            original_url,
            redirects: Vec::new(),
            cookies: HashMap::new(),
            timestamp,
        }
    }

    pub fn add_redirect(&mut self, from_url: String, to_url: String, status_code: u16) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.redirects.push(RedirectEntry {
            from_url,
            to_url,
            status_code,
            timestamp,
        });
    }

    pub fn add_cookie(&mut self, name: String, value: String) {
        self.cookies.insert(name, value);
    }

    pub fn get_all_cookies(&self) -> Vec<String> {
        self.cookies
            .iter()
            .map(|(name, value)| format!("{}={}", name, value))
            .collect()
    }

    pub fn is_expired(&self, max_age: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.timestamp > max_age
    }

    pub fn redirect_count(&self) -> usize {
        self.redirects.len()
    }

    pub fn has_loop(&self) -> bool {
        let urls: Vec<&String> = self.redirects.iter().map(|r| &r.to_url).collect();
        let mut seen = std::collections::HashSet::new();
        
        for url in urls {
            if !seen.insert(url) {
                return true;
            }
        }
        
        false
    }

    pub fn get_final_url(&self) -> Option<String> {
        self.redirects.last().map(|r| r.to_url.clone())
    }
}

impl ChallengeHandler {
    pub fn new() -> Self {
        Self {
            pending_challenges: HashMap::new(),
            redirect_chains: HashMap::new(),
        }
    }

    pub fn detect_challenge(&self, response_body: &str, headers: &HashMap<String, String>) -> bool {
        if response_body.contains("cf-browser-verification") ||
           response_body.contains("__cf_chl_jschl_tk__") ||
           response_body.contains("cf-challenge-form") ||
           response_body.contains("jschl-answer") ||
           response_body.contains("cf-captcha-container") {
            return true;
        }

        if let Some(server) = headers.get("server") {
            if server.contains("cloudflare") {
                if let Some(_status) = headers.get("cf-ray") {
                    if headers.get("cf-mitigated").is_some() {
                        return true;
                    }
                }
            }
        }

        if let Some(location) = headers.get("location") {
            if location.contains("__cf_chl_jschl_tk__") || location.contains("cdn-cgi/challenge") {
                return true;
            }
        }

        false
    }

    pub fn is_redirect(&self, status_code: u16) -> bool {
        matches!(status_code, 301 | 302 | 303 | 307 | 308)
    }

    pub fn start_redirect_chain(&mut self, original_url: String) {
        let chain = RedirectChain::new(original_url.clone());
        self.redirect_chains.insert(original_url, chain);
    }

    pub fn add_redirect(&mut self, original_url: &str, from_url: String, to_url: String, status_code: u16) -> Result<(), String> {
        if let Some(chain) = self.redirect_chains.get_mut(original_url) {
            if chain.redirect_count() >= MAX_REDIRECTS as usize {
                return Err(format!("Too many redirects: {}", chain.redirect_count()));
            }

            chain.add_redirect(from_url, to_url.clone(), status_code);

            if chain.has_loop() {
                return Err("Redirect loop detected".to_string());
            }

            Ok(())
        } else {
            Err("No redirect chain found for URL".to_string())
        }
    }

    pub fn add_redirect_cookie(&mut self, original_url: &str, name: String, value: String) {
        if let Some(chain) = self.redirect_chains.get_mut(original_url) {
            chain.add_cookie(name, value);
        }
    }

    pub fn get_redirect_cookies(&self, original_url: &str) -> Vec<String> {
        self.redirect_chains
            .get(original_url)
            .map(|chain| chain.get_all_cookies())
            .unwrap_or_default()
    }

    pub fn finish_redirect_chain(&mut self, original_url: &str) -> Option<String> {
        self.redirect_chains.remove(original_url).and_then(|chain| chain.get_final_url())
    }

    pub fn extract_challenge_cookies(&self, headers: &HashMap<String, String>) -> Vec<String> {
        let mut cookies = Vec::new();

        if let Some(set_cookie) = headers.get("set-cookie") {
            for cookie_str in set_cookie.split(';') {
                if let Ok(cookie) = Cookie::parse(cookie_str.trim()) {
                    let name = cookie.name().to_string();
                    
                    if name.starts_with("__cf") || 
                       name.starts_with("cf_") ||
                       name == "cf_clearance" ||
                       name == "__cfduid" {
                        cookies.push(cookie_str.to_string());
                    }
                }
            }
        }

        cookies
    }

    pub fn should_passthrough(&self, url: &str) -> bool {
        self.pending_challenges.contains_key(url)
    }

    pub fn register_challenge(&mut self, url: String, cookies: Vec<String>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.pending_challenges.insert(url.clone(), ChallengeState {
            url,
            timestamp,
            cookies,
            redirects: 0,
        });
    }

    pub fn complete_challenge(&mut self, url: &str) {
        self.pending_challenges.remove(url);
    }

    pub fn get_challenge_cookies(&self, url: &str) -> Option<Vec<String>> {
        self.pending_challenges
            .get(url)
            .map(|state| state.cookies.clone())
    }

    pub fn cleanup_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.pending_challenges.retain(|_, state| {
            now - state.timestamp < CHALLENGE_TIMEOUT
        });

        self.redirect_chains.retain(|_, chain| {
            !chain.is_expired(CHALLENGE_TIMEOUT)
        });
    }

    pub fn increment_redirects(&mut self, url: &str) -> Option<u32> {
        if let Some(state) = self.pending_challenges.get_mut(url) {
            state.redirects += 1;
            Some(state.redirects)
        } else {
            None
        }
    }

    pub fn has_too_many_redirects(&self, url: &str, max_redirects: u32) -> bool {
        self.pending_challenges
            .get(url)
            .map(|state| state.redirects >= max_redirects)
            .unwrap_or(false)
    }

    pub fn get_redirect_chain_length(&self, original_url: &str) -> usize {
        self.redirect_chains
            .get(original_url)
            .map(|chain| chain.redirect_count())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_challenge() {
        let handler = ChallengeHandler::new();
        
        let body = "Some <div id=\"cf-browser-verification\"> content";
        assert!(handler.detect_challenge(body, &HashMap::new()));
        
        let normal_body = "Normal website content";
        assert!(!handler.detect_challenge(normal_body, &HashMap::new()));
    }

    #[test]
    fn test_redirect_chain() {
        let mut chain = RedirectChain::new("https://example.com".to_string());
        
        chain.add_redirect(
            "https://example.com".to_string(),
            "https://example.com/redirect1".to_string(),
            302,
        );
        
        chain.add_redirect(
            "https://example.com/redirect1".to_string(),
            "https://example.com/final".to_string(),
            302,
        );
        
        assert_eq!(chain.redirect_count(), 2);
        assert_eq!(chain.get_final_url(), Some("https://example.com/final".to_string()));
        assert!(!chain.has_loop());
    }

    #[test]
    fn test_redirect_loop_detection() {
        let mut chain = RedirectChain::new("https://example.com".to_string());
        
        chain.add_redirect(
            "https://example.com".to_string(),
            "https://example.com/a".to_string(),
            302,
        );
        
        chain.add_redirect(
            "https://example.com/a".to_string(),
            "https://example.com/b".to_string(),
            302,
        );
        
        chain.add_redirect(
            "https://example.com/b".to_string(),
            "https://example.com/a".to_string(),
            302,
        );
        
        assert!(chain.has_loop());
    }

    #[test]
    fn test_challenge_handler_redirects() {
        let mut handler = ChallengeHandler::new();
        
        handler.start_redirect_chain("https://example.com".to_string());
        
        let result = handler.add_redirect(
            "https://example.com",
            "https://example.com".to_string(),
            "https://example.com/step1".to_string(),
            302,
        );
        
        assert!(result.is_ok());
        assert_eq!(handler.get_redirect_chain_length("https://example.com"), 1);
    }

    #[test]
    fn test_redirect_cookies() {
        let mut handler = ChallengeHandler::new();
        
        handler.start_redirect_chain("https://example.com".to_string());
        handler.add_redirect_cookie("https://example.com", "cf_clearance".to_string(), "test123".to_string());
        
        let cookies = handler.get_redirect_cookies("https://example.com");
        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].contains("cf_clearance"));
    }
}