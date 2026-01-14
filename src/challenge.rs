// src/challenge.rs
use anyhow::Result;
use cookie::Cookie;

#[derive(Debug, Clone)]
pub enum ChallengeType {
    CloudflareJS,
    CloudflareTurnstile,
    Captcha,
}

pub struct ChallengeManager {
    cookies: Vec<ChallengeCookie>,
}

impl ChallengeManager {
    pub fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }
    
    pub fn is_challenge_response(&self, response: &[u8]) -> Option<ChallengeType> {
        let response_str = String::from_utf8_lossy(response);
        
        if response_str.contains("jschl-answer") 
            || response_str.contains("cf-challenge") {
            return Some(ChallengeType::CloudflareJS);
        }
        
        if response_str.contains("cf-turnstile") {
            return Some(ChallengeType::CloudflareTurnstile);
        }
        
        if response_str.contains("cf-captcha") {
            return Some(ChallengeType::Captcha);
        }
        
        None
    }
    
    pub fn extract_challenge_cookies(&mut self, headers: &[u8], _url: &str) -> Vec<ChallengeCookie> {
        let headers_str = String::from_utf8_lossy(headers);
        let mut cookies = Vec::new();
        
        for line in headers_str.lines() {
            if line.to_lowercase().starts_with("set-cookie:") {
                let cookie_str = line[11..].trim();
                
                if let Ok(cookie) = Cookie::parse(cookie_str) {
                    let name = cookie.name().to_string();
                    let value = cookie.value().to_string();
                    
                    if name == "__cfduid" || name == "cf_clearance" {
                        let challenge_cookie = ChallengeCookie {
                            name,
                            value,
                        };
                        
                        cookies.push(challenge_cookie.clone());
                        self.cookies.push(challenge_cookie);
                    }
                }
            }
        }
        
        cookies
    }
    
    pub fn get_cookies(&self) -> Vec<ChallengeCookie> {
        self.cookies.clone()
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeCookie {
    pub name: String,
    pub value: String,
}
