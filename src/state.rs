// src/state.rs - State Management для cookies и sessions
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{Duration, Instant};

/// Cookie store для сохранения между запросами
#[derive(Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<u64>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
    pub created_at: Instant,
}

impl Cookie {
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires
        } else {
            false
        }
    }
    
    pub fn matches_domain(&self, domain: &str) -> bool {
        if let Some(cookie_domain) = &self.domain {
            domain.ends_with(cookie_domain) || domain == cookie_domain
        } else {
            true
        }
    }
    
    pub fn matches_path(&self, path: &str) -> bool {
        if let Some(cookie_path) = &self.path {
            path.starts_with(cookie_path)
        } else {
            true
        }
    }
}

/// Cookie Store с автоматической очисткой expired
pub struct CookieStore {
    cookies: Arc<RwLock<HashMap<String, Vec<Cookie>>>>,
}

impl CookieStore {
    pub fn new() -> Self {
        Self {
            cookies: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Добавить cookie
    pub fn add(&self, domain: &str, cookie: Cookie) {
        let mut cookies = self.cookies.write();
        let entry = cookies.entry(domain.to_string()).or_insert_with(Vec::new);
        
        // Удаляем старый cookie с тем же именем
        entry.retain(|c| c.name != cookie.name);
        
        // Добавляем новый
        entry.push(cookie);
    }
    
    /// Получить cookies для домена и пути
    pub fn get(&self, domain: &str, path: &str) -> Vec<Cookie> {
        let cookies = self.cookies.read();
        
        let mut result = Vec::new();
        
        // Проверяем все домены (включая родительские)
        for (stored_domain, domain_cookies) in cookies.iter() {
            if domain.ends_with(stored_domain) {
                for cookie in domain_cookies {
                    if !cookie.is_expired() 
                        && cookie.matches_domain(domain)
                        && cookie.matches_path(path) {
                        result.push(cookie.clone());
                    }
                }
            }
        }
        
        result
    }
    
    /// Очистить expired cookies
    pub fn cleanup_expired(&self) {
        let mut cookies = self.cookies.write();
        
        for domain_cookies in cookies.values_mut() {
            domain_cookies.retain(|c| !c.is_expired());
        }
        
        // Удаляем пустые домены
        cookies.retain(|_, v| !v.is_empty());
    }
    
    /// Получить все cookies (для отладки)
    pub fn get_all(&self) -> HashMap<String, Vec<Cookie>> {
        self.cookies.read().clone()
    }
    
    /// Очистить все cookies
    pub fn clear(&self) {
        self.cookies.write().clear();
    }
}

/// Session Store для сохранения состояния между запросами
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub data: HashMap<String, String>,
    pub created_at: Instant,
    pub last_accessed: Instant,
}

pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    timeout: Duration,
}

impl SessionStore {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timeout: Duration::from_secs(timeout_secs),
        }
    }
    
    /// Создать новую сессию
    pub fn create(&self, id: String) -> Session {
        let session = Session {
            id: id.clone(),
            data: HashMap::new(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
        };
        
        self.sessions.write().insert(id, session.clone());
        session
    }
    
    /// Получить сессию
    pub fn get(&self, id: &str) -> Option<Session> {
        let mut sessions = self.sessions.write();
        
        if let Some(session) = sessions.get_mut(id) {
            // Проверяем timeout
            if session.last_accessed.elapsed() > self.timeout {
                sessions.remove(id);
                return None;
            }
            
            // Обновляем last_accessed
            session.last_accessed = Instant::now();
            Some(session.clone())
        } else {
            None
        }
    }
    
    /// Обновить данные сессии
    pub fn update(&self, id: &str, key: String, value: String) {
        let mut sessions = self.sessions.write();
        
        if let Some(session) = sessions.get_mut(id) {
            session.data.insert(key, value);
            session.last_accessed = Instant::now();
        }
    }
    
    /// Удалить сессию
    pub fn remove(&self, id: &str) {
        self.sessions.write().remove(id);
    }
    
    /// Очистить expired сессии
    pub fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write();
        sessions.retain(|_, session| session.last_accessed.elapsed() <= self.timeout);
    }
}

/// Challenge cookies manager (интеграция с CookieStore)
pub struct ChallengeCookieManager {
    cookie_store: CookieStore,
}

impl ChallengeCookieManager {
    pub fn new() -> Self {
        Self {
            cookie_store: CookieStore::new(),
        }
    }
    
    /// Сохранить challenge cookie
    pub fn store_challenge_cookie(&self, domain: &str, name: &str, value: &str) {
        let cookie = Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: Some(domain.to_string()),
            path: Some("/".to_string()),
            expires: None, // Session cookie
            http_only: true,
            secure: true,
            same_site: Some("None".to_string()),
            created_at: Instant::now(),
        };
        
        self.cookie_store.add(domain, cookie);
    }
    
    /// Получить challenge cookies для домена
    pub fn get_challenge_cookies(&self, domain: &str) -> Vec<Cookie> {
        self.cookie_store.get(domain, "/")
            .into_iter()
            .filter(|c| {
                c.name.starts_with("__cf") || 
                c.name.starts_with("cf_") ||
                c.name.starts_with("_px")
            })
            .collect()
    }
    
    /// Форматировать cookies в Cookie header
    pub fn format_cookie_header(&self, domain: &str) -> String {
        let cookies = self.get_challenge_cookies(domain);
        
        cookies.iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// Periodic cleanup task
pub async fn cleanup_task(
    cookie_store: Arc<CookieStore>,
    session_store: Arc<SessionStore>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 минут
    
    loop {
        interval.tick().await;
        
        cookie_store.cleanup_expired();
        session_store.cleanup_expired();
        
        tracing::debug!("Cleaned up expired cookies and sessions");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cookie_store() {
        let store = CookieStore::new();
        
        let cookie = Cookie {
            name: "test".to_string(),
            value: "value".to_string(),
            domain: Some("example.com".to_string()),
            path: Some("/".to_string()),
            expires: None,
            http_only: false,
            secure: false,
            same_site: None,
            created_at: Instant::now(),
        };
        
        store.add("example.com", cookie);
        
        let cookies = store.get("example.com", "/");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "test");
    }
}
