use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use cookie::Cookie;

#[derive(Debug, Clone)]
pub struct TcpState {
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub timestamp: u64,
}

impl TcpState {
    pub fn new(seq: u32, ack: u32, window: u16) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            seq,
            ack,
            window,
            timestamp,
        }
    }

    pub fn update(&mut self, seq: u32, ack: u32, window: u16) {
        self.seq = seq;
        self.ack = ack;
        self.window = window;
        self.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: String,
    pub cookies: HashMap<String, Vec<String>>,
    pub created_at: u64,
    pub last_used: u64,
}

impl SessionState {
    pub fn new(session_id: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            session_id,
            cookies: HashMap::new(),
            created_at: now,
            last_used: now,
        }
    }

    pub fn add_cookie(&mut self, domain: String, cookie: String) {
        self.cookies.entry(domain).or_insert_with(Vec::new).push(cookie);
        self.update_last_used();
    }

    pub fn get_cookies(&self, domain: &str) -> Vec<String> {
        self.cookies.get(domain).cloned().unwrap_or_default()
    }

    pub fn update_last_used(&mut self) {
        self.last_used = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn is_expired(&self, max_age: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.last_used > max_age
    }
}

pub struct StateManager {
    tcp_states: Arc<RwLock<HashMap<String, TcpState>>>,
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
    cookies: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            tcp_states: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            cookies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn store_tcp_state(&self, conn_id: String, state: TcpState) {
        self.tcp_states.write().insert(conn_id, state);
    }

    pub fn get_tcp_state(&self, conn_id: &str) -> Option<TcpState> {
        self.tcp_states.read().get(conn_id).cloned()
    }

    pub fn update_tcp_state(&self, conn_id: &str, seq: u32, ack: u32, window: u16) {
        if let Some(state) = self.tcp_states.write().get_mut(conn_id) {
            state.update(seq, ack, window);
        }
    }

    pub fn create_session(&self, session_id: String) -> SessionState {
        let session = SessionState::new(session_id.clone());
        self.sessions.write().insert(session_id, session.clone());
        session
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionState> {
        let mut sessions = self.sessions.write();
        if let Some(session) = sessions.get_mut(session_id) {
            session.update_last_used();
            return Some(session.clone());
        }
        None
    }

    pub fn add_session_cookie(&self, session_id: &str, domain: String, cookie: String) {
        if let Some(session) = self.sessions.write().get_mut(session_id) {
            session.add_cookie(domain, cookie);
        }
    }

    pub fn store_cookie(&self, domain: String, cookie: String) {
        self.cookies.write()
            .entry(domain)
            .or_insert_with(Vec::new)
            .push(cookie);
    }

    pub fn get_cookies(&self, domain: &str) -> Vec<String> {
        let cookies = self.cookies.read();
        
        if let Some(domain_cookies) = cookies.get(domain) {
            domain_cookies.iter()
                .filter_map(|cookie_str| {
                    Cookie::parse(cookie_str).ok().and_then(|cookie| {
                        if !cookie.name().is_empty() {
                            Some(cookie_str.clone())
                        } else {
                            None
                        }
                    })
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn cleanup(&self) {
        let mut cookies = self.cookies.write();
        
        for domain_cookies in cookies.values_mut() {
            domain_cookies.retain(|cookie_str| {
                if let Ok(cookie) = Cookie::parse(cookie_str) {
                    !cookie.name().is_empty()
                } else {
                    false
                }
            });
        }

        cookies.retain(|_, v| !v.is_empty());

        let mut sessions = self.sessions.write();
        sessions.retain(|_, session| !session.is_expired(3600));

        log::debug!("Cleaned up expired cookies and sessions");
    }
}

pub struct ConnectionStateManager {
    connections: Arc<RwLock<HashMap<u64, ConnectionInfo>>>,
    next_id: Arc<RwLock<u64>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: u64,
    pub created_at: u64,
    pub last_activity: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl ConnectionInfo {
    pub fn new(id: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id,
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

impl ConnectionStateManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    pub fn create_connection(&self) -> u64 {
        let mut next_id = self.next_id.write();
        let id = *next_id;
        *next_id += 1;

        let info = ConnectionInfo::new(id);
        self.connections.write().insert(id, info);

        id
    }

    pub fn remove_connection(&self, id: u64) {
        self.connections.write().remove(&id);
    }

    pub fn update_activity(&self, id: u64) {
        if let Some(info) = self.connections.write().get_mut(&id) {
            info.update_activity();
        }
    }

    pub fn get_connection(&self, id: u64) -> Option<ConnectionInfo> {
        self.connections.read().get(&id).cloned()
    }

    pub fn get_active_count(&self) -> usize {
        self.connections.read().len()
    }

    pub fn cleanup(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.connections.write().retain(|_, info| {
            now - info.last_activity < 300
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state() {
        let mut state = TcpState::new(1000, 2000, 65535);
        assert_eq!(state.seq, 1000);
        assert_eq!(state.ack, 2000);

        state.update(1100, 2100, 65535);
        assert_eq!(state.seq, 1100);
        assert_eq!(state.ack, 2100);
    }

    #[test]
    fn test_session_state() {
        let mut session = SessionState::new("session123".to_string());
        
        session.add_cookie("example.com".to_string(), "cookie1=value1".to_string());
        
        let cookies = session.get_cookies("example.com");
        assert_eq!(cookies.len(), 1);
    }

    #[test]
    fn test_state_manager() {
        let manager = StateManager::new();
        
        let state = TcpState::new(1000, 2000, 65535);
        manager.store_tcp_state("conn1".to_string(), state);
        
        let retrieved = manager.get_tcp_state("conn1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().seq, 1000);
    }

    #[test]
    fn test_connection_state_manager() {
        let manager = ConnectionStateManager::new();
        
        let id1 = manager.create_connection();
        let id2 = manager.create_connection();
        
        assert_ne!(id1, id2);
        assert_eq!(manager.get_active_count(), 2);
        
        manager.remove_connection(id1);
        assert_eq!(manager.get_active_count(), 1);
    }
}