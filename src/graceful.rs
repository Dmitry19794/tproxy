use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Notify};
use tokio::time::{sleep, timeout};
use std::collections::HashMap;
use anyhow::Result;

const MAX_RETRIES: u32 = 3;
const RETRY_BACKOFF_MS: u64 = 100;
const SHUTDOWN_TIMEOUT_SEC: u64 = 30;
const CONNECTION_TIMEOUT_SEC: u64 = 60;

#[derive(Clone, Debug)]
pub struct ConnectionState {
    pub id: u64,
    pub established_at: Instant,
    pub last_activity: Instant,
    pub retry_count: u32,
    pub is_closing: bool,
}

impl ConnectionState {
    pub fn new(id: u64) -> Self {
        let now = Instant::now();
        Self {
            id,
            established_at: now,
            last_activity: now,
            retry_count: 0,
            is_closing: false,
        }
    }

    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    pub fn should_retry(&self) -> bool {
        self.retry_count < MAX_RETRIES && !self.is_closing
    }

    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }
}

pub struct GracefulShutdown {
    connections: Arc<RwLock<HashMap<u64, ConnectionState>>>,
    shutdown_notify: Arc<Notify>,
    is_shutting_down: Arc<RwLock<bool>>,
}

impl GracefulShutdown {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            shutdown_notify: Arc::new(Notify::new()),
            is_shutting_down: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn register_connection(&self, id: u64) {
        let state = ConnectionState::new(id);
        self.connections.write().await.insert(id, state);
    }

    pub async fn unregister_connection(&self, id: u64) {
        self.connections.write().await.remove(&id);
    }

    pub async fn mark_activity(&self, id: u64) {
        if let Some(state) = self.connections.write().await.get_mut(&id) {
            state.mark_activity();
        }
    }

    pub async fn initiate_shutdown(&self) {
        *self.is_shutting_down.write().await = true;
        self.shutdown_notify.notify_waiters();
    }

    pub async fn is_shutting_down(&self) -> bool {
        *self.is_shutting_down.read().await
    }

    pub async fn wait_for_shutdown(&self) {
        self.shutdown_notify.notified().await;
    }

    pub async fn graceful_close_all(&self) -> Result<()> {
        let timeout_duration = Duration::from_secs(SHUTDOWN_TIMEOUT_SEC);
        
        let result = timeout(timeout_duration, async {
            let mut connections = self.connections.write().await;
            for state in connections.values_mut() {
                state.is_closing = true;
            }
            
            drop(connections);
            
            loop {
                let count = self.connections.read().await.len();
                if count == 0 {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
        }).await;

        match result {
            Ok(_) => {
                log::info!("All connections closed gracefully");
                Ok(())
            }
            Err(_) => {
                let remaining = self.connections.read().await.len();
                log::warn!("Shutdown timeout: {} connections remaining", remaining);
                self.connections.write().await.clear();
                Ok(())
            }
        }
    }

    pub async fn cleanup_idle_connections(&self, idle_timeout: Duration) {
        let mut to_remove = Vec::new();
        
        {
            let connections = self.connections.read().await;
            for (id, state) in connections.iter() {
                if state.is_idle(idle_timeout) && !state.is_closing {
                    to_remove.push(*id);
                }
            }
        }
        
        if !to_remove.is_empty() {
            let mut connections = self.connections.write().await;
            for id in to_remove {
                log::debug!("Removing idle connection: {}", id);
                connections.remove(&id);
            }
        }
    }

    pub async fn get_active_connections(&self) -> usize {
        self.connections.read().await.len()
    }
}

pub struct ConnectionRecovery {
    max_retries: u32,
    backoff_ms: u64,
}

impl ConnectionRecovery {
    pub fn new() -> Self {
        Self {
            max_retries: MAX_RETRIES,
            backoff_ms: RETRY_BACKOFF_MS,
        }
    }

    pub async fn retry_with_backoff<F, Fut, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;
        
        for attempt in 0..self.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    
                    if attempt < self.max_retries - 1 {
                        let delay = self.backoff_ms * (2_u64.pow(attempt));
                        log::debug!("Retry attempt {} after {}ms", attempt + 1, delay);
                        sleep(Duration::from_millis(delay)).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Max retries exceeded")))
    }

    pub async fn recover_connection<F, Fut>(&self, reconnect: F) -> Result<()>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        self.retry_with_backoff(|| reconnect()).await
    }
}

pub struct ErrorPropagator {
    suppress_errors: bool,
}

impl ErrorPropagator {
    pub fn new(suppress_errors: bool) -> Self {
        Self { suppress_errors }
    }

    pub fn propagate<T>(&self, result: Result<T>) -> Result<T> {
        if self.suppress_errors {
            result.map_err(|e| {
                log::debug!("Suppressed error: {}", e);
                e
            })
        } else {
            result
        }
    }

    pub fn log_and_propagate<T>(&self, result: Result<T>, context: &str) -> Result<T> {
        result.map_err(|e| {
            log::error!("{}: {}", context, e);
            e
        })
    }

    pub fn should_propagate(&self, error: &anyhow::Error) -> bool {
        !self.suppress_errors || self.is_critical_error(error)
    }

    fn is_critical_error(&self, _error: &anyhow::Error) -> bool {
        false
    }
}

pub async fn shutdown_without_rst<S>(stream: S) -> Result<()>
where
    S: tokio::io::AsyncWrite + std::marker::Unpin,
{
    use tokio::io::AsyncWriteExt;
    
    let mut stream = stream;
    match stream.shutdown().await {
        Ok(_) => {
            log::debug!("Socket shutdown gracefully (FIN sent)");
            Ok(())
        }
        Err(e) => {
            log::warn!("Error during graceful shutdown: {}", e);
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let gs = GracefulShutdown::new();
        
        gs.register_connection(1).await;
        gs.register_connection(2).await;
        
        assert_eq!(gs.get_active_connections().await, 2);
        
        gs.unregister_connection(1).await;
        assert_eq!(gs.get_active_connections().await, 1);
    }

    #[tokio::test]
    async fn test_connection_recovery() {
        let recovery = ConnectionRecovery::new();
        let mut attempt = 0;
        
        let result = recovery.retry_with_backoff(|| async {
            attempt += 1;
            if attempt < 3 {
                Err(anyhow::anyhow!("Temporary failure"))
            } else {
                Ok(())
            }
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(attempt, 3);
    }

    #[test]
    fn test_connection_state() {
        let mut state = ConnectionState::new(1);
        
        assert!(!state.is_idle(Duration::from_secs(10)));
        assert!(state.should_retry());
        
        state.increment_retry();
        state.increment_retry();
        state.increment_retry();
        
        assert!(!state.should_retry());
    }
}
