use crate::config::{keys, Config};
use crate::get_time;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub peer_id: String,
    pub ip: String,
    pub timestamp: i64,
    pub success: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialUsage {
    pub peer_id: String,
    pub last_used: i64,
    pub usage_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub connection_id: String,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub avg_fps: f64,
    pub avg_latency_ms: f64,
    pub total_frames: u64,
    pub dropped_frames: u64,
    pub bytes_transferred: u64,
}

lazy_static::lazy_static! {
    static ref LOGIN_RECORDS: Arc<Mutex<Vec<LoginRecord>>> = Arc::new(Mutex::new(Vec::new()));
    static ref CREDENTIAL_USAGE: Arc<RwLock<HashMap<String, CredentialUsage>>> =
        Arc::new(RwLock::new(HashMap::new()));
    static ref PERFORMANCE_METRICS: Arc<Mutex<Vec<PerformanceMetrics>>> =
        Arc::new(Mutex::new(Vec::new()));
    static ref ALERT_TRIGGERED: Arc<Mutex<HashMap<String, i64>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

pub const DEFAULT_CREDENTIAL_EXPIRY_DAYS: i64 = 30;
pub const DEFAULT_MAX_LOGIN_FAILURES: i32 = 5;
pub const ALERT_COOLDOWN_MS: i64 = 60 * 60 * 1000;
pub const MAX_LOGIN_RECORDS: usize = 1000;
pub const MAX_PERFORMANCE_RECORDS: usize = 100;
pub const MAX_CREDENTIAL_RECORDS: usize = 10000;

pub fn is_credential_cleanup_enabled() -> bool {
    Config::get_bool_option(keys::OPTION_ENABLE_CREDENTIAL_CLEANUP)
}

pub fn get_credential_expiry_days() -> i64 {
    Config::get_option(keys::OPTION_CREDENTIAL_EXPIRY_DAYS)
        .parse()
        .unwrap_or(DEFAULT_CREDENTIAL_EXPIRY_DAYS)
}

pub fn is_login_alerts_enabled() -> bool {
    Config::get_bool_option(keys::OPTION_ENABLE_LOGIN_ALERTS)
}

pub fn get_alert_webhook_url() -> String {
    Config::get_option(keys::OPTION_ALERT_WEBHOOK_URL)
}

pub fn get_max_login_failures() -> i32 {
    Config::get_option(keys::OPTION_MAX_LOGIN_FAILURES_BEFORE_ALERT)
        .parse()
        .unwrap_or(DEFAULT_MAX_LOGIN_FAILURES)
}

pub fn is_performance_monitoring_enabled() -> bool {
    Config::get_bool_option(keys::OPTION_ENABLE_PERFORMANCE_MONITORING)
}

pub fn record_login_attempt(
    peer_id: String,
    ip: String,
    success: bool,
    failure_reason: Option<String>,
) {
    let mut records = LOGIN_RECORDS.lock().unwrap();
    let record = LoginRecord {
        peer_id: peer_id.clone(),
        ip,
        timestamp: get_time(),
        success,
        failure_reason,
    };
    records.push(record);

    let len = records.len();
    if len > MAX_LOGIN_RECORDS {
        records.drain(0..len - MAX_LOGIN_RECORDS);
    }

    if !success && is_login_alerts_enabled() {
        check_and_trigger_login_failure_alert(&peer_id);
    }
}

pub fn check_and_trigger_login_failure_alert(peer_id: &str) {
    let records = LOGIN_RECORDS.lock().unwrap();
    let now = get_time();
    let one_hour_ago = now - 3600 * 1000;

    let recent_failures = records
        .iter()
        .filter(|r| r.peer_id == peer_id && !r.success && r.timestamp > one_hour_ago)
        .count();

    let max_failures = get_max_login_failures() as usize;

    if recent_failures >= max_failures {
        let mut triggered = ALERT_TRIGGERED.lock().unwrap();
        let last_triggered = triggered.get(peer_id).copied().unwrap_or(0);

        if now - last_triggered > ALERT_COOLDOWN_MS {
            triggered.insert(peer_id.to_string(), now);
            log::warn!(
                "ALERT: Too many login failures for peer {}: {} failures in last hour",
                peer_id,
                recent_failures
            );
            send_alert_webhook(peer_id, recent_failures);
        }
    }
}

fn send_alert_webhook(peer_id: &str, failure_count: usize) {
    let webhook_url = get_alert_webhook_url();
    if !webhook_url.is_empty() {
        log::info!(
            "Would send alert to webhook: {} for peer {} with {} failures",
            webhook_url,
            peer_id,
            failure_count
        );
    }
}

pub fn update_credential_usage(peer_id: String) {
    let mut usage = CREDENTIAL_USAGE.write().unwrap();
    let now = get_time();

    if let Some(record) = usage.get_mut(&peer_id) {
        record.last_used = now;
        record.usage_count = record.usage_count.saturating_add(1);
    } else {
        if usage.len() >= MAX_CREDENTIAL_RECORDS {
            let oldest_key = usage
                .iter()
                .min_by_key(|(_, v)| v.last_used)
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest_key {
                usage.remove(&key);
            }
        }

        usage.insert(
            peer_id.clone(),
            CredentialUsage {
                peer_id,
                last_used: now,
                usage_count: 1,
            },
        );
    }
}

pub fn cleanup_expired_credentials() -> Vec<String> {
    if !is_credential_cleanup_enabled() {
        return Vec::new();
    }

    let expiry_days = get_credential_expiry_days();
    let expiry_ms = expiry_days * 24 * 60 * 60 * 1000;
    let now = get_time();
    let cutoff = now - expiry_ms;

    let mut usage = CREDENTIAL_USAGE.write().unwrap();
    let mut expired_peers = Vec::new();

    usage.retain(|peer_id, record| {
        if record.last_used < cutoff {
            expired_peers.push(peer_id.clone());
            log::info!("Cleaning up expired credential for peer: {}", peer_id);
            false
        } else {
            true
        }
    });

    expired_peers
}

pub fn start_performance_monitoring(connection_id: String) -> String {
    let metrics = PerformanceMetrics {
        connection_id: connection_id.clone(),
        start_time: get_time(),
        end_time: None,
        avg_fps: 0.0,
        avg_latency_ms: 0.0,
        total_frames: 0,
        dropped_frames: 0,
        bytes_transferred: 0,
    };

    let mut metrics_store = PERFORMANCE_METRICS.lock().unwrap();

    let len = metrics_store.len();
    if len >= MAX_PERFORMANCE_RECORDS {
        metrics_store.drain(0..len - MAX_PERFORMANCE_RECORDS + 1);
    }

    metrics_store.push(metrics);

    connection_id
}

pub fn update_performance_metrics(
    connection_id: &str,
    fps: f64,
    latency_ms: f64,
    frames: u64,
    dropped: u64,
    bytes: u64,
) {
    if !is_performance_monitoring_enabled() {
        return;
    }

    let mut metrics_store = PERFORMANCE_METRICS.lock().unwrap();
    if let Some(metrics) = metrics_store
        .iter_mut()
        .find(|m| m.connection_id == connection_id)
    {
        let new_total_frames = metrics.total_frames.saturating_add(frames);

        if new_total_frames == 0 {
            metrics.avg_fps = fps.max(0.0);
            metrics.avg_latency_ms = latency_ms.max(0.0);
        } else {
            let old_weight = metrics.total_frames as f64;
            let new_weight = 1.0;
            let total_weight = old_weight + new_weight;

            metrics.avg_fps =
                (metrics.avg_fps * old_weight + fps.max(0.0) * new_weight) / total_weight;
            metrics.avg_latency_ms = (metrics.avg_latency_ms * old_weight
                + latency_ms.max(0.0) * new_weight)
                / total_weight;
        }

        metrics.total_frames = new_total_frames;
        metrics.dropped_frames = metrics.dropped_frames.saturating_add(dropped);
        metrics.bytes_transferred = metrics.bytes_transferred.saturating_add(bytes);
    }
}

pub fn end_performance_monitoring(connection_id: &str) -> Option<PerformanceMetrics> {
    let mut metrics_store = PERFORMANCE_METRICS.lock().unwrap();
    let now = get_time();

    if let Some(metrics) = metrics_store
        .iter_mut()
        .find(|m| m.connection_id == connection_id)
    {
        metrics.end_time = Some(now);
        log::info!(
            "Connection {} ended. Avg FPS: {:.2}, Avg Latency: {:.2}ms, Frames: {}, Dropped: {}, Bytes: {}",
            connection_id,
            metrics.avg_fps,
            metrics.avg_latency_ms,
            metrics.total_frames,
            metrics.dropped_frames,
            metrics.bytes_transferred
        );
        Some(metrics.clone())
    } else {
        None
    }
}

pub fn get_recent_login_records(limit: usize) -> Vec<LoginRecord> {
    let records = LOGIN_RECORDS.lock().unwrap();
    records.iter().rev().take(limit).cloned().collect()
}

pub fn get_performance_summary() -> Vec<PerformanceMetrics> {
    PERFORMANCE_METRICS.lock().unwrap().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_recording() {
        record_login_attempt(
            "test-peer-1".to_string(),
            "192.168.1.1".to_string(),
            true,
            None,
        );

        let records = get_recent_login_records(10);
        assert!(!records.is_empty());
        assert_eq!(records[0].peer_id, "test-peer-1");
        assert!(records[0].success);
    }

    #[test]
    fn test_credential_usage() {
        update_credential_usage("test-peer-2".to_string());
        update_credential_usage("test-peer-2".to_string());

        let usage = CREDENTIAL_USAGE.read().unwrap();
        assert!(usage.contains_key("test-peer-2"));
        assert_eq!(usage.get("test-peer-2").unwrap().usage_count, 2);
    }
}
