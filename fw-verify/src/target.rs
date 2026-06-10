//! TARGET-side observation: idps-fw health/statistics and firewall events.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::adb;
use crate::config::RunConfig;

/// A `firewall_event` row as emitted by `fw-agent dump-events`.
///
/// Mirrors the on-device schema; not every column participates in matching.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct FwEvent {
    pub event_id: String,
    pub event_time_ms: i64,
    pub event_type: String,
    pub action: String,
    pub src_ip: String,
    pub src_port: i64,
    pub dst_ip: String,
    pub dst_port: i64,
    pub proto: String,
    #[serde(default)]
    pub rule_id: Option<i64>,
    #[serde(default)]
    pub detail: String,
    pub report_state: String,
}

/// Read the idps-fw health snapshot.
pub fn health(cfg: &RunConfig) -> Result<Value> {
    adb::shell_json(&cfg.target_serial, &format!("{} health", cfg.idps_fw))
}

/// Read the idps-fw statistics snapshot.
pub fn statistics(cfg: &RunConfig) -> Result<Value> {
    adb::shell_json(&cfg.target_serial, &format!("{} statistics", cfg.idps_fw))
}

/// Current firewall rule version from the health snapshot (`-1` if unknown).
pub fn firewall_rule_ver(cfg: &RunConfig) -> Result<i64> {
    Ok(health(cfg)?
        .get("firewall_rule_ver")
        .and_then(Value::as_i64)
        .unwrap_or(-1))
}

/// Device wall-clock watermark used to scope per-case events.
pub fn now_ms(cfg: &RunConfig) -> Result<i64> {
    adb::shell_json(&cfg.target_serial, &format!("{} now", cfg.fw_agent))?
        .get("now_ms")
        .and_then(Value::as_i64)
        .context("fw-agent now did not return now_ms")
}

/// Firewall events newer than `since` (epoch ms).
pub fn dump_events(cfg: &RunConfig, since: i64) -> Result<Vec<FwEvent>> {
    let cmd = format!(
        "{} dump-events --db {} --since {since}",
        cfg.fw_agent, cfg.state_db
    );
    let value = adb::shell_json(&cfg.target_serial, &cmd)?;
    let events = value.get("events").cloned().unwrap_or(Value::Array(vec![]));
    serde_json::from_value(events).context("failed to parse firewall_event rows")
}
