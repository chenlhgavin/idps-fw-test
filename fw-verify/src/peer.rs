//! Driving the on-device fw-agent: traffic generation and listeners.

use std::net::IpAddr;
use std::process::Child;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::adb;
use crate::config::RunConfig;

/// Parsed result of a `fw-agent traffic` run.
///
/// The per-outcome counts mirror the fw-agent JSON schema and are retained for
/// diagnostics even though the orchestrator decides on `verdict` alone.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TrafficOutcome {
    pub verdict: String,
    #[serde(default)]
    pub success: u32,
    #[serde(default)]
    pub timeout: u32,
    #[serde(default)]
    pub refused: u32,
    #[serde(default)]
    pub denied: u32,
    #[serde(default)]
    pub sent: u32,
    #[serde(default)]
    pub other: u32,
}

/// A traffic request to hand to `fw-agent`.
#[derive(Debug, Clone)]
pub struct TrafficCmd {
    pub proto: &'static str,
    pub to: IpAddr,
    pub dport: Option<u16>,
    pub dports: Option<Vec<u16>>,
    pub sport: Option<u16>,
    pub count: u32,
    pub timeout_ms: u64,
    pub interval_ms: u64,
    pub await_reply: bool,
    pub fin_only: bool,
}

impl TrafficCmd {
    fn render(&self, cfg: &RunConfig) -> String {
        let mut cmd = format!("{} traffic {} --to {}", cfg.fw_agent, self.proto, self.to);
        if let Some(ports) = &self.dports {
            let joined = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            cmd.push_str(&format!(" --dports {joined}"));
        } else if let Some(port) = self.dport {
            cmd.push_str(&format!(" --dport {port}"));
        }
        if let Some(sport) = self.sport {
            cmd.push_str(&format!(" --sport {sport}"));
        }
        if self.count > 1 {
            cmd.push_str(&format!(" --count {}", self.count));
        }
        if self.interval_ms > 0 {
            cmd.push_str(&format!(" --interval-ms {}", self.interval_ms));
        }
        cmd.push_str(&format!(" --timeout-ms {}", self.timeout_ms));
        if self.await_reply {
            cmd.push_str(" --await-reply");
        }
        if self.fin_only {
            cmd.push_str(" --fin-only");
        }
        cmd
    }
}

/// Generate traffic from `serial`, optionally as a specific UID.
pub fn traffic(
    serial: &str,
    cfg: &RunConfig,
    cmd: &TrafficCmd,
    uid: Option<u32>,
) -> Result<TrafficOutcome> {
    let inner = cmd.render(cfg);
    let remote = match uid {
        Some(uid) => format!("su {uid} -c '{inner}'"),
        None => inner,
    };
    let value = adb::shell_json(serial, &remote)?;
    serde_json::from_value(value).context("failed to parse traffic outcome")
}

/// Start a background listener on `serial`. Returns the local adb child.
pub fn start_listener(
    serial: &str,
    cfg: &RunConfig,
    proto: &str,
    port: u16,
    duration_secs: u64,
) -> Result<Child> {
    let cmd = format!(
        "{} listen {proto} --port {port} --duration-secs {duration_secs}",
        cfg.fw_agent
    );
    adb::spawn_shell(serial, &cmd)
}

/// Best-effort teardown of any lingering fw-agent listeners on `serial`.
pub fn stop_listeners(serial: &str, cfg: &RunConfig) {
    let _ = adb::shell(serial, &format!("pkill -f '{} listen'", cfg.fw_agent));
}
