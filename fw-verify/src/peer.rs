//! Driving the on-device fw-agent: traffic generation and listeners.

use std::net::IpAddr;
use std::process::Child;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::RunConfig;
use crate::exec::Endpoint;

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
    pub icmp_timestamp: bool,
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
        if self.icmp_timestamp {
            cmd.push_str(" --icmp-type timestamp");
        }
        cmd
    }
}

/// Generate traffic from `endpoint`, optionally as a specific UID.
pub fn traffic(
    endpoint: &Endpoint,
    cfg: &RunConfig,
    cmd: &TrafficCmd,
    uid: Option<u32>,
) -> Result<TrafficOutcome> {
    let inner = cmd.render(cfg);
    let value = endpoint.shell_json_as(uid, &inner)?;
    serde_json::from_value(value).context("failed to parse traffic outcome")
}

/// Start a background listener on `endpoint`. Returns the local child.
pub fn start_listener(
    endpoint: &Endpoint,
    cfg: &RunConfig,
    proto: &str,
    port: u16,
    duration_secs: u64,
) -> Result<Child> {
    let cmd = format!(
        "{} listen {proto} --port {port} --duration-secs {duration_secs}",
        cfg.fw_agent
    );
    endpoint.spawn_shell(&cmd)
}

/// Best-effort teardown of any lingering fw-agent listeners on `endpoint`.
pub fn stop_listeners(endpoint: &Endpoint, cfg: &RunConfig) {
    let _ = endpoint.shell(&format!("pkill -f '{} listen'", cfg.fw_agent));
}
