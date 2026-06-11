//! Driving the worker: traffic generation and listeners.
//!
//! The work runs as a re-executed `fw-verify agent <sub>` on the relevant side
//! (the PEER inside its netns, or the TARGET locally), optionally under a
//! dropped uid for app/UID-policy cases.

use std::net::IpAddr;
use std::process::Child;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::RunConfig;
use crate::exec::Endpoint;

/// Parsed result of an `agent traffic` run.
///
/// The per-outcome counts mirror the agent JSON schema and are retained for
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

/// A traffic request to hand to the worker.
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
    /// Build the `agent traffic ...` argv (uid appended when dropping privilege).
    fn argv(&self, uid: Option<u32>) -> Vec<String> {
        let mut argv = vec![
            "traffic".to_string(),
            self.proto.to_string(),
            "--to".to_string(),
            self.to.to_string(),
        ];
        if let Some(ports) = &self.dports {
            let joined = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            argv.push("--dports".to_string());
            argv.push(joined);
        } else if let Some(port) = self.dport {
            argv.push("--dport".to_string());
            argv.push(port.to_string());
        }
        if let Some(sport) = self.sport {
            argv.push("--sport".to_string());
            argv.push(sport.to_string());
        }
        if self.count > 1 {
            argv.push("--count".to_string());
            argv.push(self.count.to_string());
        }
        if self.interval_ms > 0 {
            argv.push("--interval-ms".to_string());
            argv.push(self.interval_ms.to_string());
        }
        argv.push("--timeout-ms".to_string());
        argv.push(self.timeout_ms.to_string());
        if self.await_reply {
            argv.push("--await-reply".to_string());
        }
        if self.fin_only {
            argv.push("--fin-only".to_string());
        }
        if self.icmp_timestamp {
            argv.push("--icmp-type".to_string());
            argv.push("timestamp".to_string());
        }
        if let Some(uid) = uid {
            argv.push("--uid".to_string());
            argv.push(uid.to_string());
        }
        argv
    }
}

/// Generate traffic from `endpoint`, optionally as a specific UID.
pub fn traffic(
    endpoint: &Endpoint,
    _cfg: &RunConfig,
    cmd: &TrafficCmd,
    uid: Option<u32>,
) -> Result<TrafficOutcome> {
    let value = endpoint.agent_json(&cmd.argv(uid))?;
    serde_json::from_value(value).context("failed to parse traffic outcome")
}

/// Start a background listener on `endpoint`. Returns the local child.
pub fn start_listener(
    endpoint: &Endpoint,
    _cfg: &RunConfig,
    proto: &str,
    port: u16,
    duration_secs: u64,
) -> Result<Child> {
    endpoint.agent_spawn(&[
        "listen".to_string(),
        proto.to_string(),
        "--port".to_string(),
        port.to_string(),
        "--duration-secs".to_string(),
        duration_secs.to_string(),
    ])
}

/// Best-effort teardown of any lingering agent listeners on `endpoint`.
pub fn stop_listeners(endpoint: &Endpoint, _cfg: &RunConfig) {
    let _ = endpoint.shell("pkill -f 'agent listen'");
}
