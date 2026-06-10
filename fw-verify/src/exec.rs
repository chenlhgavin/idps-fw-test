//! Endpoint abstraction over the two ways fw-verify reaches a worker.
//!
//! Android tests drive both phones over `adb shell`; host tests run the same
//! `fw-agent` / `idps-fw` commands locally, with the PEER side wrapped in a
//! network namespace (`ip netns exec <ns>`) so target↔peer traffic traverses
//! the idps-fw–monitored veth. The orchestrator owns all quoting: the whole
//! remote command is handed to a single shell invocation.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::adb;

/// One side of a test (target or peer) and how to run commands on it.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// An Android device reached over `adb -s <serial>`.
    Adb { serial: String },
    /// The local host. `netns` wraps commands in `ip netns exec <ns>` (peer).
    Host { netns: Option<String> },
}

impl Endpoint {
    /// Human label for diagnostics.
    pub fn label(&self) -> String {
        match self {
            Endpoint::Adb { serial } => serial.clone(),
            Endpoint::Host { netns: None } => "host".to_string(),
            Endpoint::Host { netns: Some(ns) } => format!("host:{ns}"),
        }
    }

    /// Build the local argv for a host command, applying the netns and an
    /// optional uid drop. Android never uses this path.
    fn host_argv(netns: &Option<String>, uid: Option<u32>, inner: &str) -> Vec<String> {
        let mut argv: Vec<String> = Vec::new();
        if let Some(ns) = netns {
            argv.extend(["ip", "netns", "exec", ns].map(str::to_string));
        }
        if let Some(uid) = uid {
            // Drop to the unprivileged uid the app/UID cases expect, matching
            // the eBPF cgroup connect-hook's socket-uid view.
            argv.extend(
                [
                    "setpriv",
                    "--reuid",
                    &uid.to_string(),
                    "--regid",
                    &uid.to_string(),
                    "--clear-groups",
                ]
                .map(str::to_string),
            );
        }
        argv.extend(["bash", "-c", inner].map(str::to_string));
        argv
    }

    /// Render the remote command for an adb side, optionally as a uid.
    fn adb_cmd(uid: Option<u32>, inner: &str) -> String {
        match uid {
            Some(uid) => format!("su {uid} -c '{inner}'"),
            None => inner.to_string(),
        }
    }

    /// Run a command, returning (exit_code, stdout, stderr).
    pub fn shell_full_as(&self, uid: Option<u32>, cmd: &str) -> Result<(i32, String, String)> {
        match self {
            Endpoint::Adb { serial } => adb::shell_full(serial, &Self::adb_cmd(uid, cmd)),
            Endpoint::Host { netns } => {
                let argv = Self::host_argv(netns, uid, cmd);
                let output = Command::new(&argv[0])
                    .args(&argv[1..])
                    .output()
                    .with_context(|| format!("failed to spawn `{}`", argv.join(" ")))?;
                Ok((
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stdout).to_string(),
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ))
            }
        }
    }

    /// Run a command and return trimmed stdout.
    pub fn shell(&self, cmd: &str) -> Result<String> {
        let (_code, stdout, _stderr) = self.shell_full_as(None, cmd)?;
        Ok(stdout.trim().to_string())
    }

    /// Run a command and parse its stdout as a single JSON value.
    pub fn shell_json(&self, cmd: &str) -> Result<Value> {
        self.shell_json_as(None, cmd)
    }

    /// Run a command (optionally as `uid`) and parse stdout as JSON.
    pub fn shell_json_as(&self, uid: Option<u32>, cmd: &str) -> Result<Value> {
        let (_code, stdout, stderr) = self.shell_full_as(uid, cmd)?;
        parse_json(&stdout).with_context(|| {
            format!(
                "`{cmd}` did not return JSON (stdout: {}, stderr: {})",
                stdout.trim(),
                stderr.trim()
            )
        })
    }

    /// Push a local file to a path on the side (adb push, or local copy).
    pub fn push(&self, local: &Path, remote: &str) -> Result<()> {
        match self {
            Endpoint::Adb { serial } => adb::push(serial, local, remote),
            Endpoint::Host { .. } => {
                std::fs::copy(local, remote)
                    .with_context(|| format!("failed to copy {} -> {remote}", local.display()))?;
                Ok(())
            }
        }
    }

    /// Spawn a background command (e.g. a listener). Returns the local child.
    pub fn spawn_shell(&self, cmd: &str) -> Result<Child> {
        match self {
            Endpoint::Adb { serial } => adb::spawn_shell(serial, cmd),
            Endpoint::Host { netns } => {
                let argv = Self::host_argv(netns, None, cmd);
                Command::new(&argv[0])
                    .args(&argv[1..])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .with_context(|| format!("failed to spawn background `{}`", argv.join(" ")))
            }
        }
    }

    /// Enable root (adb) / no-op on host.
    pub fn root(&self) -> Result<()> {
        match self {
            Endpoint::Adb { serial } => adb::root(serial),
            Endpoint::Host { .. } => Ok(()),
        }
    }

    /// Device state (`device` when reachable).
    pub fn get_state(&self) -> Result<String> {
        match self {
            Endpoint::Adb { serial } => adb::get_state(serial),
            Endpoint::Host { .. } => Ok("device".to_string()),
        }
    }

    /// Detect the IPv4 bound to `iface` on this side.
    pub fn detect_ipv4(&self, iface: &str) -> Result<String> {
        match self {
            Endpoint::Adb { serial } => adb::detect_ipv4(serial, iface),
            Endpoint::Host { .. } => {
                let out = self.shell(&format!("ip -4 addr show dev {iface}"))?;
                parse_inet(&out)
                    .with_context(|| format!("could not parse IPv4 for {iface} ({})", self.label()))
            }
        }
    }
}

/// Parse `inet 10.0.0.1/24 ...` to the bare address.
fn parse_inet(out: &str) -> Result<String> {
    out.split_whitespace()
        .skip_while(|token| *token != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .filter(|addr| addr.parse::<std::net::Ipv4Addr>().is_ok())
        .map(str::to_string)
        .context("no inet address found")
}

/// Parse JSON from command output: whole buffer, else the last JSON-looking line.
fn parse_json(stdout: &str) -> Result<Value> {
    if let Ok(value) = serde_json::from_str::<Value>(stdout.trim()) {
        return Ok(value);
    }
    let last = stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with('{') || line.starts_with('['))
        .context("no JSON object found in output")?;
    serde_json::from_str(last).context("failed to parse JSON output")
}
