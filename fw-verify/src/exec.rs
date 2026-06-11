//! Endpoint abstraction over the two sides of a single-device test.
//!
//! The orchestrator runs locally on the device under test (host or Android) as
//! root. The TARGET side is the root network namespace it already lives in;
//! the PEER side is the far end of a veth pair parked in a network namespace so
//! target↔peer traffic traverses the idps-fw–monitored interface. Worker steps
//! that must run in the peer namespace, in the background, or under a dropped
//! uid are run as `fw-verify agent <sub>` — re-executing this same binary —
//! and their single JSON line is parsed back. Namespace entry prefers
//! `nsenter --net=/run/netns/<ns>` and falls back to `ip netns exec <ns>`,
//! mirroring idps-test/nidps-verify.

use std::io::ErrorKind;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use serde_json::Value;

/// One side of a test (TARGET or PEER) and how to run commands on it.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// The local root namespace — the TARGET, where the orchestrator runs.
    Local,
    /// The PEER, reached by entering network namespace `name`.
    Netns { name: String },
}

impl Endpoint {
    /// Human label for diagnostics.
    pub fn label(&self) -> String {
        match self {
            Endpoint::Local => "target".to_string(),
            Endpoint::Netns { name } => format!("peer:{name}"),
        }
    }

    /// Spawn `program` (argv) on this side, entering the peer netns when set.
    ///
    /// `background` detaches the child with null stdio (listeners); otherwise
    /// stdout/stderr are piped for the caller to collect. Namespace entry tries
    /// `nsenter` first and falls back to `ip netns exec` when nsenter is absent.
    fn spawn_program(&self, program: &[String], background: bool) -> Result<Child> {
        let make = |argv: &[String]| -> std::io::Result<Child> {
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]).stdin(Stdio::null());
            if background {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            } else {
                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
            cmd.spawn()
        };
        match self {
            Endpoint::Local => {
                make(program).with_context(|| format!("failed to spawn `{}`", program.join(" ")))
            }
            Endpoint::Netns { name } => {
                let ns_path = format!("/run/netns/{name}");
                let mut via_nsenter = vec![
                    "nsenter".to_string(),
                    format!("--net={ns_path}"),
                    "--".to_string(),
                ];
                via_nsenter.extend_from_slice(program);
                match make(&via_nsenter) {
                    Ok(child) => Ok(child),
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        let mut via_ip = vec![
                            "ip".to_string(),
                            "netns".to_string(),
                            "exec".to_string(),
                            name.clone(),
                        ];
                        via_ip.extend_from_slice(program);
                        make(&via_ip).with_context(|| {
                            format!("failed to spawn `{}` via ip netns exec", program.join(" "))
                        })
                    }
                    Err(error) => Err(error).with_context(|| {
                        format!("failed to spawn `{}` via nsenter", program.join(" "))
                    }),
                }
            }
        }
    }

    /// Run `program` to completion, returning (exit_code, stdout, stderr).
    fn run_program(&self, program: &[String]) -> Result<(i32, String, String)> {
        let output = self
            .spawn_program(program, false)?
            .wait_with_output()
            .with_context(|| format!("failed to wait for `{}`", program.join(" ")))?;
        Ok((
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }

    /// Absolute path of this binary, for re-executing the `agent` worker.
    fn current_exe() -> Result<String> {
        Ok(std::env::current_exe()
            .context("failed to resolve current executable for agent re-exec")?
            .to_string_lossy()
            .to_string())
    }

    /// Build the argv for a re-executed `fw-verify agent <args...>` worker.
    fn agent_argv(args: &[String]) -> Result<Vec<String>> {
        let mut argv = vec![Self::current_exe()?, "agent".to_string()];
        argv.extend_from_slice(args);
        Ok(argv)
    }

    /// Run a shell snippet (`sh -c`) and return (exit_code, stdout, stderr).
    pub fn shell_full(&self, cmd: &str) -> Result<(i32, String, String)> {
        self.run_program(&["sh".to_string(), "-c".to_string(), cmd.to_string()])
    }

    /// Run a shell snippet and return trimmed stdout.
    pub fn shell(&self, cmd: &str) -> Result<String> {
        let (_code, stdout, _stderr) = self.shell_full(cmd)?;
        Ok(stdout.trim().to_string())
    }

    /// Run a shell snippet and parse its stdout as a single JSON value (used for
    /// the external `idps-fw health`/`statistics` snapshots).
    pub fn shell_json(&self, cmd: &str) -> Result<Value> {
        let (_code, stdout, stderr) = self.shell_full(cmd)?;
        parse_json(&stdout).with_context(|| {
            format!(
                "`{cmd}` did not return JSON (stdout: {}, stderr: {})",
                stdout.trim(),
                stderr.trim()
            )
        })
    }

    /// Re-execute `fw-verify agent <args...>` on this side and parse its JSON.
    pub fn agent_json(&self, args: &[String]) -> Result<Value> {
        let argv = Self::agent_argv(args)?;
        let (_code, stdout, stderr) = self.run_program(&argv)?;
        parse_json(&stdout).with_context(|| {
            format!(
                "`agent {}` did not return JSON (stdout: {}, stderr: {})",
                args.join(" "),
                stdout.trim(),
                stderr.trim()
            )
        })
    }

    /// Start a background `fw-verify agent <args...>` worker (e.g. a listener).
    pub fn agent_spawn(&self, args: &[String]) -> Result<Child> {
        let argv = Self::agent_argv(args)?;
        self.spawn_program(&argv, true)
    }

    /// Detect the IPv4 bound to `iface` on this side.
    pub fn detect_ipv4(&self, iface: &str) -> Result<String> {
        let out = self.shell(&format!("ip -4 addr show dev {iface}"))?;
        parse_inet(&out)
            .with_context(|| format!("could not parse IPv4 for {iface} ({})", self.label()))
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
