//! VSOC dashboard API client for host-mode rule delivery.
//!
//! In host mode rules reach idps-fw the production way: fw-verify upserts the
//! firewall rule into VSOC, idps-server cloud-syncs it into its depot, and
//! idps-fw loads it. The dashboard API is HTTPS with mutual TLS, so we drive
//! the system `curl` (which also lets us bypass any localhost HTTP proxy) rather
//! than pull a TLS stack into this otherwise pure-Rust, Windows-cross-compiled
//! binary.

use std::process::Command;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::config::{RunConfig, VsocApi};

fn api(cfg: &RunConfig) -> Result<&VsocApi> {
    cfg.vsoc
        .as_ref()
        .context("VSOC API is not configured (host mode requires --vsoc-url)")
}

/// Common curl args: silent, fail on HTTP errors, never use a proxy for the
/// loopback dashboard, and present the client certificate when configured.
fn base_args(vsoc: &VsocApi) -> Vec<String> {
    let mut args = vec![
        "-sS".to_string(),
        "--noproxy".to_string(),
        "*".to_string(),
        "-k".to_string(),
        "--max-time".to_string(),
        "20".to_string(),
    ];
    if let Some(cert) = &vsoc.cert {
        args.push("--cert".to_string());
        args.push(cert.clone());
    }
    if let Some(key) = &vsoc.key {
        args.push("--key".to_string());
        args.push(key.clone());
    }
    if let Some(cacert) = &vsoc.cacert {
        args.push("--cacert".to_string());
        args.push(cacert.clone());
    }
    args
}

fn run_curl(args: &[String]) -> Result<String> {
    let output = Command::new("curl")
        .args(args)
        .output()
        .context("failed to spawn curl (host-mode VSOC client)")?;
    if !output.status.success() {
        bail!(
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Upsert a firewall (or traffic) rule's raw content. Returns the new `ver`.
pub fn upsert_rule(cfg: &RunConfig, fun: i32, content: &str) -> Result<i64> {
    let vsoc = api(cfg)?;
    let url = format!(
        "{}/api/rules/{}/{}",
        vsoc.base_url.trim_end_matches('/'),
        cfg.acd,
        fun
    );
    let body = serde_json::json!({ "content": content, "enabled": true }).to_string();
    let mut args = base_args(vsoc);
    args.extend(
        [
            "-X",
            "PUT",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &url,
        ]
        .map(str::to_string),
    );
    let stdout = run_curl(&args)?;
    let value: Value = serde_json::from_str(stdout.trim())
        .with_context(|| format!("VSOC upsert did not return JSON: {}", stdout.trim()))?;
    if let Some(detail) = value.get("detail").and_then(Value::as_str) {
        bail!("VSOC rejected rule (acd={} fun={fun}): {detail}", cfg.acd);
    }
    value
        .get("ver")
        .and_then(Value::as_i64)
        .context("VSOC upsert response missing ver")
}

/// Whether any stored VSOC event mentions `needle` (e.g. the device IP/VIN).
pub fn events_mention(cfg: &RunConfig, needle: &str) -> Result<bool> {
    let vsoc = api(cfg)?;
    let url = format!(
        "{}/api/events?limit=100",
        vsoc.base_url.trim_end_matches('/')
    );
    let mut args = base_args(vsoc);
    args.push(url);
    let stdout = run_curl(&args)?;
    Ok(stdout.contains(needle))
}
