//! Rule provisioning.
//!
//! Android mode writes the encrypted depot directly (reusing idps-server's
//! `RuleDepot`) and waits for idps-fw to load it. Host mode delivers rules the
//! production way: upsert into VSOC, let idps-server cloud-sync them into its
//! depot, and wait for idps-fw to pick up the new version.

use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::agent::provision::{provision_rule, DEFAULT_CONFIG, DEFAULT_KEYSTORE};
use crate::cli::Mode;
use crate::config::RunConfig;
use crate::target;
use crate::vsoc;

const DEFAULT_DEPOT: &str = "/data/idd/rule/depot";
const POLL: Duration = Duration::from_millis(1000);
const WAIT_LOG_INTERVAL: Duration = Duration::from_secs(5);

/// Encrypt a rule into the depot in-process (Android mode, on the TARGET).
fn write_depot_rule(cfg: &RunConfig, fun: i32, ver: i64, rule_text: &str) -> Result<()> {
    let out = provision_rule(
        cfg.acd,
        fun,
        1,
        Some(ver as i32),
        rule_text.as_bytes(),
        Path::new(DEFAULT_CONFIG),
        Path::new(DEFAULT_KEYSTORE),
    )
    .context("failed to write depot rule")?;
    require_key_present(&out)
}

/// Provision the firewall rule set (fun=fw) and block until idps-fw loads it.
pub fn provision_firewall(cfg: &RunConfig, rule_text: &str) -> Result<i64> {
    match cfg.mode {
        Mode::Android => provision_firewall_android(cfg, rule_text),
        Mode::Host => provision_firewall_host(cfg, rule_text),
    }
}

/// Android: encrypt into the depot in-process, then wait for the load.
///
/// The version is forced to `current + 1` so `firewall_rule_ver` strictly
/// increases even when a higher-versioned rule was loaded before.
fn provision_firewall_android(cfg: &RunConfig, rule_text: &str) -> Result<i64> {
    let before = target::firewall_rule_ver(cfg).unwrap_or(-1);
    let target_ver = before.max(0) + 1;
    eprintln!("fw-verify: provisioning firewall rule into the depot (target_ver={target_ver})");
    write_depot_rule(cfg, cfg.fun_fw, target_ver, rule_text)?;
    wait_for(cfg, "firewall_rule_ver", target_ver)?;
    Ok(target_ver)
}

/// Host: upsert into VSOC and wait for the cloud-synced version to arrive.
fn provision_firewall_host(cfg: &RunConfig, rule_text: &str) -> Result<i64> {
    eprintln!("fw-verify: uploading firewall rule to VSOC");
    let ver = vsoc::upsert_rule(cfg, cfg.fun_fw, rule_text)?;
    wait_for(cfg, "firewall_rule_ver", ver)?;
    Ok(ver)
}

/// Write the traffic policy (fun=traffic) depot rule without waiting.
///
/// idps-fw blocks in `RuleSyncing` until it has both a fun=1 and a fun=4 rule,
/// so a fun=4 must exist before any fun=1 provision can be confirmed loaded.
pub fn write_traffic_rule(cfg: &RunConfig, cycle: u64) -> Result<()> {
    match cfg.mode {
        Mode::Android => write_traffic_rule_android(cfg, cycle),
        Mode::Host => {
            eprintln!("fw-verify: uploading traffic policy to VSOC (cycle={cycle}s)");
            vsoc::upsert_rule(cfg, cfg.fun_traffic, &format!("{{\"cycle\":{cycle}}}"))?;
            Ok(())
        }
    }
}

fn write_traffic_rule_android(cfg: &RunConfig, cycle: u64) -> Result<()> {
    let before = target::health(cfg)
        .ok()
        .and_then(|health| health.get("traffic_rule_ver").and_then(Value::as_i64))
        .unwrap_or(-1);
    let target_ver = before.max(0) + 1;
    eprintln!(
        "fw-verify: provisioning traffic policy into the depot (cycle={cycle}s target_ver={target_ver})"
    );
    write_depot_rule(
        cfg,
        cfg.fun_traffic,
        target_ver,
        &format!("{{\"cycle\":{cycle}}}"),
    )
}

/// Provision the traffic policy (fun=traffic) cycle and wait for it to load.
pub fn provision_traffic_cycle(cfg: &RunConfig, cycle: u64) -> Result<()> {
    write_traffic_rule(cfg, cycle)?;
    wait_for_cycle(cfg, cycle)
}

fn require_key_present(out: &Value) -> Result<()> {
    if out.get("key_present").and_then(Value::as_bool) == Some(false) {
        bail!(
            "fw-agent could not derive the runtime AES key (no keystore / VIN+DSN); \
             is idps-server initialized on the target?"
        );
    }
    Ok(())
}

fn wait_for(cfg: &RunConfig, field: &str, expected: i64) -> Result<()> {
    let start = Instant::now();
    let deadline = Instant::now() + cfg.reload_timeout;
    let mut next_log = start + WAIT_LOG_INTERVAL;
    let mut observed = None;
    eprintln!(
        "fw-verify: waiting for idps-fw {field} >= {expected} (timeout={}s)",
        cfg.reload_timeout.as_secs()
    );
    loop {
        if let Ok(health) = target::health(cfg) {
            observed = health.get(field).and_then(Value::as_i64);
            if observed.unwrap_or(-1) >= expected {
                eprintln!(
                    "fw-verify: idps-fw {field} reached {} after {}s",
                    observed.unwrap_or(-1),
                    start.elapsed().as_secs()
                );
                return Ok(());
            }
        }
        let now = Instant::now();
        if now >= deadline {
            bail!("timed out waiting for idps-fw {field} >= {expected}");
        }
        if now >= next_log {
            eprintln!(
                "fw-verify: still waiting for idps-fw {field} >= {expected} (observed={}, elapsed={}s, remaining={}s)",
                observed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unavailable".to_string()),
                start.elapsed().as_secs(),
                deadline.saturating_duration_since(now).as_secs()
            );
            next_log = now + WAIT_LOG_INTERVAL;
        }
        sleep(POLL);
    }
}

fn wait_for_cycle(cfg: &RunConfig, cycle: u64) -> Result<()> {
    let start = Instant::now();
    let deadline = Instant::now() + cfg.reload_timeout;
    let mut next_log = start + WAIT_LOG_INTERVAL;
    let mut observed = None;
    eprintln!(
        "fw-verify: waiting for idps-fw traffic_cycle_secs == {cycle} (timeout={}s)",
        cfg.reload_timeout.as_secs()
    );
    loop {
        if let Ok(health) = target::health(cfg) {
            observed = health.get("traffic_cycle_secs").and_then(Value::as_u64);
            if observed.unwrap_or(0) == cycle {
                eprintln!(
                    "fw-verify: idps-fw traffic_cycle_secs reached {} after {}s",
                    observed.unwrap_or(0),
                    start.elapsed().as_secs()
                );
                return Ok(());
            }
        }
        let now = Instant::now();
        if now >= deadline {
            bail!("timed out waiting for idps-fw traffic_cycle_secs == {cycle}");
        }
        if now >= next_log {
            eprintln!(
                "fw-verify: still waiting for idps-fw traffic_cycle_secs == {cycle} (observed={}, elapsed={}s, remaining={}s)",
                observed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unavailable".to_string()),
                start.elapsed().as_secs(),
                deadline.saturating_duration_since(now).as_secs()
            );
            next_log = now + WAIT_LOG_INTERVAL;
        }
        sleep(POLL);
    }
}

/// Restore rules to a permissive baseline.
///
/// Android removes provisioned depot files so idps-server falls back to
/// defaults; host upserts an allow-all firewall rule through VSOC.
pub fn reset_rules(cfg: &RunConfig) -> Result<()> {
    match cfg.mode {
        Mode::Android => {
            let pattern = format!("{DEFAULT_DEPOT}/{}-{}-*.rule*", cfg.acd, cfg.fun_fw);
            let pattern_traffic =
                format!("{DEFAULT_DEPOT}/{}-{}-*.rule*", cfg.acd, cfg.fun_traffic);
            let _ = cfg
                .target
                .shell(&format!("rm -f {pattern} {pattern_traffic}"))?;
            Ok(())
        }
        Mode::Host => {
            vsoc::upsert_rule(cfg, cfg.fun_fw, "chain=localin,action=P\n")?;
            Ok(())
        }
    }
}
