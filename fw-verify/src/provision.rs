//! Rule provisioning.
//!
//! Android mode writes the encrypted depot directly via `fw-agent` and waits
//! for idps-fw to load it. Host mode delivers rules the production way: upsert
//! into VSOC, let idps-server cloud-sync them into its depot, and wait for
//! idps-fw to pick up the new version.

use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::cli::Mode;
use crate::config::RunConfig;
use crate::target;
use crate::vsoc;

const REMOTE_RULE_PATH: &str = "/data/local/tmp/fw-verify-rule.txt";
const DEFAULT_DEPOT: &str = "/data/idd/rule/depot";
const POLL: Duration = Duration::from_millis(1000);

fn push_text(cfg: &RunConfig, text: &str) -> Result<()> {
    let mut tmp = std::env::temp_dir();
    tmp.push("fw-verify-rule.txt");
    std::fs::write(&tmp, text).context("failed to write local rule file")?;
    cfg.target.push(&tmp, REMOTE_RULE_PATH)
}

/// Provision the firewall rule set (fun=fw) and block until idps-fw loads it.
pub fn provision_firewall(cfg: &RunConfig, rule_text: &str) -> Result<i64> {
    match cfg.mode {
        Mode::Android => provision_firewall_android(cfg, rule_text),
        Mode::Host => provision_firewall_host(cfg, rule_text),
    }
}

/// Android: encrypt into the depot via fw-agent, then wait for the load.
///
/// The version is forced to `current + 1` so `firewall_rule_ver` strictly
/// increases even when a higher-versioned rule was loaded before.
fn provision_firewall_android(cfg: &RunConfig, rule_text: &str) -> Result<i64> {
    let before = target::firewall_rule_ver(cfg).unwrap_or(-1);
    let target_ver = before.max(0) + 1;
    push_text(cfg, rule_text)?;
    let cmd = format!(
        "{} provision-rule --acd {} --fun {} --ver {target_ver} --input {REMOTE_RULE_PATH}",
        cfg.fw_agent, cfg.acd, cfg.fun_fw
    );
    let out = cfg
        .target
        .shell_json(&cmd)
        .context("fw-agent provision-rule (firewall) failed")?;
    require_key_present(&out)?;
    wait_for(cfg, "firewall_rule_ver", target_ver)?;
    Ok(target_ver)
}

/// Host: upsert into VSOC and wait for the cloud-synced version to arrive.
fn provision_firewall_host(cfg: &RunConfig, rule_text: &str) -> Result<i64> {
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
    push_text(cfg, &format!("{{\"cycle\":{cycle}}}"))?;
    let cmd = format!(
        "{} provision-rule --acd {} --fun {} --ver {target_ver} --input {REMOTE_RULE_PATH}",
        cfg.fw_agent, cfg.acd, cfg.fun_traffic
    );
    let out = cfg
        .target
        .shell_json(&cmd)
        .context("fw-agent provision-rule (traffic) failed")?;
    require_key_present(&out)
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
    let deadline = Instant::now() + cfg.reload_timeout;
    loop {
        if let Ok(health) = target::health(cfg) {
            if health.get(field).and_then(Value::as_i64).unwrap_or(-1) >= expected {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for idps-fw {field} >= {expected}");
        }
        sleep(POLL);
    }
}

fn wait_for_cycle(cfg: &RunConfig, cycle: u64) -> Result<()> {
    let deadline = Instant::now() + cfg.reload_timeout;
    loop {
        if let Ok(health) = target::health(cfg) {
            if health
                .get("traffic_cycle_secs")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                == cycle
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for idps-fw traffic_cycle_secs == {cycle}");
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
            let _ = cfg.target.shell(&format!("rm -f {REMOTE_RULE_PATH}"));
            Ok(())
        }
        Mode::Host => {
            vsoc::upsert_rule(cfg, cfg.fun_fw, "chain=localin,action=P\n")?;
            Ok(())
        }
    }
}
