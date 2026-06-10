//! `fw-verify` — host-side orchestrator for idps-fw two-device WiFi tests.
//!
//! Runs on a controller PC (including Windows), drives both Android phones over
//! adb and the on-device `fw-agent`, provisions firewall rules into the depot,
//! and asserts enforcement, detection, and upload to idps-server.

mod adb;
mod catalog;
mod cli;
mod config;
mod fastprofile;
mod peer;
mod provision;
mod report;
mod target;
mod verify;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::catalog::{all_cases, Group};
use crate::cli::{Cli, Command};
use crate::config::RunConfig;

fn main() -> ExitCode {
    apply_config_env();
    let cli = Cli::parse();
    match run(cli) {
        Ok(failures) if failures > 0 => ExitCode::FAILURE,
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fw-verify error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Map a config-file key to its `FWV_*` environment variable.
fn config_key_to_env(key: &str) -> Option<&'static str> {
    Some(match key {
        "target_serial" | "target" => "FWV_TARGET",
        "peer_serial" | "peer" => "FWV_PEER",
        "target_iface" => "FWV_TARGET_IFACE",
        "peer_iface" => "FWV_PEER_IFACE",
        "target_ip" => "FWV_TARGET_IP",
        "peer_ip" => "FWV_PEER_IP",
        "acd" => "FWV_ACD",
        "fun_fw" => "FWV_FUN_FW",
        "fun_traffic" => "FWV_FUN_TRAFFIC",
        "reload_timeout_secs" => "FWV_RELOAD_TIMEOUT_SECS",
        "event_settle_ms" => "FWV_EVENT_SETTLE_MS",
        "report_confirm" => "FWV_REPORT_CONFIRM",
        "vsoc_url" => "FWV_VSOC_URL",
        "fw_agent" => "FWV_FW_AGENT",
        "idps_fw" => "FWV_IDPS_FW",
        "state_db" => "FWV_STATE_DB",
        "app_uid" => "FWV_APP_UID",
        "app_identity_key" => "FWV_APP_IDENTITY_KEY",
        "app_pkg" => "FWV_APP_PKG",
        "app_name" => "FWV_APP_NAME",
        _ => return None,
    })
}

/// Load a `--config <file>` (lines of `key = value`, `#` comments) into the
/// `FWV_*` environment variables so the clap layer applies them as defaults.
/// Real environment variables already set take precedence over the file.
fn apply_config_env() {
    let args: Vec<String> = std::env::args().collect();
    let mut path: Option<String> = None;
    for (index, arg) in args.iter().enumerate() {
        if arg == "--config" {
            path = args.get(index + 1).cloned();
        } else if let Some(rest) = arg.strip_prefix("--config=") {
            path = Some(rest.to_string());
        }
    }
    let Some(path) = path else {
        return;
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) => {
            eprintln!("fw-verify: cannot read config {path}: {error}");
            return;
        }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"');
        if let Some(env) = config_key_to_env(&key) {
            if std::env::var_os(env).is_none() {
                std::env::set_var(env, value);
            }
        }
    }
}

/// Returns the number of failed cases (0 for non-run subcommands).
fn run(cli: Cli) -> Result<usize> {
    match cli.command {
        Command::List => {
            list();
            Ok(0)
        }
        Command::Preflight => {
            let cfg = RunConfig::resolve(&cli.global)?;
            preflight(&cfg)?;
            Ok(0)
        }
        Command::ApplyFastProfile => {
            let cfg = RunConfig::resolve(&cli.global)?;
            fastprofile::apply(&cfg)?;
            Ok(0)
        }
        Command::RestoreProfile => {
            let cfg = RunConfig::resolve(&cli.global)?;
            fastprofile::restore(&cfg)?;
            Ok(0)
        }
        Command::EnsureKeystore { vin, dsn } => {
            let cfg = RunConfig::resolve(&cli.global)?;
            fastprofile::ensure_keystore(&cfg, vin.as_deref(), dsn.as_deref())?;
            Ok(0)
        }
        Command::Health => {
            let cfg = RunConfig::resolve(&cli.global)?;
            println!("{}", serde_json::to_string_pretty(&target::health(&cfg)?)?);
            Ok(0)
        }
        Command::Stats => {
            let cfg = RunConfig::resolve(&cli.global)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&target::statistics(&cfg)?)?
            );
            Ok(0)
        }
        Command::Provision {
            rules_file,
            traffic_cycle,
        } => {
            let cfg = RunConfig::resolve(&cli.global)?;
            let text = std::fs::read_to_string(&rules_file)
                .with_context(|| format!("failed to read {}", rules_file.display()))?;
            let ver = provision::provision_firewall(&cfg, &text)?;
            println!("provisioned firewall rule version {ver}");
            if let Some(cycle) = traffic_cycle {
                provision::provision_traffic_cycle(&cfg, cycle)?;
                println!("provisioned traffic cycle {cycle}s");
            }
            Ok(0)
        }
        Command::ResetRules => {
            let cfg = RunConfig::resolve(&cli.global)?;
            provision::reset_rules(&cfg)?;
            println!("removed provisioned depot rules");
            Ok(0)
        }
        Command::Run { id } => {
            let cfg = RunConfig::resolve(&cli.global)?;
            let results = verify::run_one(&cfg, &id);
            report::emit(&cli.global, &cfg, &results)
        }
        Command::RunGroup { group } => {
            let cfg = RunConfig::resolve(&cli.global)?;
            let group = Group::parse(&group)?;
            let results = verify::run_group(&cfg, group);
            report::emit(&cli.global, &cfg, &results)
        }
        Command::RunAll => {
            let cfg = RunConfig::resolve(&cli.global)?;
            let results = verify::run_all(&cfg);
            report::emit(&cli.global, &cfg, &results)
        }
    }
}

fn list() {
    println!(
        "{:<26} {:<9} {:<14} {:<8} EVENT",
        "CASE", "GROUP", "BUNDLE", "ENFORCE"
    );
    println!("{}", "-".repeat(80));
    for case in all_cases() {
        let enforce = match case.expect_enforce {
            catalog::Enforce::Blocked => "blocked",
            catalog::Enforce::Allowed => "allowed",
            catalog::Enforce::Sent => "sent",
        };
        let event = case.expect_event.as_ref().map_or_else(
            || "none".to_string(),
            |e| format!("{}/{}", e.kind, e.action),
        );
        println!(
            "{:<26} {:<9} {:<14} {:<8} {}",
            case.id,
            case.group.as_str(),
            format!("{:?}", case.bundle).to_lowercase(),
            enforce,
            event
        );
    }
}

fn preflight(cfg: &RunConfig) -> Result<()> {
    let mut checks: Vec<(String, bool, String)> = Vec::new();

    for (role, serial) in [("target", &cfg.target_serial), ("peer", &cfg.peer_serial)] {
        let _ = adb::root(serial);
        let state = adb::get_state(serial).unwrap_or_else(|_| "unknown".to_string());
        checks.push((format!("{role} adb state"), state == "device", state));
        let now = adb::shell_json(serial, &format!("{} now", cfg.fw_agent));
        let info = match &now {
            Ok(_) => "responds".to_string(),
            Err(error) => format!("{error:#}"),
        };
        checks.push((format!("{role} fw-agent"), now.is_ok(), info));
    }

    let health = target::health(cfg);
    let health_info = match &health {
        Ok(h) => format!(
            "phase={}",
            h.get("phase").and_then(|p| p.as_str()).unwrap_or("?")
        ),
        Err(error) => format!("{error:#}"),
    };
    checks.push(("idps-fw health".to_string(), health.is_ok(), health_info));

    let depot = adb::shell(
        &cfg.target_serial,
        "[ -d /data/idd/rule/depot ] && echo yes || echo no",
    )
    .unwrap_or_default();
    checks.push(("target depot dir".to_string(), depot.contains("yes"), depot));

    let mut all_ok = true;
    for (label, pass, info) in &checks {
        println!("[{}] {label}: {info}", if *pass { "ok" } else { "FAIL" });
        all_ok &= *pass;
    }

    // Keystore is advisory: `ensure-keystore` / `apply-fast-profile` can create it.
    let keystore = adb::shell(
        &cfg.target_serial,
        "[ -e /data/idd/keys/aes.keystore ] && echo yes || echo no",
    )
    .unwrap_or_default();
    if keystore.contains("yes") {
        println!("[ok] target keystore: yes");
    } else {
        println!(
            "[warn] target keystore: missing — run `fw-verify ensure-keystore` (or apply-fast-profile) to create it"
        );
    }
    println!(
        "\nTARGET={} ({})  PEER={} ({})",
        cfg.target_serial, cfg.target_ip, cfg.peer_serial, cfg.peer_ip
    );
    if all_ok {
        Ok(())
    } else {
        anyhow::bail!("preflight checks failed");
    }
}
