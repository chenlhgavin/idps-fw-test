//! `fw-agent` — on-device worker for idps-fw functional tests.
//!
//! Pushed to both Android phones by the `fw-verify` orchestrator and invoked
//! over `adb shell`. It writes encrypted rule depot files (reusing
//! idps-server's `RuleDepot` and the same VIN/DSN keystore derivation),
//! generates OS-socket traffic, and reads the idps-fw SQLite state. Each
//! subcommand emits a single JSON object on stdout.

mod cli;
mod events;
mod listen;
mod provision;
mod traffic;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("fw-agent error: {error:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ProvisionRule(args) => provision::run(&args),
        Command::DumpEvents(args) => events::dump_events(&args),
        Command::ReportStatus(args) => events::report_status(&args),
        Command::Traffic(args) => traffic::run(&args),
        Command::Listen(args) => listen::run(&args),
        Command::Now => now(),
    }
}

/// Print the device wall clock in epoch milliseconds, matching idps-fw's own
/// `now_ms` source so the orchestrator can scope per-case `firewall_event` rows.
fn now() -> Result<()> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    println!("{}", serde_json::json!({ "now_ms": now_ms }));
    Ok(())
}
