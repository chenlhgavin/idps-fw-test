//! In-process worker reused by the orchestrator.
//!
//! The same code runs two ways. TARGET-side, read-only-ish work (rule
//! provisioning, event/report queries, the clock watermark) is called directly
//! as a library function from the orchestrator process. Work that must run in
//! the PEER network namespace, in the background, or under a dropped uid is
//! re-executed as `fw-verify agent <sub>` and its single JSON line is parsed
//! back. `dispatch` is the entry point for the re-executed `agent` subcommand;
//! it prints the JSON the orchestrator's pipe reader expects.

pub mod arp;
pub mod cli;
pub mod connflood;
pub mod events;
pub mod listen;
pub mod provision;
pub mod traffic;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use serde_json::json;

use crate::agent::cli::AgentCommand;

/// Dispatch a re-executed `fw-verify agent <sub>` invocation.
pub fn dispatch(command: AgentCommand) -> Result<()> {
    match command {
        AgentCommand::ProvisionRule(args) => provision::run(&args),
        AgentCommand::DumpEvents(args) => events::dump_events(&args),
        AgentCommand::ReportStatus(args) => events::report_status(&args),
        AgentCommand::DumpReports(args) => events::dump_reports(&args),
        AgentCommand::Traffic(args) => traffic::run(&args),
        AgentCommand::Listen(args) => listen::run(&args),
        AgentCommand::ConnFlood(args) => connflood::run(&args),
        AgentCommand::ArpSpoof(args) => arp::run(&args),
        AgentCommand::Now => {
            println!("{}", json!({ "now_ms": now_ms() }));
            Ok(())
        }
    }
}

/// Device wall clock in epoch milliseconds, matching idps-fw's own `now_ms`
/// source so the orchestrator can scope per-case `firewall_event` rows.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Drop the process to `uid` (gid set to the same value, supplementary groups
/// cleared) before generating traffic. Mirrors the old host `setpriv
/// --clear-groups --reuid --regid` so the eBPF cgroup connect-hook attributes
/// the socket to the mapped app uid on both host and Android.
pub fn drop_to_uid(uid: u32) -> Result<()> {
    // SAFETY: standard credential-dropping syscalls in order (groups, gid,
    // uid); each return code is checked and any failure aborts before work.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            bail!("setgroups failed: {}", std::io::Error::last_os_error());
        }
        if libc::setgid(uid as libc::gid_t) != 0 {
            bail!("setgid({uid}) failed: {}", std::io::Error::last_os_error());
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            bail!("setuid({uid}) failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}
