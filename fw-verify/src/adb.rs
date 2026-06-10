//! Thin wrapper around the `adb` CLI.
//!
//! The whole remote command is passed as a single argument to `adb shell`, so
//! the orchestrator controls quoting rather than relying on adb's argument
//! joining. Works the same on Linux and Windows controllers.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};

fn adb_bin() -> String {
    std::env::var("FWV_ADB").unwrap_or_else(|_| "adb".to_string())
}

/// Run a raw `adb -s <serial> <args...>` and return the process output.
pub fn raw(serial: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(adb_bin())
        .arg("-s")
        .arg(serial)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn adb -s {serial} {}", args.join(" ")))
}

/// Run `adb -s <serial> shell <remote_cmd>` and return (exit_code, stdout, stderr).
pub fn shell_full(serial: &str, remote_cmd: &str) -> Result<(i32, String, String)> {
    let output = raw(serial, &["shell", remote_cmd])?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// Run a remote shell command, returning trimmed stdout. adb's exit status is
/// not trusted (it is unreliable over TCP), so callers validate via stdout.
pub fn shell(serial: &str, remote_cmd: &str) -> Result<String> {
    let (_code, stdout, _stderr) = shell_full(serial, remote_cmd)?;
    Ok(stdout.trim().to_string())
}

/// Enable root and wait for the device to come back.
pub fn root(serial: &str) -> Result<()> {
    let _ = raw(serial, &["root"])?;
    let _ = raw(serial, &["wait-for-device"])?;
    Ok(())
}

/// Best-effort remount of the system partition read-write.
pub fn remount(serial: &str) -> Result<bool> {
    let output = raw(serial, &["remount"])?;
    Ok(output.status.success())
}

/// Return the device adb state (`device`, `offline`, ...).
pub fn get_state(serial: &str) -> Result<String> {
    let output = raw(serial, &["get-state"])?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Push a local file to the device.
pub fn push(serial: &str, local: &Path, remote: &str) -> Result<()> {
    let local_str = local.to_string_lossy();
    let output = raw(serial, &["push", &local_str, remote])?;
    if !output.status.success() {
        bail!(
            "adb push {} -> {remote} failed: {}",
            local_str,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Spawn a remote shell command in the background (e.g. a listener).
pub fn spawn_shell(serial: &str, remote_cmd: &str) -> Result<Child> {
    Command::new(adb_bin())
        .arg("-s")
        .arg(serial)
        .args(["shell", remote_cmd])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn background adb shell on {serial}"))
}

/// Detect the IPv4 address bound to `iface` on a device.
///
/// Parses `inet 172.20.10.3/24 ...` from `ip -4 addr show dev <iface>`.
pub fn detect_ipv4(serial: &str, iface: &str) -> Result<String> {
    let out = shell(serial, &format!("ip -4 addr show dev {iface}"))?;
    let addr = out
        .split_whitespace()
        .skip_while(|token| *token != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .filter(|addr| addr.parse::<std::net::Ipv4Addr>().is_ok());
    match addr {
        Some(addr) => Ok(addr.to_string()),
        None => bail!("could not parse an IPv4 address for {iface} on {serial}: {out}"),
    }
}
