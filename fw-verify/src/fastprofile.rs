//! Fast-profile management: short idps-fw intervals + identity overrides.
//!
//! Only `/etc/idd/idps-fw.yaml` is rewritten (the whole file is regenerated
//! from known defaults, so no field is dropped). The previous file is backed up
//! and restored if idps-fw fails to come back healthy. idps-server config is
//! left untouched; raise `rule.sync_interval_secs` manually if a live cloud is
//! pushing competing rules.

use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::adb;
use crate::config::RunConfig;
use crate::target;

const FW_CONFIG: &str = "/etc/idd/idps-fw.yaml";
const FW_BACKUP: &str = "/etc/idd/idps-fw.yaml.fwv-bak";
const REMOTE_TMP: &str = "/data/local/tmp/fw-verify-idps-fw.yaml";

fn fast_yaml(cfg: &RunConfig) -> String {
    let iface = &cfg.target_iface;
    format!(
        "runtime_config_path: /etc/idd/idps.yaml\n\
         state_dir: /data/idd/idps-fw\n\
         state_db_path: {db}\n\
         ebpf_object_path: /etc/idd/idps-fw.bpf.o\n\
         cgroup_path: /sys/fs/cgroup\n\
         tc_ingress_ifaces:\n  - {iface}\n\
         tc_egress_ifaces:\n  - {iface}\n\
         rule_poll_interval_secs: 3\n\
         initial_rule_timeout_secs: 10\n\
         event_poll_interval_ms: 100\n\
         identity_refresh_interval_secs: 10\n\
         report_flush_interval_ms: 500\n\
         report_ack_timeout_secs: 10\n\
         traffic_cycle_secs: 5\n\
         interface_categories:\n\
         \x20 - exact: {iface}\n    category: wifi\n\
         \x20 - prefix: rmnet\n    category: mobile\n\
         \x20 - prefix: ccmni\n    category: mobile\n\
         identity_overrides:\n\
         \x20 - identity_key: \"{key}\"\n\
         \x20\x20\x20 uid: {uid}\n\
         \x20\x20\x20 pkg_name: \"{pkg}\"\n\
         \x20\x20\x20 app_name: \"{name}\"\n",
        db = cfg.state_db,
        key = cfg.app_identity_key,
        uid = cfg.app_uid,
        pkg = cfg.app_pkg,
        name = cfg.app_name,
    )
}

fn restart(cfg: &RunConfig, service: &str) -> Result<()> {
    let _ = adb::shell(&cfg.target_serial, &format!("stop {service}"))?;
    sleep(Duration::from_millis(500));
    let _ = adb::shell(&cfg.target_serial, &format!("start {service}"))?;
    Ok(())
}

fn wait_healthy(cfg: &RunConfig) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(health) = target::health(cfg) {
            if health.get("connected").and_then(Value::as_bool) == Some(true) {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_secs(1));
    }
}

const DEFAULT_DEBUG_VIN: &str = "FWVERIFYTEST00001";
const DEFAULT_DEBUG_DSN: &str = "FWVERIFYTESTDSN01";

/// Ensure the TARGET has a runtime keystore so idps-server holds an AES key.
///
/// idps-core resolves device identity as `config > debug > provider`, reading
/// debug overrides from `/data/idd/<field>_debug`. On a bench device with no
/// provider VIN/DSN, idps-server never derives `aes.keystore`. We write
/// `/data/idd/vin_debug` + `/data/idd/dsn_debug` and restart idps-server, which
/// then derives and persists the keystore itself; fw-agent reads the same
/// identity, so both agree on one key. No-op when a keystore already exists.
pub fn ensure_keystore(cfg: &RunConfig, vin: Option<&str>, dsn: Option<&str>) -> Result<()> {
    adb::root(&cfg.target_serial)?;
    if keystore_present(cfg) {
        println!("keystore already present");
        return Ok(());
    }

    let vin = vin.unwrap_or(DEFAULT_DEBUG_VIN);
    let dsn = dsn.unwrap_or(DEFAULT_DEBUG_DSN);
    // chmod + restorecon so idps-server (uid system) can read the root-written
    // files and they carry the right SELinux label for /data/idd.
    adb::shell(
        &cfg.target_serial,
        &format!(
            "printf %s '{vin}' > /data/idd/vin_debug; chmod 644 /data/idd/vin_debug; \
             restorecon /data/idd/vin_debug 2>/dev/null"
        ),
    )
    .context("failed to write /data/idd/vin_debug")?;
    adb::shell(
        &cfg.target_serial,
        &format!(
            "printf %s '{dsn}' > /data/idd/dsn_debug; chmod 644 /data/idd/dsn_debug; \
             restorecon /data/idd/dsn_debug 2>/dev/null"
        ),
    )
    .context("failed to write /data/idd/dsn_debug")?;
    println!(
        "injected /data/idd/vin_debug + dsn_debug; restarting idps-server to derive the keystore"
    );
    restart(cfg, "idps-server")?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if keystore_present(cfg) {
            println!("keystore derived by idps-server");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "keystore still missing after injecting VIN/DSN and restarting idps-server; \
                 check that idps-server is running and /data/idd is writable"
            );
        }
        sleep(Duration::from_secs(1));
    }
}

fn keystore_present(cfg: &RunConfig) -> bool {
    adb::shell(
        &cfg.target_serial,
        "[ -e /data/idd/keys/aes.keystore ] && echo yes || echo no",
    )
    .map(|out| out.contains("yes"))
    .unwrap_or(false)
}

/// Apply the fast profile. Returns `true` if idps-fw came back healthy with it.
pub fn apply(cfg: &RunConfig) -> Result<()> {
    adb::root(&cfg.target_serial)?;
    ensure_keystore(cfg, None, None)?;
    let remounted = adb::remount(&cfg.target_serial).unwrap_or(false);
    if !remounted {
        eprintln!("warning: adb remount failed; /etc/idd may be read-only and the fast profile may not apply");
    }

    // Back up the original config once.
    let _ = adb::shell(
        &cfg.target_serial,
        &format!("[ -e {FW_BACKUP} ] || cp {FW_CONFIG} {FW_BACKUP}"),
    );

    let mut tmp = std::env::temp_dir();
    tmp.push("fw-verify-idps-fw.yaml");
    std::fs::write(&tmp, fast_yaml(cfg)).context("failed to write local fast config")?;
    adb::push(&cfg.target_serial, &tmp, REMOTE_TMP)?;
    let _ = adb::shell(&cfg.target_serial, &format!("cp {REMOTE_TMP} {FW_CONFIG}"))?;

    restart(cfg, "idps-fw")?;
    if wait_healthy(cfg) {
        println!("fast profile applied; idps-fw is healthy");
        Ok(())
    } else {
        eprintln!("idps-fw did not become healthy; restoring previous config");
        let _ = adb::shell(
            &cfg.target_serial,
            &format!("[ -e {FW_BACKUP} ] && cp {FW_BACKUP} {FW_CONFIG}"),
        );
        restart(cfg, "idps-fw")?;
        bail!("fast profile failed to apply (idps-fw unhealthy); restored previous config");
    }
}

/// Restore the backed-up idps-fw config and restart.
pub fn restore(cfg: &RunConfig) -> Result<()> {
    adb::root(&cfg.target_serial)?;
    let _ = adb::remount(&cfg.target_serial);
    let restored = adb::shell(
        &cfg.target_serial,
        &format!("[ -e {FW_BACKUP} ] && cp {FW_BACKUP} {FW_CONFIG} && echo restored"),
    )?;
    if !restored.contains("restored") {
        bail!("no fast-profile backup found at {FW_BACKUP}");
    }
    restart(cfg, "idps-fw")?;
    println!("restored idps-fw config from backup");
    Ok(())
}
