//! `setup-env` / `clean-env` — stage the test environment on the device.
//!
//! Both host and Android run a single device: a veth pair whose peer end is
//! parked in a network namespace so target↔peer traffic crosses the
//! idps-fw–monitored interface. This module owns the topology (created with
//! `ip netns`/`ip link`, mirroring idps-test/nidps-verify's create-then-move
//! fallback), the idps-fw config tuned for fast tests, and the generated
//! `fw-verify.conf`. On Android it also injects a debug VIN/DSN so idps-server
//! derives a keystore, then restarts the daemons so the config takes effect.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::cli::{GlobalArgs, Mode};

const IDD_ETC: &str = "/etc/idd";
const FW_CONFIG: &str = "/etc/idd/idps-fw.yaml";
const FW_BACKUP: &str = "/etc/idd/idps-fw.yaml.fwv-bak";
const FWV_CONF: &str = "/etc/idd/fw-verify.conf";
const KEYSTORE: &str = "/data/idd/keys/aes.keystore";

const DEFAULT_TARGET_IP: Ipv4Addr = Ipv4Addr::new(10, 123, 0, 1);
const DEFAULT_PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 123, 0, 2);

const DEFAULT_DEBUG_VIN: &str = "FWVERIFYTEST00001";
const DEFAULT_DEBUG_DSN: &str = "FWVERIFYTESTDSN01";

/// Resolved topology parameters for a setup/clean run.
struct Topology {
    netns: String,
    target_iface: String,
    peer_iface: String,
    target_ip: IpAddr,
    peer_ip: IpAddr,
    prefix: u8,
}

impl Topology {
    fn from(global: &GlobalArgs) -> Self {
        Self {
            netns: global.peer_netns.clone(),
            target_iface: global.target_iface.clone(),
            peer_iface: global.peer_iface.clone(),
            target_ip: global.target_ip.unwrap_or(IpAddr::V4(DEFAULT_TARGET_IP)),
            peer_ip: global.peer_ip.unwrap_or(IpAddr::V4(DEFAULT_PEER_IP)),
            prefix: global.veth_prefix,
        }
    }
}

/// Stage the topology, write the idps-fw + fw-verify configs, and (on Android)
/// derive the keystore and restart the daemons.
pub fn setup(global: &GlobalArgs) -> Result<()> {
    let topo = Topology::from(global);
    println!(
        "fw-verify: setting up {:?}-mode test environment",
        global.mode
    );

    teardown_topology(&topo);
    create_topology(&topo)?;
    println!(
        "  topology: {}({}) <-> netns {}:{}({})",
        topo.target_iface, topo.target_ip, topo.netns, topo.peer_iface, topo.peer_ip
    );

    std::fs::create_dir_all(IDD_ETC)
        .with_context(|| format!("failed to create {IDD_ETC} (is the partition writable?)"))?;
    backup_fw_config()?;
    write_fw_config(global, &topo)?;
    println!(
        "  idps-fw config: {FW_CONFIG} (monitors {})",
        topo.target_iface
    );
    write_fwv_conf(global, &topo)?;
    println!("  fw-verify config: {FWV_CONF}");

    match global.mode {
        Mode::Android => {
            ensure_keystore_android(global)?;
            restart_service(global.mode, "idps-fw")?;
            if wait_healthy(global) {
                println!("  idps-fw restarted and healthy");
            } else {
                eprintln!("  idps-fw did not become healthy; restoring previous config");
                restore_fw_config();
                let _ = restart_service(global.mode, "idps-fw");
                bail!(
                    "idps-fw unhealthy after applying the fast config; restored the previous one"
                );
            }
        }
        Mode::Host => {
            println!("  next: (re)start idps-fw to apply this config, then: fw-verify --config {FWV_CONF} run-all");
        }
    }
    Ok(())
}

/// Tear down the topology, restore the idps-fw config, remove fw-verify.conf.
pub fn clean(global: &GlobalArgs) -> Result<()> {
    let topo = Topology::from(global);
    teardown_topology(&topo);
    let restored = restore_fw_config();
    if restored && global.mode == Mode::Android {
        let _ = restart_service(global.mode, "idps-fw");
    }
    let _ = std::fs::remove_file(FWV_CONF);
    println!(
        "fw-verify: removed netns {}, veth {}, {FWV_CONF}{}",
        topo.netns,
        topo.target_iface,
        if restored {
            "; restored idps-fw config"
        } else {
            ""
        }
    );
    Ok(())
}

// --- topology ---------------------------------------------------------------

fn teardown_topology(topo: &Topology) {
    // Deleting either veth end removes the pair; deleting the netns is idempotent.
    ignore_ip(&["netns", "del", &topo.netns]);
    ignore_ip(&["link", "del", &topo.target_iface]);
}

fn create_topology(topo: &Topology) -> Result<()> {
    run_ip(&["netns", "add", &topo.netns])?;
    create_veth(topo)?;
    run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", topo.target_ip, topo.prefix),
        "dev",
        &topo.target_iface,
    ])?;
    run_ip(&["link", "set", &topo.target_iface, "up"])?;
    run_ip_netns(&topo.netns, &["link", "set", "lo", "up"])?;
    run_ip_netns(
        &topo.netns,
        &[
            "addr",
            "add",
            &format!("{}/{}", topo.peer_ip, topo.prefix),
            "dev",
            &topo.peer_iface,
        ],
    )?;
    run_ip_netns(&topo.netns, &["link", "set", &topo.peer_iface, "up"])?;
    Ok(())
}

/// Create the veth pair with the peer end in the namespace, falling back to
/// create-in-root-then-move when direct namespace placement is unsupported.
fn create_veth(topo: &Topology) -> Result<()> {
    let direct = run_ip(&[
        "link",
        "add",
        &topo.target_iface,
        "type",
        "veth",
        "peer",
        "name",
        &topo.peer_iface,
        "netns",
        &topo.netns,
    ]);
    if direct.is_ok() {
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &topo.target_iface,
        "type",
        "veth",
        "peer",
        "name",
        &topo.peer_iface,
    ])
    .context("failed to create veth pair")?;
    run_ip(&["link", "set", &topo.peer_iface, "netns", &topo.netns])
        .context("failed to move peer veth into the namespace")
}

fn run_ip(args: &[&str]) -> Result<()> {
    run("ip", args)
}

fn run_ip_netns(netns: &str, args: &[&str]) -> Result<()> {
    let mut full = vec!["netns", "exec", netns, "ip"];
    full.extend_from_slice(args);
    run("ip", &full)
}

fn ignore_ip(args: &[&str]) {
    let _ = Command::new("ip").args(args).output();
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn `{program} {}`", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

// --- idps-fw config ---------------------------------------------------------

fn backup_fw_config() -> Result<()> {
    if Path::new(FW_CONFIG).exists() && !Path::new(FW_BACKUP).exists() {
        std::fs::copy(FW_CONFIG, FW_BACKUP)
            .with_context(|| format!("failed to back up {FW_CONFIG}"))?;
    }
    Ok(())
}

fn restore_fw_config() -> bool {
    if Path::new(FW_BACKUP).exists() && std::fs::copy(FW_BACKUP, FW_CONFIG).is_ok() {
        let _ = std::fs::remove_file(FW_BACKUP);
        return true;
    }
    false
}

/// idps-fw config tuned for fast tests: monitor the target veth on both
/// directions, short poll intervals, and the app-uid identity override. The
/// whole file is regenerated from known defaults so no field is silently kept.
fn write_fw_config(global: &GlobalArgs, topo: &Topology) -> Result<()> {
    let iface = &topo.target_iface;
    let body = format!(
        "runtime_config_path: /etc/idd/idps.yaml\n\
         state_dir: /data/idd/idps-fw\n\
         state_db_path: {db}\n\
         ebpf_object_path: /etc/idd/idps-fw.bpf.o\n\
         cgroup_path: /sys/fs/cgroup\n\
         tc_ingress_ifaces:\n  - {iface}\n\
         tc_egress_ifaces:\n  - {iface}\n\
         rule_poll_interval_secs: 3\n\
         initial_rule_timeout_secs: 30\n\
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
        db = global.state_db,
        key = global.app_identity_key,
        uid = global.app_uid,
        pkg = global.app_pkg,
        name = global.app_name,
    );
    std::fs::write(FW_CONFIG, body)
        .with_context(|| format!("failed to write {FW_CONFIG} (is the partition writable?)"))
}

// --- fw-verify.conf ---------------------------------------------------------

fn write_fwv_conf(global: &GlobalArgs, topo: &Topology) -> Result<()> {
    let mode = format!("{:?}", global.mode).to_lowercase();
    let mut body = format!(
        "# fw-verify config (generated by `fw-verify setup-env`).\n\
         mode = {mode}\n\
         target_iface = {tif}\n\
         peer_iface = {pif}\n\
         peer_netns = {ns}\n\
         target_ip = {tip}\n\
         peer_ip = {pip}\n\
         idps_fw = {idps_fw}\n\
         state_db = {db}\n\
         app_uid = {uid}\n\
         app_identity_key = {key}\n\
         app_pkg = {pkg}\n\
         app_name = {name}\n",
        tif = topo.target_iface,
        pif = topo.peer_iface,
        ns = topo.netns,
        tip = topo.target_ip,
        pip = topo.peer_ip,
        idps_fw = global.idps_fw,
        db = global.state_db,
        uid = global.app_uid,
        key = global.app_identity_key,
        pkg = global.app_pkg,
        name = global.app_name,
    );
    if global.mode == Mode::Host {
        let url = global
            .vsoc_url
            .clone()
            .unwrap_or_else(|| "https://127.0.0.1:8443".to_string());
        body.push_str(&format!("vsoc_url = {url}\n"));
        match (&global.vsoc_cert, &global.vsoc_key) {
            (Some(cert), Some(key)) => {
                body.push_str(&format!("vsoc_cert = {cert}\nvsoc_key = {key}\n"));
                if let Some(cacert) = &global.vsoc_cacert {
                    body.push_str(&format!("vsoc_cacert = {cacert}\n"));
                }
            }
            _ => body.push_str(
                "# set vsoc_cert/vsoc_key to the VSOC mTLS client certificate before running\n",
            ),
        }
    }
    std::fs::write(FWV_CONF, body).with_context(|| format!("failed to write {FWV_CONF}"))
}

// --- Android keystore + service control -------------------------------------

/// Ensure the TARGET has a runtime keystore so idps-server holds an AES key.
///
/// idps-core resolves device identity as `config > debug > provider`, reading
/// debug overrides from `/data/idd/<field>_debug`. On a bench device with no
/// provider VIN/DSN, idps-server never derives the keystore. We write the debug
/// files and restart idps-server, which then derives and persists the keystore;
/// fw-verify's depot writes read the same identity, so both agree on one key.
fn ensure_keystore_android(global: &GlobalArgs) -> Result<()> {
    if Path::new(KEYSTORE).exists() {
        println!("  keystore already present");
        return Ok(());
    }
    write_debug_id("vin_debug", DEFAULT_DEBUG_VIN)?;
    write_debug_id("dsn_debug", DEFAULT_DEBUG_DSN)?;
    println!(
        "  injected /data/idd/vin_debug + dsn_debug; restarting idps-server to derive the keystore"
    );
    restart_service(global.mode, "idps-server")?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Path::new(KEYSTORE).exists() {
            println!("  keystore derived by idps-server");
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

fn write_debug_id(name: &str, value: &str) -> Result<()> {
    let path = format!("/data/idd/{name}");
    std::fs::write(&path, value).with_context(|| format!("failed to write {path}"))?;
    // chmod 644 + restorecon so idps-server (uid system) can read the file with
    // the right SELinux label for /data/idd.
    let _ = run("chmod", &["644", &path]);
    let _ = Command::new("restorecon").arg(&path).output();
    Ok(())
}

/// Restart a daemon: Android init `stop`/`start`, host `systemctl try-restart`.
fn restart_service(mode: Mode, service: &str) -> Result<()> {
    match mode {
        Mode::Android => {
            let _ = Command::new("stop").arg(service).output();
            sleep(Duration::from_millis(500));
            Command::new("start")
                .arg(service)
                .output()
                .with_context(|| format!("failed to start {service}"))?;
            Ok(())
        }
        Mode::Host => {
            // Best-effort: deployments that manage idps-fw via systemd pick the
            // new config up; otherwise the operator restarts it manually.
            let status = Command::new("systemctl")
                .args(["try-restart", service])
                .status();
            if !matches!(status, Ok(s) if s.success()) {
                eprintln!("  note: could not auto-restart {service}; restart it manually to apply the config");
            }
            Ok(())
        }
    }
}

fn wait_healthy(global: &GlobalArgs) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(output) = Command::new("sh")
            .arg("-c")
            .arg(format!("{} health", global.idps_fw))
            .output()
        {
            if let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) {
                if value.get("connected").and_then(Value::as_bool) == Some(true) {
                    return true;
                }
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_secs(1));
    }
}
