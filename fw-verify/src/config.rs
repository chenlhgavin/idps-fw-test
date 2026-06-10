//! Resolved runtime configuration for a test session.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::cli::{GlobalArgs, Mode, ReportConfirm};
use crate::exec::Endpoint;

/// VSOC dashboard connection details for host-mode rule delivery (mTLS).
#[derive(Debug, Clone)]
pub struct VsocApi {
    pub base_url: String,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub cacert: Option<String>,
}

/// Fully resolved configuration shared by every case.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub mode: Mode,
    pub target: Endpoint,
    pub peer: Endpoint,
    pub target_serial: String,
    pub peer_serial: String,
    pub target_iface: String,
    #[allow(dead_code)]
    pub peer_iface: String,
    pub target_ip: IpAddr,
    pub peer_ip: IpAddr,
    pub acd: i32,
    pub fun_fw: i32,
    pub fun_traffic: i32,
    pub reload_timeout: Duration,
    pub event_settle: Duration,
    pub report_confirm: ReportConfirm,
    pub vsoc: Option<VsocApi>,
    pub fw_agent: String,
    pub idps_fw: String,
    pub state_db: String,
    pub app_uid: u32,
    pub app_identity_key: String,
    pub app_pkg: String,
    pub app_name: String,
}

impl RunConfig {
    /// Resolve serials/endpoints and IP addresses (auto-detecting the latter).
    pub fn resolve(global: &GlobalArgs) -> Result<Self> {
        match global.mode {
            Mode::Android => Self::resolve_android(global),
            Mode::Host => Self::resolve_host(global),
        }
    }

    fn resolve_android(global: &GlobalArgs) -> Result<Self> {
        let target_serial = global
            .target_serial
            .clone()
            .context("--target-serial (or FWV_TARGET) is required in android mode")?;
        let peer_serial = global
            .peer_serial
            .clone()
            .context("--peer-serial (or FWV_PEER) is required in android mode")?;
        let target = Endpoint::Adb {
            serial: target_serial.clone(),
        };
        let peer = Endpoint::Adb {
            serial: peer_serial.clone(),
        };

        let target_ip = resolve_ip(global.target_ip, &target, &global.target_iface, "TARGET")?;
        let peer_ip = resolve_ip(global.peer_ip, &peer, &global.peer_iface, "PEER")?;

        Ok(Self::assemble(
            global,
            target,
            peer,
            target_serial,
            peer_serial,
            global.target_iface.clone(),
            global.peer_iface.clone(),
            target_ip,
            peer_ip,
            None,
        ))
    }

    fn resolve_host(global: &GlobalArgs) -> Result<Self> {
        // Host mode defaults the veth interfaces; wlan0 is the android default,
        // so treat it as "unset" and substitute the host veth names.
        let target_iface = host_iface(&global.target_iface, "fwt0");
        let peer_iface = host_iface(&global.peer_iface, "fwp0");
        let target = Endpoint::Host { netns: None };
        let peer = Endpoint::Host {
            netns: Some(global.peer_netns.clone()),
        };

        let target_ip = resolve_ip(global.target_ip, &target, &target_iface, "TARGET")?;
        let peer_ip = resolve_ip(global.peer_ip, &peer, &peer_iface, "PEER")?;

        let base_url = global
            .vsoc_url
            .clone()
            .unwrap_or_else(|| "https://127.0.0.1:8443".to_string());
        let vsoc = Some(VsocApi {
            base_url: base_url.clone(),
            cert: global.vsoc_cert.clone(),
            key: global.vsoc_key.clone(),
            cacert: global.vsoc_cacert.clone(),
        });

        Ok(Self::assemble(
            global,
            target,
            peer,
            "host".to_string(),
            format!("host:{}", global.peer_netns),
            target_iface,
            peer_iface,
            target_ip,
            peer_ip,
            vsoc,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        global: &GlobalArgs,
        target: Endpoint,
        peer: Endpoint,
        target_serial: String,
        peer_serial: String,
        target_iface: String,
        peer_iface: String,
        target_ip: IpAddr,
        peer_ip: IpAddr,
        vsoc: Option<VsocApi>,
    ) -> Self {
        Self {
            mode: global.mode,
            target,
            peer,
            target_serial,
            peer_serial,
            target_iface,
            peer_iface,
            target_ip,
            peer_ip,
            acd: global.acd,
            fun_fw: global.fun_fw,
            fun_traffic: global.fun_traffic,
            reload_timeout: Duration::from_secs(global.reload_timeout_secs),
            event_settle: Duration::from_millis(global.event_settle_ms),
            report_confirm: global.report_confirm,
            vsoc,
            fw_agent: global.fw_agent.clone(),
            idps_fw: global.idps_fw.clone(),
            state_db: global.state_db.clone(),
            app_uid: global.app_uid,
            app_identity_key: global.app_identity_key.clone(),
            app_pkg: global.app_pkg.clone(),
            app_name: global.app_name.clone(),
        }
    }

    /// `/24` network address of the PEER, used for CIDR match-field cases.
    pub fn peer_slash24(&self) -> String {
        match self.peer_ip {
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                format!("{a}.{b}.{c}.0/24")
            }
            IpAddr::V6(_) => format!("{}/128", self.peer_ip),
        }
    }
}

fn host_iface(value: &str, default: &str) -> String {
    if value.is_empty() || value == "wlan0" {
        default.to_string()
    } else {
        value.to_string()
    }
}

fn resolve_ip(
    explicit: Option<IpAddr>,
    endpoint: &Endpoint,
    iface: &str,
    role: &str,
) -> Result<IpAddr> {
    match explicit {
        Some(ip) => Ok(ip),
        None => endpoint
            .detect_ipv4(iface)?
            .parse()
            .with_context(|| format!("failed to parse detected {role} IP")),
    }
}
