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
    pub idps_fw: String,
    pub state_db: String,
    pub app_uid: u32,
    pub app_identity_key: String,
}

impl RunConfig {
    /// Resolve endpoints and IP addresses (auto-detecting the latter).
    ///
    /// The TARGET is the local root namespace; the PEER is the far veth end in
    /// `peer_netns`. The only mode-dependent piece is rule delivery: host mode
    /// upserts through the VSOC API, Android mode writes the depot directly.
    pub fn resolve(global: &GlobalArgs) -> Result<Self> {
        let target = Endpoint::Local;
        let peer = Endpoint::Netns {
            name: global.peer_netns.clone(),
        };

        let target_ip = resolve_ip(global.target_ip, &target, &global.target_iface, "TARGET")?;
        let peer_ip = resolve_ip(global.peer_ip, &peer, &global.peer_iface, "PEER")?;

        let vsoc = match global.mode {
            Mode::Host => {
                let base_url = global
                    .vsoc_url
                    .clone()
                    .unwrap_or_else(|| "https://127.0.0.1:8443".to_string());
                Some(VsocApi {
                    base_url,
                    cert: global.vsoc_cert.clone(),
                    key: global.vsoc_key.clone(),
                    cacert: global.vsoc_cacert.clone(),
                })
            }
            Mode::Android => None,
        };

        Ok(Self {
            mode: global.mode,
            target,
            peer,
            peer_iface: global.peer_iface.clone(),
            target_ip,
            peer_ip,
            acd: global.acd,
            fun_fw: global.fun_fw,
            fun_traffic: global.fun_traffic,
            reload_timeout: Duration::from_secs(global.reload_timeout_secs),
            event_settle: Duration::from_millis(global.event_settle_ms),
            report_confirm: global.report_confirm,
            vsoc,
            idps_fw: global.idps_fw.clone(),
            state_db: global.state_db.clone(),
            app_uid: global.app_uid,
            app_identity_key: global.app_identity_key.clone(),
        })
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
