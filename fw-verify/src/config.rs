//! Resolved runtime configuration for a test session.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::adb;
use crate::cli::{GlobalArgs, ReportConfirm};

/// Fully resolved configuration shared by every case.
#[derive(Debug, Clone)]
pub struct RunConfig {
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
    pub vsoc_url: Option<String>,
    pub fw_agent: String,
    pub idps_fw: String,
    pub state_db: String,
    pub app_uid: u32,
    pub app_identity_key: String,
    pub app_pkg: String,
    pub app_name: String,
}

impl RunConfig {
    /// Resolve serials and IP addresses (auto-detecting the latter when absent).
    pub fn resolve(global: &GlobalArgs) -> Result<Self> {
        let target_serial = global
            .target_serial
            .clone()
            .context("--target-serial (or FWV_TARGET) is required")?;
        let peer_serial = global
            .peer_serial
            .clone()
            .context("--peer-serial (or FWV_PEER) is required")?;

        let target_ip = match global.target_ip {
            Some(ip) => ip,
            None => adb::detect_ipv4(&target_serial, &global.target_iface)?
                .parse()
                .context("failed to parse detected TARGET IP")?,
        };
        let peer_ip = match global.peer_ip {
            Some(ip) => ip,
            None => adb::detect_ipv4(&peer_serial, &global.peer_iface)?
                .parse()
                .context("failed to parse detected PEER IP")?,
        };

        Ok(Self {
            target_serial,
            peer_serial,
            target_iface: global.target_iface.clone(),
            peer_iface: global.peer_iface.clone(),
            target_ip,
            peer_ip,
            acd: global.acd,
            fun_fw: global.fun_fw,
            fun_traffic: global.fun_traffic,
            reload_timeout: Duration::from_secs(global.reload_timeout_secs),
            event_settle: Duration::from_millis(global.event_settle_ms),
            report_confirm: global.report_confirm,
            vsoc_url: global.vsoc_url.clone(),
            fw_agent: global.fw_agent.clone(),
            idps_fw: global.idps_fw.clone(),
            state_db: global.state_db.clone(),
            app_uid: global.app_uid,
            app_identity_key: global.app_identity_key.clone(),
            app_pkg: global.app_pkg.clone(),
            app_name: global.app_name.clone(),
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
