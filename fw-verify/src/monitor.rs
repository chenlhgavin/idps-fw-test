//! Side-channel monitor cases: feature points idps-fw reports out-of-band of
//! the per-packet firewall_event path.
//!
//! * ICMP timestamp probe   -> firewall_event `IcmpTimestampProbe` (vendor 232)
//! * per-destination-IP TCP -> outbox `tcp_conn_per_ip`            (vendor 231)
//! * total TCP connections  -> outbox `tcp_conn_total`             (vendor 102)
//! * ARP spoofing           -> outbox `arp_spoof`                  (vendor 303)
//!
//! These run under a permissive (allow-all) firewall rule so the connection
//! flood can establish; ICMP-timestamp and ARP detection are independent of the
//! tuple filter. They share the host/adb endpoint and VSOC provisioning paths.

use std::thread::sleep;
use std::time::Duration;

use serde_json::Value;

use crate::config::RunConfig;
use crate::peer::{self, TrafficCmd};
use crate::provision;
use crate::target;
use crate::verify::CaseResult;

/// idps-fw's connection-monitor cadence is 10s; sampling waits a little past it.
const MONITOR_SETTLE: Duration = Duration::from_secs(13);
const HOLD_SECS: u64 = 22;
const CONN_FLOOD_COUNT: u32 = 60;
const FLOOD_PORT: u16 = 7400;

/// What a monitor case drives and asserts.
#[derive(Debug, Clone, Copy)]
pub enum MonitorKind {
    /// Peer sends an ICMP timestamp request (type 13).
    IcmpTimestamp,
    /// Peer holds many TCP connections so one destination IP crosses threshold.
    ConnPerIp,
    /// The always-on total-connection monitor samples at least once.
    ConnTotal,
    /// Peer floods gratuitous ARP replies for a spoofed IP.
    ArpSpoof,
}

/// One side-channel monitor case.
#[derive(Debug, Clone, Copy)]
pub struct MonitorCase {
    pub id: &'static str,
    pub kind: MonitorKind,
    pub notes: &'static str,
}

/// The spoofed IP claimed by the ARP case (outside the live host addresses).
const ARP_CLAIM_IP: &str = "10.123.0.250";

/// The full monitor-case catalog.
pub fn monitor_cases() -> Vec<MonitorCase> {
    vec![
        MonitorCase {
            id: "monitor-icmp-timestamp",
            kind: MonitorKind::IcmpTimestamp,
            notes: "ICMP timestamp request (type 13) -> IcmpTimestampProbe event (232)",
        },
        MonitorCase {
            id: "monitor-conn-total",
            kind: MonitorKind::ConnTotal,
            notes: "always-on total established-TCP monitor emits a sample (102)",
        },
        MonitorCase {
            id: "monitor-conn-perip",
            kind: MonitorKind::ConnPerIp,
            notes: "many held connections push one dst IP past the threshold (231)",
        },
        MonitorCase {
            id: "monitor-arp-spoof",
            kind: MonitorKind::ArpSpoof,
            notes: "gratuitous ARP replies for a spoofed IP -> ArpSpoof event (303)",
        },
    ]
}

/// Look up a monitor case by id.
pub fn monitor_case_by_id(id: &str) -> Option<MonitorCase> {
    monitor_cases().into_iter().find(|case| case.id == id)
}

fn result(
    case: &MonitorCase,
    status: &str,
    observed: &str,
    detail: impl Into<String>,
) -> CaseResult {
    CaseResult {
        id: case.id.to_string(),
        group: "monitor".to_string(),
        bundle: "monitor".to_string(),
        result: status.to_string(),
        enforce_expected: "report".to_string(),
        enforce_observed: observed.to_string(),
        event_expected: monitor_expect_label(case.kind).to_string(),
        event_observed: observed.to_string(),
        report_confirmed: None,
        rule_id: None,
        detail: detail.into(),
    }
}

fn monitor_expect_label(kind: MonitorKind) -> &'static str {
    match kind {
        MonitorKind::IcmpTimestamp => "IcmpTimestampProbe",
        MonitorKind::ConnPerIp => "tcp_conn_per_ip",
        MonitorKind::ConnTotal => "tcp_conn_total",
        MonitorKind::ArpSpoof => "arp_spoof",
    }
}

/// Provision the allow-all baseline the monitor cases need, then run them all.
pub fn run_monitor_all(cfg: &RunConfig) -> Vec<CaseResult> {
    run_monitor_filtered(cfg, |_| true)
}

/// Run monitor cases matching `keep`, provisioning the allow-all baseline once.
pub fn run_monitor_filtered(
    cfg: &RunConfig,
    keep: impl Fn(&MonitorCase) -> bool,
) -> Vec<CaseResult> {
    let cases: Vec<MonitorCase> = monitor_cases().into_iter().filter(|c| keep(c)).collect();
    if cases.is_empty() {
        return Vec::new();
    }
    let _ = provision::write_traffic_rule(cfg, 5);
    if let Err(error) = provision::provision_firewall(cfg, "chain=localin,action=P\n") {
        return cases
            .iter()
            .map(|case| result(case, "FAIL", "none", format!("provision failed: {error:#}")))
            .collect();
    }
    cases.iter().map(|case| run_monitor(cfg, case)).collect()
}

/// Run one monitor case by id (provisioning the allow-all baseline first).
pub fn run_monitor_one(cfg: &RunConfig, id: &str) -> Option<Vec<CaseResult>> {
    monitor_case_by_id(id).map(|_| run_monitor_filtered(cfg, |c| c.id == id))
}

fn run_monitor(cfg: &RunConfig, case: &MonitorCase) -> CaseResult {
    match case.kind {
        MonitorKind::IcmpTimestamp => run_icmp_timestamp(cfg, case),
        MonitorKind::ConnPerIp => run_conn_perip(cfg, case),
        MonitorKind::ConnTotal => run_conn_total(cfg, case),
        MonitorKind::ArpSpoof => run_arp_spoof(cfg, case),
    }
}

fn run_icmp_timestamp(cfg: &RunConfig, case: &MonitorCase) -> CaseResult {
    let since = match target::now_ms(cfg) {
        Ok(value) => value,
        Err(error) => return result(case, "FAIL", "none", format!("watermark failed: {error:#}")),
    };
    let cmd = TrafficCmd {
        proto: "icmp",
        to: cfg.target_ip,
        dport: None,
        dports: None,
        sport: None,
        count: 1,
        timeout_ms: 500,
        interval_ms: 0,
        await_reply: false,
        fin_only: false,
        icmp_timestamp: true,
    };
    if let Err(error) = peer::traffic(&cfg.peer, cfg, &cmd, None) {
        return result(case, "FAIL", "none", format!("probe failed: {error:#}"));
    }
    sleep(cfg.event_settle);
    let events = target::dump_events(cfg, since).unwrap_or_default();
    let src = cfg.peer_ip.to_string();
    if events
        .iter()
        .any(|e| e.event_type == "IcmpTimestampProbe" && e.src_ip == src)
    {
        result(case, "PASS", "IcmpTimestampProbe", "")
    } else {
        result(case, "FAIL", "none", "no IcmpTimestampProbe event recorded")
    }
}

fn run_conn_perip(cfg: &RunConfig, case: &MonitorCase) -> CaseResult {
    let since = match target::now_ms(cfg) {
        Ok(value) => value,
        Err(error) => return result(case, "FAIL", "none", format!("watermark failed: {error:#}")),
    };
    // Held listener on the target; flood from the peer, held across a monitor cycle.
    let listener = match cfg.target.spawn_shell(&format!(
        "{} listen tcp --port {FLOOD_PORT} --duration-secs {} --hold",
        cfg.fw_agent,
        HOLD_SECS + 6
    )) {
        Ok(child) => child,
        Err(error) => return result(case, "FAIL", "none", format!("listener failed: {error:#}")),
    };
    sleep(Duration::from_millis(500));
    let flood = cfg.peer.spawn_shell(&format!(
        "{} conn-flood --to {} --dport {FLOOD_PORT} --count {CONN_FLOOD_COUNT} --hold-secs {HOLD_SECS}",
        cfg.fw_agent, cfg.target_ip
    ));
    let mut flood = match flood {
        Ok(child) => child,
        Err(error) => {
            let _ = teardown(listener);
            return result(
                case,
                "FAIL",
                "none",
                format!("conn-flood failed: {error:#}"),
            );
        }
    };
    sleep(MONITOR_SETTLE);
    let reports = target::dump_reports(cfg, since).unwrap_or_default();
    let _ = flood.kill();
    let _ = teardown(listener);

    let peer = cfg.peer_ip.to_string();
    let matched = reports
        .iter()
        .filter(|r| r.report_type == "tcp_conn_per_ip")
        .any(|r| {
            r.payload
                .get("ips")
                .and_then(Value::as_array)
                .is_some_and(|ips| {
                    ips.iter().any(|entry| {
                        entry.get("ip").and_then(Value::as_str) == Some(peer.as_str())
                            && entry.get("count").and_then(Value::as_u64).unwrap_or(0) >= 50
                    })
                })
        });
    if matched {
        result(
            case,
            "PASS",
            "tcp_conn_per_ip",
            format!("{peer} >= 50 conns"),
        )
    } else {
        result(
            case,
            "FAIL",
            "none",
            "no tcp_conn_per_ip breach for the peer IP",
        )
    }
}

fn run_conn_total(cfg: &RunConfig, case: &MonitorCase) -> CaseResult {
    let since = match target::now_ms(cfg) {
        Ok(value) => value,
        Err(error) => return result(case, "FAIL", "none", format!("watermark failed: {error:#}")),
    };
    // The total-connection monitor samples unconditionally each cycle.
    sleep(MONITOR_SETTLE);
    let reports = target::dump_reports(cfg, since).unwrap_or_default();
    match reports.iter().find(|r| r.report_type == "tcp_conn_total") {
        Some(report) => {
            let total = report
                .payload
                .get("total")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            result(case, "PASS", "tcp_conn_total", format!("total={total}"))
        }
        None => result(case, "FAIL", "none", "no tcp_conn_total sample emitted"),
    }
}

fn run_arp_spoof(cfg: &RunConfig, case: &MonitorCase) -> CaseResult {
    let since = match target::now_ms(cfg) {
        Ok(value) => value,
        Err(error) => return result(case, "FAIL", "none", format!("watermark failed: {error:#}")),
    };
    let cmd = format!(
        "{} arp-spoof --iface {} --claim-ip {ARP_CLAIM_IP} --count 6",
        cfg.fw_agent, cfg.peer_iface
    );
    if let Err(error) = cfg.peer.shell_json(&cmd) {
        return result(case, "FAIL", "none", format!("arp-spoof failed: {error:#}"));
    }
    sleep(MONITOR_SETTLE);
    let reports = target::dump_reports(cfg, since).unwrap_or_default();
    let matched = reports
        .iter()
        .filter(|r| r.report_type == "arp_spoof")
        .any(|r| r.payload.get("sip").and_then(Value::as_str) == Some(ARP_CLAIM_IP));
    if matched {
        result(case, "PASS", "arp_spoof", format!("sip={ARP_CLAIM_IP}"))
    } else {
        result(
            case,
            "FAIL",
            "none",
            "no arp_spoof event for the claimed IP",
        )
    }
}

fn teardown(mut listener: std::process::Child) -> std::io::Result<()> {
    listener.kill()
}
