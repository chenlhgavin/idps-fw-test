//! Per-case orchestration: provision, generate traffic, assert enforcement +
//! detection + upload-to-idps-server, and the bundle-batched runners.

use std::net::IpAddr;
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::catalog::{
    all_cases, bundle_order, case_by_id, firewall_text, traffic_cycle, Bundle, Enforce,
    ExpectEvent, FwCase, Group, Side, TrafficKind,
};
use crate::cli::{Mode, ReportConfirm};
use crate::config::RunConfig;
use crate::exec::Endpoint;
use crate::peer::{self, TrafficCmd};
use crate::provision;
use crate::target::{self, FwEvent};
use crate::vsoc;

const LISTEN_SECS: u64 = 12;
const LISTEN_READY: Duration = Duration::from_millis(500);

/// Outcome of a single case.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub group: String,
    pub bundle: String,
    pub result: String,
    pub enforce_expected: String,
    pub enforce_observed: String,
    pub event_expected: String,
    pub event_observed: String,
    pub report_confirmed: Option<bool>,
    pub rule_id: Option<i64>,
    pub detail: String,
}

fn bundle_name(bundle: Bundle) -> &'static str {
    match bundle {
        Bundle::IngressTuple => "ingress_tuple",
        Bundle::DefaultDeny => "default_deny",
        Bundle::DefaultAllow => "default_allow",
        Bundle::EgressTuple => "egress_tuple",
        Bundle::AppDeny => "app_deny",
        Bundle::AppAllow => "app_allow",
        Bundle::MatchFields => "match_fields",
        Bundle::Detection => "detection",
        Bundle::Traffic => "traffic",
        Bundle::Priority => "priority",
    }
}

fn result(case: &FwCase, status: &str, detail: impl Into<String>) -> CaseResult {
    CaseResult {
        id: case.id.to_string(),
        group: case.group.as_str().to_string(),
        bundle: bundle_name(case.bundle).to_string(),
        result: status.to_string(),
        enforce_expected: enforce_str(case.expect_enforce).to_string(),
        enforce_observed: String::new(),
        event_expected: case
            .expect_event
            .as_ref()
            .map_or_else(|| "none".to_string(), describe_expect),
        event_observed: String::new(),
        report_confirmed: None,
        rule_id: case.expect_event.as_ref().and_then(|e| e.rule_id),
        detail: detail.into(),
    }
}

fn enforce_str(enforce: Enforce) -> &'static str {
    match enforce {
        Enforce::Blocked => "blocked",
        Enforce::Allowed => "allowed",
        Enforce::Sent => "sent",
        Enforce::Refused => "refused",
    }
}

fn describe_expect(expect: &ExpectEvent) -> String {
    format!("{}/{}/{}", expect.kind, expect.action, expect.proto)
}

fn endpoint(cfg: &RunConfig, side: Side) -> &Endpoint {
    match side {
        Side::Peer => &cfg.peer,
        Side::Target => &cfg.target,
    }
}

/// (`src_ip`, `dst_ip`, `to`) for traffic originating from `origin`.
fn flow(cfg: &RunConfig, origin: Side) -> (String, String, IpAddr) {
    match origin {
        Side::Peer => (
            cfg.peer_ip.to_string(),
            cfg.target_ip.to_string(),
            cfg.target_ip,
        ),
        Side::Target => (
            cfg.target_ip.to_string(),
            cfg.peer_ip.to_string(),
            cfg.peer_ip,
        ),
    }
}

fn build_cmd(case: &FwCase, to: IpAddr) -> TrafficCmd {
    let base = TrafficCmd {
        proto: "tcp",
        to,
        dport: None,
        dports: None,
        sport: case.sport,
        count: 1,
        timeout_ms: 1500,
        interval_ms: 0,
        await_reply: false,
        fin_only: false,
        icmp_timestamp: false,
    };
    match &case.traffic {
        TrafficKind::Tcp { dport } => TrafficCmd {
            dport: Some(*dport),
            ..base
        },
        TrafficKind::Icmp => TrafficCmd {
            proto: "icmp",
            ..base
        },
        TrafficKind::Udp { dport, await_reply } => TrafficCmd {
            proto: "udp",
            dport: Some(*dport),
            await_reply: *await_reply,
            ..base
        },
        TrafficKind::TcpScan { dports } => TrafficCmd {
            dports: Some(dports.clone()),
            timeout_ms: 250,
            ..base
        },
        TrafficKind::UdpScan { dports } => TrafficCmd {
            proto: "udp",
            dports: Some(dports.clone()),
            timeout_ms: 250,
            ..base
        },
        TrafficKind::TcpFinScan { dports } => TrafficCmd {
            dports: Some(dports.clone()),
            timeout_ms: 250,
            fin_only: true,
            ..base
        },
        TrafficKind::TcpBurst { dport, count } => TrafficCmd {
            dport: Some(*dport),
            count: *count,
            timeout_ms: 200,
            ..base
        },
        TrafficKind::UdpVolume { dport, count } => TrafficCmd {
            proto: "udp",
            dport: Some(*dport),
            count: *count,
            timeout_ms: 200,
            ..base
        },
    }
}

fn case_dport(case: &FwCase) -> Option<i64> {
    match &case.traffic {
        TrafficKind::Tcp { dport }
        | TrafficKind::Udp { dport, .. }
        | TrafficKind::TcpBurst { dport, .. }
        | TrafficKind::UdpVolume { dport, .. } => Some(i64::from(*dport)),
        _ => None,
    }
}

fn event_matches(cfg: &RunConfig, case: &FwCase, ev: &FwEvent, expect: &ExpectEvent) -> bool {
    if ev.event_type != expect.kind || ev.action != expect.action || ev.proto != expect.proto {
        return false;
    }
    let (src, dst, _to) = flow(cfg, case.origin);
    // PolicyDeny events may carry an incomplete tuple; match on kind/action/proto only.
    if expect.kind != "PolicyDeny" && ev.src_ip != src {
        return false;
    }
    if let Some(dport) = expect.match_dport {
        if ev.dst_port != i64::from(dport) || ev.dst_ip != dst {
            return false;
        }
    }
    if let Some(want_detail) = expect.detail {
        if ev.detail != want_detail {
            return false;
        }
    }
    true
}

/// Confirm idps-fw delivered the event to idps-server (`report_state = 'sent'`).
fn confirm_local_sent(cfg: &RunConfig, since: i64, event_id: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Ok(events) = target::dump_events(cfg, since) {
            if events
                .iter()
                .any(|e| e.event_id == event_id && e.report_state == "sent")
            {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(700));
    }
}

fn confirm_server_log(cfg: &RunConfig) -> String {
    // logcat is Android-only; on host idps-server logs to its own stream.
    if cfg.mode == Mode::Host {
        return "server-log:n/a-host".to_string();
    }
    match cfg.target.shell("logcat -d -t 400") {
        Ok(log) if log.contains("received report") => "server-log:found".to_string(),
        Ok(_) => "server-log:absent".to_string(),
        Err(_) => "server-log:unavailable".to_string(),
    }
}

fn confirm_vsoc(cfg: &RunConfig) -> String {
    match vsoc::events_mention(cfg, &cfg.target_ip.to_string()) {
        Ok(true) => "vsoc:found".to_string(),
        Ok(false) => "vsoc:absent".to_string(),
        Err(error) => format!("vsoc:error({error:#})"),
    }
}

/// Run a single case (its bundle must already be provisioned).
pub fn run_case(cfg: &RunConfig, case: &FwCase) -> CaseResult {
    if let Some(reason) = case.skip {
        return result(case, "SKIP", reason);
    }
    if case.group == Group::Traffic {
        return run_traffic_case(cfg, case);
    }

    // Start listeners and let them bind.
    let mut children = Vec::new();
    for spec in &case.listen {
        match peer::start_listener(
            endpoint(cfg, spec.side),
            cfg,
            spec.proto,
            spec.port,
            LISTEN_SECS,
        ) {
            Ok(child) => children.push(child),
            Err(error) => return result(case, "SKIP", format!("listener failed: {error:#}")),
        }
    }
    if !case.listen.is_empty() {
        sleep(LISTEN_READY);
    }

    let (_src, _dst, to) = flow(cfg, case.origin);
    let since = match target::now_ms(cfg) {
        Ok(value) => value,
        Err(error) => {
            return finish(
                case,
                "FAIL",
                format!("watermark failed: {error:#}"),
                children,
                cfg,
            )
        }
    };

    let cmd = build_cmd(case, to);
    let uid = case.uid.then_some(cfg.app_uid);
    let outcome = match peer::traffic(endpoint(cfg, case.origin), cfg, &cmd, uid) {
        Ok(outcome) => outcome,
        Err(error) => {
            return finish(
                case,
                "FAIL",
                format!("traffic failed: {error:#}"),
                children,
                cfg,
            )
        }
    };

    sleep(cfg.event_settle);
    let events = target::dump_events(cfg, since).unwrap_or_default();

    let mut res = result(case, "PASS", String::new());
    res.enforce_observed = outcome.verdict.clone();

    // Enforcement.
    let enforce_ok = match case.expect_enforce {
        Enforce::Blocked => outcome.verdict == "blocked",
        Enforce::Allowed => outcome.verdict == "allowed",
        Enforce::Sent => outcome.verdict == "sent",
        Enforce::Refused => outcome.verdict == "refused",
    };

    // Detection.
    let mut detail = Vec::new();
    let (event_ok, matched) = match &case.expect_event {
        Some(expect) => match events
            .iter()
            .find(|ev| event_matches(cfg, case, ev, expect))
        {
            Some(ev) => {
                res.event_observed = format!("{}/{}/{}", ev.event_type, ev.action, ev.proto);
                if let (Some(want), Some(got)) = (expect.rule_id, ev.rule_id) {
                    if want != got {
                        detail.push(format!("rule_id expected {want} got {got}"));
                    }
                }
                (true, Some(ev.clone()))
            }
            None => {
                res.event_observed = "none".to_string();
                (false, None)
            }
        },
        None => {
            // Expect no event for this flow (Pass / BlockSilent).
            let dport = case_dport(case);
            let (src, _dst, _to) = flow(cfg, case.origin);
            let violating = events
                .iter()
                .find(|ev| ev.src_ip == src && dport.is_some_and(|d| ev.dst_port == d));
            match violating {
                Some(ev) => {
                    res.event_observed = format!("unexpected {}/{}", ev.event_type, ev.action);
                    (false, None)
                }
                None => {
                    res.event_observed = "none".to_string();
                    (true, None)
                }
            }
        }
    };

    // Report-to-server confirmation (only when an event was expected + found).
    if let Some(ev) = &matched {
        let local = confirm_local_sent(cfg, since, &ev.event_id);
        res.report_confirmed = Some(local);
        if !local {
            detail.push("report not confirmed sent to idps-server".to_string());
        }
        match cfg.report_confirm {
            ReportConfirm::Local => {}
            ReportConfirm::Server => detail.push(confirm_server_log(cfg)),
            ReportConfirm::Vsoc => {
                detail.push(confirm_server_log(cfg));
                detail.push(confirm_vsoc(cfg));
            }
        }
    }

    let report_gate = res.report_confirmed != Some(false);
    let status = if enforce_ok && event_ok && report_gate {
        "PASS"
    } else {
        if !enforce_ok {
            detail.push(format!(
                "enforce expected {} got {}",
                enforce_str(case.expect_enforce),
                outcome.verdict
            ));
        }
        if !event_ok {
            detail.push("event expectation not met".to_string());
        }
        "FAIL"
    };

    finish_with(case, status, detail.join("; "), res, children, cfg)
}

fn run_traffic_case(cfg: &RunConfig, case: &FwCase) -> CaseResult {
    let before = match target::statistics(cfg) {
        Ok(value) => value,
        Err(error) => return result(case, "FAIL", format!("stats failed: {error:#}")),
    };
    let (_src, _dst, to) = flow(cfg, case.origin);
    let cmd = build_cmd(case, to);
    let uid = case.uid.then_some(cfg.app_uid);
    if let Err(error) = peer::traffic(endpoint(cfg, case.origin), cfg, &cmd, uid) {
        return result(case, "FAIL", format!("traffic failed: {error:#}"));
    }
    // Wait for a traffic window (cycle=5s) to close plus a settle margin.
    sleep(Duration::from_secs(7));
    let after = match target::statistics(cfg) {
        Ok(value) => value,
        Err(error) => return result(case, "FAIL", format!("stats failed: {error:#}")),
    };

    let get = |v: &serde_json::Value, key: &str| {
        v.get(key).and_then(serde_json::Value::as_i64).unwrap_or(0)
    };
    let mut res = result(case, "PASS", String::new());
    res.enforce_observed = "allowed".to_string();
    let (ok, detail) = if case.id == "traffic-per-app" {
        let bytes = get(&after, "egress_bytes") > get(&before, "egress_bytes");
        let windows = get(&after, "app_traffic_windows") > get(&before, "app_traffic_windows");
        (
            bytes && windows,
            format!(
                "egress_bytes +{}, app_windows +{}",
                get(&after, "egress_bytes") - get(&before, "egress_bytes"),
                get(&after, "app_traffic_windows") - get(&before, "app_traffic_windows")
            ),
        )
    } else {
        let bytes = get(&after, "ingress_bytes") > get(&before, "ingress_bytes");
        let windows =
            get(&after, "global_traffic_windows") > get(&before, "global_traffic_windows");
        (
            bytes && windows,
            format!(
                "ingress_bytes +{}, global_windows +{}",
                get(&after, "ingress_bytes") - get(&before, "ingress_bytes"),
                get(&after, "global_traffic_windows") - get(&before, "global_traffic_windows")
            ),
        )
    };
    res.event_observed = detail.clone();
    res.result = if ok {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    };
    res.detail = detail;
    res
}

fn finish(
    case: &FwCase,
    status: &str,
    detail: String,
    children: Vec<std::process::Child>,
    cfg: &RunConfig,
) -> CaseResult {
    let res = result(case, status, detail);
    finish_with(case, status, res.detail.clone(), res, children, cfg)
}

fn finish_with(
    case: &FwCase,
    status: &str,
    detail: String,
    mut res: CaseResult,
    mut children: Vec<std::process::Child>,
    cfg: &RunConfig,
) -> CaseResult {
    for child in &mut children {
        let _ = child.kill();
    }
    for spec in &case.listen {
        peer::stop_listeners(endpoint(cfg, spec.side), cfg);
    }
    res.result = status.to_string();
    res.detail = detail;
    res
}

fn provision_bundle(cfg: &RunConfig, bundle: Bundle) -> anyhow::Result<()> {
    provision::provision_firewall(cfg, &firewall_text(bundle, cfg))?;
    if let Some(cycle) = traffic_cycle(bundle) {
        provision::provision_traffic_cycle(cfg, cycle)?;
    }
    Ok(())
}

fn provision_error(case: &FwCase, error: &anyhow::Error) -> CaseResult {
    result(case, "FAIL", format!("provision failed: {error:#}"))
}

/// Run one case by id (provisioning its bundle first).
pub fn run_one(cfg: &RunConfig, id: &str) -> Vec<CaseResult> {
    if let Some(results) = crate::monitor::run_monitor_one(cfg, id) {
        return results;
    }
    let Some(case) = case_by_id(id) else {
        return vec![CaseResult {
            id: id.to_string(),
            group: String::new(),
            bundle: String::new(),
            result: "FAIL".to_string(),
            enforce_expected: String::new(),
            enforce_observed: String::new(),
            event_expected: String::new(),
            event_observed: String::new(),
            report_confirmed: None,
            rule_id: None,
            detail: "unknown case id".to_string(),
        }];
    };
    let _ = provision::write_traffic_rule(cfg, 5);
    if let Err(error) = provision_bundle(cfg, case.bundle) {
        return vec![provision_error(&case, &error)];
    }
    vec![run_case(cfg, &case)]
}

/// Run the cases in a group, provisioning each needed bundle once.
pub fn run_group(cfg: &RunConfig, group: Group) -> Vec<CaseResult> {
    if group == Group::Monitor {
        return crate::monitor::run_monitor_all(cfg);
    }
    run_filtered(cfg, |case| case.group == group)
}

/// Run the whole catalog, batching by bundle, then the side-channel monitors.
pub fn run_all(cfg: &RunConfig) -> Vec<CaseResult> {
    let mut results = run_filtered(cfg, |_| true);
    results.extend(crate::monitor::run_monitor_all(cfg));
    results
}

fn run_filtered(cfg: &RunConfig, keep: impl Fn(&FwCase) -> bool) -> Vec<CaseResult> {
    // idps-fw needs a fun=4 rule to leave RuleSyncing before any fun=1 loads.
    let _ = provision::write_traffic_rule(cfg, 5);
    let cases = all_cases();
    let mut results = Vec::new();
    for &bundle in bundle_order() {
        let members: Vec<&FwCase> = cases
            .iter()
            .filter(|case| case.bundle == bundle && keep(case))
            .collect();
        if members.is_empty() {
            continue;
        }
        if let Err(error) = provision_bundle(cfg, bundle) {
            for case in &members {
                results.push(provision_error(case, &error));
            }
            continue;
        }
        for case in members {
            results.push(run_case(cfg, case));
        }
    }
    results
}
