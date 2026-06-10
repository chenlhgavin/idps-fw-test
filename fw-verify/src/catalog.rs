//! Test-case catalog: data-driven cases grouped into provisioning bundles.

use anyhow::{bail, Result};

use crate::config::RunConfig;

/// Logical case group (also the `run-group` argument).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Ingress,
    Default,
    Egress,
    App,
    Match,
    Detection,
    Traffic,
    Monitor,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Ingress => "ingress",
            Group::Default => "default",
            Group::Egress => "egress",
            Group::App => "app",
            Group::Match => "match",
            Group::Detection => "detection",
            Group::Traffic => "traffic",
            Group::Monitor => "monitor",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "ingress" => Group::Ingress,
            "default" => Group::Default,
            "egress" => Group::Egress,
            "app" => Group::App,
            "match" => Group::Match,
            "detection" => Group::Detection,
            "traffic" => Group::Traffic,
            "monitor" => Group::Monitor,
            other => bail!(
                "unknown group `{other}` (ingress|default|egress|app|match|detection|traffic|monitor)"
            ),
        })
    }
}

/// A provisioning bundle: one firewall rule set shared by several cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bundle {
    IngressTuple,
    DefaultDeny,
    DefaultAllow,
    EgressTuple,
    AppDeny,
    AppAllow,
    MatchFields,
    Detection,
    Traffic,
    Priority,
}

/// Which device performs an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Peer,
    Target,
}

/// How traffic is generated for a case.
#[derive(Debug, Clone)]
pub enum TrafficKind {
    Tcp {
        dport: u16,
    },
    Icmp,
    Udp {
        dport: u16,
        await_reply: bool,
    },
    TcpScan {
        dports: Vec<u16>,
    },
    UdpScan {
        dports: Vec<u16>,
    },
    TcpBurst {
        dport: u16,
        count: u32,
    },
    UdpVolume {
        dport: u16,
        count: u32,
    },
    /// Bare-FIN TCP packets to several ports (raw socket, needs root).
    TcpFinScan {
        dports: Vec<u16>,
    },
}

/// Expected enforcement outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforce {
    Blocked,
    Allowed,
    /// Raw packet sent with no handshake/reply to judge (e.g. FIN scan).
    Sent,
    /// Connection actively refused (RST). For NLD the first new-flow packet is
    /// permitted, so a probe to a closed port is refused rather than dropped —
    /// this is what distinguishes NLD (silent IPS-handoff) from LD (drop).
    Refused,
}

/// Expected firewall_event for a case (`None` asserts no event).
#[derive(Debug, Clone)]
pub struct ExpectEvent {
    pub kind: &'static str,
    pub action: &'static str,
    pub proto: &'static str,
    pub rule_id: Option<i64>,
    pub match_dport: Option<u16>,
    /// Exact vendor `detail` string to assert, or `None` to skip.
    pub detail: Option<&'static str>,
}

/// A listener to start before generating traffic.
#[derive(Debug, Clone)]
pub struct Listen {
    pub side: Side,
    pub proto: &'static str,
    pub port: u16,
}

/// A single test case.
#[derive(Debug, Clone)]
pub struct FwCase {
    pub id: &'static str,
    pub group: Group,
    pub bundle: Bundle,
    pub origin: Side,
    pub uid: bool,
    pub sport: Option<u16>,
    pub listen: Vec<Listen>,
    pub traffic: TrafficKind,
    pub expect_enforce: Enforce,
    pub expect_event: Option<ExpectEvent>,
    pub skip: Option<&'static str>,
    #[allow(dead_code)]
    pub notes: &'static str,
}

/// Firewall rule text (fun=1) for a bundle, rendered for the live IPs.
///
/// Lines are emitted with no blanks or comments so a tuple rule's `rule_id`
/// equals its 1-based line number (idps-fw assigns rule_id = line number).
pub fn firewall_text(bundle: Bundle, cfg: &RunConfig) -> String {
    let peer = cfg.peer_ip;
    let target = cfg.target_ip;
    let peer24 = cfg.peer_slash24();
    let key = &cfg.app_identity_key;
    match bundle {
        Bundle::IngressTuple => format!(
            "chain=localin,action=P\n\
             sip={peer},dip={target},dport=5001,proto=tcp,action=P,chain=localin\n\
             sip={peer},dip={target},dport=5002,proto=tcp,action=LP,chain=localin\n\
             sip={peer},dip={target},dport=5003,proto=tcp,action=LD,chain=localin\n\
             sip={peer},dip={target},dport=5004,proto=tcp,action=NLD,chain=localin\n"
        ),
        Bundle::DefaultDeny => format!(
            "chain=localin,action=LD\n\
             sip={peer},dip={target},dport=5101,proto=tcp,action=P,chain=localin\n"
        ),
        Bundle::DefaultAllow => "chain=localin,action=P\n".to_string(),
        Bundle::EgressTuple => format!(
            "chain=localin,action=P\n\
             sip={target},dip={peer},dport=6001,proto=tcp,action=LD,chain=output\n\
             sip={target},dip={peer},dport=6002,proto=tcp,action=LP,chain=output\n\
             sip={target},dip={peer},dport=6003,proto=udp,action=LD,chain=output\n"
        ),
        Bundle::AppDeny => format!("chain=localin,action=P\nprog={key},action=LD\n"),
        Bundle::AppAllow => format!("chain=localin,action=P\nprog={key},action=LP\n"),
        Bundle::MatchFields => format!(
            "chain=localin,action=P\n\
             sip={peer}/32,dip={target},dport=7001,proto=tcp,action=LD,chain=localin\n\
             sip={peer24},dip={target},dport=7002,proto=tcp,action=LD,chain=localin\n\
             sip=*,dip={target},dport=7100-7110,proto=tcp,action=LD,chain=localin\n\
             sip=*,sport=8000-8005,dip={target},dport=7200,proto=udp,action=LD,chain=localin\n\
             sip=*,dip={target},proto=icmp,action=LD,chain=localin\n\
             sip=*,dip={target},dport=7300,proto=*,action=LD,chain=localin\n"
        ),
        Bundle::Detection => "chain=localin,action=LD\n".to_string(),
        // Two overlapping ingress rules on the same port: idps-fw ranks later
        // lines higher, so the line-3 block must win over the line-2 pass.
        Bundle::Priority => format!(
            "chain=localin,action=P\n\
             sip={peer},dip={target},dport=8001,proto=tcp,action=P,chain=localin\n\
             sip={peer},dip={target},dport=8001,proto=tcp,action=LD,chain=localin\n\
             sip={peer},dip={target},dport=8002,proto=tcp,action=P,chain=localin\n"
        ),
        // The app policy registers the mapped uid as a known identity so the
        // per-app traffic window is attributed (idps-fw only enriches app_ids
        // that carry a policy); LP is allow, so it does not block the volume.
        Bundle::Traffic => format!(
            "chain=localin,action=P\n\
             prog={key},action=LP\n\
             sip={peer},dip={target},dport=5301,proto=udp,action=P,chain=localin\n"
        ),
    }
}

/// Traffic-policy cycle (fun=4) in seconds for a bundle, if any.
pub fn traffic_cycle(bundle: Bundle) -> Option<u64> {
    matches!(bundle, Bundle::Traffic).then_some(5)
}

fn event(
    kind: &'static str,
    action: &'static str,
    proto: &'static str,
    rule_id: Option<i64>,
    match_dport: Option<u16>,
) -> Option<ExpectEvent> {
    Some(ExpectEvent {
        kind,
        action,
        proto,
        rule_id,
        match_dport,
        detail: None,
    })
}

/// Like `event`, but also asserts the exact vendor `detail` string.
fn event_d(
    kind: &'static str,
    action: &'static str,
    proto: &'static str,
    rule_id: Option<i64>,
    match_dport: Option<u16>,
    detail: &'static str,
) -> Option<ExpectEvent> {
    Some(ExpectEvent {
        kind,
        action,
        proto,
        rule_id,
        match_dport,
        detail: Some(detail),
    })
}

fn listen(side: Side, proto: &'static str, port: u16) -> Vec<Listen> {
    vec![Listen { side, proto, port }]
}

/// The full case catalog.
pub fn all_cases() -> Vec<FwCase> {
    use Bundle::*;
    use Enforce::{Allowed, Blocked, Refused, Sent};
    use Group as G;
    use Side::{Peer, Target};
    use TrafficKind::*;

    vec![
        // --- INGRESS_TUPLE ---
        FwCase {
            id: "ingress-tuple-pass",
            group: G::Ingress,
            bundle: IngressTuple,
            origin: Peer,
            uid: false,
            sport: None,
            listen: listen(Target, "tcp", 5001),
            traffic: Tcp { dport: 5001 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Pass action allows the SYN and emits no event",
        },
        FwCase {
            id: "ingress-tuple-alert",
            group: G::Ingress,
            bundle: IngressTuple,
            origin: Peer,
            uid: false,
            sport: None,
            listen: listen(Target, "tcp", 5002),
            traffic: Tcp { dport: 5002 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Ingress LP allows the SYN; single connections emit no event (vendor-aligned)",
        },
        FwCase {
            id: "ingress-tuple-block",
            group: G::Ingress,
            bundle: IngressTuple,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 5003 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Ingress LD drops the SYN; single connections emit no event (only scans do)",
        },
        FwCase {
            id: "ingress-tuple-blocksilent",
            group: G::Ingress,
            bundle: IngressTuple,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 5004 },
            expect_enforce: Refused,
            expect_event: None,
            skip: None,
            notes: "NLD passes the first new-flow SYN (IPS handoff): the probe reaches the closed port and is refused (RST), with no event — distinct from LD which drops the SYN (blocked)",
        },
        // --- DEFAULT policy ---
        FwCase {
            id: "default-deny-blocks",
            group: G::Default,
            bundle: DefaultDeny,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 5102 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Default ingress deny drops unlisted traffic; emits no per-connection event",
        },
        FwCase {
            id: "default-deny-carveout",
            group: G::Default,
            bundle: DefaultDeny,
            origin: Peer,
            uid: false,
            sport: None,
            listen: listen(Target, "tcp", 5101),
            traffic: Tcp { dport: 5101 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Explicit Pass rule overrides the default deny",
        },
        FwCase {
            id: "default-allow",
            group: G::Default,
            bundle: DefaultAllow,
            origin: Peer,
            uid: false,
            sport: None,
            listen: listen(Target, "tcp", 5201),
            traffic: Tcp { dport: 5201 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Default ingress allow passes unlisted traffic",
        },
        // --- EGRESS_TUPLE ---
        FwCase {
            id: "egress-tcp-block",
            group: G::Egress,
            bundle: EgressTuple,
            origin: Target,
            uid: false,
            sport: None,
            listen: listen(Peer, "tcp", 6001),
            traffic: Tcp { dport: 6001 },
            expect_enforce: Blocked,
            expect_event: event_d(
                "NetworkBlock",
                "Block",
                "tcp",
                Some(2),
                Some(6001),
                "connection state invalid attack",
            ),
            skip: None,
            notes: "Egress Block drops the target's outbound SYN and records a NetworkBlock",
        },
        FwCase {
            id: "egress-tcp-alert",
            group: G::Egress,
            bundle: EgressTuple,
            origin: Target,
            uid: false,
            sport: None,
            listen: listen(Peer, "tcp", 6002),
            traffic: Tcp { dport: 6002 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Egress LP allows outbound and emits no event (vendor egress has no LPASS log)",
        },
        FwCase {
            id: "egress-udp-block",
            group: G::Egress,
            bundle: EgressTuple,
            origin: Target,
            uid: false,
            sport: None,
            listen: listen(Peer, "udp", 6003),
            traffic: Udp {
                dport: 6003,
                await_reply: true,
            },
            expect_enforce: Blocked,
            expect_event: event_d(
                "NetworkBlock",
                "Block",
                "udp",
                Some(4),
                Some(6003),
                "connection state invalid attack",
            ),
            skip: None,
            notes: "Egress UDP Block drops the outbound datagram (no echo) and records a NetworkBlock",
        },
        // --- APP/UID policy ---
        FwCase {
            id: "app-policy-deny",
            group: G::App,
            bundle: AppDeny,
            origin: Target,
            uid: true,
            sport: None,
            listen: listen(Peer, "tcp", 6101),
            traffic: Tcp { dport: 6101 },
            expect_enforce: Blocked,
            expect_event: event("PolicyDeny", "Block", "tcp", None, None),
            skip: None,
            notes: "App policy LD denies the mapped UID's connect (cgroup connect4)",
        },
        FwCase {
            id: "app-policy-allow",
            group: G::App,
            bundle: AppAllow,
            origin: Target,
            uid: true,
            sport: None,
            listen: listen(Peer, "tcp", 6101),
            traffic: Tcp { dport: 6101 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "App policy LP allows the mapped UID's connect",
        },
        // --- MATCH_FIELDS (full 5-tuple coverage) ---
        FwCase {
            id: "match-sip-host",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 7001 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Exact /32 source IP match; blocked proves the rule matched (no ingress event)",
        },
        FwCase {
            id: "match-sip-cidr",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 7002 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "CIDR /24 source match; blocked proves the rule matched (no ingress event)",
        },
        FwCase {
            id: "match-dport-range-lo",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 7100 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Destination port range low bound; blocked proves the match (no ingress event)",
        },
        FwCase {
            id: "match-dport-range-hi",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 7110 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Destination port range high bound; blocked proves the match (no ingress event)",
        },
        FwCase {
            id: "match-dport-range-out",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: listen(Target, "tcp", 7111),
            traffic: Tcp { dport: 7111 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Negative: port just outside the range falls through to default allow",
        },
        FwCase {
            id: "match-sport-range",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: Some(8000),
            listen: vec![],
            traffic: Udp {
                dport: 7200,
                await_reply: true,
            },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Source port range + UDP protocol match; blocked proves the match (no event)",
        },
        FwCase {
            id: "match-proto-icmp",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Icmp,
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "ICMP protocol match; blocked (no reply) proves the match (no ingress event)",
        },
        FwCase {
            id: "match-proto-any-tcp",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Tcp { dport: 7300 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Wildcard protocol match (tcp); blocked proves the match (no ingress event)",
        },
        FwCase {
            id: "match-proto-any-udp",
            group: G::Match,
            bundle: MatchFields,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: Udp {
                dport: 7300,
                await_reply: true,
            },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Wildcard protocol match (udp); drop -> no echo -> timeout=blocked (no event)",
        },
        // --- DETECTION (port-scan / connection-abnormality) ---
        FwCase {
            id: "detect-portscan-tcp",
            group: G::Detection,
            bundle: Detection,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: TcpScan {
                dports: vec![9001, 9002, 9003, 9004, 9005],
            },
            expect_enforce: Blocked,
            expect_event: event_d("PortScan", "Block", "tcp", None, None, "tcp portscan attack"),
            skip: None,
            notes: "≥3 distinct dst ports in a <1s burst -> PortScan; sent as 5 so the global vendor detector fires even if prior cases left slot residue",
        },
        FwCase {
            id: "detect-portscan-udp",
            group: G::Detection,
            bundle: Detection,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: UdpScan {
                dports: vec![9001, 9002, 9003, 9004, 9005],
            },
            expect_enforce: Sent,
            expect_event: event_d("PortScan", "Block", "udp", None, None, "udp portscan attack"),
            skip: None,
            notes: "≥3 distinct UDP dst ports in a <1s burst -> PortScan (UDP fire-and-forget => verdict 'sent'); 5 ports for detector robustness",
        },
        FwCase {
            id: "detect-portscan-tcp-fin",
            group: G::Detection,
            bundle: Detection,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: TcpFinScan {
                dports: vec![9011, 9012, 9013, 9014, 9015],
            },
            expect_enforce: Sent,
            expect_event: event_d(
                "PortScan",
                "Block",
                "tcp",
                None,
                None,
                "tcp fin portscan attack",
            ),
            skip: None,
            notes: "≥3 distinct dst ports hit by bare-FIN packets in a <1s burst -> FIN PortScan (raw socket on PEER, needs root; verdict 'sent'); 5 ports for detector robustness",
        },
        FwCase {
            id: "detect-conn-abnormal",
            group: G::Detection,
            bundle: Detection,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: TcpBurst {
                dport: 9100,
                count: 5,
            },
            expect_enforce: Blocked,
            expect_event: event_d(
                "ConnectionAbnormal",
                "Block",
                "tcp",
                None,
                Some(9100),
                "translation layer --tcp state unnormal",
            ),
            skip: None,
            notes: "5 distinct flows (fresh source ports) to one dst port -> ConnectionAbnormal (same dst port 4th hit across flows)",
        },
        FwCase {
            id: "detect-below-threshold",
            group: G::Detection,
            bundle: Detection,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: TcpScan {
                dports: vec![9201, 9202],
            },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Negative: only 2 distinct ports -> sub-threshold -> no event (blocked, no escalation)",
        },
        // --- TRAFFIC statistics ---
        FwCase {
            id: "traffic-global",
            group: G::Traffic,
            bundle: Traffic,
            origin: Peer,
            uid: false,
            sport: None,
            listen: vec![],
            traffic: UdpVolume {
                dport: 5301,
                count: 200,
            },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Allowed volume bumps global ingress counters and a traffic window",
        },
        FwCase {
            id: "traffic-per-app",
            group: G::Traffic,
            bundle: Traffic,
            origin: Target,
            uid: true,
            sport: None,
            listen: vec![],
            traffic: UdpVolume {
                dport: 5301,
                count: 200,
            },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Volume from the mapped UID attributes wifi bytes to an app window",
        },
        // --- PRIORITY (rule precedence) ---
        FwCase {
            id: "priority-later-wins",
            group: G::Match,
            bundle: Priority,
            origin: Peer,
            uid: false,
            sport: None,
            listen: listen(Target, "tcp", 8001),
            traffic: Tcp { dport: 8001 },
            expect_enforce: Blocked,
            expect_event: None,
            skip: None,
            notes: "Two rules on dport 8001 (Pass then Block): the later, higher-priority Block wins -> blocked",
        },
        FwCase {
            id: "priority-control-pass",
            group: G::Match,
            bundle: Priority,
            origin: Peer,
            uid: false,
            sport: None,
            listen: listen(Target, "tcp", 8002),
            traffic: Tcp { dport: 8002 },
            expect_enforce: Allowed,
            expect_event: None,
            skip: None,
            notes: "Control: dport 8002 has only a Pass rule -> allowed (proves the block above is rule-specific, not a side effect)",
        },
    ]
}

/// Bundle provisioning order for `run-all` / `run-group`.
pub fn bundle_order() -> &'static [Bundle] {
    &[
        Bundle::IngressTuple,
        Bundle::DefaultDeny,
        Bundle::DefaultAllow,
        Bundle::EgressTuple,
        Bundle::AppDeny,
        Bundle::AppAllow,
        Bundle::MatchFields,
        Bundle::Detection,
        Bundle::Traffic,
        Bundle::Priority,
    ]
}

/// Look up a case by id.
pub fn case_by_id(id: &str) -> Option<FwCase> {
    all_cases().into_iter().find(|case| case.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_ids_are_unique() {
        let cases = all_cases();
        let mut ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate case ids in catalog");
    }

    #[test]
    fn every_case_bundle_is_ordered() {
        for case in all_cases() {
            assert!(
                bundle_order().contains(&case.bundle),
                "{} uses an unordered bundle",
                case.id
            );
        }
    }

    #[test]
    fn group_strings_round_trip() {
        for group in [
            Group::Ingress,
            Group::Default,
            Group::Egress,
            Group::App,
            Group::Match,
            Group::Detection,
            Group::Traffic,
            Group::Monitor,
        ] {
            assert_eq!(Group::parse(group.as_str()).unwrap(), group);
        }
    }

    #[test]
    fn traffic_bundle_sets_cycle() {
        assert_eq!(traffic_cycle(Bundle::Traffic), Some(5));
        assert_eq!(traffic_cycle(Bundle::IngressTuple), None);
    }
}
