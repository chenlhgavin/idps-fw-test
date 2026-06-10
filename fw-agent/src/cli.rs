//! Command line surface for the on-device fw-agent worker.
//!
//! Every subcommand prints a single JSON object to stdout so the host-side
//! `fw-verify` orchestrator can parse the result over `adb shell`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// On-device worker for idps-fw functional tests.
#[derive(Debug, Parser)]
#[command(name = "fw-agent", about, version)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write an encrypted firewall/traffic rule into the idps-server depot.
    ProvisionRule(ProvisionArgs),
    /// Dump `firewall_event` rows newer than a timestamp as JSON.
    DumpEvents(EventQueryArgs),
    /// Report upload state for recent events (confirms delivery to idps-server).
    ReportStatus(EventQueryArgs),
    /// Generate OS-socket traffic toward a target and report the outcome.
    Traffic(TrafficArgs),
    /// Run a short-lived TCP/UDP listener so allowed connections truly succeed.
    Listen(ListenArgs),
    /// Open many concurrent TCP connections and hold them (TCP connection-count monitors).
    ConnFlood(ConnFloodArgs),
    /// Send gratuitous ARP replies for an IP (ARP-spoof detection, event 303).
    ArpSpoof(ArpSpoofArgs),
    /// Dump side-channel monitor reports (events 102/231/303) from the outbox.
    DumpReports(ReportQueryArgs),
    /// Print the device wall clock as epoch milliseconds (event watermark).
    Now,
}

/// `provision-rule` arguments.
#[derive(Debug, Args)]
pub struct ProvisionArgs {
    /// Access-control domain id.
    #[arg(long, default_value_t = 1)]
    pub acd: i32,

    /// Function id (1 = firewall, 4 = traffic policy).
    #[arg(long, default_value_t = 1)]
    pub fun: i32,

    /// Protocol version.
    #[arg(long, default_value_t = 1)]
    pub prot_ver: i32,

    /// Explicit rule version. When omitted the current depot version is bumped by one.
    #[arg(long)]
    pub ver: Option<i32>,

    /// Plaintext rule file to encrypt and store.
    #[arg(long)]
    pub input: PathBuf,

    /// idps-server runtime config path (provides depot/default paths + shipped keys).
    #[arg(long, default_value = "/etc/idd/idps.yaml")]
    pub config: PathBuf,

    /// Keystore directory used to derive the runtime AES key from VIN/DSN.
    #[arg(long, default_value = "/data/idd/keys")]
    pub keystore: PathBuf,
}

/// Shared arguments for the event/report queries.
#[derive(Debug, Args)]
pub struct EventQueryArgs {
    /// idps-fw SQLite state database.
    #[arg(long, default_value = "/data/idd/idps-fw/state.sqlite3")]
    pub db: PathBuf,

    /// Only consider events with `event_time_ms` strictly greater than this.
    #[arg(long, default_value_t = 0)]
    pub since: i64,
}

/// Transport for generated traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Proto {
    /// TCP connect attempt.
    Tcp,
    /// UDP datagram probe.
    Udp,
    /// ICMP request.
    Icmp,
}

/// ICMP message kind (for `proto icmp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IcmpKind {
    /// Echo request (type 8).
    Echo,
    /// Timestamp request (type 13) — vendor probe event 232.
    Timestamp,
}

/// `traffic` arguments.
#[derive(Debug, Args)]
pub struct TrafficArgs {
    /// Transport protocol.
    #[arg(value_enum)]
    pub proto: Proto,

    /// Destination IP address.
    #[arg(long)]
    pub to: std::net::IpAddr,

    /// Destination port (ignored for ICMP).
    #[arg(long)]
    pub dport: Option<u16>,

    /// Comma-separated destination ports for a port-scan burst (overrides `--dport`).
    #[arg(long)]
    pub dports: Option<String>,

    /// Bind the local source port (TCP/UDP) before sending.
    #[arg(long)]
    pub sport: Option<u16>,

    /// Number of attempts (per port). Used for connection-abnormality bursts.
    #[arg(long, default_value_t = 1)]
    pub count: u32,

    /// Delay between attempts in milliseconds.
    #[arg(long, default_value_t = 0)]
    pub interval_ms: u64,

    /// Per-attempt timeout in milliseconds.
    #[arg(long, default_value_t = 1000)]
    pub timeout_ms: u64,

    /// For UDP/ICMP, wait for an echo/reply to judge allowed vs blocked.
    #[arg(long, default_value_t = false)]
    pub await_reply: bool,

    /// For TCP, send a bare FIN packet via a raw socket instead of a connect
    /// (needs root). Used to exercise FIN-only port-scan detection.
    #[arg(long, default_value_t = false)]
    pub fin_only: bool,

    /// For ICMP, which request kind to send (echo or timestamp).
    #[arg(long, value_enum, default_value_t = IcmpKind::Echo)]
    pub icmp_type: IcmpKind,
}

/// `conn-flood` arguments: open and hold many concurrent TCP connections.
#[derive(Debug, Args)]
pub struct ConnFloodArgs {
    /// Destination IP address.
    #[arg(long)]
    pub to: std::net::IpAddr,

    /// Destination port (a held listener must accept here).
    #[arg(long)]
    pub dport: u16,

    /// Number of concurrent connections to establish.
    #[arg(long, default_value_t = 60)]
    pub count: u32,

    /// How long to hold the connections open, in seconds.
    #[arg(long, default_value_t = 15)]
    pub hold_secs: u64,

    /// Per-connection connect timeout in milliseconds.
    #[arg(long, default_value_t = 2000)]
    pub timeout_ms: u64,
}

/// `arp-spoof` arguments: emit gratuitous ARP replies for an IP.
#[derive(Debug, Args)]
pub struct ArpSpoofArgs {
    /// Interface to send on (e.g. the peer veth `fwp0`).
    #[arg(long)]
    pub iface: String,

    /// The IPv4 address to falsely claim (sender protocol address).
    #[arg(long)]
    pub claim_ip: std::net::Ipv4Addr,

    /// Number of gratuitous ARP replies to send.
    #[arg(long, default_value_t = 5)]
    pub count: u32,
}

/// Shared arguments for the side-channel report query.
#[derive(Debug, Args)]
pub struct ReportQueryArgs {
    /// idps-fw SQLite state database.
    #[arg(long, default_value = "/data/idd/idps-fw/state.sqlite3")]
    pub db: PathBuf,

    /// Only consider outbox rows with `created_at_ms` strictly greater than this.
    #[arg(long, default_value_t = 0)]
    pub since: i64,

    /// Optional report-type filter (e.g. `tcp_conn_total`, `tcp_conn_per_ip`, `arp_spoof`).
    #[arg(long)]
    pub report_type: Option<String>,
}

/// Transport for the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ListenProto {
    /// TCP accept loop.
    Tcp,
    /// UDP echo loop.
    Udp,
}

/// `listen` arguments.
#[derive(Debug, Args)]
pub struct ListenArgs {
    /// Transport protocol.
    #[arg(value_enum)]
    pub proto: ListenProto,

    /// Port to bind.
    #[arg(long)]
    pub port: u16,

    /// How long to keep the listener open.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// Retain accepted TCP connections (do not close them) so they stay
    /// ESTABLISHED for the connection-count monitors.
    #[arg(long, default_value_t = false)]
    pub hold: bool,
}
