//! Command line surface for the fw-verify tool.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::agent::cli::AgentCommand;

/// Single-binary functional test tool for idps-fw.
#[derive(Debug, Parser)]
#[command(
    name = "fw-verify",
    about = "Functional test tool for idps-fw (runs on the device under test).",
    long_about = None,
    version
)]
pub struct Cli {
    /// Shared connection / runtime options.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// How thoroughly to confirm an event reached idps-server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportConfirm {
    /// Confirm via idps-fw local outbox state (`report_state = 'sent'`).
    Local,
    /// Additionally grep idps-server logcat for the received report.
    Server,
    /// Additionally poll the VSOC dashboard `/api/events` endpoint.
    Vsoc,
}

/// How firewall rules are delivered to idps-fw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Write the encrypted depot directly (Android device under test).
    Android,
    /// Deliver rules through the VSOC dashboard API (host).
    Host,
}

/// Shared options that apply to every device-touching subcommand.
///
/// Every option can also be set via a config file (`--config <file>`, lines of
/// `key = value`, `#` comments) or its `FWV_*` environment variable. Precedence:
/// command-line flag > environment variable > config file > built-in default.
#[derive(Debug, Clone, Args)]
pub struct GlobalArgs {
    /// Config file with `key = value` lines (keys match the long option names).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Rule delivery: `host` (via the VSOC API) or `android` (write the depot
    /// directly). Topology and execution are identical; only this differs.
    #[arg(long, env = "FWV_MODE", value_enum, default_value_t = Mode::Host, global = true)]
    pub mode: Mode,

    /// Network namespace holding the PEER veth end.
    #[arg(long, env = "FWV_PEER_NETNS", default_value = "fwpeer", hide = true)]
    pub peer_netns: String,

    /// Host mode: VSOC dashboard client certificate (mTLS) for rule delivery.
    #[arg(long, env = "FWV_VSOC_CERT", hide = true)]
    pub vsoc_cert: Option<String>,

    /// Host mode: VSOC dashboard client key (mTLS) for rule delivery.
    #[arg(long, env = "FWV_VSOC_KEY", hide = true)]
    pub vsoc_key: Option<String>,

    /// Host mode: VSOC dashboard CA certificate (mTLS, optional).
    #[arg(long, env = "FWV_VSOC_CACERT", hide = true)]
    pub vsoc_cacert: Option<String>,

    /// TARGET network interface (the idps-fw-monitored veth end).
    #[arg(long, env = "FWV_TARGET_IFACE", default_value = "fwt0", hide = true)]
    pub target_iface: String,

    /// PEER network interface (the veth end inside the namespace).
    #[arg(long, env = "FWV_PEER_IFACE", default_value = "fwp0", hide = true)]
    pub peer_iface: String,

    /// TARGET IPv4 (auto-detected from the interface when omitted).
    #[arg(long, env = "FWV_TARGET_IP", hide = true)]
    pub target_ip: Option<IpAddr>,

    /// PEER IPv4 (auto-detected from the interface when omitted).
    #[arg(long, env = "FWV_PEER_IP", hide = true)]
    pub peer_ip: Option<IpAddr>,

    /// `/24` network prefix length used when staging the veth topology.
    #[arg(long, env = "FWV_VETH_PREFIX", default_value_t = 24, hide = true)]
    pub veth_prefix: u8,

    /// Access-control domain id.
    #[arg(long, env = "FWV_ACD", default_value_t = 1, hide = true)]
    pub acd: i32,

    /// Firewall rule function id.
    #[arg(long, env = "FWV_FUN_FW", default_value_t = 1, hide = true)]
    pub fun_fw: i32,

    /// Traffic policy function id.
    #[arg(long, env = "FWV_FUN_TRAFFIC", default_value_t = 4, hide = true)]
    pub fun_traffic: i32,

    /// Deadline waiting for idps-fw to load a freshly provisioned rule.
    #[arg(
        long,
        env = "FWV_RELOAD_TIMEOUT_SECS",
        default_value_t = 30,
        hide = true
    )]
    pub reload_timeout_secs: u64,

    /// Settle time after traffic before reading firewall_event.
    #[arg(long, env = "FWV_EVENT_SETTLE_MS", default_value_t = 1500, hide = true)]
    pub event_settle_ms: u64,

    /// How thoroughly to confirm upload to idps-server.
    #[arg(
        long,
        env = "FWV_REPORT_CONFIRM",
        value_enum,
        default_value_t = ReportConfirm::Local,
        hide = true
    )]
    pub report_confirm: ReportConfirm,

    /// VSOC dashboard base URL (for `--report-confirm vsoc`).
    #[arg(long, env = "FWV_VSOC_URL", hide = true)]
    pub vsoc_url: Option<String>,

    /// idps-fw binary path/name on the device.
    #[arg(long, env = "FWV_IDPS_FW", default_value = "idps-fw", hide = true)]
    pub idps_fw: String,

    /// idps-fw SQLite state database path on the TARGET.
    #[arg(
        long,
        env = "FWV_STATE_DB",
        default_value = "/data/idd/idps-fw/state.sqlite3",
        hide = true
    )]
    pub state_db: String,

    /// UID used for app/UID-policy and per-app traffic cases.
    #[arg(long, env = "FWV_APP_UID", default_value_t = 2000, hide = true)]
    pub app_uid: u32,

    /// Identity key mapped to `app_uid` via idps-fw `identity_overrides`.
    #[arg(
        long,
        env = "FWV_APP_IDENTITY_KEY",
        default_value = "com.demo.browser",
        hide = true
    )]
    pub app_identity_key: String,

    /// Package name reported for the app/UID identity.
    #[arg(
        long,
        env = "FWV_APP_PKG",
        default_value = "com.demo.browser",
        hide = true
    )]
    pub app_pkg: String,

    /// App display name reported for the app/UID identity.
    #[arg(long, env = "FWV_APP_NAME", default_value = "Browser", hide = true)]
    pub app_name: String,

    /// Write the JSON report to this file.
    #[arg(long)]
    pub report: Option<PathBuf>,

    /// Print the JSON report to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Stage the veth/netns topology and write the idps-fw + fw-verify configs.
    SetupEnv,
    /// Tear down the topology, restore the idps-fw config, remove generated files.
    CleanEnv,
    /// Verify the topology, idps-fw responsiveness, and rule delivery path.
    Preflight,
    /// List the case catalog.
    List,
    /// Run one case by id.
    Run {
        /// Case id.
        id: String,
    },
    /// Run all cases in a group.
    RunGroup {
        /// Group name (ingress|default|egress|app|match|detection|traffic).
        group: String,
    },
    /// Run the entire catalog, batching by bundle.
    RunAll,
    /// Provision a raw firewall rule file (and optional traffic cycle).
    #[command(hide = true)]
    Provision {
        /// Plaintext firewall rule file to provision.
        rules_file: PathBuf,
        /// Also set the traffic policy cycle (fun=4) to this many seconds.
        #[arg(long)]
        traffic_cycle: Option<u64>,
    },
    /// Restore depot rules to repo defaults by removing provisioned files.
    #[command(hide = true)]
    ResetRules,
    /// Print the TARGET idps-fw health snapshot.
    #[command(hide = true)]
    Health,
    /// Print the TARGET idps-fw statistics snapshot.
    #[command(hide = true)]
    Stats,
    /// Hidden self-invoked worker (traffic/listener/depot/event queries).
    #[command(hide = true, subcommand)]
    Agent(AgentCommand),
}
