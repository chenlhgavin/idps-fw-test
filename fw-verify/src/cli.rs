//! Command line surface for the fw-verify orchestrator.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Two-device WiFi functional test orchestrator for idps-fw.
#[derive(Debug, Parser)]
#[command(name = "fw-verify", about, version)]
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

/// Where the workers run and how rules are delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Two Android phones over adb; rules written directly into the depot.
    Android,
    /// Local host with a veth/netns peer; rules delivered through the VSOC API.
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

    /// Execution mode: `android` (two phones over adb) or `host` (local
    /// veth/netns, rules delivered via the VSOC API).
    #[arg(long, env = "FWV_MODE", value_enum, default_value_t = Mode::Android)]
    pub mode: Mode,

    /// adb serial of the TARGET device (android mode; runs idps-fw + idps-server).
    #[arg(long, env = "FWV_TARGET")]
    pub target_serial: Option<String>,

    /// adb serial of the PEER device (android mode; traffic source/sink).
    #[arg(long, env = "FWV_PEER")]
    pub peer_serial: Option<String>,

    /// Host mode: network namespace holding the PEER veth end.
    #[arg(long, env = "FWV_PEER_NETNS", default_value = "fwpeer")]
    pub peer_netns: String,

    /// Host mode: VSOC dashboard client certificate (mTLS) for rule delivery.
    #[arg(long, env = "FWV_VSOC_CERT")]
    pub vsoc_cert: Option<String>,

    /// Host mode: VSOC dashboard client key (mTLS) for rule delivery.
    #[arg(long, env = "FWV_VSOC_KEY")]
    pub vsoc_key: Option<String>,

    /// Host mode: VSOC dashboard CA certificate (mTLS, optional).
    #[arg(long, env = "FWV_VSOC_CACERT")]
    pub vsoc_cacert: Option<String>,

    /// TARGET network interface.
    #[arg(long, env = "FWV_TARGET_IFACE", default_value = "wlan0")]
    pub target_iface: String,

    /// PEER network interface.
    #[arg(long, env = "FWV_PEER_IFACE", default_value = "wlan0")]
    pub peer_iface: String,

    /// TARGET IPv4 (auto-detected from the interface when omitted).
    #[arg(long, env = "FWV_TARGET_IP")]
    pub target_ip: Option<IpAddr>,

    /// PEER IPv4 (auto-detected from the interface when omitted).
    #[arg(long, env = "FWV_PEER_IP")]
    pub peer_ip: Option<IpAddr>,

    /// Access-control domain id.
    #[arg(long, env = "FWV_ACD", default_value_t = 1)]
    pub acd: i32,

    /// Firewall rule function id.
    #[arg(long, env = "FWV_FUN_FW", default_value_t = 1)]
    pub fun_fw: i32,

    /// Traffic policy function id.
    #[arg(long, env = "FWV_FUN_TRAFFIC", default_value_t = 4)]
    pub fun_traffic: i32,

    /// Deadline waiting for idps-fw to load a freshly provisioned rule.
    #[arg(long, env = "FWV_RELOAD_TIMEOUT_SECS", default_value_t = 30)]
    pub reload_timeout_secs: u64,

    /// Settle time after traffic before reading firewall_event.
    #[arg(long, env = "FWV_EVENT_SETTLE_MS", default_value_t = 1500)]
    pub event_settle_ms: u64,

    /// How thoroughly to confirm upload to idps-server.
    #[arg(long, env = "FWV_REPORT_CONFIRM", value_enum, default_value_t = ReportConfirm::Local)]
    pub report_confirm: ReportConfirm,

    /// VSOC dashboard base URL (for `--report-confirm vsoc`).
    #[arg(long, env = "FWV_VSOC_URL")]
    pub vsoc_url: Option<String>,

    /// fw-agent binary path/name on device.
    #[arg(long, env = "FWV_FW_AGENT", default_value = "fw-agent")]
    pub fw_agent: String,

    /// idps-fw binary path/name on device.
    #[arg(long, env = "FWV_IDPS_FW", default_value = "idps-fw")]
    pub idps_fw: String,

    /// idps-fw SQLite state database path on the TARGET.
    #[arg(
        long,
        env = "FWV_STATE_DB",
        default_value = "/data/idd/idps-fw/state.sqlite3"
    )]
    pub state_db: String,

    /// UID used for app/UID-policy and per-app traffic cases.
    #[arg(long, env = "FWV_APP_UID", default_value_t = 2000)]
    pub app_uid: u32,

    /// Identity key mapped to `app_uid` via idps-fw `identity_overrides`.
    #[arg(long, env = "FWV_APP_IDENTITY_KEY", default_value = "com.demo.browser")]
    pub app_identity_key: String,

    /// Package name reported for the app/UID identity.
    #[arg(long, env = "FWV_APP_PKG", default_value = "com.demo.browser")]
    pub app_pkg: String,

    /// App display name reported for the app/UID identity.
    #[arg(long, env = "FWV_APP_NAME", default_value = "Browser")]
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
    /// Verify both devices, idps-fw responsiveness, and fw-agent presence.
    Preflight,
    /// Push short-interval config and restart the daemons for fast tests.
    ApplyFastProfile,
    /// Restore the default daemon config and restart.
    RestoreProfile,
    /// Create the TARGET keystore if missing so idps-server has a runtime key.
    EnsureKeystore {
        /// Explicit VIN (defaults to the device identity, then a test VIN).
        #[arg(long)]
        vin: Option<String>,
        /// Explicit DSN (defaults to the device identity, then a test DSN).
        #[arg(long)]
        dsn: Option<String>,
    },
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
    Provision {
        /// Plaintext firewall rule file to provision.
        rules_file: PathBuf,
        /// Also set the traffic policy cycle (fun=4) to this many seconds.
        #[arg(long)]
        traffic_cycle: Option<u64>,
    },
    /// Restore depot rules to repo defaults by removing provisioned files.
    ResetRules,
    /// Print the TARGET idps-fw health snapshot.
    Health,
    /// Print the TARGET idps-fw statistics snapshot.
    Stats,
}
