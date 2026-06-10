//! `provision-rule` — write an encrypted rule into the idps-server depot.
//!
//! Reuses idps-server's `RuleDepot` and the same VIN/DSN keystore derivation
//! the server itself performs at startup, so the written file is byte-for-byte
//! something idps-server will decrypt and serve to idps-fw on its next poll.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use idps_core::config::loader::IdpsConfig;
use idps_core::crypto::hash::sha256_hex;
use idps_core::crypto::keystore::KeyStore;
use idps_core::device::info::collect_device_info_with_config;
use idps_server::rule::depot::{RuleDepot, RuleMetadata};
use serde_json::json;

use crate::cli::ProvisionArgs;

pub fn run(args: &ProvisionArgs) -> Result<()> {
    let rule_bytes = fs::read(&args.input)
        .with_context(|| format!("failed to read rule file {}", args.input.display()))?;

    let loaded = IdpsConfig::load_runtime(&args.config)
        .with_context(|| format!("failed to load config {}", args.config.display()))?;
    let config = loaded.config;

    let device =
        collect_device_info_with_config(&config).context("failed to collect device info")?;
    let keystore = KeyStore::open(&args.keystore)
        .with_context(|| format!("failed to open keystore {}", args.keystore.display()))?;
    let key = keystore
        .resolve_keys(&device.vin, &device.dsn)
        .context("failed to resolve runtime AES key")?
        .map(|keys| keys.key);
    let key_present = key.is_some();

    let depot = RuleDepot::new(
        Path::new(&config.rule.depot_path),
        Path::new(&config.rule.default_rules_path),
        key,
        loaded.aes_key,
        loaded.aes_iv,
    )
    .context("failed to open rule depot")?;

    let prot_ver = args.prot_ver.max(1);
    let previous = depot
        .load_metadata_for_protocol(args.acd, args.fun, prot_ver)
        .unwrap_or_default();
    let ver = args.ver.unwrap_or(previous.ver.saturating_add(1));
    let sha256 = sha256_hex(&rule_bytes);
    let meta = RuleMetadata {
        ver,
        rule_ver: ver,
        prot_ver,
        major_ver: previous.major_ver.max(1),
        minor_ver: previous.minor_ver,
        sha256: sha256.clone(),
        sign: String::new(),
    };

    depot
        .save_rule(args.acd, args.fun, &rule_bytes, &meta)
        .context("failed to write depot rule")?;

    let path = format!(
        "{}/{}-{}-{}.rule",
        config.rule.depot_path.trim_end_matches('/'),
        args.acd,
        args.fun,
        prot_ver,
    );
    let out = json!({
        "acd": args.acd,
        "fun": args.fun,
        "prot_ver": prot_ver,
        "ver": ver,
        "sha256": sha256,
        "bytes": rule_bytes.len(),
        "path": path,
        "key_present": key_present,
    });
    println!("{out}");
    Ok(())
}
