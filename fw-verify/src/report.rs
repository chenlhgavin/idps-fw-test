//! Result reporting: a human table plus an optional JSON document.

use anyhow::{Context, Result};
use serde_json::json;

use crate::cli::GlobalArgs;
use crate::config::RunConfig;
use crate::verify::CaseResult;

/// Print the result table, optionally emit JSON, and return the failure count.
pub fn emit(global: &GlobalArgs, cfg: &RunConfig, results: &[CaseResult]) -> Result<usize> {
    println!(
        "{:<26} {:<9} {:<7} {:<8} {:<8} DETAIL",
        "CASE", "GROUP", "RESULT", "ENFORCE", "EVENT"
    );
    println!("{}", "-".repeat(96));
    for case in results {
        println!(
            "{:<26} {:<9} {:<7} {:<8} {:<8} {}",
            case.id,
            case.group,
            case.result,
            case.enforce_observed,
            case.event_observed,
            case.detail
        );
    }

    let passed = results.iter().filter(|c| c.result == "PASS").count();
    let failed = results.iter().filter(|c| c.result == "FAIL").count();
    let skipped = results.iter().filter(|c| c.result == "SKIP").count();
    println!(
        "\nsummary: total={} passed={} failed={} skipped={}",
        results.len(),
        passed,
        failed,
        skipped
    );

    let document = json!({
        "target": cfg.target_serial,
        "peer": cfg.peer_serial,
        "target_ip": cfg.target_ip.to_string(),
        "peer_ip": cfg.peer_ip.to_string(),
        "cases": results,
        "summary": {
            "total": results.len(),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        },
    });

    if global.json {
        println!("{}", serde_json::to_string_pretty(&document)?);
    }
    if let Some(path) = &global.report {
        std::fs::write(path, serde_json::to_string_pretty(&document)?)
            .with_context(|| format!("failed to write report {}", path.display()))?;
        println!("report written to {}", path.display());
    }

    Ok(failed)
}
