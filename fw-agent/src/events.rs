//! `dump-events` and `report-status` — read the idps-fw SQLite state.
//!
//! The `firewall_event` table stores `event_type` and `action` as
//! `serde_json::to_string(enum)` values — i.e. JSON-quoted strings such as
//! `"Block"`. We strip the quotes here so the orchestrator receives clean
//! enum names. The database is opened read-write (without create) because an
//! idps-fw WAL database cannot always be opened strictly read-only.

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::cli::{EventQueryArgs, ReportQueryArgs};

fn open_db(args: &EventQueryArgs) -> Result<Connection> {
    Connection::open_with_flags(&args.db, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("failed to open idps-fw state db {}", args.db.display()))
}

/// Strip the surrounding JSON quotes from a stored enum column.
fn unquote(value: &str) -> String {
    serde_json::from_str::<String>(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::unquote;

    #[test]
    fn unquote_strips_json_quotes() {
        assert_eq!(unquote("\"Block\""), "Block");
        assert_eq!(unquote("\"PortScan\""), "PortScan");
        assert_eq!(unquote("plain"), "plain");
    }
}

pub fn dump_events(args: &EventQueryArgs) -> Result<()> {
    let connection = open_db(args)?;
    let mut statement = connection
        .prepare(
            "SELECT event_id, event_time_ms, event_type, action, app_id, ifindex, \
             src_ip, src_port, dst_ip, dst_port, proto, rule_id, detail, report_state \
             FROM firewall_event WHERE event_time_ms > ?1 ORDER BY event_time_ms ASC",
        )
        .context("failed to prepare firewall_event query")?;

    let rows = statement
        .query_map([args.since], |row| {
            Ok(json!({
                "event_id": row.get::<_, String>(0)?,
                "event_time_ms": row.get::<_, i64>(1)?,
                "event_type": unquote(&row.get::<_, String>(2)?),
                "action": unquote(&row.get::<_, String>(3)?),
                "app_id": row.get::<_, Option<i64>>(4)?,
                "ifindex": row.get::<_, Option<i64>>(5)?,
                "src_ip": row.get::<_, String>(6)?,
                "src_port": row.get::<_, i64>(7)?,
                "dst_ip": row.get::<_, String>(8)?,
                "dst_port": row.get::<_, i64>(9)?,
                "proto": row.get::<_, String>(10)?,
                "rule_id": row.get::<_, Option<i64>>(11)?,
                "detail": row.get::<_, String>(12)?,
                "report_state": row.get::<_, String>(13)?,
            }))
        })
        .context("failed to query firewall_event")?
        .collect::<rusqlite::Result<Vec<Value>>>()
        .context("failed to read firewall_event rows")?;

    println!(
        "{}",
        json!({ "since": args.since, "count": rows.len(), "events": rows })
    );
    Ok(())
}

/// Dump side-channel monitor reports from the outbox (events 102/231/303),
/// optionally filtered by `report_type`, newer than `since` (epoch ms).
pub fn dump_reports(args: &ReportQueryArgs) -> Result<()> {
    let connection = Connection::open_with_flags(&args.db, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("failed to open idps-fw state db {}", args.db.display()))?;
    let sql = "SELECT report_id, report_type, payload, created_at_ms \
               FROM report_outbox \
               WHERE created_at_ms > ?1 AND (?2 IS NULL OR report_type = ?2) \
               ORDER BY created_at_ms ASC";
    let mut statement = connection
        .prepare(sql)
        .context("failed to prepare report_outbox query")?;
    let type_filter = args.report_type.clone();
    let rows = statement
        .query_map(rusqlite::params![args.since, type_filter], |row| {
            let payload: String = row.get(2)?;
            let parsed: Value = serde_json::from_str(&payload).unwrap_or(Value::String(payload));
            Ok(json!({
                "report_id": row.get::<_, String>(0)?,
                "report_type": row.get::<_, String>(1)?,
                "payload": parsed,
                "created_at_ms": row.get::<_, i64>(3)?,
            }))
        })
        .context("failed to query report_outbox")?
        .collect::<rusqlite::Result<Vec<Value>>>()
        .context("failed to read report_outbox rows")?;

    println!(
        "{}",
        json!({ "since": args.since, "count": rows.len(), "reports": rows })
    );
    Ok(())
}

pub fn report_status(args: &EventQueryArgs) -> Result<()> {
    let connection = open_db(args)?;

    // Per-event report_state for events newer than `since`.
    let mut event_stmt = connection
        .prepare(
            "SELECT event_id, event_time_ms, event_type, report_state \
             FROM firewall_event WHERE event_time_ms > ?1 ORDER BY event_time_ms ASC",
        )
        .context("failed to prepare report_state query")?;
    let events = event_stmt
        .query_map([args.since], |row| {
            Ok(json!({
                "event_id": row.get::<_, String>(0)?,
                "event_time_ms": row.get::<_, i64>(1)?,
                "event_type": unquote(&row.get::<_, String>(2)?),
                "report_state": row.get::<_, String>(3)?,
            }))
        })
        .context("failed to query report_state")?
        .collect::<rusqlite::Result<Vec<Value>>>()
        .context("failed to read report_state rows")?;

    let sent = events
        .iter()
        .filter(|e| e["report_state"] == "sent")
        .count();
    let pending = events
        .iter()
        .filter(|e| e["report_state"] == "pending")
        .count();

    // Outbox aggregate (state, count, worst retry, last error).
    let mut outbox_stmt = connection
        .prepare(
            "SELECT state, COUNT(*), MAX(retry_count), MAX(last_error) \
             FROM report_outbox GROUP BY state",
        )
        .context("failed to prepare report_outbox query")?;
    let outbox = outbox_stmt
        .query_map([], |row| {
            Ok(json!({
                "state": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?,
                "max_retry": row.get::<_, Option<i64>>(2)?,
                "last_error": row.get::<_, Option<String>>(3)?,
            }))
        })
        .context("failed to query report_outbox")?
        .collect::<rusqlite::Result<Vec<Value>>>()
        .context("failed to read report_outbox rows")?;

    println!(
        "{}",
        json!({
            "since": args.since,
            "events_total": events.len(),
            "events_sent": sent,
            "events_pending": pending,
            "events": events,
            "outbox": outbox,
        })
    );
    Ok(())
}
