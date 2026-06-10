//! `conn-flood` — establish and hold many concurrent TCP connections.
//!
//! Drives the idps-fw connection-count monitors: the total established count
//! (event 102) and the per-destination-IP threshold breach (event 231). A
//! held listener on the target must accept and retain the connections so they
//! stay ESTABLISHED for the duration.

use std::net::{SocketAddr, TcpStream};
use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;

use crate::cli::ConnFloodArgs;

pub fn run(args: &ConnFloodArgs) -> Result<()> {
    let dst = SocketAddr::new(args.to, args.dport);
    let timeout = Duration::from_millis(args.timeout_ms);
    let mut held: Vec<TcpStream> = Vec::new();
    let mut failed = 0_u32;

    for _ in 0..args.count {
        match TcpStream::connect_timeout(&dst, timeout) {
            Ok(stream) => held.push(stream),
            Err(_) => failed += 1,
        }
    }

    let established = held.len();
    // Keep the sockets open so the kernel reports them as ESTABLISHED while the
    // idps-fw monitor samples /proc/net/tcp (its cycle is several seconds).
    sleep(Duration::from_secs(args.hold_secs));
    drop(held);

    println!(
        "{}",
        json!({
            "to": args.to.to_string(),
            "dport": args.dport,
            "requested": args.count,
            "established": established,
            "failed": failed,
            "held_secs": args.hold_secs,
        })
    );
    Ok(())
}
