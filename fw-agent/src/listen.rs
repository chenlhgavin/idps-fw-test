//! `listen` — short-lived TCP/UDP listener.
//!
//! Started on the side that should *accept* traffic for a test case so that an
//! allowed connection actually completes (distinguishing Allowed from a bare
//! "connection refused" when nothing is listening). Exits after `duration_secs`.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;

use crate::cli::{ListenArgs, ListenProto};

const POLL: Duration = Duration::from_millis(100);

pub fn run(args: &ListenArgs) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    println!(
        "{}",
        json!({
            "status": "listening",
            "proto": format!("{:?}", args.proto).to_lowercase(),
            "port": args.port,
            "duration_secs": args.duration_secs,
        })
    );

    match args.proto {
        ListenProto::Tcp => listen_tcp(args.port, deadline, args.hold),
        ListenProto::Udp => listen_udp(args.port, deadline),
    }
}

fn listen_tcp(port: u16, deadline: Instant, hold: bool) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .with_context(|| format!("failed to bind tcp listener on {port}"))?;
    listener
        .set_nonblocking(true)
        .context("failed to set tcp listener nonblocking")?;

    // In hold mode retain every accepted connection so it stays ESTABLISHED for
    // the connection-count monitors; otherwise echo one read and move on.
    let mut held = Vec::new();
    let mut accepted: u64 = 0;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                accepted += 1;
                if hold {
                    held.push(stream);
                    continue;
                }
                let mut buf = [0_u8; 256];
                let _ = stream.set_read_timeout(Some(POLL));
                if let Ok(read) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..read]);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL);
            }
            Err(error) => return Err(error).context("tcp accept failed"),
        }
    }
    drop(held);
    println!("{}", json!({ "status": "closed", "accepted": accepted }));
    Ok(())
}

fn listen_udp(port: u16, deadline: Instant) -> Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
        .with_context(|| format!("failed to bind udp listener on {port}"))?;
    socket
        .set_read_timeout(Some(POLL))
        .context("failed to set udp read timeout")?;

    let mut echoed: u64 = 0;
    let mut buf = [0_u8; 2048];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((read, peer)) => {
                echoed += 1;
                let _ = socket.send_to(&buf[..read], peer);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error).context("udp recv failed"),
        }
    }
    println!("{}", json!({ "status": "closed", "echoed": echoed }));
    Ok(())
}
