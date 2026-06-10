//! `traffic` — OS-socket traffic generation.
//!
//! Uses real kernel sockets (so frames traverse the Wi-Fi AP normally) to make
//! enforcement observable: a blocked flow times out, an allowed flow succeeds,
//! and an unreachable/no-listener flow is refused. Port-scan and
//! connection-abnormality bursts are produced by firing several short-timeout
//! attempts within one second.

use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};

use crate::cli::{Proto, TrafficArgs};

/// Result of a single attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Success,
    Timeout,
    Refused,
    Denied,
    Sent,
    Other,
}

#[derive(Debug, Default)]
struct Tally {
    success: u32,
    timeout: u32,
    refused: u32,
    denied: u32,
    sent: u32,
    other: u32,
}

impl Tally {
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Success => self.success += 1,
            Outcome::Timeout => self.timeout += 1,
            Outcome::Refused => self.refused += 1,
            Outcome::Denied => self.denied += 1,
            Outcome::Sent => self.sent += 1,
            Outcome::Other => self.other += 1,
        }
    }

    fn attempts(&self) -> u32 {
        self.success + self.timeout + self.refused + self.denied + self.sent + self.other
    }

    fn verdict(&self) -> &'static str {
        // A drop (timeout) and a cgroup policy deny (EPERM) both mean enforced.
        if self.success > 0 {
            "allowed"
        } else if self.timeout > 0 || self.denied > 0 {
            "blocked"
        } else if self.refused > 0 {
            "refused"
        } else if self.sent > 0 {
            "sent"
        } else {
            "unknown"
        }
    }
}

fn unspecified(domain: Domain) -> SocketAddr {
    if domain == Domain::IPV4 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

fn classify_io(error: &std::io::Error) -> Outcome {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Outcome::Timeout,
        std::io::ErrorKind::ConnectionRefused => Outcome::Refused,
        // A cgroup connect-hook policy deny surfaces as EPERM.
        std::io::ErrorKind::PermissionDenied => Outcome::Denied,
        _ => Outcome::Other,
    }
}

fn tcp_attempt(dst: SocketAddr, sport: Option<u16>, timeout: Duration) -> Result<Outcome> {
    let domain = Domain::for_address(dst);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("failed to create tcp socket")?;
    if let Some(port) = sport {
        socket
            .set_reuse_address(true)
            .context("failed to set reuse_address")?;
        let mut bind_addr = unspecified(domain);
        bind_addr.set_port(port);
        socket
            .bind(&bind_addr.into())
            .with_context(|| format!("failed to bind source port {port}"))?;
    }
    Ok(match socket.connect_timeout(&dst.into(), timeout) {
        Ok(()) => Outcome::Success,
        Err(error) => classify_io(&error),
    })
}

fn udp_attempt(
    dst: SocketAddr,
    sport: Option<u16>,
    timeout: Duration,
    await_reply: bool,
) -> Result<Outcome> {
    let bind = if dst.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), sport.unwrap_or(0))
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), sport.unwrap_or(0))
    };
    let socket = UdpSocket::bind(bind).context("failed to bind udp socket")?;
    socket
        .connect(dst)
        .context("failed to connect udp socket")?;
    socket
        .send(b"fw-agent-probe")
        .context("failed to send udp probe")?;
    if !await_reply {
        return Ok(Outcome::Sent);
    }
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set udp read timeout")?;
    let mut buf = [0_u8; 128];
    Ok(match socket.recv(&mut buf) {
        Ok(_) => Outcome::Success,
        Err(error) => classify_io(&error),
    })
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_icmp_echo(ident: u16, seq: u16) -> [u8; 16] {
    let mut packet = [0_u8; 16];
    packet[0] = 8; // echo request
    packet[4..6].copy_from_slice(&ident.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet[8..16].copy_from_slice(b"fwagentp");
    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn icmp_attempt(dst: IpAddr, ident: u16, seq: u16, timeout: Duration) -> Result<Outcome> {
    let IpAddr::V4(_) = dst else {
        return Err(anyhow!("icmp traffic currently supports IPv4 only"));
    };
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .context("failed to create raw icmp socket (needs root)")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set icmp read timeout")?;
    let packet = build_icmp_echo(ident, seq);
    let target = SocketAddr::new(dst, 0);
    socket
        .send_to(&packet, &target.into())
        .context("failed to send icmp echo")?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    match socket.recv(&mut buf) {
        Ok(received) => {
            // SAFETY: the kernel initialized the first `received` bytes of `buf`.
            let filled = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), received) };
            Ok(if is_matching_echo_reply(filled, ident) {
                Outcome::Success
            } else {
                Outcome::Other
            })
        }
        Err(error) => Ok(classify_io(&error)),
    }
}

/// Parse a raw IPv4 frame and check it is an ICMP echo reply for `ident`.
fn is_matching_echo_reply(frame: &[u8], ident: u16) -> bool {
    let Some(&first) = frame.first() else {
        return false;
    };
    let ihl = usize::from(first & 0x0f) * 4;
    let icmp = &frame[ihl.min(frame.len())..];
    icmp.len() >= 6
        && icmp[0] == 0 // echo reply
        && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
}

/// Resolve the local source IPv4 the kernel would route to `dst` (used for the
/// TCP pseudo-header checksum).
fn local_src_ipv4(dst: IpAddr) -> Result<Ipv4Addr> {
    let probe =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("failed to bind probe socket")?;
    probe
        .connect(SocketAddr::new(dst, 9))
        .context("failed to connect probe socket")?;
    match probe
        .local_addr()
        .context("failed to read probe local_addr")?
        .ip()
    {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(anyhow!("fin-only traffic currently supports IPv4 only")),
    }
}

/// Internet checksum over the TCP pseudo-header + TCP segment.
fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for octets in [src.octets(), dst.octets()] {
        sum += u32::from(u16::from_be_bytes([octets[0], octets[1]]));
        sum += u32::from(u16::from_be_bytes([octets[2], octets[3]]));
    }
    sum += u32::from(6_u16); // protocol = TCP
    sum += u32::from(tcp.len() as u16); // TCP length
    let mut chunks = tcp.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a 20-byte bare-FIN TCP segment (data offset 5, only the FIN flag set).
fn build_fin(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) -> [u8; 20] {
    let mut tcp = [0_u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    let off_flags: u16 = (5_u16 << 12) | 0x0001; // data offset 5 words, FIN
    tcp[12..14].copy_from_slice(&off_flags.to_be_bytes());
    tcp[14..16].copy_from_slice(&1024_u16.to_be_bytes()); // window
    let checksum = tcp_checksum(src, dst, &tcp);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    tcp
}

/// Send a single bare-FIN TCP packet via a raw socket (needs root).
fn fin_attempt(dst: SocketAddr, sport: Option<u16>, seq: u32) -> Result<Outcome> {
    let IpAddr::V4(dst_v4) = dst.ip() else {
        return Err(anyhow!("fin-only traffic currently supports IPv4 only"));
    };
    let src_v4 = local_src_ipv4(dst.ip())?;
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .context("failed to create raw tcp socket (needs root)")?;
    let packet = build_fin(src_v4, dst_v4, sport.unwrap_or(40000), dst.port(), seq);
    let target = SocketAddr::new(dst.ip(), 0);
    socket
        .send_to(&packet, &target.into())
        .context("failed to send tcp fin")?;
    Ok(Outcome::Sent)
}

pub fn run(args: &TrafficArgs) -> Result<()> {
    let timeout = Duration::from_millis(args.timeout_ms);
    let interval = Duration::from_millis(args.interval_ms);

    let ports: Vec<u16> = if let Some(list) = &args.dports {
        list.split(',')
            .filter(|item| !item.trim().is_empty())
            .map(|item| {
                item.trim()
                    .parse::<u16>()
                    .with_context(|| format!("invalid port `{item}`"))
            })
            .collect::<Result<_>>()?
    } else if let Some(port) = args.dport {
        vec![port]
    } else if args.proto == Proto::Icmp {
        vec![0]
    } else {
        return Err(anyhow!("--dport or --dports is required for tcp/udp"));
    };

    let mut tally = Tally::default();
    let ident = (std::process::id() & 0xffff) as u16;
    let mut seq: u16 = 0;
    let mut first = true;

    for &port in &ports {
        for _ in 0..args.count.max(1) {
            if !first && !interval.is_zero() {
                sleep(interval);
            }
            first = false;
            let outcome = match args.proto {
                Proto::Tcp if args.fin_only => {
                    seq = seq.wrapping_add(1);
                    fin_attempt(SocketAddr::new(args.to, port), args.sport, u32::from(seq))?
                }
                Proto::Tcp => tcp_attempt(SocketAddr::new(args.to, port), args.sport, timeout)?,
                Proto::Udp => udp_attempt(
                    SocketAddr::new(args.to, port),
                    args.sport,
                    timeout,
                    args.await_reply,
                )?,
                Proto::Icmp => {
                    seq = seq.wrapping_add(1);
                    icmp_attempt(args.to, ident, seq, timeout)?
                }
            };
            tally.record(outcome);
        }
    }

    let out = json!({
        "proto": format!("{:?}", args.proto).to_lowercase(),
        "to": args.to.to_string(),
        "ports": ports,
        "attempts": tally.attempts(),
        "success": tally.success,
        "timeout": tally.timeout,
        "refused": tally.refused,
        "denied": tally.denied,
        "sent": tally.sent,
        "other": tally.other,
        "verdict": tally.verdict(),
    });
    println!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{build_fin, build_icmp_echo, icmp_checksum, tcp_checksum, Tally};

    #[test]
    fn fin_packet_is_well_formed() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let packet = build_fin(src, dst, 40000, 9011, 1);
        assert_eq!(packet.len(), 20);
        let off_flags = u16::from_be_bytes([packet[12], packet[13]]);
        assert_eq!(off_flags >> 12, 5, "data offset is 5 words");
        assert_eq!(off_flags & 0x01ff, 0x0001, "only the FIN flag is set");
        // Re-summing a segment that already carries its checksum yields zero.
        assert_eq!(tcp_checksum(src, dst, &packet), 0);
    }

    #[test]
    fn icmp_echo_is_well_formed() {
        let packet = build_icmp_echo(0x1234, 1);
        assert_eq!(packet.len(), 16);
        assert_eq!(packet[0], 8, "echo request type");
        // Re-summing a packet that already carries its checksum yields zero.
        assert_eq!(icmp_checksum(&packet), 0);
    }

    #[test]
    fn verdict_reflects_outcomes() {
        let mut tally = Tally::default();
        tally.denied = 1;
        assert_eq!(tally.verdict(), "blocked");
        tally.success = 1;
        assert_eq!(tally.verdict(), "allowed");
    }
}
