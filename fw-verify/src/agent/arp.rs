//! `arp-spoof` — emit gratuitous ARP replies for an IP.
//!
//! Drives the idps-fw ARP-spoof monitor (event 303): the data plane accounts
//! ARP replies per sender IP and userspace flags any IP whose replies exceed
//! requests by the tolerance. We craft Ethernet/ARP frames and send them on the
//! given interface via an `AF_PACKET` raw socket (needs root/CAP_NET_RAW).

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};
use serde_json::json;

const ETH_P_ARP: u16 = 0x0806;
const ARPHRD_ETHER: u16 = 1;
const ARPOP_REPLY: u16 = 2;

pub fn run(args: &crate::agent::cli::ArpSpoofArgs) -> Result<()> {
    let iface = CString::new(args.iface.as_str()).context("invalid interface name")?;
    // SAFETY: if_nametoindex reads a NUL-terminated name and returns 0 on error.
    let ifindex = unsafe { libc::if_nametoindex(iface.as_ptr()) };
    if ifindex == 0 {
        bail!("interface {} not found", args.iface);
    }
    let src_mac = interface_mac(&args.iface)?;

    // SAFETY: socket(2) with AF_PACKET; the fd is closed before returning.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ARP.to_be() as i32) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open AF_PACKET socket (needs root)");
    }

    let frame = build_arp_reply(src_mac, args.claim_ip);
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ARP.to_be();
    addr.sll_ifindex = ifindex as i32;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

    let mut sent = 0_u32;
    for _ in 0..args.count {
        // SAFETY: sending `frame` to the broadcast L2 address on `ifindex`.
        let ret = unsafe {
            libc::sendto(
                fd,
                frame.as_ptr().cast(),
                frame.len(),
                0,
                std::ptr::addr_of!(addr).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret >= 0 {
            sent += 1;
        }
    }
    // SAFETY: closing our own fd.
    unsafe { libc::close(fd) };

    println!(
        "{}",
        json!({
            "iface": args.iface,
            "claim_ip": args.claim_ip.to_string(),
            "requested": args.count,
            "sent": sent,
        })
    );
    Ok(())
}

/// Read the 6-byte hardware address of `iface` via `SIOCGIFHWADDR`.
fn interface_mac(iface: &str) -> Result<[u8; 6]> {
    // SAFETY: ioctl on a temporary datagram socket with a zeroed ifreq.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open ioctl socket");
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = iface.as_bytes();
    if name.len() >= req.ifr_name.len() {
        unsafe { libc::close(fd) };
        bail!("interface name too long: {iface}");
    }
    for (slot, &byte) in req.ifr_name.iter_mut().zip(name) {
        *slot = byte as libc::c_char;
    }
    let mut hw: MaybeUninit<libc::ifreq> = MaybeUninit::new(req);
    // The ioctl request type differs across libc targets (c_ulong on glibc,
    // c_int on Android bionic), so cast to the platform's `Ioctl` alias. The
    // cast is a no-op on glibc, hence the allow.
    #[allow(clippy::unnecessary_cast)]
    let ret =
        unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::Ioctl, hw.as_mut_ptr()) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCGIFHWADDR failed");
    }
    let hw = unsafe { hw.assume_init() };
    let mut mac = [0_u8; 6];
    // sa_data holds the hardware address starting at byte 0.
    for (slot, src) in mac
        .iter_mut()
        .zip(unsafe { hw.ifr_ifru.ifru_hwaddr.sa_data })
    {
        *slot = src as u8;
    }
    Ok(mac)
}

/// Build a 42-byte Ethernet + ARP reply frame claiming `claim_ip` at `src_mac`,
/// broadcast to all hosts (gratuitous ARP).
fn build_arp_reply(src_mac: [u8; 6], claim_ip: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0_u8; 42];
    // Ethernet header: dst broadcast, src = our MAC, type ARP.
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    // ARP payload.
    frame[14..16].copy_from_slice(&ARPHRD_ETHER.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes()); // IPv4
    frame[18] = 6; // hw addr len
    frame[19] = 4; // proto addr len
    frame[20..22].copy_from_slice(&ARPOP_REPLY.to_be_bytes());
    frame[22..28].copy_from_slice(&src_mac); // sender hw
    frame[28..32].copy_from_slice(&claim_ip.octets()); // sender proto (the claim)
    frame[32..38].copy_from_slice(&[0xff; 6]); // target hw (broadcast)
    frame[38..42].copy_from_slice(&claim_ip.octets()); // target proto
    frame
}
