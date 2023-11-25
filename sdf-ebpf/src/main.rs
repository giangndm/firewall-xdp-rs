#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{xdp, map}, programs::XdpContext, maps::HashMap};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, udp::UdpHdr, tcp::TcpHdr};
use sdf_common::PortRange;

use crate::parse::ptr_at;

mod parse;

#[map]
static SRC_BLACKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4096, 0);

#[map]
static DST_BLACKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4096, 0);

#[map]
static SRC_WHITELIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4096, 0);

#[map]
static DST_WHITELIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4096, 0);

#[map]
static BLOCKED_STATS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4096, 0);

#[xdp]
pub fn sdf(ctx: XdpContext) -> u32 {
    match try_sdf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn increase_map(map: &HashMap<u32, u32>, key: u32) {
    if let Some(slot) = map.get_ptr_mut(&key) {
        unsafe { *slot += 1 };
    } else {
        map.insert(&key, &1, 0);
    }
}

fn allow_tuple(ctx: &XdpContext, blacklist: &HashMap<u32, u32>, whitelist: &HashMap<u32, u32>, addr: u32, port: u16) -> bool {
    if let Some(port_range) = unsafe { blacklist.get(&addr) } {
        let range = PortRange::from(*port_range);
        if range.0 > port || range.1 < port {
            return true;
        }
    } else {
        return true;
    };

    if let Some(port_range) = unsafe { whitelist.get(&addr) } {
        let range = PortRange::from(*port_range);
        if range.0 <= port && port <= range.1 {
            return true;
        }
    };

    false
}

fn try_sdf(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (source_port, dest_port) = unsafe { 
        match (*ipv4hdr).proto {
            IpProto::Udp => {
                let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                ((*udphdr).source.to_be(), (*udphdr).dest.to_be())
            },
            IpProto::Tcp => {
                let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                ((*tcphdr).source.to_be(), (*tcphdr).dest.to_be())
            }
            _ => return Ok(xdp_action::XDP_PASS)
        }
    };

    if !allow_tuple(&ctx, &SRC_BLACKLIST, &SRC_WHITELIST, source, source_port) {
        increase_map(&BLOCKED_STATS, source);
        return Ok(xdp_action::XDP_DROP)
    }

    if !allow_tuple(&ctx, &DST_BLACKLIST, &DST_WHITELIST, dest, dest_port) {
        increase_map(&BLOCKED_STATS, source);
        return Ok(xdp_action::XDP_DROP)
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
