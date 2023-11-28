#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{xdp, classifier, map}, programs::{XdpContext, TcContext}, maps::HashMap};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, udp::UdpHdr, tcp::TcpHdr};

use crate::parse::ptr_at;

mod parse;

#[map]
static SRC_BLACKLIST: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(4096, 0);

#[map]
static SRC_WHITELIST: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(4096, 0);

#[map]
static PORT_BLACKLIST: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(4096, 0);

#[map]
static BLOCKED_STATS: HashMap<u16, u64> = HashMap::<u16, u64>::with_max_entries(1 << 16, 0);

#[xdp]
pub fn sdf_ingress(ctx: XdpContext) -> u32 {
    match try_sdf_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn sdf_egress(ctx: TcContext) -> i32 {
    match try_sdf_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn increase_drop(map: &HashMap<u16, u64>, port: u16) {
    if let Some(slot) = map.get_ptr_mut(&port) {
        unsafe { *slot += 1 };
    } else {
        map.insert(&port, &1, 0);
    }
}

fn allow_port(_ctx: &XdpContext, blacklist: &HashMap<u16, u8>, port: u16) -> bool {
    unsafe { blacklist.get(&port).is_none() }
}

fn try_sdf_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    // let dest = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (source_port, _dest_port) = unsafe { 
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

    if unsafe { SRC_WHITELIST.get(&source).is_some() } {
        return Ok(xdp_action::XDP_PASS);
    }

    if unsafe { SRC_BLACKLIST.get(&source).is_some() } {
        return Ok(xdp_action::XDP_DROP);
    }

    if !allow_port(&ctx, &PORT_BLACKLIST, source_port) {
        increase_drop(&BLOCKED_STATS, source_port);
        return Ok(xdp_action::XDP_DROP)
    }

    Ok(xdp_action::XDP_PASS)
}

fn try_sdf_egress(ctx: TcContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}