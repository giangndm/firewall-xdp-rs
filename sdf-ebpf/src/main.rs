#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{xdp, classifier, map}, programs::{XdpContext, TcContext}, maps::HashMap};
use aya_log_ebpf::{info, error};
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, udp::UdpHdr};

use crate::parse::{ptr_at, tc_ptr_at};

const ETH_IP_V4_TYPE: u16 = 0x0800_u16;

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

fn increase_drop(ctx: &XdpContext, map: &HashMap<u16, u64>, port: u16) {
    if let Some(slot) = map.get_ptr_mut(&port) {
        unsafe { *slot += 1 };
    } else {
        if let Err(e) = map.insert(&port, &1, 0) {
            error!(ctx, "add port {} to BLOCKED_STATS error {}", port, e);
        }
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
            // IpProto::Tcp => {
            //     let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            //     ((*tcphdr).source.to_be(), (*tcphdr).dest.to_be())
            // }
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
        increase_drop(&ctx, &BLOCKED_STATS, source_port);
        return Ok(xdp_action::XDP_DROP)
    }

    Ok(xdp_action::XDP_PASS)
}

fn try_sdf_egress(ctx: TcContext) -> Result<i32, i32> {
    let mut buf: [u8; 4] = [0; 4];
    unsafe { tc_ptr_at(&ctx, 12, &mut buf[0..2])? };

    if buf[0] != (ETH_IP_V4_TYPE >> 8) as u8 || buf[1] != 0 {
        return Ok(1);
    }

    unsafe { tc_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN, &mut buf[0..4])? };

    let dest_port = (buf[2] as u16) << 8 | buf[3] as u16;
    if unsafe { PORT_BLACKLIST.get(&dest_port).is_some() } {
        unsafe { tc_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN - 4, &mut buf[0..4])? };
        let dest_ip = u32::from_be_bytes(buf);
        if unsafe { SRC_WHITELIST.get(&dest_ip).is_none() } {
            if let Err(e) = SRC_WHITELIST.insert(&dest_ip, &0, 0) {
                error!(&ctx, "add {:x}:{} to whitelist error {}", dest_ip, dest_port, e);
            } else {
                info!(&ctx, "auto added {:x}:{} to whitelist", dest_ip, dest_port);
            }
        }
    }
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}