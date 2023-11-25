use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use sdf_common::PortRange;
use tokio::sync::mpsc;
use tokio::{select, signal};

mod http;
mod utils;

use http::{start_http_server, ApiResult, ControlApiCmd, HttpCmd};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens192")]
    iface: String,

    #[clap(long, default_value = "0.0.0.0:3000")]
    http_port: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sdf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sdf"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("sdf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

    let (tx, mut rx) = mpsc::channel(100);

    tokio::spawn(async move {
        start_http_server(tx, &opt.http_port)
            .await
            .expect("must work");
    });

    info!("Waiting for Ctrl-C...");
    loop {
        select! {
            event = rx.recv() => match event.expect("should Some") {
                HttpCmd::ControlApi(ControlApiCmd::SetBlacklistSourceRule(rule, res)) => {
                    let mut src_blacklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("SRC_BLACKLIST").unwrap())?;
                    if let Some(ip) = utils::to_ipv4(&rule.ip) {
                        if src_blacklist.insert(ip, u32::from(PortRange (rule.port_begin, rule.port_end)), 0).is_ok() {
                            info!("added source blacklist {}:[{}-{}]", rule.ip, rule.port_begin, rule.port_end);
                            res.send(ApiResult::success("ADDED".to_string())).expect("Should work");
                        } else {
                            res.send(ApiResult::error("CANNOT_ADD_TO_MAP")).expect("Should work");
                        }
                    } else {
                        res.send(ApiResult::error("ONLY_SUPPORT_IP_V4")).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::DelBlacklistSourceRule(ip, res)) => {
                    let mut src_blacklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("SRC_BLACKLIST").unwrap())?;
                    if let Some(ip) = utils::to_ipv4(&ip) {
                        if src_blacklist.remove(&ip).is_ok() {
                            info!("removed source blacklist {}", ip);
                            res.send(ApiResult::success("REMOVED".to_string())).expect("Should work");
                        } else {
                            res.send(ApiResult::error("IP_NOT_FOUND")).expect("Should work");
                        }
                    } else {
                        res.send(ApiResult::error("ONLY_SUPPORT_IP_V4")).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::SetBlacklistDestRule(rule, res)) => {
                    let mut dst_blacklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("DST_BLACKLIST").unwrap())?;
                    if let Some(ip) = utils::to_ipv4(&rule.ip) {
                        if dst_blacklist.insert(ip, u32::from(PortRange (rule.port_begin, rule.port_end)), 0).is_ok() {
                            info!("added dest blacklist {}:[{}-{}]", rule.ip, rule.port_begin, rule.port_end);
                            res.send(ApiResult::success("ADDED".to_string())).expect("Should work");
                        } else {
                            res.send(ApiResult::error("CANNOT_ADD_TO_MAP")).expect("Should work");
                        }
                    } else {
                        res.send(ApiResult::error("ONLY_SUPPORT_IP_V4")).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::DelBlacklistDestRule(ip, res)) => {
                    let mut dst_blacklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("DST_BLACKLIST").unwrap())?;
                    if let Some(ip) = utils::to_ipv4(&ip) {
                        if dst_blacklist.remove(&ip).is_ok() {
                            info!("removed source blacklist {}", ip);
                            res.send(ApiResult::success("REMOVED".to_string())).expect("Should work");
                        } else {
                            res.send(ApiResult::error("IP_NOT_FOUND")).expect("Should work");
                        }
                    } else {
                        res.send(ApiResult::error("ONLY_SUPPORT_IP_V4")).expect("Should work");
                    }
                },
            },
            _ = interval.tick() => {

            },
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }
    info!("Exiting...");

    Ok(())
}
