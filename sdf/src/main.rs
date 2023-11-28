use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use config_file::FromConfigFile;
use log::{debug, info, warn};
use sdf_common::IpV4Addr;
use tokio::sync::mpsc;
use tokio::{select, signal};

mod config;
mod http;
mod utils;

use config::StaticConfig;
use http::{start_http_server, ApiResult, ControlApiCmd, HttpCmd};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens192")]
    iface: String,

    #[clap(long, default_value = "0.0.0.0:3000")]
    http_port: String,

    #[clap(long)]
    config: Option<String>,
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

    // Reading data
    let reload_config = |bpf: &mut Bpf| -> Result<(), String> {
        if let Some(file) = &opt.config {
            let config = StaticConfig::from_config_file(&file).map_err(|e| e.to_string())?;

            let mut src_blacklist: HashMap<_, u32, u8> =
                HashMap::try_from(bpf.map_mut("SRC_BLACKLIST").unwrap())
                    .map_err(|e| e.to_string())?;
            let keys = src_blacklist.keys().collect::<Result<Vec<_>, _>>().unwrap();
            for ip in keys {
                src_blacklist.remove(&ip);
            }

            for ip in config.source_blacklist {
                if let Err(e) = src_blacklist.insert(u32::from(IpV4Addr(ip.octets())), 0, 0) {
                    warn!("add source blacklist rule {} error {}", ip, e);
                } else {
                    info!("added source blacklist rule {}", ip);
                }
            }

            let mut src_whitelist: HashMap<_, u32, u8> =
                HashMap::try_from(bpf.map_mut("SRC_WHITELIST").unwrap())
                    .map_err(|e| e.to_string())?;
            let keys: Vec<u32> = src_whitelist.keys().collect::<Result<Vec<_>, _>>().unwrap();
            for ip in keys {
                src_whitelist.remove(&ip);
            }

            for ip in config.source_whitelist {
                if let Err(e) = src_whitelist.insert(u32::from(IpV4Addr(ip.octets())), 0, 0) {
                    warn!("add source whitelist rule {} error {}", ip, e);
                } else {
                    info!("added source whitelist rule {}", ip);
                }
            }

            let mut port_blacklist: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("PORT_BLACKLIST").unwrap())
                    .map_err(|e| e.to_string())?;
            let keys: Vec<u16> = port_blacklist
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            for port in keys {
                port_blacklist.remove(&port);
            }

            for port in config.port_blacklist {
                if let Err(e) = port_blacklist.insert(port, 0, 0) {
                    warn!("add port blacklist rule {} error {}", port, e);
                } else {
                    info!("added port blacklist rule {}", port);
                }
            }
        }
        Ok(())
    };
    reload_config(&mut bpf).expect("Config file need to valid");
    // End of reading data

    info!("Waiting for Ctrl-C...");
    loop {
        select! {
            event = rx.recv() => match event.expect("should Some") {
                HttpCmd::ControlApi(ControlApiCmd::Reload(res)) => {
                    if let Err(e) = reload_config(&mut bpf) {
                        res.send(ApiResult::error(&e)).expect("Should work");
                    } else {
                        res.send(ApiResult::success("RELOADED".to_string())).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::BlockedStats(res)) => {
                    let blocked: HashMap<_, u16, u64> = HashMap::try_from(bpf.map_mut("BLOCKED_STATS").unwrap())?;
                    let mut stats = std::collections::HashMap::new();
                    for row in blocked.iter() {
                        if let Ok((port, count)) = row {
                            stats.insert(port, count);
                        }
                    }
                    res.send(ApiResult::success(stats)).expect("Should work");
                }
                HttpCmd::ControlApi(ControlApiCmd::SetBlacklistSourceRule(ip, res)) => {
                    let mut src_blacklist: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("SRC_BLACKLIST").unwrap())?;
                    if let Some(ip) = utils::to_ipv4(&ip) {
                        if src_blacklist.insert(ip, 0, 0).is_ok() {
                            info!("added source blacklist {}", ip);
                            res.send(ApiResult::success("ADDED".to_string())).expect("Should work");
                        } else {
                            res.send(ApiResult::error("CANNOT_ADD_TO_MAP")).expect("Should work");
                        }
                    } else {
                        res.send(ApiResult::error("ONLY_SUPPORT_IP_V4")).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::DelBlacklistSourceRule(ip, res)) => {
                    let mut src_blacklist: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("SRC_BLACKLIST").unwrap())?;
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
                HttpCmd::ControlApi(ControlApiCmd::SetWhitelistSourceRule(ip, res)) => {
                    let mut src_whitelist: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("SRC_WHITELIST").unwrap())?;
                    if let Some(ip) = utils::to_ipv4(&ip) {
                        if src_whitelist.insert(ip, 0, 0).is_ok() {
                            info!("added source whitelist {}", ip);
                            res.send(ApiResult::success("ADDED".to_string())).expect("Should work");
                        } else {
                            res.send(ApiResult::error("CANNOT_ADD_TO_MAP")).expect("Should work");
                        }
                    } else {
                        res.send(ApiResult::error("ONLY_SUPPORT_IP_V4")).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::DelWhitelistSourceRule(ip, res)) => {
                    let mut src_whitelist: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("SRC_WHITELIST").unwrap())?;
                    if let Some(ip) = utils::to_ipv4(&ip) {
                        if src_whitelist.remove(&ip).is_ok() {
                            info!("removed source whitelist {}", ip);
                            res.send(ApiResult::success("REMOVED".to_string())).expect("Should work");
                        } else {
                            res.send(ApiResult::error("IP_NOT_FOUND")).expect("Should work");
                        }
                    } else {
                        res.send(ApiResult::error("ONLY_SUPPORT_IP_V4")).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::SetBlacklistPortRule(port, res)) => {
                    let mut port_blacklist: HashMap<_, u16, u8> = HashMap::try_from(bpf.map_mut("PORT_BLACKLIST").unwrap())?;
                    if port_blacklist.insert(port, 0, 0).is_ok() {
                        info!("added port blacklist {}", port);
                        res.send(ApiResult::success("ADDED".to_string())).expect("Should work");
                    } else {
                        res.send(ApiResult::error("CANNOT_ADD_TO_MAP")).expect("Should work");
                    }
                },
                HttpCmd::ControlApi(ControlApiCmd::DelBlacklistPortRule(port, res)) => {
                    let mut port_blacklist: HashMap<_, u16, u8> = HashMap::try_from(bpf.map_mut("PORT_BLACKLIST").unwrap())?;
                    if port_blacklist.remove(&port).is_ok() {
                        info!("removed port blacklist {}", port);
                        res.send(ApiResult::success("REMOVED".to_string())).expect("Should work");
                    } else {
                        res.send(ApiResult::error("IP_NOT_FOUND")).expect("Should work");
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
