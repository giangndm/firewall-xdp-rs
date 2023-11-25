use sdf_common::PortRange;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize, Debug)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub port: Option<[u16; 2]>,
}

impl Target {
    pub fn port_range(&self) -> PortRange {
        match self.port {
            None => PortRange(0, 0xffff),
            Some(ports) => PortRange(ports[0], ports[1]),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StaticConfig {
    pub source_blacklist: Option<Vec<Target>>,
    pub dest_blacklist: Option<Vec<Target>>,
}
