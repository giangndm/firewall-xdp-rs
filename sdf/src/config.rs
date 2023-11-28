use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize, Debug)]
pub struct StaticConfig {
    pub source_blacklist: Vec<Ipv4Addr>,
    pub source_whitelist: Vec<Ipv4Addr>,
    pub port_blacklist: Vec<u16>,
}
