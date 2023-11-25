use std::net::IpAddr;

use sdf_common::IpV4Addr;

pub fn to_ipv4(ip: &str) -> Option<u32> {
    match ip.parse::<IpAddr>() {
        Ok(ip) => match ip {
            IpAddr::V4(ip) => Some(u32::from(IpV4Addr(ip.octets()))),
            _ => None,
        },
        Err(e) => None,
    }
}
