use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use log::{info, trace};

use crate::dns::*;

pub fn resolve(
    domain_name: &str,
    record_type: DNSRecordType,
) -> Result<(DNSPacket, Ipv4Addr), DNSError> {
    let mut nameserver = "198.41.0.4:53".parse::<SocketAddr>()?;

    info!("Resolving {}", domain_name);

    loop {
        trace!("Querying {:?} for {}", nameserver, domain_name);
        let query = DNSQuery::new(
            domain_name,
            record_type,
            DNSRecordClass::IN,
            DNSHeaderFlag::None,
        );
        let response = query.query(nameserver)?;

        if let Some(answer) = response.get_answer() {
            return Ok((response, answer));
        }
        if let Some(nameserver_ip) = response.get_nameserver_ip() {
            nameserver.set_ip(IpAddr::V4(nameserver_ip));
        } else if let Some(nameserver_domain) = response.get_nameserver() {
            let (_, resolved) = resolve(&nameserver_domain, record_type)?;
            nameserver.set_ip(IpAddr::V4(resolved));
        } else {
            return Err(DNSError::Other);
        }
    }
}
