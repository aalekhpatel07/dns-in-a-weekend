use std::{io::{Write, Seek}, net::{Ipv4Addr, SocketAddr, IpAddr}};
use rand::Rng;
use log::{info, debug, warn, trace, error};

use crate::dns::*;

pub fn build_query(domain_name: &str, record_type: DNSRecordType) -> DNSQuery {
    let id: Int = rand::thread_rng().gen();
    let header = DNSHeader {
        id,
        flags: DNSHeaderFlag::None,
        num_answers: 0,
        num_questions: 1,
        num_additionals: 0,
        num_authorities: 0
    };

    let query = DNSQuery {
        header,
        question: DNSQuestion { name: domain_name.to_string(), r#type: record_type, class: DNSRecordClass::IN }
    };
    query
}

pub fn resolve(domain_name: &str, record_type: DNSRecordType) -> Result<Ipv4Addr, DNSError> {
    let mut nameserver = "198.41.0.4:53".parse::<SocketAddr>()?;

    info!("Resolving {}", domain_name);

    loop {
        trace!("Querying {:?} for {}", nameserver, domain_name);
        let query = build_query(domain_name, record_type);
        let response = query.query(nameserver)?;
        
        if let Some(answer) = response.get_answer() {
            return Ok(answer)
        }
        if let Some(nameserver_ip) = response.get_nameserver_ip() {
            nameserver.set_ip(IpAddr::V4(nameserver_ip));
        } else if let Some(nameserver_domain) = response.get_nameserver() {
            nameserver.set_ip(IpAddr::V4(resolve(&nameserver_domain, record_type)?));
        } else {
            return Err(DNSError::Other)
        }
    }
}