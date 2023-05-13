use bytes::Bytes;
use bytes::BytesMut;
use rand::prelude::*;
use rand::thread_rng;
use structure::{structure, structure_impl};
use thiserror::Error;

pub type Int = u16;

#[derive(Debug, Clone, Copy)]
pub struct DNSHeader {
    pub id: Int,
    pub flags: DNSHeaderFlag,
    pub num_questions: Int,
    pub num_answers: Int,
    pub num_authorities: Int,
    pub num_additionals: Int,
}

pub trait ToBytes {
    fn to_bytes(&self) -> Result<Bytes, Box<dyn std::error::Error>>;
}

impl ToBytes for DNSHeader {
    fn to_bytes(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        Ok(Bytes::from(
            structure!("HHHHHH")
                .pack(
                    self.id,
                    self.flags as Int,
                    self.num_questions,
                    self.num_answers,
                    self.num_authorities,
                    self.num_additionals,
                )
                .unwrap(),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum DNSRecordType {
    A = 1,
    // NS = 2,
    // MD = 3,
    // MF = 4,
    // CNAME = 5,
    // SOA = 6,
    // add more
}

#[derive(Debug, Clone, Copy)]
pub enum DNSRecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

#[derive(Error, Debug)]
pub enum DNSError<'a> {
    #[error("Found a part with more than 255 chars in the url. (part: {part}, domain_name: {domain_name})")]
    DomainNameHasTooLongPart { part: &'a str, domain_name: &'a str },
}

#[derive(Debug, Clone)]
pub struct DNSQuestion {
    pub name: bytes::Bytes,
    pub r#type: DNSRecordType,
    pub class: DNSRecordClass,
}

impl DNSQuestion {
    pub fn new(
        domain_name: &str,
        r#type: DNSRecordType,
        class: DNSRecordClass,
    ) -> Result<Self, DNSError<'_>> {
        match encode::dns_name(domain_name) {
            Ok(encoded) => Ok(Self {
                name: encoded,
                r#type,
                class,
            }),
            Err(err) => Err(err),
        }
    }
}

impl ToBytes for DNSQuestion {
    fn to_bytes(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        let mut result = Vec::new();
        result.extend(self.name.iter());

        let s = structure!("HH");
        let packed = s.pack(self.r#type as u16, self.class as u16).unwrap();
        result.extend_from_slice(&packed);
        Ok(Bytes::from(result))
    }
}

#[derive(Debug, Clone)]
pub struct DNSQuery {
    header: DNSHeader,
    question: DNSQuestion,
}

impl ToBytes for DNSQuery {
    fn to_bytes(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        let mut result = BytesMut::new();
        result.extend_from_slice(&self.header.to_bytes()?);
        result.extend_from_slice(&self.question.to_bytes()?);
        Ok(result.into())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DNSHeaderFlag {
    RecursionDesired = 1 << 8,
    None = 0,
}

impl DNSQuery {
    pub fn new(
        domain_name: &str,
        record_type: DNSRecordType,
        record_class: DNSRecordClass,
    ) -> Result<Self, DNSError> {
        match DNSQuestion::new(domain_name, record_type, record_class) {
            Ok(question) => {
                let header_id = thread_rng().gen();
                Ok(Self {
                    question,
                    header: DNSHeader {
                        id: header_id,
                        num_questions: 1,
                        flags: DNSHeaderFlag::RecursionDesired,
                        num_additionals: 0,
                        num_answers: 0,
                        num_authorities: 0,
                    },
                })
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(test)]
    pub fn send_to_8_8_8_8(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        use std::net::{SocketAddr, UdpSocket};

        let data = self.to_bytes()?.to_vec();
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let recipient = "8.8.8.8:53".parse::<SocketAddr>().unwrap();

        socket
            .send_to(&data, recipient)
            .expect("to send to 8.8.8.8:53");

        let mut recv_buf = [0; 1024];
        let (size, _) = socket.recv_from(&mut recv_buf).unwrap();

        let observed = recv_buf[0..size].to_vec();
        Ok(Bytes::from(observed))
    }
}

pub mod encode {
    use super::DNSError;
    use bytes::Bytes;

    /// Given a domain name encode it into bytes.
    pub fn dns_name(domain_name: &str) -> Result<Bytes, DNSError> {
        let mut encoded = Vec::new();
        for part in domain_name.split('.') {
            let part_as_bytes = part.as_bytes();
            let len = part_as_bytes.len();
            if len > 255 {
                return Err(DNSError::DomainNameHasTooLongPart { part, domain_name });
            }
            let len = len as u8;

            encoded.push(len);
            encoded.extend_from_slice(part_as_bytes);
        }
        encoded.push(0);

        Ok(Bytes::from(encoded))
    }
}
