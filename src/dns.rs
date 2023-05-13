use bytes::Bytes;
use bytes::BytesMut;
use structure::{structure, structure_impl};
use thiserror::Error;
use rand::thread_rng;
use rand::prelude::*;


pub type Int = u16;

#[derive(Debug, Clone, Copy)]
pub struct DNSHeader {
    pub id: Int,
    pub flags: DNSHeaderFlag,
    pub num_questions: Int,
    pub num_answers: Int,
    pub num_authorities: Int,
    pub num_additionals: Int
}

pub trait ToBytes {
    fn to_bytes(&self) -> Result<Bytes, Box<dyn std::error::Error>>;
}

impl ToBytes for DNSHeader {
    fn to_bytes(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        Ok(
            Bytes::from(
                structure!("HHHHHH")
                .pack(
                    self.id,
                    self.flags as Int,
                    self.num_questions,
                    self.num_answers,
                    self.num_authorities,
                    self.num_additionals
                )
                .unwrap()
            )
        )
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
    HS = 4
}


#[derive(Error, Debug)]
pub enum DNSError<'a> {
    #[error("Found a part with more than 255 chars in the url. (part: {part}, domain_name: {domain_name})")]
    DomainNameHasTooLongPart {
        part: &'a str,
        domain_name: &'a str
    }
}




#[derive(Debug, Clone)]
pub struct DNSQuestion {
    pub name: bytes::Bytes,
    pub r#type: DNSRecordType,
    pub class: DNSRecordClass
}

impl DNSQuestion {
    pub fn new<'a>(domain_name: &'a str, r#type: DNSRecordType, class: DNSRecordClass) -> Result<Self, DNSError<'a>> {
        match encode::dns_name(domain_name) {
            Ok(encoded) => Ok(Self {name: encoded, r#type, class}),
            Err(err) => Err(err)
        }
    }
}


impl ToBytes for DNSQuestion {
    fn to_bytes(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        let mut result = Vec::new();
        result.extend(self.name.iter());

        let s = structure!("HH");
        let packed =
        s.pack(
            self.r#type as u16,
            self.class as u16
        )
        .unwrap();
        result.extend_from_slice(&packed);
        Ok(Bytes::from(result))
    }
}


#[derive(Debug, Clone)]
pub struct DNSQuery {
    header: DNSHeader,
    question: DNSQuestion
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
    None = 0
}


impl DNSQuery {
    pub fn new<'a>(
        domain_name: &'a str, 
        record_type: DNSRecordType,
        record_class: DNSRecordClass
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
                        num_authorities: 0
                    }
                })
            },
            Err(err) => Err(err)
        }
    }

    #[cfg(test)]
    pub fn send_to_8_8_8_8(&self) -> Result<Bytes, Box<dyn std::error::Error>> {
        use std::net::{UdpSocket, SocketAddr};

        let data = self.to_bytes()?.to_vec();
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let recipient = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
        
        socket.send_to(&data, recipient).expect("to send to 8.8.8.8:53");

        let mut recv_buf = [0; 1024];
        let (size, _) = socket.recv_from(&mut recv_buf).unwrap();

        let observed = (&recv_buf[0..size]).to_vec();
        Ok(Bytes::from(observed))
    }
}


mod encode {
    use super::DNSError;
    use bytes::Bytes;

    /// Given a domain name encode it into bytes.
    pub fn dns_name(domain_name: &str) -> Result<Bytes, DNSError> {
        let mut encoded = Vec::new();
        for part in domain_name.split('.') {
            let part_as_bytes = part.as_bytes();
            let len = part_as_bytes.len();
            if len > 255 {
                return Err(DNSError::DomainNameHasTooLongPart { part, domain_name })
            }
            let len = len as u8;

            encoded.push(len);
            encoded.extend_from_slice(&part_as_bytes);
        }
        encoded.push(0);

        return Ok(Bytes::from(encoded))
    }
}






#[cfg(test)]
mod tests {

    use super::*;
    use structure::{structure_impl, structure};

    #[test]
    fn test_header_to_bytes() {
        let header = DNSHeader {
            id: 0x1314,
            flags: DNSHeaderFlag::None,
            num_questions: 1,
            num_additionals: 0,
            num_authorities: 0,
            num_answers: 0
        };
        let observed = header.to_bytes().unwrap();
        let expected = b"\x13\x14\0\0\0\x01\0\0\0\0\0\0";
        assert_eq!(observed, Bytes::copy_from_slice(expected));
    }

    #[test]
    fn test_encode_dns_name() {
        let observed = encode::dns_name("google.com").unwrap();
        let expected = b"\x06google\x03com\0";
        assert_eq!(observed, Bytes::from_static(expected));
    }

    #[test]
    fn test_dns_question_to_bytes() {
        let question = DNSQuestion {
            name: encode::dns_name("google.com").unwrap(),
            r#type: DNSRecordType::A,
            class: DNSRecordClass::IN
        };

        let observed = question.to_bytes().unwrap();
        let expected = Bytes::from_static(b"\x06google\x03com\0\0\x01\0\x01");
        assert_eq!(observed, expected);
        // let expected = Bytes::from(b"a");

    }

    #[test]
    fn test_dns_question_new() {
        let question = DNSQuestion::new("google.com", DNSRecordType::A, DNSRecordClass::IN).unwrap();
        let observed = question.to_bytes().unwrap();
        let expected = Bytes::from_static(b"\x06google\x03com\0\0\x01\0\x01");
        assert_eq!(observed, expected);
    }

    #[test]
    fn test_dns_query_new() {
        let query = DNSQuery::new("example.com", DNSRecordType::A, DNSRecordClass::IN).unwrap();

        let observed = query.to_bytes().unwrap();
        // except for the random id in the first two bytes, 
        // everything should be fixed.
        let expected_tail = Bytes::from_static(b"\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01");
        assert!(observed.ends_with(&expected_tail.to_vec()));

    }


    #[test]
    fn test_dns_query_roundtrip() {
        let query = DNSQuery::new("www.example.com", DNSRecordType::A, DNSRecordClass::IN).unwrap();
        let response = query.send_to_8_8_8_8().unwrap();
        assert!(response.ends_with(&[93, 184, 216, 34]));
    }
}