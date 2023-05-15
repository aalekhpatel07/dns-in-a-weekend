use std::io::{Cursor, Read, Seek};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

use rand::prelude::*;
use rand::thread_rng;
use structure::byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

pub type Int = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DNSHeader {
    pub id: Int,
    pub flags: DNSHeaderFlag,
    pub num_questions: Int,
    pub num_answers: Int,
    pub num_authorities: Int,
    pub num_additionals: Int,
}

pub trait ToBytes {
    fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, DNSError>;
}

pub trait FromBytes: Sized {
    type Error;
    fn from_bytes<R: Read + Seek>(data: &mut R) -> Result<Self, Self::Error>;
}

impl ToBytes for DNSHeader {
    fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, DNSError> {
        writer.write_u16::<BigEndian>(self.id)?;
        writer.write_u16::<BigEndian>(self.flags.into())?;
        writer.write_u16::<BigEndian>(self.num_questions)?;
        writer.write_u16::<BigEndian>(self.num_answers)?;
        writer.write_u16::<BigEndian>(self.num_authorities)?;
        writer.write_u16::<BigEndian>(self.num_additionals)?;

        Ok(12)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DNSRecordType {
    A = 1,
    AAAA = 28,
    NS = 2,
    // MD = 3,
    // MF = 4,
    CNAME = 5,
    TXT = 16,
    OPT = 41,
    SOA = 6,
    // add more,
}

impl TryFrom<Int> for DNSRecordType {
    type Error = DNSError;
    fn try_from(value: Int) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            5 => Ok(Self::CNAME),
            6 => Ok(Self::SOA),
            16 => Ok(Self::TXT),
            28 => Ok(Self::AAAA),
            41 => Ok(Self::OPT),
            _ => Err(DNSError::BadRecordType(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DNSRecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl TryFrom<Int> for DNSRecordClass {
    type Error = DNSError;
    fn try_from(value: Int) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::IN),
            2 => Ok(Self::CS),
            3 => Ok(Self::CH),
            4 => Ok(Self::HS),
            _ => Err(DNSError::BadRecordClass(value)),
        }
    }
}

#[derive(Error, Debug)]
pub enum DNSError {
    #[error("Found a part with more than 255 chars in the url. (part: {part}, domain_name: {domain_name})")]
    DomainNameHasTooLongPart { part: String, domain_name: String },
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    InvalidUTF8(#[from] FromUtf8Error),
    #[error("Could not recognize header flag: {0}")]
    BadHeader(Int),
    #[error("Could not recognize dns record type: {0}")]
    BadRecordType(Int),
    #[error("Could not recognize dns record class: {0}")]
    BadRecordClass(Int),
    #[error(transparent)]
    IntTooLarge(#[from] TryFromIntError),
    #[error(transparent)]
    BadAddress(#[from] AddrParseError),
    #[error("Couldn't find an ip address in the answer section.")]
    NoIpAddressFound,
    #[error("ToSocketAddrs produced no addresses when at least one was expected.")]
    ToSocketAddrsProducedNoAddrs,
    #[error("Something went wrong.")]
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSQuestion {
    pub name: String,
    pub r#type: DNSRecordType,
    pub class: DNSRecordClass,
}

impl DNSQuestion {
    pub fn new(domain_name: &str, r#type: DNSRecordType, class: DNSRecordClass) -> Self {
        Self {
            name: domain_name.to_string(),
            r#type,
            class,
        }
    }
}

impl ToBytes for DNSQuestion {
    fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, DNSError> {
        let dns_name_size = encode::dns_name(writer, &self.name)?;
        writer.write_u16::<BigEndian>(self.r#type as u16)?;
        writer.write_u16::<BigEndian>(self.class as u16)?;

        Ok(dns_name_size + 4)
    }
}

#[derive(Debug, Clone)]
pub struct DNSQuery {
    pub header: DNSHeader,
    pub question: DNSQuestion,
}

impl ToBytes for DNSQuery {
    fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, DNSError> {
        let mut total_bytes = 0;
        total_bytes += self.header.to_bytes(writer)?;
        total_bytes += self.question.to_bytes(writer)?;

        Ok(total_bytes)
    }
}

impl FromBytes for DNSQuery {
    type Error = DNSError;
    fn from_bytes<R: Read + Seek>(reader: &mut R) -> Result<Self, Self::Error> {
        let header = DNSHeader::from_bytes(reader)?;
        let question = DNSQuestion::from_bytes(reader)?;

        Ok(Self { header, question })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DNSHeaderFlag {
    RecursionDesired,
    None,
    Other(Int),
}

impl From<DNSHeaderFlag> for Int {
    fn from(value: DNSHeaderFlag) -> Self {
        match value {
            DNSHeaderFlag::None => 0,
            DNSHeaderFlag::RecursionDesired => 1 << 8,
            DNSHeaderFlag::Other(v) => v,
        }
    }
}

impl From<Int> for DNSHeaderFlag {
    fn from(value: Int) -> Self {
        match value {
            0 => Self::None,
            256 => Self::RecursionDesired,
            _ => Self::Other(value),
        }
    }
}

impl DNSQuery {
    pub fn new(
        domain_name: &str,
        record_type: DNSRecordType,
        record_class: DNSRecordClass,
        flags: DNSHeaderFlag,
    ) -> Self {
        let question = DNSQuestion::new(domain_name, record_type, record_class);
        let header_id = thread_rng().gen();
        Self {
            question,
            header: DNSHeader {
                id: header_id,
                num_questions: 1,
                flags,
                num_additionals: 0,
                num_answers: 0,
                num_authorities: 0,
            },
        }
    }

    pub fn query(&self, addr: impl ToSocketAddrs) -> Result<DNSPacket, DNSError> {
        let mut contents = vec![];
        self.to_bytes(&mut contents)?;

        let recipient = addr
            .to_socket_addrs()?
            .next()
            .ok_or(DNSError::ToSocketAddrsProducedNoAddrs)?;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.send_to(&contents, recipient)?;

        let mut recv_buf = [0; 1024];
        let (size, _) = socket.recv_from(&mut recv_buf)?;
        let mut cursor = std::io::Cursor::new(&recv_buf[0..size]);

        DNSPacket::from_bytes(&mut cursor)
    }

    #[cfg(test)]
    pub fn send_to_8_8_8_8(&self) -> Result<Vec<u8>, DNSError> {
        use std::net::SocketAddr;
        let mut contents = vec![];
        self.to_bytes(&mut contents)?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let recipient = "8.8.8.8:53".parse::<SocketAddr>()?;

        socket.send_to(&contents, recipient)?;

        let mut recv_buf = [0; 1024];
        let (size, _) = socket.recv_from(&mut recv_buf)?;

        let observed = recv_buf[0..size].to_vec();
        Ok(observed)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DNSRecord {
    pub name: String,
    pub r#type: DNSRecordType,
    pub class: DNSRecordClass,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl ToBytes for DNSRecord {
    fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, DNSError> {
        let mut total = 0;
        total += encode::dns_name(writer, &self.name)?;

        writer.write_u16::<BigEndian>(self.r#type as Int)?;
        writer.write_u16::<BigEndian>(self.class as Int)?;
        writer.write_u32::<BigEndian>(self.ttl)?;
        writer.write_u16::<BigEndian>(self.data.len().try_into()?)?;

        total += 10;
        total += self.data.len();

        writer.write_all(&self.data)?;

        Ok(total)
    }
}

impl core::fmt::Display for DNSRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl core::fmt::Debug for DNSRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DNSRecord")
            .field("name", &self.name)
            .field("type", &self.r#type)
            .field("class", &self.class)
            .field("ttl", &self.ttl)
            .field("data", &self.try_get_data_as_string())
            .finish()
    }
}

impl DNSRecord {
    fn try_parse_aaaa_record(&self) -> Result<Ipv6Addr, DNSError> {
        let mut cursor = Cursor::new(&self.data);
        let ipv6 = Ipv6Addr::new(
            cursor.read_u16::<BigEndian>()?,
            cursor.read_u16::<BigEndian>()?,
            cursor.read_u16::<BigEndian>()?,
            cursor.read_u16::<BigEndian>()?,
            cursor.read_u16::<BigEndian>()?,
            cursor.read_u16::<BigEndian>()?,
            cursor.read_u16::<BigEndian>()?,
            cursor.read_u16::<BigEndian>()?,
        );
        Ok(ipv6)
    }

    fn try_parse_a_record(&self) -> Result<Ipv4Addr, DNSError> {
        let mut cursor = Cursor::new(&self.data);
        Ok(Ipv4Addr::new(
            cursor.read_u8()?,
            cursor.read_u8()?,
            cursor.read_u8()?,
            cursor.read_u8()?,
        ))
    }

    pub fn try_get_data_as_string(&self) -> Option<String> {
        match self.r#type {
            DNSRecordType::A => self
                .try_parse_a_record()
                .map(|record| record.to_string())
                .ok(),
            DNSRecordType::NS | DNSRecordType::CNAME => {
                let mut cursor = Cursor::new(&self.data);
                decode::dns_name(&mut cursor).map(|(name, _)| name).ok()
            }
            DNSRecordType::AAAA => self
                .try_parse_aaaa_record()
                .map(|record| record.to_string())
                .ok(),
            _ => Some(format!("{:?}", self.data)),
        }
    }
}

impl FromBytes for DNSHeader {
    type Error = DNSError;
    fn from_bytes<R: Read>(data: &mut R) -> Result<Self, Self::Error> {
        Ok(Self {
            id: data.read_u16::<BigEndian>()?,
            flags: data.read_u16::<BigEndian>()?.into(),
            num_questions: data.read_u16::<BigEndian>()?,
            num_answers: data.read_u16::<BigEndian>()?,
            num_additionals: data.read_u16::<BigEndian>()?,
            num_authorities: data.read_u16::<BigEndian>()?,
        })
    }
}

impl FromBytes for DNSQuestion {
    type Error = DNSError;
    fn from_bytes<R: Read + Seek>(reader: &mut R) -> Result<Self, Self::Error> {
        match decode::dns_name_simple(reader) {
            Ok((domain_name, _)) => {
                let r#type = reader.read_u16::<BigEndian>()?;
                let class = reader.read_u16::<BigEndian>()?;
                Ok(Self {
                    name: domain_name,
                    r#type: r#type.try_into()?,
                    class: class.try_into()?,
                })
            }
            Err(err) => Err(err),
        }
    }
}

impl FromBytes for DNSRecord {
    type Error = DNSError;
    fn from_bytes<R: Read + Seek>(reader: &mut R) -> Result<Self, Self::Error> {
        let (domain_name, _) = decode::dns_name(reader)?;

        let r#type = reader.read_u16::<BigEndian>()?.try_into()?;
        let class = reader.read_u16::<BigEndian>()?.try_into()?;
        let ttl = reader.read_u32::<BigEndian>()?;
        let data_len = reader.read_u16::<BigEndian>()?;

        let mut buf = vec![0; data_len as usize];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            name: domain_name,
            r#type,
            class,
            ttl,
            data: buf,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

impl ToBytes for DNSPacket {
    fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, DNSError> {
        let mut total_bytes_written = 0;
        total_bytes_written += self.header.to_bytes(writer)?;

        for question in self.questions.iter() {
            total_bytes_written += question.to_bytes(writer)?
        }
        for record in self.answers.iter() {
            total_bytes_written += record.to_bytes(writer)?
        }
        for record in self.authorities.iter() {
            total_bytes_written += record.to_bytes(writer)?
        }
        for record in self.additionals.iter() {
            total_bytes_written += record.to_bytes(writer)?
        }
        Ok(total_bytes_written)
    }
}

impl DNSPacket {
    pub fn ip(&self) -> Option<String> {
        self.answers.iter().find_map(|answer| {
            if answer.r#type == DNSRecordType::A {
                answer.try_parse_a_record().map(|ip| ip.to_string()).ok()
            } else {
                None
            }
        })
    }

    pub(crate) fn get_nameserver_from_authorities(&self) -> Option<String> {
        self.authorities
            .iter()
            .find_map(|answer| match answer.r#type == DNSRecordType::NS {
                true => {
                    let mut cursor = Cursor::new(&answer.data);
                    Some(decode::dns_name(&mut cursor).map(|(name, _)| name).unwrap())
                }
                false => None,
            })
    }

    pub(crate) fn get_nameserver_from_additionals(&self) -> Option<String> {
        self.additionals
            .iter()
            .find_map(|answer| match answer.r#type == DNSRecordType::NS {
                true => {
                    let mut cursor = Cursor::new(&answer.data);
                    Some(decode::dns_name(&mut cursor).map(|(name, _)| name).unwrap())
                }
                false => None,
            })
    }

    pub(crate) fn get_nameserver(&self) -> Option<String> {
        if let Some(result) = self.get_nameserver_from_authorities() {
            return Some(result);
        }
        self.get_nameserver_from_additionals()
    }

    pub(crate) fn get_cname_record(&self) -> Option<String> {
        self.answers
            .iter()
            .find_map(|answer| match answer.r#type == DNSRecordType::CNAME {
                true => {
                    let mut cursor = Cursor::new(&answer.data);
                    Some(decode::dns_name(&mut cursor).map(|(name, _)| name).unwrap())
                }
                false => None,
            })
    }

    pub fn get_nameserver_ip(&self) -> Option<IpAddr> {
        self.additionals
            .iter()
            .find_map(|answer| match answer.r#type == DNSRecordType::A {
                true => {
                    if let Ok(a_record) = answer.try_parse_a_record() {
                        return Some(IpAddr::V4(a_record));
                    }
                    answer.try_parse_aaaa_record().map(IpAddr::V6).ok()
                }
                false => None,
            })
    }

    pub fn get_answer(&self) -> Option<IpAddr> {
        self.answers
            .iter()
            .find_map(|answer| match answer.r#type == DNSRecordType::A {
                true => {
                    if let Ok(a_record) = answer.try_parse_a_record() {
                        return Some(IpAddr::V4(a_record));
                    }
                    answer.try_parse_aaaa_record().map(IpAddr::V6).ok()
                }
                false => None,
            })
    }
}

impl FromBytes for DNSPacket {
    type Error = DNSError;
    fn from_bytes<R: Read + Seek>(data: &mut R) -> Result<Self, Self::Error> {
        let header = DNSHeader::from_bytes(data)?;

        let questions = (0..header.num_questions)
            .map(|_| DNSQuestion::from_bytes(data))
            .collect::<Result<Vec<DNSQuestion>, DNSError>>()?;

        let answers = (0..header.num_answers)
            .map(|_| DNSRecord::from_bytes(data))
            .collect::<Result<Vec<DNSRecord>, DNSError>>()?;

        let authorities = (0..header.num_authorities)
            .map(|_| DNSRecord::from_bytes(data))
            .collect::<Result<Vec<DNSRecord>, DNSError>>()?;

        let additionals = (0..header.num_additionals)
            .map(|_| DNSRecord::from_bytes(data))
            .collect::<Result<Vec<DNSRecord>, DNSError>>()?;

        Ok(Self {
            header,
            answers,
            additionals,
            authorities,
            questions,
        })
    }
}

#[cfg(test)]
pub fn lookup_domain(domain_name: &str) -> Result<String, DNSError> {
    let query = DNSQuery::new(
        domain_name,
        DNSRecordType::A,
        DNSRecordClass::IN,
        DNSHeaderFlag::RecursionDesired,
    );
    let response = query.send_to_8_8_8_8()?;
    let mut reader = std::io::Cursor::new(response);
    let packet = DNSPacket::from_bytes(&mut reader)?;
    packet.ip().ok_or(DNSError::NoIpAddressFound)
}

pub mod encode {
    use super::DNSError;
    use structure::byteorder::WriteBytesExt;

    /// Given a domain name encode it into bytes.
    pub fn dns_name<W: std::io::Write>(
        writer: &mut W,
        domain_name: &str,
    ) -> Result<usize, DNSError> {
        let mut total_bytes_written = 0;

        for part in domain_name.split('.') {
            let part_as_bytes = part.as_bytes();
            let len: u8 = part_as_bytes.len().try_into()?;

            writer.write_u8(len)?;
            total_bytes_written += 1;

            writer.write_all(part_as_bytes)?;
            total_bytes_written += part_as_bytes.len();
        }
        writer.write_u8(0)?;

        Ok(total_bytes_written)
    }
}

pub mod decode {
    use super::DNSError;
    use std::io::{Read, Seek, SeekFrom};
    use structure::byteorder::ReadBytesExt;

    pub fn dns_name_simple<R: Read>(reader: &mut R) -> Result<(String, usize), DNSError> {
        let mut parts = vec![];
        let mut total_bytes_read: usize = 0;

        loop {
            let length = reader.read_u8()?;
            total_bytes_read += 1;

            if length == 0 {
                break;
            }
            let mut buf = vec![0; length as usize];
            reader.read_exact(&mut buf)?;
            total_bytes_read += length as usize;

            let part = String::from_utf8(buf)?;
            parts.push(part);
        }
        Ok((parts.join("."), total_bytes_read))
    }

    pub fn dns_name<R: Read + Seek>(reader: &mut R) -> Result<(String, usize), DNSError> {
        let mut parts = vec![];
        let mut total_bytes_read: usize = 0;

        loop {
            let length = reader.read_u8()?;
            total_bytes_read += 1;

            if length == 0 {
                break;
            }

            // Both of the two first bits set implies
            // we need to decompress the value.
            match length & 0b1100_0000 > 0 {
                true => {
                    let top_half = length & 0b0011_1111;
                    let (part, bytes_read) = dns_name_compressed(reader, top_half)?;
                    total_bytes_read += bytes_read;
                    parts.push(part);
                    break;
                }
                false => {
                    let mut buf = vec![0; length as usize];
                    reader.read_exact(&mut buf)?;
                    total_bytes_read += length as usize;
                    parts.push(String::from_utf8(buf)?);
                }
            }
        }
        Ok((parts.join("."), total_bytes_read))
    }

    pub fn dns_name_compressed<R: Read + Seek>(
        reader: &mut R,
        top_half: u8,
    ) -> Result<(String, usize), DNSError> {
        let bottom_half = reader.read_u8()? as u16;
        let pointer: u16 = ((top_half as u16) << 8) | bottom_half;
        let current_position = reader.stream_position()?;
        reader.seek(SeekFrom::Start(pointer as u64))?;
        let (result, bytes_read) = dns_name(reader)?;
        reader.seek(SeekFrom::Start(current_position))?;
        Ok((result, bytes_read))
    }
}
