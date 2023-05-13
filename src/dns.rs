use std::io::Read;
use std::io::Seek;
use std::net::AddrParseError;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

use bytes::Bytes;
use rand::prelude::*;
use rand::thread_rng;
use structure::byteorder::{
    BigEndian,
    ReadBytesExt,
    WriteBytesExt
};
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
    // NS = 2,
    // MD = 3,
    // MF = 4,
    CNAME = 5,
    // SOA = 6,
    // add more,
}

impl TryFrom<Int> for DNSRecordType {
    type Error = DNSError;
    fn try_from(value: Int) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            5 => Ok(Self::CNAME),
            _ => Err(DNSError::BadRecordType(value))
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
            _ => Err(DNSError::BadRecordClass(value))
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
    NoIpAddressFound
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSQuestion {
    pub name: String,
    pub r#type: DNSRecordType,
    pub class: DNSRecordClass,
}

impl DNSQuestion {
    pub fn new(
        domain_name: &str,
        r#type: DNSRecordType,
        class: DNSRecordClass,
    ) -> Self {
        Self {
            name: domain_name.to_string(),
            r#type,
            class
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
    header: DNSHeader,
    question: DNSQuestion,
}

impl ToBytes for DNSQuery {
    fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, DNSError> {
        let mut total_bytes = 0;
        total_bytes += self.header.to_bytes(writer)?;
        total_bytes += self.question.to_bytes(writer)?;

        Ok(total_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DNSHeaderFlag {
    RecursionDesired,
    None,
    Other(Int)
}


impl From<DNSHeaderFlag> for Int {
    fn from(value: DNSHeaderFlag) -> Self {
        match value {
            DNSHeaderFlag::None => 0,
            DNSHeaderFlag::RecursionDesired => 1 << 8,
            DNSHeaderFlag::Other(v) => v
        }
    }
}


impl From<Int> for DNSHeaderFlag {
    fn from(value: Int) -> Self {
        match value {
            0 => Self::None,
            256 => Self::RecursionDesired,
            _ => Self::Other(value)
        }
    }
}

impl DNSQuery {
    pub fn new(
        domain_name: &str,
        record_type: DNSRecordType,
        record_class: DNSRecordClass,
    ) -> Self {
        let question = DNSQuestion::new(domain_name, record_type, record_class);
        let header_id = thread_rng().gen();
        Self {
            question,
            header: DNSHeader {
                id: header_id,
                num_questions: 1,
                flags: DNSHeaderFlag::RecursionDesired,
                num_additionals: 0,
                num_answers: 0,
                num_authorities: 0,
            },
        }
    }

    #[cfg(test)]
    pub fn send_to_8_8_8_8(&self) -> Result<Bytes, DNSError> {
        use std::net::{SocketAddr, UdpSocket};

        let mut contents = vec![];
        self.to_bytes(&mut contents)?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let recipient = "8.8.8.8:53".parse::<SocketAddr>()?;

        socket.send_to(&contents, recipient)?;

        let mut recv_buf = [0; 1024];
        let (size, _) = socket.recv_from(&mut recv_buf)?;

        let observed = recv_buf[0..size].to_vec();
        Ok(Bytes::from(observed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSRecord {
    pub name: String,
    pub r#type: DNSRecordType,
    pub class: DNSRecordClass,
    pub ttl: u32,
    pub data: Bytes
}

impl FromBytes for DNSHeader {
    type Error = DNSError;
    fn from_bytes<R: Read>(data: &mut R) -> Result<Self, Self::Error> {
        Ok( Self {
            id: data.read_u16::<BigEndian>()?,
            flags: data.read_u16::<BigEndian>()?.into(),
            num_questions: data.read_u16::<BigEndian>()?,
            num_answers: data.read_u16::<BigEndian>()?,
            num_additionals: data.read_u16::<BigEndian>()?,
            num_authorities: data.read_u16::<BigEndian>()?
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
                    class: class.try_into()?
                })
            },
            Err(err) => {
                Err(err)
            }
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
            data: Bytes::from(buf)
        })
    }
}

impl DNSRecord {

    #[inline(always)]
    pub fn ip(&self) -> Option<String> {
        let octets = self.data.iter().map(|&x| format!("{x}")).collect::<Vec<String>>();
        Some(octets.join("."))
    }
}

#[derive(Debug, Clone)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>
}


impl FromBytes for DNSPacket {
    type Error = DNSError;
    fn from_bytes<R: Read + Seek>(data: &mut R) -> Result<Self, Self::Error> {
        let header = DNSHeader::from_bytes(data)?;
        
        let questions =
        (0..header.num_questions)
        .map(|_| {
            DNSQuestion::from_bytes(data)
        })
        .collect::<Result<Vec<DNSQuestion>, DNSError>>()?;
        
        let answers =
        (0..header.num_answers)
        .map(|_| {
            DNSRecord::from_bytes(data)
        })
        .collect::<Result<Vec<DNSRecord>, DNSError>>()?;

        let authorities =
        (0..header.num_authorities)
        .map(|_| {
            DNSRecord::from_bytes(data)
        })
        .collect::<Result<Vec<DNSRecord>, DNSError>>()?;

        let additionals =
        (0..header.num_additionals)
        .map(|_| {
            DNSRecord::from_bytes(data)
        })
        .collect::<Result<Vec<DNSRecord>, DNSError>>()?;

        Ok(Self {
            header,
            answers,
            additionals,
            authorities,
            questions
        })
    }
}


#[cfg(test)]
pub fn lookup_domain(domain_name: &str) -> Result<String, DNSError> {
    let query = DNSQuery::new(domain_name, DNSRecordType::A, DNSRecordClass::IN);
    let response = query.send_to_8_8_8_8()?;
    let mut reader = std::io::Cursor::new(response);
    let packet = DNSPacket::from_bytes(&mut reader)?;
    packet.answers[0].ip().ok_or(DNSError::NoIpAddressFound)
}


pub mod encode {
    use super::DNSError;
    use structure::byteorder::WriteBytesExt;

    /// Given a domain name encode it into bytes.
    pub fn dns_name<W: std::io::Write>(writer: &mut W, domain_name: &str) -> Result<usize, DNSError> {
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
    use std::io::{Read, Seek, SeekFrom};
    use super::DNSError;
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
                },
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
        top_half: u8
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
