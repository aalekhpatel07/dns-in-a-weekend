use clap::Parser;
use log::{debug, error};
use rdns::{resolve, DNSError, DNSPacket, DNSQuery, FromBytes, ToBytes};
use std::{io::Cursor, net::UdpSocket};

#[derive(Debug, Parser)]
pub struct Opts {
    #[clap(short, long, help = "The port for the dns server to listen on.")]
    port: u16,
}

pub fn handle_datagram(mut message: Cursor<Vec<u8>>) -> Result<DNSPacket, DNSError> {
    let query = DNSQuery::from_bytes(&mut message)?;
    let query_id = query.header.id;
    let (mut packet, _) = resolve(&query.question.name, query.question.r#type)?;
    packet.header.id = query_id;
    Ok(packet)
}

pub fn start_server(socket: UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let mut buf = [0; 1024];
        let (bytes_read, sender) = socket.recv_from(&mut buf)?;
        let socket_cp = socket.try_clone()?;
        let contents = Cursor::new(buf[0..bytes_read].to_vec());
        std::thread::spawn(move || match handle_datagram(contents) {
            Ok(packet) => {
                let mut writer = Vec::new();
                packet.to_bytes(&mut writer).unwrap();
                socket_cp.send_to(&writer, sender).unwrap();
                debug!(
                    "Found IP: {:#?} for {} requested by {}",
                    packet.ip(),
                    packet.questions[0].name,
                    sender
                );
            }
            Err(err) => {
                error!("{}", err);
            }
        });
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    simple_logger::init()?;

    let socket = UdpSocket::bind(("0.0.0.0", opts.port))?;

    std::thread::spawn(move || start_server(socket).unwrap())
        .join()
        .unwrap();

    Ok(())
}
