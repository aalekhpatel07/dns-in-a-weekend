use clap::Parser;
use log::{error, info};
use dns_in_a_weekend::{resolve, DNSError, DNSPacket, DNSQuery, FromBytes, ToBytes};
use std::{io::Cursor, net::UdpSocket, collections::HashMap};

#[derive(Debug, Parser)]
pub struct Opts {
    #[clap(short, long, help = "The port for the dns server to listen on.")]
    port: u16,
}

pub type Shared<T> = std::sync::Arc<std::sync::Mutex<T>>;
pub type Database = Shared<std::collections::HashMap<String, DNSPacket>>;

pub fn handle_datagram(mut message: Cursor<Vec<u8>>, cache: Database) -> Result<DNSPacket, DNSError> {
    let query = DNSQuery::from_bytes(&mut message)?;
    let query_id = query.header.id;
    info!("Resolving {}", query.question.name);
    let mut cache_guard = cache.lock().unwrap();

    if let Some(packet) = cache_guard.get(&query.question.name) {
        // some packet is stored.
        // just update ids and send it back.
        let mut packet_cp = packet.clone();
        info!("looked up {} from cache (packet: {:#?})", query.question.name, packet_cp);
        packet_cp.header.id = query_id;
        return Ok(packet_cp)
    }

    let (mut packet, _) = resolve(&query.question.name, query.question.r#type)?;    
    cache_guard.insert(query.question.name, packet.clone());
    packet.header.id = query_id;
    Ok(packet)
}

pub fn start_server(socket: UdpSocket, cache: Database) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let mut buf = [0; 1024];
        let (bytes_read, sender) = socket.recv_from(&mut buf)?;
        let socket_cp = socket.try_clone()?;
        let contents = Cursor::new(buf[0..bytes_read].to_vec());
        let cache_cp = cache.clone();
        std::thread::spawn(move || match handle_datagram(contents, cache_cp) {
            Ok(packet) => {
                let mut writer = Vec::new();
                packet.to_bytes(&mut writer).unwrap();
                socket_cp.send_to(&writer, sender).unwrap();
                info!(
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
    env_logger::init();

    let db = HashMap::new();

    let cache: Database = std::sync::Arc::new(std::sync::Mutex::new(db));

    let socket = UdpSocket::bind(("0.0.0.0", opts.port))?;

    std::thread::spawn(move || start_server(socket, cache).unwrap())
        .join()
        .unwrap();

    Ok(())
}
