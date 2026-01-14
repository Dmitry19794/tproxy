// src/tcp.rs
use std::net::Ipv4Addr;
use std::time::Instant;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionId {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl ConnectionId {
    pub fn from_packets(ip: &Ipv4Packet, tcp: &TcpPacket) -> Self {
        Self {
            src_ip: ip.get_source(),
            dst_ip: ip.get_destination(),
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpOptionsExact {
    pub options_raw: Vec<u8>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamp_value: Option<u32>,
    pub timestamp_echo: Option<u32>,
}

impl TcpOptionsExact {
    pub fn from_packet(packet: &TcpPacket) -> Self {
        let mut options_raw = Vec::new();
        let mut mss = None;
        let mut window_scale = None;
        let mut sack_permitted = false;
        let mut timestamp_value = None;
        let mut timestamp_echo = None;
        
        let tcp_header_len = (packet.get_data_offset() * 4) as usize;
        let options_len = tcp_header_len.saturating_sub(20);
        
        if options_len > 0 && packet.packet().len() >= tcp_header_len {
            options_raw = packet.packet()[20..tcp_header_len].to_vec();
        }
        
        for opt in packet.get_options_iter() {
            match opt.get_number().0 {
                2 => {
                    let data = opt.payload();
                    if data.len() >= 2 {
                        mss = Some(u16::from_be_bytes([data[0], data[1]]));
                    }
                }
                3 => {
                    let data = opt.payload();
                    if !data.is_empty() {
                        window_scale = Some(data[0]);
                    }
                }
                4 => {
                    sack_permitted = true;
                }
                8 => {
                    let data = opt.payload();
                    if data.len() >= 8 {
                        timestamp_value = Some(u32::from_be_bytes([
                            data[0], data[1], data[2], data[3]
                        ]));
                        timestamp_echo = Some(u32::from_be_bytes([
                            data[4], data[5], data[6], data[7]
                        ]));
                    }
                }
                _ => {}
            }
        }
        
        Self {
            options_raw,
            mss,
            window_scale,
            sack_permitted,
            timestamp_value,
            timestamp_echo,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpParametersExact {
    pub ttl: u8,
    pub tos: u8,
    pub df_flag: bool,
}

impl IpParametersExact {
    pub fn from_packet(packet: &Ipv4Packet) -> Self {
        Self {
            ttl: packet.get_ttl(),
            tos: packet.get_dscp() << 2 | packet.get_ecn(),
            df_flag: (packet.get_flags() & 0x02) != 0,
        }
    }
}

#[derive(Debug)]
pub struct ConnectionState {
    pub id: ConnectionId,
    pub client_seq: u32,
    pub server_seq: u32,
    pub client_options: TcpOptionsExact,
    pub client_ip: IpParametersExact,
    pub tls_modified: bool,
    pub created_at: Instant,
}

impl ConnectionState {
    pub fn new(id: ConnectionId, ip: &Ipv4Packet, tcp: &TcpPacket) -> Self {
        Self {
            id,
            client_seq: tcp.get_sequence(),
            server_seq: 0,
            client_options: TcpOptionsExact::from_packet(tcp),
            client_ip: IpParametersExact::from_packet(ip),
            tls_modified: false,
            created_at: Instant::now(),
        }
    }
}
