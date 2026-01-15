use std::net::Ipv4Addr;

use pnet::packet::tcp::TcpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use log::debug;

pub struct PacketModifier {
}

impl PacketModifier {
    pub fn new() -> Self {
        Self {}
    }

    pub fn modify_packet(&self, packet_data: &[u8]) -> Option<Vec<u8>> {
        if packet_data.len() < 20 {
            return None;
        }

        let mut modified = packet_data.to_vec();

        if let Some(ip_header_len) = self.get_ip_header_length(&modified) {
            self.preserve_ttl(&mut modified, ip_header_len);
            self.preserve_tcp_options(&mut modified, ip_header_len);
        }

        Some(modified)
    }

    fn get_ip_header_length(&self, packet_data: &[u8]) -> Option<usize> {
        let ip_packet = Ipv4Packet::new(packet_data)?;

        let ihl = (packet_data[0] & 0x0F) as usize;
        let ip_header_len = ihl * 4;

        if ip_packet.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        Some(ip_header_len)
    }

    fn preserve_ttl(&self, packet: &mut [u8], ip_header_len: usize) {
        if packet.len() < ip_header_len {
            return;
        }
    }

    fn preserve_tcp_options(&self, packet: &mut [u8], ip_header_len: usize) {
        if packet.len() < ip_header_len + 20 {
            return;
        }

        if let Some(tcp_packet) = TcpPacket::new(&packet[ip_header_len..]) {
            let data_offset = tcp_packet.get_data_offset() as usize;
            let tcp_header_len = data_offset * 4;

            if tcp_header_len > 20 {
                debug!("TCP options present, length: {}", tcp_header_len - 20);
            }
        }
    }

    pub fn modify_window_size(&self, packet: &mut [u8], ip_header_len: usize, new_window: u16) {
        if packet.len() < ip_header_len + 20 {
            return;
        }

        let window_offset = ip_header_len + 14;
        packet[window_offset] = (new_window >> 8) as u8;
        packet[window_offset + 1] = (new_window & 0xFF) as u8;

        self.recalculate_tcp_checksum(packet, ip_header_len, 20);
    }

    pub fn preserve_tcp_timestamps(&self, packet: &[u8], ip_header_len: usize) -> Option<u32> {
        if packet.len() < ip_header_len + 20 {
            return None;
        }

        let tcp_start = ip_header_len;
        let data_offset = ((packet[tcp_start + 12] >> 4) & 0x0F) as usize;
        let tcp_header_len = data_offset * 4;

        if tcp_header_len <= 20 {
            return None;
        }

        let mut offset = tcp_start + 20;
        let options_end = tcp_start + tcp_header_len;

        while offset < options_end {
            let kind = packet[offset];

            match kind {
                0 => break,
                1 => offset += 1,
                8 => {
                    if offset + 10 <= options_end {
                        let timestamp = u32::from_be_bytes([
                            packet[offset + 2],
                            packet[offset + 3],
                            packet[offset + 4],
                            packet[offset + 5],
                        ]);
                        return Some(timestamp);
                    }
                    break;
                }
                _ => {
                    if offset + 1 < options_end {
                        let len = packet[offset + 1] as usize;
                        if len < 2 {
                            break;
                        }
                        offset += len;
                    } else {
                        break;
                    }
                }
            }
        }

        None
    }

    pub fn set_tcp_timestamp(&self, packet: &mut [u8], ip_header_len: usize, timestamp: u32) {
        if packet.len() < ip_header_len + 20 {
            return;
        }

        let tcp_start = ip_header_len;
        let data_offset = ((packet[tcp_start + 12] >> 4) & 0x0F) as usize;
        let tcp_header_len = data_offset * 4;

        if tcp_header_len <= 20 {
            return;
        }

        let mut offset = tcp_start + 20;
        let options_end = tcp_start + tcp_header_len;

        while offset < options_end {
            let kind = packet[offset];

            match kind {
                0 => break,
                1 => offset += 1,
                8 => {
                    if offset + 10 <= options_end {
                        let ts_bytes = timestamp.to_be_bytes();
                        packet[offset + 2] = ts_bytes[0];
                        packet[offset + 3] = ts_bytes[1];
                        packet[offset + 4] = ts_bytes[2];
                        packet[offset + 5] = ts_bytes[3];
                    }
                    break;
                }
                _ => {
                    if offset + 1 < options_end {
                        let len = packet[offset + 1] as usize;
                        if len < 2 {
                            break;
                        }
                        offset += len;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    fn recalculate_tcp_checksum(&self, packet: &mut [u8], ip_header_len: usize, _tcp_header_len: usize) {
        if packet.len() < ip_header_len + 20 {
            return;
        }

        let tcp_start = ip_header_len;
        packet[tcp_start + 16] = 0;
        packet[tcp_start + 17] = 0;

        let src_ip = Ipv4Addr::new(
            packet[12],
            packet[13],
            packet[14],
            packet[15],
        );
        let dst_ip = Ipv4Addr::new(
            packet[16],
            packet[17],
            packet[18],
            packet[19],
        );

        let tcp_length = packet.len() - ip_header_len;

        let mut sum: u32 = 0;

        for byte in src_ip.octets() {
            sum += byte as u32;
        }
        for byte in dst_ip.octets() {
            sum += byte as u32;
        }

        sum += 6;
        sum += tcp_length as u32;

        let tcp_data = &packet[tcp_start..];
        for i in (0..tcp_data.len()).step_by(2) {
            let word = if i + 1 < tcp_data.len() {
                ((tcp_data[i] as u32) << 8) | (tcp_data[i + 1] as u32)
            } else {
                (tcp_data[i] as u32) << 8
            };
            sum += word;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let checksum = !sum as u16;
        packet[tcp_start + 16] = (checksum >> 8) as u8;
        packet[tcp_start + 17] = (checksum & 0xFF) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_modifier_creation() {
        let modifier = PacketModifier::new();
        assert!(true);
    }
}