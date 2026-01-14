// src/packet.rs
use anyhow::Result;
use std::sync::Arc;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use tracing::{debug, error, info};

use crate::config::Config;
use crate::tcp::{ConnectionId, ConnectionState, TcpOptionsExact, IpParametersExact};
use crate::tls::TlsModifier;

pub struct PacketInterceptor {
    config: Arc<Config>,
    tls_modifier: TlsModifier,
}

impl PacketInterceptor {
    pub fn new(config: Arc<Config>) -> Self {
        let tls_modifier = TlsModifier::new(config.clone());
        
        Self {
            config,
            tls_modifier,
        }
    }
    
    /// Обработка пакета - ТОЛЬКО ClientHello модифицируем, остальное passthrough
    pub fn process_packet(&self, packet_data: &[u8]) -> Result<Vec<u8>> {
        // Парсим IP пакет
        let ip_packet = match Ipv4Packet::new(packet_data) {
            Some(p) => p,
            None => {
                debug!("Invalid IP packet, passthrough");
                return Ok(packet_data.to_vec());
            }
        };
        
        // Проверяем что это TCP
        if ip_packet.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
            debug!("Not TCP, passthrough");
            return Ok(packet_data.to_vec());
        }
        
        // Парсим TCP пакет
        let tcp_packet = match TcpPacket::new(ip_packet.payload()) {
            Some(p) => p,
            None => {
                debug!("Invalid TCP packet, passthrough");
                return Ok(packet_data.to_vec());
            }
        };
        
        // Извлекаем TCP payload
        let tcp_payload = tcp_packet.payload();
        
        // Проверяем на TLS ClientHello
        if !TlsModifier::is_client_hello(tcp_payload) {
            // НЕ ClientHello - passthrough без изменений
            return Ok(packet_data.to_vec());
        }
        
        info!("🔍 Detected TLS ClientHello from {}:{} -> {}:{}", 
            ip_packet.get_source(),
            tcp_packet.get_source(),
            ip_packet.get_destination(),
            tcp_packet.get_destination()
        );
        
        // Модифицируем ТОЛЬКО ClientHello
        let mut modified_payload = tcp_payload.to_vec();
        
        match self.tls_modifier.modify_client_hello(&mut modified_payload) {
            Ok(_) => {
                info!("✓ Modified ClientHello");
                
                // Собираем модифицированный пакет
                self.rebuild_packet(packet_data, &modified_payload)
            }
            Err(e) => {
                error!("Failed to modify ClientHello: {}, passthrough original", e);
                Ok(packet_data.to_vec())
            }
        }
    }
    
    /// Пересборка пакета с новым payload
    fn rebuild_packet(&self, original: &[u8], new_payload: &[u8]) -> Result<Vec<u8>> {
        let ip_packet = Ipv4Packet::new(original)
            .ok_or_else(|| anyhow::anyhow!("Invalid IP packet"))?;
        
        let tcp_packet = TcpPacket::new(ip_packet.payload())
            .ok_or_else(|| anyhow::anyhow!("Invalid TCP packet"))?;
        
        // Вычисляем размеры
        let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
        let tcp_header_len = (tcp_packet.get_data_offset() as usize) * 4;
        
        // Новый размер пакета
        let new_packet_size = ip_header_len + tcp_header_len + new_payload.len();
        let mut new_packet = vec![0u8; new_packet_size];
        
        // Копируем IP header
        new_packet[..ip_header_len].copy_from_slice(&original[..ip_header_len]);
        
        // Копируем TCP header
        new_packet[ip_header_len..ip_header_len + tcp_header_len]
            .copy_from_slice(&original[ip_header_len..ip_header_len + tcp_header_len]);
        
        // Копируем новый payload
        new_packet[ip_header_len + tcp_header_len..].copy_from_slice(new_payload);
        
        // Обновляем IP total length
        let new_ip_len = (new_packet_size - ip_header_len) as u16;
        new_packet[2] = (new_ip_len >> 8) as u8;
        new_packet[3] = (new_ip_len & 0xFF) as u8;
        
        // Пересчитываем IP checksum
        self.recalculate_ip_checksum(&mut new_packet, ip_header_len);
        
        // Пересчитываем TCP checksum
        self.recalculate_tcp_checksum(&mut new_packet, ip_header_len, tcp_header_len);
        
        Ok(new_packet)
    }
    
    /// Пересчёт IP checksum
    fn recalculate_ip_checksum(&self, packet: &mut [u8], header_len: usize) {
        // Обнуляем старый checksum
        packet[10] = 0;
        packet[11] = 0;
        
        let mut sum: u32 = 0;
        
        for i in (0..header_len).step_by(2) {
            let word = ((packet[i] as u32) << 8) | (packet[i + 1] as u32);
            sum += word;
        }
        
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        let checksum = !sum as u16;
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xFF) as u8;
    }
    
    /// Пересчёт TCP checksum
    fn recalculate_tcp_checksum(&self, packet: &mut [u8], ip_header_len: usize, tcp_header_len: usize) {
        // Извлекаем IP адреса
        let src_ip = [packet[12], packet[13], packet[14], packet[15]];
        let dst_ip = [packet[16], packet[17], packet[18], packet[19]];
        
        let tcp_start = ip_header_len;
        let tcp_len = packet.len() - ip_header_len;
        
        // Обнуляем старый checksum
        packet[tcp_start + 16] = 0;
        packet[tcp_start + 17] = 0;
        
        let mut sum: u32 = 0;
        
        // Pseudo-header
        for i in (0..4).step_by(2) {
            sum += ((src_ip[i] as u32) << 8) | (src_ip[i + 1] as u32);
        }
        for i in (0..4).step_by(2) {
            sum += ((dst_ip[i] as u32) << 8) | (dst_ip[i + 1] as u32);
        }
        sum += 6; // TCP protocol
        sum += tcp_len as u32;
        
        // TCP segment
        for i in (tcp_start..packet.len()).step_by(2) {
            let word = if i + 1 < packet.len() {
                ((packet[i] as u32) << 8) | (packet[i + 1] as u32)
            } else {
                (packet[i] as u32) << 8
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
    fn test_client_hello_detection() {
        let config = Arc::new(Config::default());
        let interceptor = PacketInterceptor::new(config);
        
        // TLS ClientHello packet начинается с 0x16 0x03 0x01 ... 0x01
        let tls_hello = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x01];
        assert!(TlsModifier::is_client_hello(&tls_hello));
    }
}
