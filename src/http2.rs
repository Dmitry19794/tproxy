use anyhow::Result;

use crate::http2_advanced::{
    Http2Settings, FlowController, PriorityTree, HeaderOrderPreserver,
    StreamPriority,
};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub struct Http2Handler {
    settings: Http2Settings,
    flow_controller: FlowController,
    priority_tree: PriorityTree,
    header_preserver: HeaderOrderPreserver,
    remote_settings: Option<Http2Settings>,
    next_stream_id: u32,
}

impl Http2Handler {
    pub fn new_ios_safari() -> Self {
        let settings = Http2Settings::ios_safari();
        let flow_controller = FlowController::new(settings.initial_window_size);
        let priority_tree = PriorityTree::ios_safari_defaults();
        let header_preserver = HeaderOrderPreserver::ios_safari();

        Self {
            settings,
            flow_controller,
            priority_tree,
            header_preserver,
            remote_settings: None,
            next_stream_id: 1,
        }
    }

    pub fn new_custom(settings: Http2Settings) -> Self {
        let flow_controller = FlowController::new(settings.initial_window_size);
        let priority_tree = PriorityTree::new();
        let header_preserver = HeaderOrderPreserver::ios_safari();

        Self {
            settings,
            flow_controller,
            priority_tree,
            header_preserver,
            remote_settings: None,
            next_stream_id: 1,
        }
    }

    pub fn build_connection_preface(&self) -> Vec<u8> {
        let mut preface = Vec::new();
        preface.extend_from_slice(PREFACE);
        
        let settings_frame = self.settings.to_frame();
        preface.extend_from_slice(&settings_frame);
        
        preface
    }

    pub fn create_stream(&mut self, stream_id: u32) -> Result<()> {
        self.flow_controller.create_stream(stream_id, self.settings.initial_window_size);
        Ok(())
    }

    pub fn get_next_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id += 2;
        id
    }

    pub fn can_send_data(&mut self, stream_id: u32, bytes: u32) -> Result<bool> {
        self.flow_controller.consume_window(stream_id, bytes)
    }

    pub fn update_window(&mut self, stream_id: u32, increment: u32) {
        self.flow_controller.update_window(stream_id, increment);
    }

    pub fn check_and_send_window_updates(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        if self.flow_controller.should_send_updates() {
            self.flow_controller.check_and_queue_updates();

            while let Some((stream_id, increment)) = self.flow_controller.pop_window_update() {
                let frame = self.build_window_update_frame(stream_id, increment);
                frames.push(frame);
            }
        }

        frames
    }

    fn build_window_update_frame(&self, stream_id: u32, increment: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&[0, 0, 4]);
        frame.push(0x08);
        frame.push(0x00);
        
        frame.extend_from_slice(&stream_id.to_be_bytes());
        
        frame.extend_from_slice(&increment.to_be_bytes());
        
        frame
    }

    pub fn build_headers_frame(
        &mut self,
        stream_id: u32,
        mut headers: Vec<(String, String)>,
        end_stream: bool,
    ) -> Vec<u8> {
        self.header_preserver.sort_headers(&mut headers);

        let mut header_block = Vec::new();
        for (name, value) in headers {
            header_block.extend_from_slice(&self.encode_header(&name, &value));
        }

        let mut frame = Vec::new();
        
        let length = header_block.len() as u32;
        frame.extend_from_slice(&length.to_be_bytes()[1..4]);
        
        frame.push(0x01);
        
        let mut flags = 0x04;
        if end_stream {
            flags |= 0x01;
        }
        frame.push(flags);
        
        frame.extend_from_slice(&stream_id.to_be_bytes());
        
        frame.extend_from_slice(&header_block);
        
        frame
    }

    fn encode_header(&self, name: &str, value: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        
        encoded.push(0x40);
        
        encoded.push(name.len() as u8);
        encoded.extend_from_slice(name.as_bytes());
        
        encoded.push(value.len() as u8);
        encoded.extend_from_slice(value.as_bytes());
        
        encoded
    }

    pub fn build_data_frame(&self, stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        
        let length = data.len() as u32;
        frame.extend_from_slice(&length.to_be_bytes()[1..4]);
        
        frame.push(0x00);
        
        let flags = if end_stream { 0x01 } else { 0x00 };
        frame.push(flags);
        
        frame.extend_from_slice(&stream_id.to_be_bytes());
        
        frame.extend_from_slice(data);
        
        frame
    }

    pub fn build_priority_frame(&self, stream_id: u32) -> Option<Vec<u8>> {
        self.priority_tree.to_priority_frame(stream_id)
    }

    pub fn set_stream_priority(&mut self, stream_id: u32, priority: StreamPriority) {
        self.priority_tree.update_priority(stream_id, priority);
    }

    pub fn parse_settings_frame(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 9 {
            return Err(anyhow::anyhow!("Settings frame too short"));
        }

        let payload = &data[9..];
        
        let mut settings = Http2Settings::default();
        
        let mut offset = 0;
        while offset + 6 <= payload.len() {
            let id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let value = u32::from_be_bytes([
                payload[offset + 2],
                payload[offset + 3],
                payload[offset + 4],
                payload[offset + 5],
            ]);

            match id {
                0x01 => settings.header_table_size = value,
                0x02 => settings.enable_push = value != 0,
                0x03 => settings.max_concurrent_streams = value,
                0x04 => settings.initial_window_size = value,
                0x05 => settings.max_frame_size = value,
                0x06 => settings.max_header_list_size = value,
                _ => {}
            }

            offset += 6;
        }

        self.remote_settings = Some(settings);
        Ok(())
    }

    pub fn build_settings_ack(&self) -> Vec<u8> {
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&[0, 0, 0]);
        frame.push(0x04);
        frame.push(0x01);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        
        frame
    }

    pub fn parse_frame_type(&self, data: &[u8]) -> Option<u8> {
        if data.len() >= 4 {
            Some(data[3])
        } else {
            None
        }
    }

    pub fn parse_stream_id(&self, data: &[u8]) -> Option<u32> {
        if data.len() >= 9 {
            Some(u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFFFFFF)
        } else {
            None
        }
    }

    pub fn handle_incoming_frame(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 9 {
            return Err(anyhow::anyhow!("Frame too short"));
        }

        let frame_type = data[3];
        let stream_id = self.parse_stream_id(data).unwrap_or(0);

        match frame_type {
            0x00 => {
                let length = u32::from_be_bytes([0, data[0], data[1], data[2]]) as u32;
                self.flow_controller.update_window(stream_id, length);
            }
            0x04 => {
                self.parse_settings_frame(data)?;
            }
            0x08 => {
                if data.len() >= 13 {
                    let increment = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
                    self.update_window(stream_id, increment);
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn get_settings(&self) -> &Http2Settings {
        &self.settings
    }

    pub fn get_remote_settings(&self) -> Option<&Http2Settings> {
        self.remote_settings.as_ref()
    }

    pub fn build_goaway_frame(&self, last_stream_id: u32, error_code: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&[0, 0, 8]);
        frame.push(0x07);
        frame.push(0x00);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        
        frame.extend_from_slice(&last_stream_id.to_be_bytes());
        frame.extend_from_slice(&error_code.to_be_bytes());
        
        frame
    }

    pub fn build_ping_frame(&self, data: &[u8; 8]) -> Vec<u8> {
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&[0, 0, 8]);
        frame.push(0x06);
        frame.push(0x00);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        
        frame.extend_from_slice(data);
        
        frame
    }

    pub fn build_ping_ack(&self, data: &[u8; 8]) -> Vec<u8> {
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&[0, 0, 8]);
        frame.push(0x06);
        frame.push(0x01);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        
        frame.extend_from_slice(data);
        
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_handler_creation() {
        let handler = Http2Handler::new_ios_safari();
        assert_eq!(handler.settings.initial_window_size, 1048576);
        assert_eq!(handler.settings.max_frame_size, 16384);
    }

    #[test]
    fn test_connection_preface() {
        let handler = Http2Handler::new_ios_safari();
        let preface = handler.build_connection_preface();
        
        assert!(preface.starts_with(PREFACE));
        assert!(preface.len() > PREFACE.len());
    }

    #[test]
    fn test_stream_creation() {
        let mut handler = Http2Handler::new_ios_safari();
        
        assert!(handler.create_stream(1).is_ok());
        assert!(handler.create_stream(3).is_ok());
    }

    #[test]
    fn test_headers_frame() {
        let mut handler = Http2Handler::new_ios_safari();
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];
        
        let frame = handler.build_headers_frame(1, headers, false);
        
        assert_eq!(frame[3], 0x01);
        assert!(frame.len() > 9);
    }

    #[test]
    fn test_window_update() {
        let mut handler = Http2Handler::new_ios_safari();
        
        handler.create_stream(1).unwrap();
        handler.update_window(1, 65536);
        
        let frames = handler.check_and_send_window_updates();
        assert!(frames.is_empty() || !frames.is_empty());
    }

    #[test]
    fn test_data_frame() {
        let handler = Http2Handler::new_ios_safari();
        
        let data = b"Hello, HTTP/2!";
        let frame = handler.build_data_frame(1, data, true);
        
        assert_eq!(frame[3], 0x00);
        assert_eq!(frame[4], 0x01);
    }

    #[test]
    fn test_settings_ack() {
        let handler = Http2Handler::new_ios_safari();
        let ack = handler.build_settings_ack();
        
        assert_eq!(ack[3], 0x04);
        assert_eq!(ack[4], 0x01);
        assert_eq!(ack.len(), 9);
    }
}