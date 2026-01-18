use anyhow::Result;
use std::collections::HashMap;

use crate::http2_advanced::{
    Http2Settings, FlowController, PriorityTree, HeaderOrderPreserver,
    StreamPriority,
};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types
const FRAME_DATA: u8 = 0x00;
const FRAME_HEADERS: u8 = 0x01;
const FRAME_PRIORITY: u8 = 0x02;
const FRAME_RST_STREAM: u8 = 0x03;
const FRAME_SETTINGS: u8 = 0x04;
const FRAME_PUSH_PROMISE: u8 = 0x05;
const FRAME_PING: u8 = 0x06;
const FRAME_GOAWAY: u8 = 0x07;
const FRAME_WINDOW_UPDATE: u8 = 0x08;
const FRAME_CONTINUATION: u8 = 0x09;

// Frame flags
const FLAG_END_STREAM: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;
const FLAG_ACK: u8 = 0x01;

#[derive(Debug, Clone)]
pub struct Http2Frame {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Http2Frame {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 9 {
            return Err(anyhow::anyhow!("Frame too short"));
        }

        let length = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let frame_type = data[3];
        let flags = data[4];
        let stream_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFFFFFF;

        let payload = if data.len() >= 9 + length as usize {
            data[9..9 + length as usize].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
            payload,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut frame = Vec::new();
        
        frame.extend_from_slice(&self.length.to_be_bytes()[1..4]);
        frame.push(self.frame_type);
        frame.push(self.flags);
        frame.extend_from_slice(&self.stream_id.to_be_bytes());
        frame.extend_from_slice(&self.payload);
        
        frame
    }

    pub fn is_end_stream(&self) -> bool {
        (self.flags & FLAG_END_STREAM) != 0
    }

    pub fn is_end_headers(&self) -> bool {
        (self.flags & FLAG_END_HEADERS) != 0
    }
}

pub struct Http2Handler {
    settings: Http2Settings,
    flow_controller: FlowController,
    priority_tree: PriorityTree,
    header_preserver: HeaderOrderPreserver,
    remote_settings: Option<Http2Settings>,
    next_stream_id: u32,
    stream_states: HashMap<u32, StreamState>,
    preface_sent: bool,
    preface_received: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
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
            stream_states: HashMap::new(),
            preface_sent: false,
            preface_received: false,
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
            stream_states: HashMap::new(),
            preface_sent: false,
            preface_received: false,
        }
    }

    pub fn build_connection_preface(&mut self) -> Vec<u8> {
        let mut preface = Vec::new();
        preface.extend_from_slice(PREFACE);
        
        let settings_frame = self.settings.to_frame();
        preface.extend_from_slice(&settings_frame);
        
        self.preface_sent = true;
        preface
    }

    pub fn create_stream(&mut self, stream_id: u32) -> Result<()> {
        self.flow_controller.create_stream(stream_id, self.settings.initial_window_size);
        self.stream_states.insert(stream_id, StreamState::Open);
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
        let frame = Http2Frame {
            length: 4,
            frame_type: FRAME_WINDOW_UPDATE,
            flags: 0,
            stream_id,
            payload: increment.to_be_bytes().to_vec(),
        };
        frame.serialize()
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

        let flags = if end_stream {
            FLAG_END_STREAM | FLAG_END_HEADERS
        } else {
            FLAG_END_HEADERS
        };

        let frame = Http2Frame {
            length: header_block.len() as u32,
            frame_type: FRAME_HEADERS,
            flags,
            stream_id,
            payload: header_block,
        };

        frame.serialize()
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
        let flags = if end_stream { FLAG_END_STREAM } else { 0 };

        let frame = Http2Frame {
            length: data.len() as u32,
            frame_type: FRAME_DATA,
            flags,
            stream_id,
            payload: data.to_vec(),
        };

        frame.serialize()
    }

    pub fn build_priority_frame(&self, stream_id: u32) -> Option<Vec<u8>> {
        self.priority_tree.to_priority_frame(stream_id)
    }

    pub fn set_stream_priority(&mut self, stream_id: u32, priority: StreamPriority) {
        self.priority_tree.update_priority(stream_id, priority);
    }

    pub fn handle_incoming_frame(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.preface_received && data.starts_with(PREFACE) {
            self.preface_received = true;
            if data.len() > PREFACE.len() {
                return self.handle_incoming_frame(&data[PREFACE.len()..]);
            }
            return Ok(Vec::new());
        }

        let frame = Http2Frame::parse(data)?;
        let response = self.process_frame(&frame)?;

        Ok(response)
    }

    fn process_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        match frame.frame_type {
            FRAME_DATA => self.handle_data_frame(frame),
            FRAME_HEADERS => self.handle_headers_frame(frame),
            FRAME_PRIORITY => self.handle_priority_frame(frame),
            FRAME_RST_STREAM => self.handle_rst_stream_frame(frame),
            FRAME_SETTINGS => self.handle_settings_frame(frame),
            FRAME_PUSH_PROMISE => self.handle_push_promise_frame(frame),
            FRAME_PING => self.handle_ping_frame(frame),
            FRAME_GOAWAY => self.handle_goaway_frame(frame),
            FRAME_WINDOW_UPDATE => self.handle_window_update_frame(frame),
            FRAME_CONTINUATION => self.handle_continuation_frame(frame),
            _ => {
                log::warn!("Unknown frame type: {}", frame.frame_type);
                Ok(Vec::new())
            }
        }
    }

    fn handle_data_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        self.flow_controller.update_window(frame.stream_id, frame.length);

        if frame.is_end_stream() {
            if let Some(state) = self.stream_states.get_mut(&frame.stream_id) {
                *state = match state {
                    StreamState::Open => StreamState::HalfClosedRemote,
                    StreamState::HalfClosedLocal => StreamState::Closed,
                    _ => state.clone(),
                };
            }
        }

        Ok(Vec::new())
    }

    fn handle_headers_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        if !self.stream_states.contains_key(&frame.stream_id) {
            self.create_stream(frame.stream_id)?;
        }

        if frame.is_end_stream() {
            if let Some(state) = self.stream_states.get_mut(&frame.stream_id) {
                *state = StreamState::HalfClosedRemote;
            }
        }

        Ok(Vec::new())
    }

    fn handle_priority_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        if frame.payload.len() >= 5 {
            let depends_on = u32::from_be_bytes([
                frame.payload[0] & 0x7F,
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]);
            let exclusive = (frame.payload[0] & 0x80) != 0;
            let weight = frame.payload[4];

            let priority = StreamPriority {
                depends_on,
                weight,
                exclusive,
            };

            self.set_stream_priority(frame.stream_id, priority);
        }

        Ok(Vec::new())
    }

    fn handle_rst_stream_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        if let Some(state) = self.stream_states.get_mut(&frame.stream_id) {
            *state = StreamState::Closed;
        }
        self.flow_controller.remove_stream(frame.stream_id);

        Ok(Vec::new())
    }

    fn handle_settings_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        if (frame.flags & FLAG_ACK) != 0 {
            return Ok(Vec::new());
        }

        let mut settings = Http2Settings::default();
        let mut offset = 0;

        while offset + 6 <= frame.payload.len() {
            let id = u16::from_be_bytes([frame.payload[offset], frame.payload[offset + 1]]);
            let value = u32::from_be_bytes([
                frame.payload[offset + 2],
                frame.payload[offset + 3],
                frame.payload[offset + 4],
                frame.payload[offset + 5],
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

        Ok(self.build_settings_ack())
    }

    fn handle_push_promise_frame(&mut self, _frame: &Http2Frame) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn handle_ping_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        if (frame.flags & FLAG_ACK) != 0 {
            return Ok(Vec::new());
        }

        if frame.payload.len() >= 8 {
            let mut ping_data = [0u8; 8];
            ping_data.copy_from_slice(&frame.payload[..8]);
            Ok(self.build_ping_ack(&ping_data))
        } else {
            Ok(Vec::new())
        }
    }

    fn handle_goaway_frame(&mut self, _frame: &Http2Frame) -> Result<Vec<u8>> {
        log::info!("Received GOAWAY frame");
        Ok(Vec::new())
    }

    fn handle_window_update_frame(&mut self, frame: &Http2Frame) -> Result<Vec<u8>> {
        if frame.payload.len() >= 4 {
            let increment = u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]) & 0x7FFFFFFF;

            self.update_window(frame.stream_id, increment);
        }

        Ok(Vec::new())
    }

    fn handle_continuation_frame(&mut self, _frame: &Http2Frame) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    pub fn build_settings_ack(&self) -> Vec<u8> {
        let frame = Http2Frame {
            length: 0,
            frame_type: FRAME_SETTINGS,
            flags: FLAG_ACK,
            stream_id: 0,
            payload: Vec::new(),
        };
        frame.serialize()
    }

    pub fn build_goaway_frame(&self, last_stream_id: u32, error_code: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&last_stream_id.to_be_bytes());
        payload.extend_from_slice(&error_code.to_be_bytes());

        let frame = Http2Frame {
            length: 8,
            frame_type: FRAME_GOAWAY,
            flags: 0,
            stream_id: 0,
            payload,
        };
        frame.serialize()
    }

    pub fn build_ping_frame(&self, data: &[u8; 8]) -> Vec<u8> {
        let frame = Http2Frame {
            length: 8,
            frame_type: FRAME_PING,
            flags: 0,
            stream_id: 0,
            payload: data.to_vec(),
        };
        frame.serialize()
    }

    pub fn build_ping_ack(&self, data: &[u8; 8]) -> Vec<u8> {
        let frame = Http2Frame {
            length: 8,
            frame_type: FRAME_PING,
            flags: FLAG_ACK,
            stream_id: 0,
            payload: data.to_vec(),
        };
        frame.serialize()
    }

    pub fn get_settings(&self) -> &Http2Settings {
        &self.settings
    }

    pub fn get_remote_settings(&self) -> Option<&Http2Settings> {
        self.remote_settings.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_parse() {
        let data = vec![0, 0, 4, FRAME_SETTINGS, 0, 0, 0, 0, 0, 1, 2, 3, 4];
        let frame = Http2Frame::parse(&data).unwrap();
        
        assert_eq!(frame.length, 4);
        assert_eq!(frame.frame_type, FRAME_SETTINGS);
        assert_eq!(frame.stream_id, 0);
    }

    #[test]
    fn test_http2_handler_creation() {
        let handler = Http2Handler::new_ios_safari();
        assert_eq!(handler.settings.initial_window_size, 1048576);
        assert_eq!(handler.settings.max_frame_size, 16384);
    }
}