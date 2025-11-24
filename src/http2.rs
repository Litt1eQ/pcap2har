use hpack::Decoder;
use std::collections::HashMap;

const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
const FRAME_CONTINUATION: u8 = 9;

const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct Http2Frame {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Http2Request {
    pub method: String,
    pub path: String,
    pub authority: String,
    pub scheme: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub stream_id: u32,
}

#[derive(Debug, Clone)]
pub struct Http2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub stream_id: u32,
}

pub fn parse_http2_frames(data: &[u8]) -> Vec<Http2Frame> {
    let mut frames = Vec::new();
    let mut pos = 0;

    if data.len() >= 24 && &data[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        pos = 24;
    }

    while pos + 9 <= data.len() {
        let length = u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]);
        let frame_type = data[pos + 3];
        let flags = data[pos + 4];
        let stream_id = u32::from_be_bytes([
            data[pos + 5] & 0x7f,
            data[pos + 6],
            data[pos + 7],
            data[pos + 8],
        ]);

        let payload_end = pos + 9 + length as usize;
        if payload_end > data.len() {
            break;
        }

        let payload = data[pos + 9..payload_end].to_vec();

        frames.push(Http2Frame {
            length,
            frame_type,
            flags,
            stream_id,
            payload,
        });

        pos = payload_end;
    }

    frames
}

pub fn parse_http2_stream(
    frames: &[Http2Frame],
    is_client: bool,
) -> (Vec<Http2Request>, Vec<Http2Response>) {
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    let mut decoder = Decoder::new();

    let mut stream_headers: HashMap<u32, Vec<(String, String)>> = HashMap::new();
    let mut stream_data: HashMap<u32, Vec<u8>> = HashMap::new();

    for frame in frames {
        match frame.frame_type {
            FRAME_HEADERS => {
                let mut payload = &frame.payload[..];

                if frame.flags & FLAG_PADDED != 0 && !payload.is_empty() {
                    let pad_len = payload[0] as usize;
                    payload = &payload[1..payload.len().saturating_sub(pad_len)];
                }

                if frame.flags & FLAG_PRIORITY != 0 && payload.len() >= 5 {
                    payload = &payload[5..];
                }

                if let Ok(headers) = decoder.decode(payload) {
                    let header_list: Vec<(String, String)> = headers
                        .into_iter()
                        .map(|(name, value)| {
                            (
                                String::from_utf8_lossy(&name).to_string(),
                                String::from_utf8_lossy(&value).to_string(),
                            )
                        })
                        .collect();

                    stream_headers
                        .entry(frame.stream_id)
                        .or_default()
                        .extend(header_list);
                }

                if frame.flags & FLAG_END_HEADERS != 0 {
                    if let Some(hdrs) = stream_headers.get(&frame.stream_id) {
                        if is_client {
                            let mut req = Http2Request {
                                method: String::new(),
                                path: String::new(),
                                authority: String::new(),
                                scheme: String::new(),
                                headers: Vec::new(),
                                body: Vec::new(),
                                stream_id: frame.stream_id,
                            };

                            for (name, value) in hdrs {
                                match name.as_str() {
                                    ":method" => req.method = value.clone(),
                                    ":path" => req.path = value.clone(),
                                    ":authority" => req.authority = value.clone(),
                                    ":scheme" => req.scheme = value.clone(),
                                    _ if !name.starts_with(':') => {
                                        req.headers.push((name.clone(), value.clone()));
                                    }
                                    _ => {}
                                }
                            }

                            requests.push(req);
                        } else {
                            let mut resp = Http2Response {
                                status: 200,
                                headers: Vec::new(),
                                body: Vec::new(),
                                stream_id: frame.stream_id,
                            };

                            for (name, value) in hdrs {
                                if name == ":status" {
                                    resp.status = value.parse().unwrap_or(200);
                                } else if !name.starts_with(':') {
                                    resp.headers.push((name.clone(), value.clone()));
                                }
                            }

                            responses.push(resp);
                        }
                    }
                }
            }
            FRAME_DATA => {
                let mut payload = &frame.payload[..];

                // Handle padding
                if frame.flags & FLAG_PADDED != 0 && !payload.is_empty() {
                    let pad_len = payload[0] as usize;
                    payload = &payload[1..payload.len().saturating_sub(pad_len)];
                }

                stream_data
                    .entry(frame.stream_id)
                    .or_default()
                    .extend_from_slice(payload);

                if is_client {
                    if let Some(req) = requests.iter_mut().find(|r| r.stream_id == frame.stream_id) {
                        req.body = stream_data.get(&frame.stream_id).cloned().unwrap_or_default();
                    }
                } else if let Some(resp) = responses.iter_mut().find(|r| r.stream_id == frame.stream_id) {
                    resp.body = stream_data.get(&frame.stream_id).cloned().unwrap_or_default();
                }
            }
            FRAME_CONTINUATION => {
                if let Ok(headers) = decoder.decode(&frame.payload) {
                    let header_list: Vec<(String, String)> = headers
                        .into_iter()
                        .map(|(name, value)| {
                            (
                                String::from_utf8_lossy(&name).to_string(),
                                String::from_utf8_lossy(&value).to_string(),
                            )
                        })
                        .collect();

                    stream_headers
                        .entry(frame.stream_id)
                        .or_default()
                        .extend(header_list);
                }
            }
            _ => {}
        }
    }

    (requests, responses)
}

// Check if data looks like HTTP/2
pub fn is_http2(data: &[u8]) -> bool {
    // Check for HTTP/2 connection preface
    if data.len() >= 24 && &data[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return true;
    }

    // Check for valid HTTP/2 frame header
    if data.len() >= 9 {
        let length = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let frame_type = data[3];

        // Valid frame types are 0-9
        if frame_type <= 9 && length < 16777216 {
            return true;
        }
    }

    false
}
