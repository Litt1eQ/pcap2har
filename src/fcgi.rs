use std::collections::HashMap;
use std::io::{Cursor, Read};

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;

#[derive(Debug)]
pub struct FcgiRecord {
    pub version: u8,
    pub record_type: u8,
    pub request_id: u16,
    pub content_length: u16,
    pub padding_length: u8,
    pub content: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct FcgiRequest {
    pub params: HashMap<String, String>,
    pub stdin: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct FcgiResponse {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn parse_fcgi_records(data: &[u8]) -> Vec<FcgiRecord> {
    let mut records = Vec::new();
    let mut pos = 0;

    while pos + 8 <= data.len() {
        let version = data[pos];
        let record_type = data[pos + 1];
        let request_id = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let content_length = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
        let padding_length = data[pos + 6];

        let content_start = pos + 8;
        let content_end = content_start + content_length as usize;

        if content_end > data.len() {
            break;
        }

        let content = data[content_start..content_end].to_vec();

        records.push(FcgiRecord {
            version,
            record_type,
            request_id,
            content_length,
            padding_length,
            content,
        });

        pos = content_end + padding_length as usize;
    }

    records
}

pub fn parse_fcgi_request(data: &[u8]) -> Option<FcgiRequest> {
    let records = parse_fcgi_records(data);

    if records.is_empty() {
        return None;
    }

    let has_begin = records.iter().any(|r| r.record_type == FCGI_BEGIN_REQUEST);
    if !has_begin {
        return None;
    }

    let mut request = FcgiRequest::default();

    for record in &records {
        match record.record_type {
            FCGI_PARAMS => {
                parse_params(&record.content, &mut request.params);
            }
            FCGI_STDIN => {
                request.stdin.extend_from_slice(&record.content);
            }
            _ => {}
        }
    }

    if request.params.is_empty() {
        return None;
    }

    Some(request)
}

pub fn parse_fcgi_response(data: &[u8]) -> Option<FcgiResponse> {
    let records = parse_fcgi_records(data);

    if records.is_empty() {
        return None;
    }

    let mut response = FcgiResponse::default();
    let mut has_stdout = false;

    for record in &records {
        match record.record_type {
            FCGI_STDOUT => {
                response.stdout.extend_from_slice(&record.content);
                has_stdout = true;
            }
            FCGI_STDERR => {
                response.stderr.extend_from_slice(&record.content);
            }
            _ => {}
        }
    }

    if has_stdout {
        Some(response)
    } else {
        None
    }
}

fn parse_params(data: &[u8], params: &mut HashMap<String, String>) {
    let mut cursor = Cursor::new(data);

    while (cursor.position() as usize) < data.len() {
        let name_len = match read_length(&mut cursor) {
            Some(len) => len,
            None => break,
        };

        let value_len = match read_length(&mut cursor) {
            Some(len) => len,
            None => break,
        };

        let pos = cursor.position() as usize;
        if pos + name_len + value_len > data.len() {
            break;
        }

        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        let value = String::from_utf8_lossy(&data[pos + name_len..pos + name_len + value_len]).to_string();

        params.insert(name, value);
        cursor.set_position((pos + name_len + value_len) as u64);
    }
}

fn read_length(cursor: &mut Cursor<&[u8]>) -> Option<usize> {
    let mut byte = [0u8; 1];
    if cursor.read_exact(&mut byte).is_err() {
        return None;
    }

    if byte[0] >> 7 == 0 {
        Some(byte[0] as usize)
    } else {
        let mut bytes = [0u8; 3];
        if cursor.read_exact(&mut bytes).is_err() {
            return None;
        }
        let len = ((byte[0] & 0x7f) as usize) << 24
            | (bytes[0] as usize) << 16
            | (bytes[1] as usize) << 8
            | bytes[2] as usize;
        Some(len)
    }
}

pub fn fcgi_to_http_request(fcgi: &FcgiRequest) -> Option<crate::http::ParsedRequest> {
    let method = fcgi.params.get("REQUEST_METHOD")?.clone();
    let path = fcgi.params.get("REQUEST_URI").cloned().unwrap_or_else(|| "/".to_string());

    let mut headers = Vec::new();

    for (key, value) in &fcgi.params {
        if let Some(header_name) = cgi_to_header_name(key) {
            headers.push((header_name, value.clone()));
        }
    }

    Some(crate::http::ParsedRequest {
        method,
        path,
        version: String::new(), // FastCGI doesn't preserve HTTP version
        headers,
        body: fcgi.stdin.clone(),
        header_size: 0,
    })
}

fn cgi_to_header_name(cgi_name: &str) -> Option<String> {
    if let Some(name) = cgi_name.strip_prefix("HTTP_") {
        let header = name
            .split('_')
            .map(|part| {
                let mut chars: Vec<char> = part.to_lowercase().chars().collect();
                if let Some(c) = chars.first_mut() {
                    *c = c.to_ascii_uppercase();
                }
                chars.into_iter().collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("-");
        Some(header)
    } else {
        match cgi_name {
            "CONTENT_TYPE" => Some("Content-Type".to_string()),
            "CONTENT_LENGTH" => Some("Content-Length".to_string()),
            _ => None,
        }
    }
}

pub fn fcgi_to_http_response(fcgi: &FcgiResponse) -> Option<crate::http::ParsedResponse> {
    if fcgi.stdout.is_empty() {
        return None;
    }

    let separator_pos = fcgi.stdout
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| {
            fcgi.stdout
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|p| p + 2)
        });

    let (header_data, body) = match separator_pos {
        Some(pos) => (&fcgi.stdout[..pos], fcgi.stdout[pos..].to_vec()),
        None => (fcgi.stdout.as_slice(), Vec::new()),
    };

    // Parse headers
    let header_str = String::from_utf8_lossy(header_data);
    let mut headers = Vec::new();
    let mut status = 200u16;
    let mut status_text = "OK".to_string();

    for line in header_str.lines() {
        if line.is_empty() {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("Status") {
                let parts: Vec<&str> = value.splitn(2, ' ').collect();
                if let Some(code) = parts.first() {
                    status = code.parse().unwrap_or(200);
                }
                if parts.len() > 1 {
                    status_text = format!("{} {}", status, parts[1]);
                } else {
                    status_text = format!("{}", status);
                }
            } else {
                headers.push((name.to_string(), value.to_string()));
            }
        }
    }

    let is_gzip = headers
        .iter()
        .any(|(k, v)| k.to_lowercase() == "content-encoding" && v.to_lowercase().contains("gzip"));

    let body = if is_gzip {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(body.as_slice());
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap_or(0);
        decompressed
    } else {
        body
    };

    Some(crate::http::ParsedResponse {
        status,
        reason: status_text,
        version: "HTTP/1.0".to_string(),
        headers,
        body,
        header_size: header_data.len(),
    })
}
