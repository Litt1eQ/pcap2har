use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use httparse::{Request, Response, Status, EMPTY_HEADER};
use std::io::Read;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Incomplete data")]
    Incomplete,
}

#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub header_size: usize,
}

#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub header_size: usize,
}

pub fn parse_request(data: &[u8]) -> Result<Option<ParsedRequest>, HttpError> {
    let mut headers = [EMPTY_HEADER; 64];
    let mut req = Request::new(&mut headers);

    match req.parse(data) {
        Ok(Status::Complete(header_len)) => {
            let method = req.method.unwrap_or("").to_string();
            let path = req.path.unwrap_or("").to_string();
            let version = format!("HTTP/1.{}", req.version.unwrap_or(1));

            let headers: Vec<(String, String)> = req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();

            let body = extract_body(&data[header_len..], &headers);

            Ok(Some(ParsedRequest {
                method,
                path,
                version,
                headers,
                body,
                header_size: header_len,
            }))
        }
        Ok(Status::Partial) => Err(HttpError::Incomplete),
        Err(e) => Err(HttpError::Parse(e.to_string())),
    }
}

/// Parse multiple HTTP requests from a single data stream (HTTP/1.1 Keep-Alive)
pub fn parse_all_requests(data: &[u8]) -> Vec<ParsedRequest> {
    let mut requests = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];

        let mut headers = [EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);

        match req.parse(remaining) {
            Ok(Status::Complete(header_len)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let version = format!("HTTP/1.{}", req.version.unwrap_or(1));

                let headers: Vec<(String, String)> = req
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                let (body, body_len) = extract_body_with_length(&remaining[header_len..], &headers);

                requests.push(ParsedRequest {
                    method,
                    path,
                    version,
                    headers,
                    body,
                    header_size: header_len,
                });

                offset += header_len + body_len;
            }
            _ => break,
        }
    }

    requests
}

pub fn parse_response(data: &[u8]) -> Result<Option<ParsedResponse>, HttpError> {
    let mut headers = [EMPTY_HEADER; 64];
    let mut resp = Response::new(&mut headers);

    match resp.parse(data) {
        Ok(Status::Complete(header_len)) => {
            let status = resp.code.unwrap_or(0);
            let reason = resp.reason.unwrap_or("").to_string();
            let version = format!("HTTP/1.{}", resp.version.unwrap_or(1));

            let headers: Vec<(String, String)> = resp
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();

            let body = extract_body(&data[header_len..], &headers);

            Ok(Some(ParsedResponse {
                status,
                reason,
                version,
                headers,
                body,
                header_size: header_len,
            }))
        }
        Ok(Status::Partial) => Err(HttpError::Incomplete),
        Err(e) => Err(HttpError::Parse(e.to_string())),
    }
}

/// Parse multiple HTTP responses from a single data stream (HTTP/1.1 Keep-Alive)
pub fn parse_all_responses(data: &[u8]) -> Vec<ParsedResponse> {
    let mut responses = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];

        let mut headers = [EMPTY_HEADER; 64];
        let mut resp = Response::new(&mut headers);

        match resp.parse(remaining) {
            Ok(Status::Complete(header_len)) => {
                let status = resp.code.unwrap_or(0);
                let reason = resp.reason.unwrap_or("").to_string();
                let version = format!("HTTP/1.{}", resp.version.unwrap_or(1));

                let headers: Vec<(String, String)> = resp
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect();

                let (body, body_len) = extract_body_with_length(&remaining[header_len..], &headers);

                responses.push(ParsedResponse {
                    status,
                    reason,
                    version,
                    headers,
                    body,
                    header_size: header_len,
                });

                offset += header_len + body_len;
            }
            _ => break,
        }
    }

    responses
}

fn extract_body(data: &[u8], headers: &[(String, String)]) -> Vec<u8> {
    let (body, _) = extract_body_with_length(data, headers);
    body
}

fn extract_body_with_length(data: &[u8], headers: &[(String, String)]) -> (Vec<u8>, usize) {
    let content_length = headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok());

    let is_chunked = headers
        .iter()
        .any(|(k, v)| k.to_lowercase() == "transfer-encoding" && v.to_lowercase().contains("chunked"));

    let (body, consumed) = if is_chunked {
        let body = decode_chunked(data);
        let consumed = find_chunked_end(data);
        (body, consumed)
    } else if let Some(len) = content_length {
        let actual_len = len.min(data.len());
        (data[..actual_len].to_vec(), actual_len)
    } else {
        (data.to_vec(), data.len())
    };

    let is_gzip = headers
        .iter()
        .any(|(k, v)| k.to_lowercase() == "content-encoding" && v.to_lowercase().contains("gzip"));

    let body = if is_gzip {
        decompress_gzip(&body).unwrap_or(body)
    } else {
        body
    };

    (body, consumed)
}

fn find_chunked_end(data: &[u8]) -> usize {
    let mut pos = 0;

    while pos < data.len() {
        let line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p);

        let Some(line_end) = line_end else {
            return data.len();
        };

        let size_str = String::from_utf8_lossy(&data[pos..line_end]);
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);

        if size == 0 {
            return (line_end + 4).min(data.len());
        }

        let chunk_start = line_end + 2;
        let chunk_end = chunk_start + size;
        pos = chunk_end + 2;
    }

    data.len()
}

fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p);

        let Some(line_end) = line_end else {
            break;
        };

        let size_str = String::from_utf8_lossy(&data[pos..line_end]);
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);

        if size == 0 {
            break;
        }

        let chunk_start = line_end + 2;
        let chunk_end = chunk_start + size;

        if chunk_end <= data.len() {
            result.extend_from_slice(&data[chunk_start..chunk_end]);
        }

        pos = chunk_end + 2;
    }

    result
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

#[derive(Debug)]
pub struct HttpConversation {
    pub request: ParsedRequest,
    pub response: Option<ParsedResponse>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub request_timestamps: Vec<DateTime<Utc>>,
    pub response_timestamps: Vec<DateTime<Utc>>,
}

impl HttpConversation {
    pub fn start_time(&self) -> DateTime<Utc> {
        self.request_timestamps
            .first()
            .copied()
            .unwrap_or_else(Utc::now)
    }

    pub fn duration_ns(&self) -> i64 {
        let start = self.request_timestamps.first();
        let end = self
            .response_timestamps
            .last()
            .or(self.request_timestamps.last());

        match (start, end) {
            (Some(s), Some(e)) => (*e - *s).num_nanoseconds().unwrap_or(0),
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_request() {
        let data = b"GET / HTTP/1.1\r\nHost: localhost:3000\r\n\r\n";
        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0, "Host");
        assert_eq!(req.headers[0].1, "localhost:3000");
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_parse_request_with_query_string() {
        let data = b"GET /test.html?q=3&v=4 HTTP/1.1\r\nHost: localhost:3000\r\n\r\n";
        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/test.html?q=3&v=4");
        assert_eq!(req.version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_post_request_with_body() {
        let data = b"POST /api HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      Content-Length: 13\r\n\
                      Content-Type: application/json\r\n\
                      \r\n\
                      {\"key\":\"val\"}";

        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api");
        assert_eq!(req.body, b"{\"key\":\"val\"}");
        
        let has_content_type = req.headers.iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json");
        assert!(has_content_type);
    }

    #[test]
    fn test_parse_simple_response() {
        let data = b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/json\r\n\
                      Content-Length: 2\r\n\
                      \r\n\
                      {}";

        let result = parse_response(data).unwrap();

        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.body, b"{}");
        
        let content_type = resp.headers.iter()
            .find(|(k, _)| k == "Content-Type")
            .map(|(_, v)| v.as_str());
        assert_eq!(content_type, Some("application/json"));
    }

    #[test]
    fn test_parse_multiple_requests_keepalive() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGET /next HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";

        let requests = parse_all_requests(data);

        assert_eq!(requests.len(), 2, "Should parse 2 requests");
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/");
        assert_eq!(requests[1].method, "GET");
        assert_eq!(requests[1].path, "/next");
    }

    #[test]
    fn test_parse_multiple_responses_keepalive() {
        let data = b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/json\r\n\
                      Content-Length: 2\r\n\
                      \r\n\
                      {}\
                      HTTP/1.1 404 Not Found\r\n\
                      Content-Length: 2\r\n\
                      \r\n\
                      --";

        let responses = parse_all_responses(data);

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].status, 200);
        assert_eq!(responses[0].reason, "OK");
        assert_eq!(responses[0].body, b"{}");
        assert_eq!(responses[1].status, 404);
        assert_eq!(responses[1].reason, "Not Found");
        assert_eq!(responses[1].body, b"--");
    }

    #[test]
    fn test_parse_chunked_response() {
        let data = b"HTTP/1.1 200 OK\r\n\
                      Transfer-Encoding: chunked\r\n\
                      \r\n\
                      5\r\n\
                      Hello\r\n\
                      6\r\n\
                      World!\r\n\
                      0\r\n\
                      \r\n";

        let result = parse_response(data).unwrap();

        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"HelloWorld!");
    }

    #[test]
    fn test_parse_request_with_multiple_headers() {
        let data = b"GET /api HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      User-Agent: test/1.0\r\n\
                      Accept: */*\r\n\
                      Authorization: Bearer token123\r\n\
                      \r\n";

        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.headers.len(), 4);
        
        let has_host = req.headers.iter().any(|(k, _)| k == "Host");
        let has_auth = req.headers.iter().any(|(k, _)| k == "Authorization");
        assert!(has_host);
        assert!(has_auth);
    }

    #[test]
    fn test_parse_incomplete_request() {
        let data = b"GET / HTTP/1.1\r\n";
        let result = parse_request(data);

        assert!(result.is_err());
        match result {
            Err(HttpError::Incomplete) => (),
            _ => panic!("Expected Incomplete error"),
        }
    }

    #[test]
    fn test_parse_invalid_request() {
        let data = b"INVALID DATA\r\n\r\n";
        let result = parse_request(data);

        assert!(result.is_err());
        match result {
            Err(HttpError::Parse(_)) => (),
            _ => panic!("Expected Parse error"),
        }
    }

    #[test]
    fn test_decode_chunked_multiple_chunks() {
        let data = b"3\r\n\
                     foo\r\n\
                     3\r\n\
                     bar\r\n\
                     4\r\n\
                     test\r\n\
                     0\r\n\
                     \r\n";

        let result = decode_chunked(data);
        assert_eq!(result, b"foobartest");
    }

    #[test]
    fn test_http_conversation_start_time() {
        let now = Utc::now();
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            request_timestamps: vec![now],
            response_timestamps: vec![],
        };

        assert_eq!(conv.start_time(), now);
    }

    #[test]
    fn test_http_conversation_duration() {
        use chrono::Duration;
        
        let start = Utc::now();
        let end = start + Duration::milliseconds(100);
        
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            request_timestamps: vec![start],
            response_timestamps: vec![end],
        };

        let duration_ns = conv.duration_ns();
        assert!(duration_ns >= 99_000_000 && duration_ns <= 101_000_000);
    }

    #[test]
    fn test_parse_response_with_redirect() {
        let data = b"HTTP/1.1 301 Moved Permanently\r\n\
                      Location: https://example.com/new-location\r\n\
                      Content-Length: 0\r\n\
                      \r\n";

        let result = parse_response(data).unwrap();

        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status, 301);
        assert_eq!(resp.reason, "Moved Permanently");
        
        let location = resp.headers.iter()
            .find(|(k, _)| k == "Location")
            .map(|(_, v)| v.as_str());
        assert_eq!(location, Some("https://example.com/new-location"));
    }

    #[test]
    fn test_extract_body_with_content_length_larger_than_data() {
        let headers = vec![
            ("Content-Length".to_string(), "1000".to_string()),
        ];
        let data = b"short body";

        let (body, consumed) = extract_body_with_length(data, &headers);
        assert_eq!(body, b"short body");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_request_with_form_data() {
        let data = b"POST /submit HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      Content-Type: application/x-www-form-urlencoded\r\n\
                      Content-Length: 29\r\n\
                      \r\n\
                      name=John&email=j%40e.com";

        let result = parse_request(data).unwrap();

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"name=John&email=j%40e.com");
        
        let content_type = req.headers.iter()
            .find(|(k, _)| k == "Content-Type")
            .map(|(_, v)| v.as_str());
        assert_eq!(content_type, Some("application/x-www-form-urlencoded"));
    }
}
