use crate::fcgi::{
    fcgi_to_http_request, fcgi_to_http_response, parse_fcgi_request, parse_fcgi_response,
};
use crate::har::{
    Cache, Content, Cookie, Entry, Har, Header, Param, PostData, QueryParam, Request, Response,
    Timings,
};
use crate::http::{parse_request, parse_response, parse_all_requests, parse_all_responses, HttpConversation, ParsedRequest, ParsedResponse};
use crate::http2::{is_http2, parse_http2_frames, parse_http2_stream, Http2Request, Http2Response};
use crate::tcp::{StreamKey, TcpReassembler, TcpStream};
use crate::tls::{
    decrypt_tls12_record, decrypt_tls13_record_full, derive_tls12_keys, extract_cipher_suite,
    extract_client_random, extract_server_random, parse_tls_records, CipherSuiteInfo, TlsSecrets,
};
use std::collections::HashMap;
use url::Url;

pub struct Converter {
    conversations: Vec<HttpConversation>,
}

impl Converter {
    pub fn new() -> Self {
        Converter {
            conversations: Vec::new(),
        }
    }

    pub fn process_streams(&mut self, streams: HashMap<StreamKey, TcpStream>) {
        let mut request_streams: HashMap<StreamKey, (Vec<chrono::DateTime<chrono::Utc>>, Vec<ParsedRequest>)> = HashMap::new();
        let mut response_streams: HashMap<StreamKey, (Vec<chrono::DateTime<chrono::Utc>>, Vec<ParsedResponse>)> = HashMap::new();

        for (key, stream) in &streams {
            let (data, timestamps) = stream.reassemble();
            if data.is_empty() {
                continue;
            }

            let requests = parse_all_requests(&data);
            if !requests.is_empty() {
                request_streams.insert(key.clone(), (timestamps.clone(), requests));
                continue;
            }

            let responses = parse_all_responses(&data);
            if !responses.is_empty() {
                response_streams.insert(key.clone(), (timestamps.clone(), responses));
                continue;
            }

            if let Some(fcgi_req) = parse_fcgi_request(&data) {
                if let Some(req) = fcgi_to_http_request(&fcgi_req) {
                    request_streams.insert(key.clone(), (timestamps.clone(), vec![req]));
                    continue;
                }
            }

            if let Some(fcgi_resp) = parse_fcgi_response(&data) {
                if let Some(resp) = fcgi_to_http_response(&fcgi_resp) {
                    response_streams.insert(key.clone(), (timestamps.clone(), vec![resp]));
                }
            }
        }

        for (req_key, (req_timestamps, requests)) in &request_streams {
            let resp_key = req_key.reverse();
            let response_data = response_streams.get(&resp_key);

            let responses = response_data.map(|(_, resps)| resps.as_slice()).unwrap_or(&[]);
            let resp_timestamps = response_data.map(|(ts, _)| ts.clone()).unwrap_or_default();

            for (i, request) in requests.iter().enumerate() {
                let response = responses.get(i).cloned();

                let conversation = HttpConversation {
                    request: request.clone(),
                    response,
                    src_ip: req_key.src_ip.to_string(),
                    dst_ip: req_key.dst_ip.to_string(),
                    src_port: req_key.src_port,
                    dst_port: req_key.dst_port,
                    request_timestamps: req_timestamps.clone(),
                    response_timestamps: resp_timestamps.clone(),
                };

                self.conversations.push(conversation);
            }
        }
    }

    pub fn process_streams_with_tls(
        &mut self,
        streams: HashMap<StreamKey, TcpStream>,
        tls_secrets: &TlsSecrets,
    ) {
        let mut tls_streams: HashMap<StreamKey, (Vec<u8>, Vec<chrono::DateTime<chrono::Utc>>)> =
            HashMap::new();
        let mut client_randoms: HashMap<StreamKey, String> = HashMap::new();
        let mut server_randoms: HashMap<StreamKey, String> = HashMap::new();
        let mut cipher_suites: HashMap<StreamKey, u16> = HashMap::new();

        for (key, stream) in &streams {
            let (data, timestamps) = stream.reassemble();
            if data.is_empty() {
                continue;
            }

            if key.dst_port == 443 || key.src_port == 443 || is_tls_data(&data) {
                let records = parse_tls_records(&data);
                for record in &records {
                    if record.content_type == 22 {
                        if let Some(random) = extract_client_random(&record.payload) {
                            client_randoms.insert(key.clone(), random);
                        }
                        if let Some(random) = extract_server_random(&record.payload) {
                            server_randoms.insert(key.clone(), random);
                        }
                        if let Some(suite) = extract_cipher_suite(&record.payload) {
                            cipher_suites.insert(key.clone(), suite);
                        }
                    }
                }
                tls_streams.insert(key.clone(), (data, timestamps));
            }
        }

        let mut decrypted_streams: HashMap<StreamKey, (Vec<u8>, Vec<chrono::DateTime<chrono::Utc>>)> =
            HashMap::new();
        for (key, (data, timestamps)) in &tls_streams {
            let reverse = key.reverse();
            let client_random = client_randoms.get(key).or_else(|| client_randoms.get(&reverse));

            let Some(random) = client_random else {
                continue;
            };

            if let Some(secrets) = tls_secrets.traffic_secrets.get(random) {
                let is_client = key.dst_port == 443;
                let secret = if is_client {
                    secrets.client_traffic_secret_0.as_ref()
                } else {
                    secrets.server_traffic_secret_0.as_ref()
                };

                if let Some(secret) = secret {
                    if let Some(decrypted) = self.decrypt_tls13_stream(data, secret) {
                        decrypted_streams.insert(key.clone(), (decrypted, timestamps.clone()));
                    }
                }
            } else if let Some(client_secrets) = tls_secrets.client_randoms.get(random) {
                if let Some(master_secret) = &client_secrets.master_secret {
                    let is_client = key.dst_port == 443;
                    let server_random_hex = if is_client {
                        server_randoms.get(&reverse)
                    } else {
                        server_randoms.get(key)
                    };

                    let cipher_suite = if is_client {
                        cipher_suites.get(&reverse).copied()
                    } else {
                        cipher_suites.get(key).copied()
                    };

                    if let (Some(server_random_hex), Some(suite)) = (server_random_hex, cipher_suite)
                    {
                        if let Some(cipher_info) = CipherSuiteInfo::from_id(suite) {
                            if let Some(decrypted) = self.decrypt_tls12_stream(
                                data,
                                master_secret,
                                random,
                                server_random_hex,
                                &cipher_info,
                                is_client,
                            ) {
                                decrypted_streams.insert(key.clone(), (decrypted, timestamps.clone()));
                            }
                        }
                    }
                }
            }
        }

        let mut request_streams: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, ParsedRequest),
        > = HashMap::new();
        let mut response_streams: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, ParsedResponse),
        > = HashMap::new();
        let mut h2_requests: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, Vec<Http2Request>),
        > = HashMap::new();
        let mut h2_responses: HashMap<
            StreamKey,
            (Vec<chrono::DateTime<chrono::Utc>>, Vec<Http2Response>),
        > = HashMap::new();

        for (key, (data, timestamps)) in &decrypted_streams {
            if is_http2(data) {
                let frames = parse_http2_frames(data);
                let is_client = key.dst_port == 443;
                let (reqs, resps) = parse_http2_stream(&frames, is_client);

                if is_client && !reqs.is_empty() {
                    h2_requests.insert(key.clone(), (timestamps.clone(), reqs));
                } else if !is_client && !resps.is_empty() {
                    h2_responses.insert(key.clone(), (timestamps.clone(), resps));
                }
            } else if let Ok(Some(req)) = parse_request(data) {
                request_streams.insert(key.clone(), (timestamps.clone(), req));
            } else if let Ok(Some(resp)) = parse_response(data) {
                response_streams.insert(key.clone(), (timestamps.clone(), resp));
            }
        }

        for (req_key, (req_timestamps, request)) in &request_streams {
            let resp_key = req_key.reverse();
            let response_data = response_streams.remove(&resp_key);

            let conversation = HttpConversation {
                request: request.clone(),
                response: response_data.as_ref().map(|(_, resp)| resp.clone()),
                src_ip: req_key.src_ip.to_string(),
                dst_ip: req_key.dst_ip.to_string(),
                src_port: req_key.src_port,
                dst_port: req_key.dst_port,
                request_timestamps: req_timestamps.clone(),
                response_timestamps: response_data.map(|(ts, _)| ts).unwrap_or_default(),
            };

            self.conversations.push(conversation);
        }

        for (req_key, (req_timestamps, requests)) in h2_requests {
            let resp_key = req_key.reverse();
            let response_data = h2_responses.remove(&resp_key);

            for h2_req in requests {
                let h2_resp = response_data
                    .as_ref()
                    .and_then(|(_, resps)| resps.iter().find(|r| r.stream_id == h2_req.stream_id));

                let mut headers = h2_req.headers.clone();
                if !h2_req.authority.is_empty() {
                    headers.push(("host".to_string(), h2_req.authority.clone()));
                }

                let parsed_req = ParsedRequest {
                    method: h2_req.method.clone(),
                    path: h2_req.path.clone(),
                    version: "HTTP/2".to_string(),
                    headers,
                    body: h2_req.body.clone(),
                    header_size: 0,
                };

                let parsed_resp = h2_resp.map(|r| ParsedResponse {
                    version: "HTTP/2".to_string(),
                    status: r.status,
                    reason: String::new(),
                    headers: r.headers.clone(),
                    body: r.body.clone(),
                    header_size: 0,
                });

                let conversation = HttpConversation {
                    request: parsed_req,
                    response: parsed_resp,
                    src_ip: req_key.src_ip.to_string(),
                    dst_ip: req_key.dst_ip.to_string(),
                    src_port: req_key.src_port,
                    dst_port: req_key.dst_port,
                    request_timestamps: req_timestamps.clone(),
                    response_timestamps: response_data
                        .as_ref()
                        .map(|(ts, _)| ts.clone())
                        .unwrap_or_default(),
                };

                self.conversations.push(conversation);
            }
        }

        let non_tls_streams: HashMap<StreamKey, TcpStream> = streams
            .into_iter()
            .filter(|(key, _)| !tls_streams.contains_key(key))
            .collect();

        self.process_streams(non_tls_streams);
    }

    fn decrypt_tls13_stream(&self, data: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
        let records = parse_tls_records(data);
        let app_records: Vec<_> = records.iter().filter(|r| r.content_type == 23).collect();
        
        if app_records.is_empty() {
            return None;
        }

        // Try different skip values - first records may use handshake keys
        for skip in 0..app_records.len().min(6) {
            let mut decrypted = Vec::new();
            let mut success = true;

            for (i, record) in app_records.iter().skip(skip).enumerate() {
                if let Some(result) =
                    decrypt_tls13_record_full(&record.payload, secret, i as u64, record.length)
                {
                    if result.content_type == 23 {
                        decrypted.extend_from_slice(&result.data);
                    }
                } else {
                    if !decrypted.is_empty() {
                        break; // Got some data before failure
                    }
                    success = false;
                    break;
                }
            }

            if (success || !decrypted.is_empty()) && !decrypted.is_empty() {
                return Some(decrypted);
            }
        }

        None
    }

    fn decrypt_tls12_stream(
        &self,
        data: &[u8],
        master_secret: &[u8],
        client_random_hex: &str,
        server_random_hex: &str,
        cipher_info: &CipherSuiteInfo,
        is_client: bool,
    ) -> Option<Vec<u8>> {
        let client_random = hex::decode(client_random_hex).ok()?;
        let server_random = hex::decode(server_random_hex).ok()?;

        let keys = derive_tls12_keys(master_secret, &client_random, &server_random, cipher_info);

        let (write_key, write_iv) = if is_client {
            (&keys.client_write_key, &keys.client_write_iv)
        } else {
            (&keys.server_write_key, &keys.server_write_iv)
        };

        let records = parse_tls_records(data);
        let app_records: Vec<_> = records.iter().filter(|r| r.content_type == 23).collect();

        let mut decrypted = Vec::new();

        for (i, record) in app_records.iter().enumerate() {
            let seq = (i + 1) as u64;
            if let Some(plaintext) =
                decrypt_tls12_record(&record.payload, write_key, write_iv, seq, 23)
            {
                decrypted.extend_from_slice(&plaintext);
            } else {
                break;
            }
        }

        if decrypted.is_empty() {
            None
        } else {
            Some(decrypted)
        }
    }

    pub fn to_har(mut self) -> Har {
        let mut har = Har::new();

        self.conversations.sort_by_key(|c| c.start_time());

        for (i, conv) in self.conversations.iter().enumerate() {
            let mut entry = self.conversation_to_entry(conv);
            entry.pageref = format!("page_{}", i);
            har.add_entry(entry);
        }

        har
    }

    fn conversation_to_entry(&self, conv: &HttpConversation) -> Entry {
        let url = self.build_url(conv);
        let request = self.build_request(&conv.request, &url);
        let response = self.build_response(conv.response.as_ref());

        Entry {
            pageref: String::new(),
            started_date_time: conv.start_time(),
            time: conv.duration_ns(),
            request,
            response,
            cache: Cache {},
            timings: Timings::default(),
            server_ip_address: Some(conv.dst_ip.clone()),
        }
    }

    fn build_url(&self, conv: &HttpConversation) -> String {
        let host = conv
            .request
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "host")
            .map(|(_, v)| v.as_str())
            .unwrap_or(&conv.dst_ip);

        let scheme = if conv.dst_port == 443 { "https" } else { "http" };

        format!("{}://{}{}", scheme, host, conv.request.path)
    }

    fn build_request(&self, req: &ParsedRequest, url: &str) -> Request {
        let headers: Vec<Header> = req
            .headers
            .iter()
            .map(|(k, v)| Header {
                name: k.clone(),
                value: v.clone(),
            })
            .collect();

        let cookies = self.parse_cookies(&req.headers);
        let query_string = self.parse_query_string(url);
        let post_data = self.parse_post_data(req);

        Request {
            method: req.method.clone(),
            url: url.to_string(),
            http_version: req.version.clone(),
            cookies,
            headers,
            query_string,
            post_data,
            headers_size: req.header_size as i64,
            body_size: req.body.len() as i64,
        }
    }

    fn build_response(&self, resp: Option<&ParsedResponse>) -> Response {
        match resp {
            Some(resp) => {
                let headers: Vec<Header> = resp
                    .headers
                    .iter()
                    .map(|(k, v)| Header {
                        name: k.clone(),
                        value: v.clone(),
                    })
                    .collect();

                let cookies = self.parse_set_cookies(&resp.headers);
                let content = self.build_content(resp);

                let redirect_url = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == "location")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();

                Response {
                    status: resp.status,
                    status_text: resp.reason.clone(),
                    http_version: resp.version.clone(),
                    cookies,
                    headers,
                    content,
                    redirect_url,
                    headers_size: resp.header_size as i64,
                    body_size: resp.body.len() as i64,
                }
            }
            None => Response {
                status: 0,
                status_text: String::new(),
                http_version: "HTTP/1.1".to_string(),
                cookies: Vec::new(),
                headers: Vec::new(),
                content: Content {
                    size: 0,
                    compression: None,
                    mime_type: String::new(),
                    text: None,
                    encoding: None,
                },
                redirect_url: String::new(),
                headers_size: -1,
                body_size: -1,
            },
        }
    }

    fn build_content(&self, resp: &ParsedResponse) -> Content {
        let mime_type = resp
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
            .unwrap_or_default();

        let (text, encoding) = if resp.body.is_empty() {
            (Some(String::new()), None)
        } else if is_text_content(&mime_type) {
            (Some(String::from_utf8_lossy(&resp.body).to_string()), None)
        } else {
            use base64::{engine::general_purpose::STANDARD, Engine};
            (
                Some(STANDARD.encode(&resp.body)),
                Some("base64".to_string()),
            )
        };

        Content {
            size: resp.body.len() as i64,
            compression: None,
            mime_type,
            text,
            encoding,
        }
    }

    fn parse_cookies(&self, headers: &[(String, String)]) -> Vec<Cookie> {
        headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "cookie")
            .flat_map(|(_, v)| {
                v.split(';').filter_map(|cookie| {
                    let mut parts = cookie.trim().splitn(2, '=');
                    let name = parts.next()?.to_string();
                    let value = parts.next().unwrap_or("").to_string();
                    Some(Cookie {
                        name,
                        value,
                        path: None,
                        domain: None,
                        expires: None,
                        http_only: None,
                        secure: None,
                    })
                })
            })
            .collect()
    }

    fn parse_set_cookies(&self, headers: &[(String, String)]) -> Vec<Cookie> {
        headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "set-cookie")
            .filter_map(|(_, v)| {
                let mut parts = v.split(';');
                let main_part = parts.next()?;
                let mut kv = main_part.splitn(2, '=');
                let name = kv.next()?.trim().to_string();
                let value = kv.next().unwrap_or("").trim().to_string();

                let mut cookie = Cookie {
                    name,
                    value,
                    path: None,
                    domain: None,
                    expires: None,
                    http_only: None,
                    secure: None,
                };

                for attr in parts {
                    let attr = attr.trim().to_lowercase();
                    if attr == "httponly" {
                        cookie.http_only = Some(true);
                    } else if attr == "secure" {
                        cookie.secure = Some(true);
                    } else if let Some(path) = attr.strip_prefix("path=") {
                        cookie.path = Some(path.to_string());
                    } else if let Some(domain) = attr.strip_prefix("domain=") {
                        cookie.domain = Some(domain.to_string());
                    } else if let Some(expires) = attr.strip_prefix("expires=") {
                        cookie.expires = Some(expires.to_string());
                    }
                }

                Some(cookie)
            })
            .collect()
    }

    fn parse_query_string(&self, url: &str) -> Vec<QueryParam> {
        Url::parse(url)
            .map(|u| {
                u.query_pairs()
                    .map(|(k, v)| QueryParam {
                        name: k.to_string(),
                        value: v.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_post_data(&self, req: &ParsedRequest) -> Option<PostData> {
        if req.body.is_empty() {
            return None;
        }

        let content_type = req
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        let mime_type = content_type.split(';').next().unwrap_or("").trim();

        if mime_type == "application/x-www-form-urlencoded" {
            let text = String::from_utf8_lossy(&req.body);
            let params: Vec<Param> = text
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let name = parts.next()?.to_string();
                    let value = parts.next().map(|s| s.to_string());
                    Some(Param {
                        name,
                        value,
                        file_name: None,
                        content_type: None,
                    })
                })
                .collect();

            Some(PostData {
                mime_type: mime_type.to_string(),
                text: Some(text.to_string()),
                params: Some(params),
            })
        } else {
            Some(PostData {
                mime_type: mime_type.to_string(),
                text: Some(String::from_utf8_lossy(&req.body).to_string()),
                params: None,
            })
        }
    }
}

impl Default for Converter {
    fn default() -> Self {
        Self::new()
    }
}

fn is_text_content(mime_type: &str) -> bool {
    mime_type.starts_with("text/")
        || mime_type.contains("json")
        || mime_type.contains("xml")
        || mime_type.contains("javascript")
        || mime_type.contains("html")
}

fn is_tls_data(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let content_type = data[0];
    let version_major = data[1];
    let version_minor = data[2];

    (20..=23).contains(&content_type) && version_major == 3 && version_minor <= 3
}

pub fn convert_pcap_to_har(pcap_path: &str) -> Result<Har, crate::tcp::TcpError> {
    let mut reassembler = TcpReassembler::new();
    reassembler.process_pcap(pcap_path)?;

    let tls_secrets = reassembler.tls_secrets.clone();
    let streams = reassembler.get_streams();

    let mut converter = Converter::new();
    converter.process_streams_with_tls(streams, &tls_secrets);

    Ok(converter.to_har())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ParsedRequest, ParsedResponse};
    use chrono::Utc;

    #[test]
    fn test_converter_new() {
        let converter = Converter::new();
        assert_eq!(converter.conversations.len(), 0);
    }

    #[test]
    fn test_build_url_with_host_header() {
        let converter = Converter::new();
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/api/data".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![
                    ("Host".to_string(), "example.com".to_string()),
                ],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 54321,
            dst_port: 80,
            request_timestamps: vec![],
            response_timestamps: vec![],
        };

        let url = converter.build_url(&conv);
        assert_eq!(url, "http://example.com/api/data");
    }

    #[test]
    fn test_build_url_https_port() {
        let converter = Converter::new();
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/secure".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![
                    ("Host".to_string(), "secure.example.com".to_string()),
                ],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 54321,
            dst_port: 443,  // HTTPS port
            request_timestamps: vec![],
            response_timestamps: vec![],
        };

        let url = converter.build_url(&conv);
        assert_eq!(url, "https://secure.example.com/secure");
    }

    #[test]
    fn test_build_url_without_host_header() {
        let converter = Converter::new();
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
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 54321,
            dst_port: 8080,
            request_timestamps: vec![],
            response_timestamps: vec![],
        };

        let url = converter.build_url(&conv);
        assert_eq!(url, "http://127.0.0.1/");
    }

    #[test]
    fn test_parse_cookies_from_headers() {
        let converter = Converter::new();
        let headers = vec![
            ("Cookie".to_string(), "session=abc123; user=john".to_string()),
        ];

        let cookies = converter.parse_cookies(&headers);
        assert_eq!(cookies.len(), 2);
        
        assert_eq!(cookies[0].name, "session");
        assert_eq!(cookies[0].value, "abc123");
        assert_eq!(cookies[1].name, "user");
        assert_eq!(cookies[1].value, "john");
    }

    #[test]
    fn test_parse_set_cookies_with_attributes() {
        let converter = Converter::new();
        let headers = vec![
            ("Set-Cookie".to_string(), 
             "session=xyz; Path=/; Domain=.example.com; HttpOnly; Secure".to_string()),
        ];

        let cookies = converter.parse_set_cookies(&headers);
        assert_eq!(cookies.len(), 1);
        
        let cookie = &cookies[0];
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "xyz");
        assert_eq!(cookie.path, Some("/".to_string()));
        assert_eq!(cookie.domain, Some(".example.com".to_string()));
        assert_eq!(cookie.http_only, Some(true));
        assert_eq!(cookie.secure, Some(true));
    }

    #[test]
    fn test_parse_query_string() {
        let converter = Converter::new();
        let url = "http://example.com/search?q=rust&lang=en&page=1";

        let params = converter.parse_query_string(url);
        assert_eq!(params.len(), 3);
        
        assert_eq!(params[0].name, "q");
        assert_eq!(params[0].value, "rust");
        assert_eq!(params[1].name, "lang");
        assert_eq!(params[1].value, "en");
        assert_eq!(params[2].name, "page");
        assert_eq!(params[2].value, "1");
    }

    #[test]
    fn test_parse_query_string_with_encoding() {
        let converter = Converter::new();
        let url = "http://example.com/search?q=hello%20world&special=%3D%26";

        let params = converter.parse_query_string(url);
        assert_eq!(params.len(), 2);
        
        assert_eq!(params[0].name, "q");
        assert_eq!(params[0].value, "hello world");
        assert_eq!(params[1].name, "special");
        assert_eq!(params[1].value, "=&");
    }

    #[test]
    fn test_parse_post_data_json() {
        let converter = Converter::new();
        let req = ParsedRequest {
            method: "POST".to_string(),
            path: "/api".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json; charset=utf-8".to_string()),
            ],
            body: br#"{"name":"test","value":123}"#.to_vec(),
            header_size: 0,
        };

        let post_data = converter.parse_post_data(&req);
        assert!(post_data.is_some());
        
        let data = post_data.unwrap();
        assert_eq!(data.mime_type, "application/json");
        assert_eq!(data.text.unwrap(), r#"{"name":"test","value":123}"#);
        assert!(data.params.is_none());
    }

    #[test]
    fn test_parse_post_data_form_urlencoded() {
        let converter = Converter::new();
        let req = ParsedRequest {
            method: "POST".to_string(),
            path: "/submit".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ],
            body: b"name=John&email=john%40example.com&age=30".to_vec(),
            header_size: 0,
        };

        let post_data = converter.parse_post_data(&req);
        assert!(post_data.is_some());
        
        let data = post_data.unwrap();
        assert_eq!(data.mime_type, "application/x-www-form-urlencoded");
        assert!(data.params.is_some());
        
        let params = data.params.unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].name, "name");
        assert_eq!(params[0].value, Some("John".to_string()));
    }

    #[test]
    fn test_parse_post_data_empty_body() {
        let converter = Converter::new();
        let req = ParsedRequest {
            method: "POST".to_string(),
            path: "/api".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![],
            body: vec![],
            header_size: 0,
        };

        let post_data = converter.parse_post_data(&req);
        assert!(post_data.is_none());
    }

    #[test]
    fn test_build_response_with_content() {
        let converter = Converter::new();
        let resp = ParsedResponse {
            status: 200,
            reason: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), "13".to_string()),
            ],
            body: br#"{"ok":true}"#.to_vec(),
            header_size: 0,
        };

        let response = converter.build_response(Some(&resp));
        assert_eq!(response.status, 200);
        assert_eq!(response.status_text, "OK");
        assert_eq!(response.content.mime_type, "application/json");
        assert_eq!(response.content.size, 11);
        assert!(response.content.text.is_some());
    }

    #[test]
    fn test_build_response_none() {
        let converter = Converter::new();
        let response = converter.build_response(None);
        
        assert_eq!(response.status, 0);
        assert_eq!(response.status_text, "");
        assert_eq!(response.content.size, 0);
        assert_eq!(response.headers_size, -1);
        assert_eq!(response.body_size, -1);
    }

    #[test]
    fn test_build_content_text() {
        let converter = Converter::new();
        let resp = ParsedResponse {
            status: 200,
            reason: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "text/html; charset=utf-8".to_string()),
            ],
            body: b"<html><body>Hello</body></html>".to_vec(),
            header_size: 0,
        };

        let content = converter.build_content(&resp);
        assert_eq!(content.mime_type, "text/html");
        assert!(content.text.is_some());
        assert_eq!(content.encoding, None);
    }

    #[test]
    fn test_build_content_binary() {
        let converter = Converter::new();
        let resp = ParsedResponse {
            status: 200,
            reason: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "image/png".to_string()),
            ],
            body: vec![0x89, 0x50, 0x4E, 0x47], // PNG header
            header_size: 0,
        };

        let content = converter.build_content(&resp);
        assert_eq!(content.mime_type, "image/png");
        assert!(content.text.is_some());
        assert_eq!(content.encoding, Some("base64".to_string()));
    }

    #[test]
    fn test_is_text_content() {
        assert!(is_text_content("text/html"));
        assert!(is_text_content("text/plain"));
        assert!(is_text_content("application/json"));
        assert!(is_text_content("application/xml"));
        assert!(is_text_content("application/javascript"));
        
        assert!(!is_text_content("image/png"));
        assert!(!is_text_content("application/octet-stream"));
        assert!(!is_text_content("video/mp4"));
    }

    #[test]
    fn test_is_tls_data() {
        let tls_handshake = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        assert!(is_tls_data(&tls_handshake));

        let tls_app_data = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        assert!(is_tls_data(&tls_app_data));

        let http_data = b"GET / HTTP/1.1\r\n";
        assert!(!is_tls_data(http_data));

        let short_data = vec![0x16, 0x03];
        assert!(!is_tls_data(&short_data));
    }

    #[test]
    fn test_conversation_to_entry() {
        let converter = Converter::new();
        let now = Utc::now();
        
        let conv = HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/test".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![
                    ("Host".to_string(), "example.com".to_string()),
                ],
                body: vec![],
                header_size: 100,
            },
            response: Some(ParsedResponse {
                status: 200,
                reason: "OK".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 80,
            }),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 54321,
            dst_port: 80,
            request_timestamps: vec![now],
            response_timestamps: vec![now],
        };

        let entry = converter.conversation_to_entry(&conv);
        assert_eq!(entry.request.method, "GET");
        assert_eq!(entry.response.status, 200);
        assert_eq!(entry.server_ip_address, Some("93.184.216.34".to_string()));
    }

    #[test]
    fn test_to_har_empty() {
        let converter = Converter::new();
        let har = converter.to_har();

        assert_eq!(har.log.version, "1.2");
        assert_eq!(har.log.creator.name, "pcap2har");
        assert!(har.log.entries.is_empty());
        assert!(har.log.pages.is_empty());
    }

    #[test]
    fn test_to_har_with_conversations() {
        let mut converter = Converter::new();
        let now = Utc::now();

        // Add a conversation
        converter.conversations.push(HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![
                    ("Host".to_string(), "example.com".to_string()),
                ],
                body: vec![],
                header_size: 0,
            },
            response: Some(ParsedResponse {
                status: 200,
                reason: "OK".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            }),
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            request_timestamps: vec![now],
            response_timestamps: vec![now],
        });

        let har = converter.to_har();

        assert_eq!(har.log.entries.len(), 1);
        assert_eq!(har.log.pages.len(), 1);
        assert_eq!(har.log.entries[0].request.method, "GET");
        assert_eq!(har.log.entries[0].response.status, 200);
    }

    #[test]
    fn test_converter_sorts_conversations_by_time() {
        use chrono::Duration;
        
        let mut converter = Converter::new();
        let now = Utc::now();
        let earlier = now - Duration::seconds(10);
        let later = now + Duration::seconds(10);

        converter.conversations.push(HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/second".to_string(),
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
        });

        converter.conversations.push(HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/first".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12346,
            dst_port: 80,
            request_timestamps: vec![earlier],
            response_timestamps: vec![],
        });

        converter.conversations.push(HttpConversation {
            request: ParsedRequest {
                method: "GET".to_string(),
                path: "/third".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
                header_size: 0,
            },
            response: None,
            src_ip: "127.0.0.1".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            src_port: 12347,
            dst_port: 80,
            request_timestamps: vec![later],
            response_timestamps: vec![],
        });

        let har = converter.to_har();

        assert_eq!(har.log.entries[0].request.url, "http://127.0.0.1/first");
        assert_eq!(har.log.entries[1].request.url, "http://127.0.0.1/second");
        assert_eq!(har.log.entries[2].request.url, "http://127.0.0.1/third");
    }
}
