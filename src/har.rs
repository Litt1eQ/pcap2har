use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

#[derive(Debug, Serialize)]
pub struct Har {
    pub log: Log,
}

#[derive(Debug, Serialize)]
pub struct Log {
    pub version: String,
    pub creator: Creator,
    pub pages: Vec<Page>,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Serialize)]
pub struct Creator {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub started_date_time: DateTime<Utc>,
    pub id: String,
    pub title: String,
    pub page_timings: PageTimings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageTimings {
    pub on_content_load: i64,
    pub on_load: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub pageref: String,
    pub started_date_time: DateTime<Utc>,
    #[serde(serialize_with = "serialize_time_ms")]
    pub time: i64,
    pub request: Request,
    pub response: Response,
    pub cache: Cache,
    pub timings: Timings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_ip_address: Option<String>,
}

fn serialize_time_ms<S>(time_ns: &i64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ms = *time_ns as f64 / 1_000_000.0;
    serializer.serialize_f64(ms)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub query_string: Vec<QueryParam>,
    pub post_data: Option<PostData>,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub content: Content,
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Serialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct QueryParam {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostData {
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<Param>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Param {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<i64>,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Cache {}

#[derive(Debug, Serialize)]
pub struct Timings {
    pub blocked: i64,
    pub dns: i64,
    pub connect: i64,
    pub send: i64,
    pub wait: i64,
    pub receive: i64,
    pub ssl: i64,
}

impl Default for Timings {
    fn default() -> Self {
        Timings {
            blocked: -1,
            dns: -1,
            connect: -1,
            send: -1,
            wait: -1,
            receive: -1,
            ssl: -1,
        }
    }
}

impl Har {
    pub fn new() -> Self {
        Har {
            log: Log {
                version: "1.2".to_string(),
                creator: Creator {
                    name: "pcap2har".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                pages: Vec::new(),
                entries: Vec::new(),
            },
        }
    }

    pub fn add_entry(&mut self, entry: Entry) {
        let page_id = format!("page_{}", self.log.pages.len());

        let page = Page {
            started_date_time: entry.started_date_time,
            id: page_id.clone(),
            title: entry.request.url.clone(),
            page_timings: PageTimings {
                on_content_load: -1,
                on_load: -1,
            },
        };

        self.log.pages.push(page);

        let mut entry = entry;
        entry.pageref = page_id;
        self.log.entries.push(entry);
    }
}

impl Default for Har {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::Value;

    fn default_datetime() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn test_empty_har_output() {
        let har = Har::new();
        let json_str = serde_json::to_string(&har).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["log"]["version"], "1.2");
        assert_eq!(parsed["log"]["creator"]["name"], "pcap2har");
        assert!(parsed["log"]["pages"].as_array().unwrap().is_empty());
        assert!(parsed["log"]["entries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_har_request_only() {
        let mut har = Har::new();

        let entry = Entry {
            pageref: String::new(),
            started_date_time: default_datetime(),
            time: 0,
            request: Request {
                method: "GET".to_string(),
                url: "http://localhost:3000/test.html?q=3&v=4".to_string(),
                http_version: "HTTP/1.1".to_string(),
                cookies: vec![],
                headers: vec![Header {
                    name: "Host".to_string(),
                    value: "localhost:3000".to_string(),
                }],
                query_string: vec![
                    QueryParam {
                        name: "q".to_string(),
                        value: "3".to_string(),
                    },
                    QueryParam {
                        name: "v".to_string(),
                        value: "4".to_string(),
                    },
                ],
                post_data: None,
                headers_size: -1,
                body_size: 0,
            },
            response: Response {
                status: 0,
                status_text: String::new(),
                http_version: String::new(),
                cookies: vec![],
                headers: vec![],
                content: Content {
                    size: 0,
                    compression: None,
                    mime_type: String::new(),
                    text: None,
                    encoding: None,
                },
                redirect_url: String::new(),
                headers_size: -1,
                body_size: 0,
            },
            cache: Cache {},
            timings: Timings::default(),
            server_ip_address: Some("127.0.0.1".to_string()),
        };

        har.add_entry(entry);

        let json_str = serde_json::to_string_pretty(&har).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        let request = &parsed["log"]["entries"][0]["request"];
        assert_eq!(request["method"], "GET");
        assert_eq!(
            request["url"],
            "http://localhost:3000/test.html?q=3&v=4"
        );
        assert_eq!(request["httpVersion"], "HTTP/1.1");

        let headers = request["headers"].as_array().unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0]["name"], "Host");
        assert_eq!(headers[0]["value"], "localhost:3000");

        let query_string = request["queryString"].as_array().unwrap();
        assert_eq!(query_string.len(), 2);

        let pages = parsed["log"]["pages"].as_array().unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0]["id"], "page_0");

        if let Some(server_ip) = parsed["log"]["entries"][0].get("serverIPAddress") {
            if !server_ip.is_null() {
                assert_eq!(server_ip.as_str().unwrap(), "127.0.0.1");
            }
        }
    }

    #[test]
    fn test_har_full_conversation() {
        let mut har = Har::new();

        let entry = Entry {
            pageref: String::new(),
            started_date_time: default_datetime(),
            time: 1_500_000, // 1.5ms in nanoseconds
            request: Request {
                method: "POST".to_string(),
                url: "http://localhost:3000/api/data".to_string(),
                http_version: "HTTP/1.1".to_string(),
                cookies: vec![Cookie {
                    name: "session".to_string(),
                    value: "abc123".to_string(),
                    path: Some("/".to_string()),
                    domain: None,
                    expires: None,
                    http_only: Some(true),
                    secure: None,
                }],
                headers: vec![
                    Header {
                        name: "Host".to_string(),
                        value: "localhost:3000".to_string(),
                    },
                    Header {
                        name: "Content-Type".to_string(),
                        value: "application/json".to_string(),
                    },
                ],
                query_string: vec![],
                post_data: Some(PostData {
                    mime_type: "application/json".to_string(),
                    text: Some(r#"{"key":"value"}"#.to_string()),
                    params: None,
                }),
                headers_size: 128,
                body_size: 15,
            },
            response: Response {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                cookies: vec![],
                headers: vec![
                    Header {
                        name: "Content-Type".to_string(),
                        value: "application/json".to_string(),
                    },
                    Header {
                        name: "Content-Length".to_string(),
                        value: "13".to_string(),
                    },
                ],
                content: Content {
                    size: 13,
                    compression: None,
                    mime_type: "application/json".to_string(),
                    text: Some(r#"{"ok":true}"#.to_string()),
                    encoding: None,
                },
                redirect_url: String::new(),
                headers_size: 64,
                body_size: 13,
            },
            cache: Cache {},
            timings: Timings {
                blocked: 0,
                dns: 1,
                connect: 5,
                send: 2,
                wait: 10,
                receive: 3,
                ssl: -1,
            },
            server_ip_address: Some("127.0.0.1".to_string()),
        };

        har.add_entry(entry);

        let json_str = serde_json::to_string_pretty(&har).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        let response = &parsed["log"]["entries"][0]["response"];
        assert_eq!(response["status"], 200);
        assert_eq!(response["statusText"], "OK");

        let content = &response["content"];
        assert_eq!(content["size"], 13);
        assert_eq!(content["mimeType"], "application/json");
        assert_eq!(content["text"], r#"{"ok":true}"#);

        let timings = &parsed["log"]["entries"][0]["timings"];
        assert_eq!(timings["wait"], 10);
        assert_eq!(timings["ssl"], -1);

        let time = parsed["log"]["entries"][0]["time"].as_f64().unwrap();
        assert!((time - 1.5).abs() < 0.001);

        let post_data = &parsed["log"]["entries"][0]["request"]["postData"];
        assert_eq!(post_data["mimeType"], "application/json");
        assert_eq!(post_data["text"], r#"{"key":"value"}"#);

        let cookies = parsed["log"]["entries"][0]["request"]["cookies"]
            .as_array()
            .unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0]["name"], "session");
        if let Some(http_only) = cookies[0].get("httpOnly") {
            if !http_only.is_null() {
                assert_eq!(http_only.as_bool(), Some(true));
            }
        }
    }

    #[test]
    fn test_har_multiple_entries() {
        let mut har = Har::new();

        for i in 0..3 {
            let entry = Entry {
                pageref: String::new(),
                started_date_time: default_datetime(),
                time: i * 1_000_000,
                request: Request {
                    method: "GET".to_string(),
                    url: format!("http://example.com/page{}", i),
                    http_version: "HTTP/1.1".to_string(),
                    cookies: vec![],
                    headers: vec![],
                    query_string: vec![],
                    post_data: None,
                    headers_size: -1,
                    body_size: 0,
                },
                response: Response {
                    status: 200,
                    status_text: "OK".to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    cookies: vec![],
                    headers: vec![],
                    content: Content {
                        size: 0,
                        compression: None,
                        mime_type: "text/html".to_string(),
                        text: None,
                        encoding: None,
                    },
                    redirect_url: String::new(),
                    headers_size: -1,
                    body_size: 0,
                },
                cache: Cache {},
                timings: Timings::default(),
                server_ip_address: None,
            };
            har.add_entry(entry);
        }

        assert_eq!(har.log.entries.len(), 3);
        assert_eq!(har.log.pages.len(), 3);

        assert_eq!(har.log.entries[0].pageref, "page_0");
        assert_eq!(har.log.entries[1].pageref, "page_1");
        assert_eq!(har.log.entries[2].pageref, "page_2");
    }

    #[test]
    fn test_timings_default() {
        let timings = Timings::default();

        assert_eq!(timings.blocked, -1);
        assert_eq!(timings.dns, -1);
        assert_eq!(timings.connect, -1);
        assert_eq!(timings.send, -1);
        assert_eq!(timings.wait, -1);
        assert_eq!(timings.receive, -1);
        assert_eq!(timings.ssl, -1);
    }

    #[test]
    fn test_har_serialization_roundtrip() {
        let mut har = Har::new();

        let entry = Entry {
            pageref: String::new(),
            started_date_time: Utc::now(),
            time: 100_000_000,
            request: Request {
                method: "GET".to_string(),
                url: "http://example.com/".to_string(),
                http_version: "HTTP/2.0".to_string(),
                cookies: vec![],
                headers: vec![],
                query_string: vec![],
                post_data: None,
                headers_size: 0,
                body_size: 0,
            },
            response: Response {
                status: 304,
                status_text: "Not Modified".to_string(),
                http_version: "HTTP/2.0".to_string(),
                cookies: vec![],
                headers: vec![],
                content: Content {
                    size: 0,
                    compression: None,
                    mime_type: String::new(),
                    text: None,
                    encoding: None,
                },
                redirect_url: String::new(),
                headers_size: 0,
                body_size: 0,
            },
            cache: Cache {},
            timings: Timings::default(),
            server_ip_address: None,
        };

        har.add_entry(entry);

        let json_str = serde_json::to_string(&har).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert!(parsed["log"].is_object());
        assert!(parsed["log"]["entries"].is_array());
        assert!(parsed["log"]["pages"].is_array());
    }
}
