use crate::tls::TlsSecrets;
use chrono::{DateTime, Utc};
use etherparse::{IpNumber, SlicedPacket};
use pcap::Capture;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TcpError {
    #[error("PCAP error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("Parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct StreamKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl StreamKey {
    pub fn reverse(&self) -> StreamKey {
        StreamKey {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub fin: bool,
}

#[derive(Debug)]
pub struct TcpStream {
    pub key: StreamKey,
    pub segments: Vec<TcpSegment>,
}

impl TcpStream {
    pub fn new(key: StreamKey) -> Self {
        TcpStream {
            key,
            segments: Vec::new(),
        }
    }

    pub fn add_segment(&mut self, segment: TcpSegment) {
        self.segments.push(segment);
    }

    pub fn reassemble(&self) -> (Vec<u8>, Vec<DateTime<Utc>>) {
        if self.segments.is_empty() {
            return (Vec::new(), Vec::new());
        }

        let mut sorted_segments = self.segments.clone();
        sorted_segments.sort_by_key(|s| s.seq);

        let mut data = Vec::new();
        let mut timestamps = Vec::new();

        for segment in sorted_segments {
            if !segment.data.is_empty() {
                data.extend_from_slice(&segment.data);
                timestamps.push(segment.timestamp);
            }
        }

        (data, timestamps)
    }

    pub fn first_timestamp(&self) -> Option<DateTime<Utc>> {
        self.segments.iter().map(|s| s.timestamp).min()
    }

    pub fn last_timestamp(&self) -> Option<DateTime<Utc>> {
        self.segments.iter().map(|s| s.timestamp).max()
    }
}

pub struct TcpReassembler {
    streams: HashMap<StreamKey, TcpStream>,
    pub tls_secrets: TlsSecrets,
}

impl TcpReassembler {
    pub fn new() -> Self {
        TcpReassembler {
            streams: HashMap::new(),
            tls_secrets: TlsSecrets::new(),
        }
    }

    pub fn process_pcap<P: AsRef<Path>>(&mut self, path: P) -> Result<(), TcpError> {
        self.extract_dsb_secrets(path.as_ref())?;

        let mut cap = Capture::from_file(path)?;

        while let Ok(packet) = cap.next_packet() {
            let timestamp = {
                let ts = packet.header.ts;
                DateTime::from_timestamp(ts.tv_sec, (ts.tv_usec * 1000) as u32)
                    .unwrap_or_else(Utc::now)
            };

            if let Ok(sliced) = SlicedPacket::from_ethernet(packet.data) {
                self.process_packet(&sliced, timestamp);
            }
        }

        Ok(())
    }

    fn extract_dsb_secrets(&mut self, path: &Path) -> Result<(), TcpError> {
        let mut file = File::open(path).map_err(|e| TcpError::Parse(e.to_string()))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| TcpError::Parse(e.to_string()))?;

        if data.len() < 12 {
            return Ok(());
        }

        if data[0..4] != [0x0A, 0x0D, 0x0D, 0x0A] {
            return Ok(());
        }

        let mut pos = 0;
        while pos + 8 <= data.len() {
            let block_type = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let block_len = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;

            if block_len < 12 || pos + block_len > data.len() {
                break;
            }

            if block_type == 0x0000000A {
                if block_len >= 16 {
                    let secrets_type = u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
                    let secrets_len = u32::from_le_bytes([data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15]]) as usize;

                    if (secrets_type == 0x544c534b || secrets_type == 0x4b534c54)
                        && pos + 16 + secrets_len <= data.len()
                    {
                        let secrets_data = &data[pos + 16..pos + 16 + secrets_len];
                        self.tls_secrets.parse_keylog(secrets_data);
                    }
                }
            }

            pos += block_len;
        }

        Ok(())
    }

    fn process_packet(&mut self, packet: &SlicedPacket, timestamp: DateTime<Utc>) {
        let (src_ip, dst_ip) = match &packet.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                if header.protocol() != IpNumber::TCP {
                    return;
                }
                (
                    IpAddr::V4(header.source_addr()),
                    IpAddr::V4(header.destination_addr()),
                )
            }
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                let header = ipv6.header();
                if header.next_header() != IpNumber::TCP {
                    return;
                }
                (
                    IpAddr::V6(header.source_addr()),
                    IpAddr::V6(header.destination_addr()),
                )
            }
            _ => return,
        };

        let tcp = match &packet.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => tcp,
            _ => return,
        };

        let key = StreamKey {
            src_ip,
            dst_ip,
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
        };

        let segment = TcpSegment {
            seq: tcp.sequence_number(),
            data: tcp.payload().to_vec(),
            timestamp,
            fin: tcp.fin(),
        };

        let stream = self.streams.entry(key.clone()).or_insert_with(|| TcpStream::new(key));
        stream.add_segment(segment);
    }

    pub fn get_streams(self) -> HashMap<StreamKey, TcpStream> {
        self.streams
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_stream_key_creation() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 80);
    }

    #[test]
    fn test_stream_key_reverse() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let reversed = key.reverse();

        assert_eq!(reversed.src_ip, key.dst_ip);
        assert_eq!(reversed.dst_ip, key.src_ip);
        assert_eq!(reversed.src_port, key.dst_port);
        assert_eq!(reversed.dst_port, key.src_port);
    }

    #[test]
    fn test_stream_key_equality() {
        let key1 = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let key2 = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_tcp_stream_new() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let stream = TcpStream::new(key.clone());

        assert_eq!(stream.key, key);
        assert!(stream.segments.is_empty());
    }

    #[test]
    fn test_tcp_stream_add_segment() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);

        let segment = TcpSegment {
            seq: 100,
            data: b"Hello".to_vec(),
            timestamp: Utc::now(),
            fin: false,
        };

        stream.add_segment(segment);

        assert_eq!(stream.segments.len(), 1);
        assert_eq!(stream.segments[0].seq, 100);
        assert_eq!(stream.segments[0].data, b"Hello");
    }

    #[test]
    fn test_tcp_stream_reassemble_empty() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let stream = TcpStream::new(key);
        let (data, timestamps) = stream.reassemble();

        assert!(data.is_empty());
        assert!(timestamps.is_empty());
    }

    #[test]
    fn test_tcp_stream_reassemble_single_segment() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello World".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, timestamps) = stream.reassemble();

        assert_eq!(data, b"Hello World");
        assert_eq!(timestamps.len(), 1);
        assert_eq!(timestamps[0], now);
    }

    #[test]
    fn test_tcp_stream_reassemble_multiple_segments_in_order() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello ".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 106,
            data: b"World".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, timestamps) = stream.reassemble();

        assert_eq!(data, b"Hello World");
        assert_eq!(timestamps.len(), 2);
    }

    #[test]
    fn test_tcp_stream_reassemble_out_of_order() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 200,
            data: b"World".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello ".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, _) = stream.reassemble();

        assert_eq!(data, b"Hello World");
    }

    #[test]
    fn test_tcp_stream_reassemble_skips_empty_segments() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        let now = Utc::now();

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"Hello".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 105,
            data: vec![],
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 106,
            data: b"World".to_vec(),
            timestamp: now,
            fin: false,
        });

        let (data, timestamps) = stream.reassemble();

        assert_eq!(data, b"HelloWorld");
        assert_eq!(timestamps.len(), 2);
    }

    #[test]
    fn test_tcp_stream_first_timestamp() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        
        use chrono::Duration;
        let now = Utc::now();
        let later = now + Duration::seconds(1);

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"First".to_vec(),
            timestamp: later,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 200,
            data: b"Second".to_vec(),
            timestamp: now,
            fin: false,
        });

        let first = stream.first_timestamp();
        assert_eq!(first, Some(now));
    }

    #[test]
    fn test_tcp_stream_last_timestamp() {
        let key = StreamKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
        };

        let mut stream = TcpStream::new(key);
        
        use chrono::Duration;
        let now = Utc::now();
        let later = now + Duration::seconds(1);

        stream.add_segment(TcpSegment {
            seq: 100,
            data: b"First".to_vec(),
            timestamp: now,
            fin: false,
        });

        stream.add_segment(TcpSegment {
            seq: 200,
            data: b"Second".to_vec(),
            timestamp: later,
            fin: false,
        });

        let last = stream.last_timestamp();
        assert_eq!(last, Some(later));
    }

    #[test]
    fn test_tcp_reassembler_new() {
        let reassembler = TcpReassembler::new();
        let streams = reassembler.get_streams();
        
        assert!(streams.is_empty());
    }

    #[test]
    fn test_tcp_reassembler_default() {
        let reassembler = TcpReassembler::default();
        let streams = reassembler.get_streams();
        
        assert!(streams.is_empty());
    }

    #[test]
    fn test_tcp_segment_with_fin_flag() {
        let segment = TcpSegment {
            seq: 100,
            data: b"FIN".to_vec(),
            timestamp: Utc::now(),
            fin: true,
        };

        assert!(segment.fin);
        assert_eq!(segment.data, b"FIN");
    }
}
