# pcap2har

English | [简体中文](README_CN.md)

A high-performance PCAP to HAR converter written in Rust, designed to analyze network traffic and convert packet captures into HTTP Archive (HAR) format for easy inspection and debugging.

## Overview

This tool converts network packet capture files (PCAP) into HAR (HTTP Archive) JSON format, making it easier to analyze HTTP/HTTPS traffic. It supports multiple protocols including HTTP/1.x, HTTP/2, HTTPS (with TLS decryption), and FastCGI, making it particularly useful for web development, API debugging, and network traffic analysis.

## Features

- **Multiple Protocol Support**
  - HTTP/1.0 and HTTP/1.1
  - HTTP/2 (with HPACK header decompression)
  - HTTPS with TLS 1.2 and TLS 1.3 decryption
  - FastCGI protocol parsing

- **Advanced Capabilities**
  - TCP stream reassembly for accurate conversation tracking
  - TLS traffic decryption using keylog files
  - Automatic request-response pairing
  - Multiple concurrent requests handling
  - Gzip/deflate content decompression
  - Base64 encoding for binary content

- **Performance**
  - Written in Rust for high performance and memory safety
  - Efficient stream processing
  - Minimal resource overhead

## Installation

### Prerequisites

- Rust 1.70 or higher
- libpcap (Linux/macOS) or WinPcap/Npcap (Windows)

### Building from Source

```bash
git clone https://github.com/Litt1eQ/pcap2har.git
cd pcap2har
cargo build --release
```

The compiled binary will be available at `target/release/pcap2har`.

### Installing

```bash
cargo install --path .
```

## Usage

### Basic Usage

Convert a PCAP file to HAR format and output to stdout:

```bash
pcap2har capture.pcap
```

Save the output to a file:

```bash
pcap2har capture.pcap -o output.har
```

Or redirect stdout:

```bash
pcap2har capture.pcap > output.har
```

### Capturing Traffic

You can capture network traffic using standard tools like `tcpdump`:

```bash
# Capture HTTP traffic on port 80
sudo tcpdump -i any port 80 -w capture.pcap

# Capture HTTPS traffic on port 443
sudo tcpdump -i any port 443 -w capture.pcap

# Capture all TCP traffic
sudo tcpdump -i any tcp -w capture.pcap
```

### Using with eCapture

This tool is particularly useful when combined with [eCapture](https://github.com/gojue/ecapture), an eBPF-based SSL/TLS capture tool that can capture encrypted traffic without requiring application modifications.

#### Step 1: Capture Traffic with eCapture

eCapture can capture HTTPS traffic and automatically decrypt TLS communications, saving the decrypted plaintext directly into PCAP files:

```bash
# Install eCapture (Linux only, requires kernel 4.18+)
# Follow instructions at https://github.com/gojue/ecapture

# Capture HTTPS traffic and save as pcapng with decrypted content
sudo ecapture tls -m pcapng -i eth0 --pcapfile=capture.pcapng "tcp port 443"

# Capture traffic from all interfaces
sudo ecapture tls -m pcapng -i any --pcapfile=capture.pcapng

# Capture HTTP traffic on port 80
sudo ecapture tls -m pcapng -i any --pcapfile=capture.pcapng "tcp port 80"
```

#### Step 2: Convert to HAR

Since eCapture outputs decrypted plaintext directly in the PCAP file, you can convert it immediately without any additional configuration:

```bash
pcap2har capture.pcapng -o output.har
```

## Viewing HAR Files

Once you've generated a HAR file, you can view and analyze it using various tools. We recommend using **[Reqable](https://reqable.com/)**, a professional HTTP traffic analysis tool with excellent HAR file support.

### Using Reqable

[Reqable](https://reqable.com/) is a modern, cross-platform API debugging and HTTP traffic analysis tool that provides:

- **Beautiful HAR Viewer**: Clean, intuitive interface for viewing HTTP conversations
- **Request/Response Inspection**: Detailed view of headers, body, cookies, and timing information
- **Protocol Support**: HTTP/1.x, HTTP/2, WebSocket, and more
- **Content Formatting**: Automatic formatting for JSON, XML, HTML, and images
- **Search and Filter**: Quickly find specific requests by URL, method, status code, etc.
- **Export Options**: Export individual requests or entire sessions

#### How to View HAR Files in Reqable

1. **Download and Install**: Get Reqable from [https://reqable.com/](https://reqable.com/)
2. **Open HAR File**: 
   - Launch Reqable
   - Click `File > Open` or drag and drop your HAR file into the application
3. **Analyze Traffic**:
   - Browse the list of HTTP requests
   - Click on any request to view detailed information
   - Inspect headers, body content, cookies, and timing data
   - Use filters to focus on specific types of requests

![Reqable HAR Viewer](images/reqable.png)

*Example: Viewing HTTP traffic in Reqable*

### Alternative HAR Viewers

- **Chrome DevTools**: Open Chrome DevTools > Network tab > Right-click > "Import HAR file"
- **Firefox DevTools**: Similar import functionality in Network tab
- **Online Viewers**: [HAR Viewer](http://www.softwareishard.com/har/viewer/) (web-based)
- **Charles Proxy**: Professional HTTP debugging tool with HAR import
- **Fiddler**: Another popular HTTP debugging tool

## Project Architecture

The project is organized into several modules:

- `tcp.rs`: TCP stream reassembly and packet ordering
- `http.rs`: HTTP/1.x protocol parsing
- `http2.rs`: HTTP/2 frame parsing and HPACK decompression
- `tls.rs`: TLS record parsing and decryption
- `fcgi.rs`: FastCGI protocol parsing
- `har.rs`: HAR format data structures
- `converter.rs`: Core conversion logic
- `main.rs`: CLI interface

## Supported Protocols

### HTTP/1.x
- Request and response parsing
- Header parsing
- Cookie extraction
- Query string parsing
- POST data handling
- Content encoding (gzip, deflate)

### HTTP/2
- Frame parsing
- HPACK header compression
- Stream multiplexing
- Server push (experimental)

### HTTPS/TLS
- TLS 1.2 decryption
- TLS 1.3 decryption
- Keylog file support
- Multiple cipher suites

### FastCGI
- Request parsing
- Response parsing
- Conversion to HTTP format

## Limitations

- **TLS Decryption**: Requires keylog files; Perfect Forward Secrecy (PFS) connections cannot be decrypted without keylog
- **WebSocket**: WebSocket frame parsing is not yet implemented
- **QUIC/HTTP3**: Not currently supported
- **Fragmented Packets**: Some edge cases in TCP reassembly may not be handled perfectly
- **Memory Usage**: Large PCAP files are loaded into memory; very large files (>1GB) may require significant RAM

## Dependencies

This project uses the following major crates:

- [pcap](https://crates.io/crates/pcap) - PCAP file parsing
- [etherparse](https://crates.io/crates/etherparse) - Network protocol parsing
- [httparse](https://crates.io/crates/httparse) - HTTP header parsing
- [serde_json](https://crates.io/crates/serde_json) - JSON serialization
- [rustls](https://crates.io/crates/rustls) - TLS protocol support
- [clap](https://crates.io/crates/clap) - Command-line argument parsing

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Acknowledgments

This project is inspired by and references:

- **[pcap2har-go](https://github.com/colinnewell/pcap2har-go)**: A Go implementation of PCAP to HAR conversion that served as a reference for the architecture and approach
- **[eCapture](https://github.com/gojue/ecapture)**: An eBPF-based tool for capturing SSL/TLS traffic, highly recommended for capturing HTTPS traffic to use with this tool
- **[Reqable](https://reqable.com/)**: An excellent HTTP traffic analysis tool for viewing and analyzing generated HAR files

Special thanks to the Rust community and the maintainers of the excellent crates this project depends on.

## References

- [HAR 1.2 Specification](http://www.softwareishard.com/blog/har-12-spec/)
- [HTTP/2 Specification (RFC 7540)](https://tools.ietf.org/html/rfc7540)
- [TLS 1.3 Specification (RFC 8446)](https://tools.ietf.org/html/rfc8446)
- [HPACK Specification (RFC 7541)](https://tools.ietf.org/html/rfc7541)
- [NSS Key Log Format](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related Tools

- [Wireshark](https://www.wireshark.org/): The world's foremost network protocol analyzer
- [tcpdump](https://www.tcpdump.org/): Command-line packet analyzer
- [eCapture](https://github.com/gojue/ecapture): Capture SSL/TLS traffic using eBPF
- [mitmproxy](https://mitmproxy.org/): Interactive HTTPS proxy
- [Reqable](https://reqable.com/): API debugging and HTTP traffic analysis tool

