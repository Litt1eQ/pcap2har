# pcap2har

[English](README.md) | 简体中文

一款用 Rust 编写的高性能 PCAP 到 HAR 转换工具，旨在分析网络流量并将数据包捕获文件转换为 HTTP Archive (HAR) 格式，便于检查和调试。

## 项目概述

该工具将网络数据包捕获文件 (PCAP) 转换为 HAR (HTTP Archive) JSON 格式，使分析 HTTP/HTTPS 流量变得更加容易。它支持多种协议，包括 HTTP/1.x、HTTP/2、HTTPS（支持 TLS 解密）和 FastCGI，特别适用于 Web 开发、API 调试和网络流量分析。

## 功能特性

- **多协议支持**
  - HTTP/1.0 和 HTTP/1.1
  - HTTP/2（支持 HPACK 头部解压缩）
  - 支持 TLS 1.2 和 TLS 1.3 解密的 HTTPS
  - FastCGI 协议解析

- **高级功能**
  - TCP 流重组，精确跟踪会话
  - 使用 keylog 文件解密 TLS 流量
  - 自动配对请求和响应
  - 处理多个并发请求
  - Gzip/deflate 内容解压缩
  - 二进制内容 Base64 编码

- **性能优势**
  - 使用 Rust 编写，具有高性能和内存安全性
  - 高效的流处理
  - 最小化资源开销

## 安装

### 前置要求

- Rust 1.70 或更高版本
- libpcap (Linux/macOS) 或 WinPcap/Npcap (Windows)

### 从源码编译

```bash
git clone https://github.com/Litt1eQ/pcap2har.git
cd pcap2har
cargo build --release
```

编译后的二进制文件将位于 `target/release/pcap2har`。

### 安装

```bash
cargo install --path .
```

## 使用方法

### 基本用法

将 PCAP 文件转换为 HAR 格式并输出到标准输出：

```bash
pcap2har capture.pcap
```

将输出保存到文件：

```bash
pcap2har capture.pcap -o output.har
```

或者使用重定向：

```bash
pcap2har capture.pcap > output.har
```

### 捕获流量

你可以使用标准工具如 `tcpdump` 来捕获网络流量：

```bash
# 捕获 80 端口的 HTTP 流量
sudo tcpdump -i any port 80 -w capture.pcap

# 捕获 443 端口的 HTTPS 流量
sudo tcpdump -i any port 443 -w capture.pcap

# 捕获所有 TCP 流量
sudo tcpdump -i any tcp -w capture.pcap
```

### 配合 eCapture 使用

该工具与 [eCapture](https://github.com/gojue/ecapture) 配合使用效果特别好。eCapture 是一个基于 eBPF 的 SSL/TLS 捕获工具，可以捕获加密流量而无需修改应用程序。

#### 步骤 1：使用 eCapture 捕获流量

eCapture 可以捕获 HTTPS 流量并自动解密 TLS 通信，将解密后的明文直接保存到 PCAP 文件中：

```bash
# 安装 eCapture（仅支持 Linux，需要内核 4.18+）
# 请访问 https://github.com/gojue/ecapture 查看安装说明

# 捕获 HTTPS 流量并保存为包含解密内容的 pcapng 文件
sudo ecapture tls -m pcapng -i eth0 --pcapfile=capture.pcapng "tcp port 443"

# 捕获所有网络接口的流量
sudo ecapture tls -m pcapng -i any --pcapfile=capture.pcapng

# 捕获 80 端口的 HTTP 流量
sudo ecapture tls -m pcapng -i any --pcapfile=capture.pcapng "tcp port 80"
```

#### 步骤 2：转换为 HAR

由于 eCapture 直接在 PCAP 文件中输出解密的明文，你可以立即转换它，无需任何额外配置：

```bash
pcap2har capture.pcapng -o output.har
```

## 查看 HAR 文件

生成 HAR 文件后，你可以使用各种工具来查看和分析它。我们推荐使用 **[Reqable](https://reqable.com/)**，这是一款专业的 HTTP 流量分析工具，对 HAR 文件有出色的支持。

### 使用 Reqable

[Reqable](https://reqable.com/) 是一款现代化的跨平台 API 调试和 HTTP 流量分析工具，提供以下功能：

- **精美的 HAR 查看器**：清晰、直观的界面，用于查看 HTTP 会话
- **请求/响应检查**：详细查看头部、正文、Cookie 和时间信息
- **协议支持**：HTTP/1.x、HTTP/2、WebSocket 等
- **内容格式化**：自动格式化 JSON、XML、HTML 和图片
- **搜索和过滤**：通过 URL、方法、状态码等快速查找特定请求
- **导出选项**：导出单个请求或整个会话

#### 如何在 Reqable 中查看 HAR 文件

1. **下载并安装**：从 [https://reqable.com/](https://reqable.com/) 获取 Reqable
2. **打开 HAR 文件**：
   - 启动 Reqable
   - 点击 `文件 > 打开` 或将 HAR 文件拖放到应用程序中
3. **分析流量**：
   - 浏览 HTTP 请求列表
   - 点击任意请求查看详细信息
   - 检查头部、正文内容、Cookie 和时间数据
   - 使用过滤器聚焦于特定类型的请求

![Reqable HAR 查看器](images/reqable.png)

*示例：在 Reqable 中查看 HTTP 流量*

### 其他 HAR 查看器

- **Chrome 开发者工具**：打开 Chrome DevTools > Network 标签 > 右键 > "Import HAR file"
- **Firefox 开发者工具**：Network 标签中有类似的导入功能
- **在线查看器**：[HAR Viewer](http://www.softwareishard.com/har/viewer/)（基于 Web）
- **Charles Proxy**：专业的 HTTP 调试工具，支持 HAR 导入
- **Fiddler**：另一款流行的 HTTP 调试工具

## 项目架构

项目组织为多个模块：

- `tcp.rs`：TCP 流重组和数据包排序
- `http.rs`：HTTP/1.x 协议解析
- `http2.rs`：HTTP/2 帧解析和 HPACK 解压缩
- `tls.rs`：TLS 记录解析和解密
- `fcgi.rs`：FastCGI 协议解析
- `har.rs`：HAR 格式数据结构
- `converter.rs`：核心转换逻辑
- `main.rs`：命令行界面

## 支持的协议

### HTTP/1.x
- 请求和响应解析
- 头部解析
- Cookie 提取
- 查询字符串解析
- POST 数据处理
- 内容编码（gzip、deflate）

### HTTP/2
- 帧解析
- HPACK 头部压缩
- 流多路复用
- 服务器推送（实验性）

### HTTPS/TLS
- TLS 1.2 解密
- TLS 1.3 解密
- Keylog 文件支持
- 多种密码套件

### FastCGI
- 请求解析
- 响应解析
- 转换为 HTTP 格式

## 局限性

- **TLS 解密**：需要 keylog 文件；没有 keylog 无法解密完全前向保密 (PFS) 连接
- **WebSocket**：尚未实现 WebSocket 帧解析
- **QUIC/HTTP3**：目前不支持
- **分片数据包**：TCP 重组中的某些边缘情况可能无法完美处理
- **内存使用**：大型 PCAP 文件会加载到内存中；超大文件（>1GB）可能需要大量 RAM

## 依赖项

该项目使用以下主要 crate：

- [pcap](https://crates.io/crates/pcap) - PCAP 文件解析
- [etherparse](https://crates.io/crates/etherparse) - 网络协议解析
- [httparse](https://crates.io/crates/httparse) - HTTP 头部解析
- [serde_json](https://crates.io/crates/serde_json) - JSON 序列化
- [rustls](https://crates.io/crates/rustls) - TLS 协议支持
- [clap](https://crates.io/crates/clap) - 命令行参数解析

## 贡献

欢迎贡献！请随时提交 issue 或 pull request。

## 致谢

本项目的灵感来源和参考：

- **[pcap2har-go](https://github.com/colinnewell/pcap2har-go)**：Go 语言实现的 PCAP 到 HAR 转换工具，为本项目的架构和方法提供了参考
- **[eCapture](https://github.com/gojue/ecapture)**：基于 eBPF 的 SSL/TLS 流量捕获工具，强烈推荐用于捕获 HTTPS 流量并配合本工具使用
- **[Reqable](https://reqable.com/)**：优秀的 HTTP 流量分析工具，用于查看和分析生成的 HAR 文件

特别感谢 Rust 社区和本项目所依赖的优秀 crate 的维护者们。

## 参考资料

- [HAR 1.2 规范](http://www.softwareishard.com/blog/har-12-spec/)
- [HTTP/2 规范 (RFC 7540)](https://tools.ietf.org/html/rfc7540)
- [TLS 1.3 规范 (RFC 8446)](https://tools.ietf.org/html/rfc8446)
- [HPACK 规范 (RFC 7541)](https://tools.ietf.org/html/rfc7541)
- [NSS Key Log 格式](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)

## 许可证

本项目采用 MIT 许可证 - 详见 LICENSE 文件。

## 相关工具

- [Wireshark](https://www.wireshark.org/)：世界领先的网络协议分析器
- [tcpdump](https://www.tcpdump.org/)：命令行数据包分析器
- [eCapture](https://github.com/gojue/ecapture)：使用 eBPF 捕获 SSL/TLS 流量
- [mitmproxy](https://mitmproxy.org/)：交互式 HTTPS 代理
- [Reqable](https://reqable.com/)：API 调试和 HTTP 流量分析工具

