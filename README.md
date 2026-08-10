<div align="center">

# Prism

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

**Clash 服务端** — 单端口服务全部协议

</div>

---

## 协议支持

### 代理协议

| 协议 | TCP | UDP | smux | yamux | h2mux | TLS 伪装 | QUIC |
|------|:---:|:---:|:---:|:---:|:---:|:--------:|:----:|
| HTTP | ✅ | — | — | — | — | — | — |
| SOCKS5 | ✅ | ✅ | — | — | — | — | — |
| Trojan | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| VLESS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| SS2022 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| VMess | ✅ | ✅ | — | — | — | — | — |
| AnyTLS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| TrustTunnel | ✅ | ✅ | — | — | — | ✅ | — |
| Hysteria2 | ✅ | ✅ | — | — | — | — | ✅ |
| TUIC v5 | ✅ | ✅ | — | — | — | — | ✅ |

✅ 支持 · — 不支持

### TLS 伪装方案

| 方案 | 形态 | 说明 |
|------|:---:|------|
| Reality | 嵌套 | TLS 指纹伪装，X25519 密钥交换，免证书 |
| ShadowTLS v3 | 嵌套 | TLS 握手代理，规避主动探测 |
| Restls | 嵌套 | TLS 探测抵抗，自定义脚本认证 |
| AnyTLS | 独立 | 自带 TLS + 应用层认证 + 内部多路复用 |
| TrustTunnel | 独立 | 自带 TLS + HTTP/2 CONNECT，Basic Auth（仅 h2，不支持 QUIC）|
| WebSocket | 嵌套 | TLS + HTTP/1.1 升级（WebSocket），SNI 路由 |
| XHTTP | 嵌套 | TLS + HTTP/2（stream-one / stream-up / packet-up）|
| gRPC (Gun) | 嵌套 | TLS + HTTP/2 + gRPC 帧伪装 |
| ECH | 增强 | Encrypted Client Hello，隐藏 SNI |

- **嵌套**：TLS 传输层伪装，承载内层代理协议
- **独立**：方案自身即完整代理协议（AnyTLS / TrustTunnel）
- **多路复用**：smux v1（Mihomo/xtaci 兼容）· yamux（窗口流控）· h2mux，协商制通用层
- **SNI 路由**：伪装方案按 SNI 识别（如 `www.microsoft.com` → Reality、`www.apple.com` → ShadowTLS），单端口可同时服务全部协议组合
- **QUIC 协议**（Hysteria2 / TUIC v5）：基于 ngtcp2 + nghttp3 的 UDP 网关，与 TCP 监听同端口共存

---


## 架构概览

```
listener ──► balancer（亲和性哈希 + 负载均衡）──► worker × N（独立 io_context）
                                                   └─► session
                                                        ├─ probe：首包识别协议类型
                                                        ├─ 伪装方案 / 协议处理
                                                        └─ 双向异步中继（含多路复用协商）
```

详见 [架构说明](docs/ARCHITECTURE.md)

---

## 性能

本机回环实测（Windows 11 · Release · 1GB/连接大文件，每组 3 轮取均值，单位 Gbps）

| 协议 | 方向 | 单 worker | 8 worker |
|------|------|:---:|:---:|
| HTTP 代理 | 下行 | 19.6 | 65.0 |
| HTTP 代理 | 上行 | 10.2 | 39.4 |
| Trojan（TLS 内层）| 下行 | 8.1 | 32.0 * |
| Trojan（TLS 内层）| 上行 | 6.8 | 30.7 |

- 回环 I/O 上限约 13 GB/s（104 Gbps，CPU <5%），瓶颈为系统 I/O 栈，非计算
- 同源 IP 连接集中于单 worker（上限 ~2.7 GB/s）；多客户端 IP 分散后吞吐随 worker 扩展
- 实际网络取决于链路带宽与 RTT
- \* TLS 8 worker 偶发识别失败，值为单次实测

---

## 快速开始

### 环境要求

C++23 / CMake 3.23+ / MinGW 或 GCC 工具链

### 构建与启动

```bash
git clone https://github.com/Hatedatastructures/Prism.git
cd Prism

# 构建
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j 16

# 配置
cp src/configuration.json build/src/

# 启动（自动加载同目录配置，或指定路径）
./build/src/Prism.exe
./build/src/Prism.exe /path/to/config

# 测试
ctest --test-dir build --output-on-failure -j 1 --timeout 30

# Go 互操作测试（mihomo 同栈客户端，需 Go 1.22+）
ctest --test-dir build -R GoCompat --output-on-failure -j 1
```

> 配置文件中的路径需改为绝对路径，详见 [配置详解](docs/tutorial/configuration.md)

### 客户端示例（Mihomo/Clash）

```yaml
proxies:
  - name: "Prism-Trojan"
    type: trojan
    server: 192.168.x.x
    port: 8081
    password: "prism"
    udp: true
    skip-cert-verify: true

  - name: "Prism-VMess"
    type: vmess
    server: 192.168.x.x
    port: 8081
    uuid: "123e4567-e89b-12d3-a456-426614174000"
    alterId: 0
    cipher: auto
    udp: true

  - name: "Prism-TUIC"
    type: tuic
    server: 192.168.x.x
    port: 8081
    uuid: "123e4567-e89b-12d3-a456-426614174000"
    password: "tuic_password"
    udp: true
    skip-cert-verify: true
```

> VMess 复用 SS2022 探测通道（SS2022 握手失败自动回退）；TUIC/Hysteria2 走 UDP 端口，与 TCP 监听同端口共存。

---

## 开发路线

- [x] QUIC / Hysteria2 / TUIC v5
- [x] VMess / WebSocket / XHTTP / gRPC (Gun) / ECH
- [ ] smux v2 · sing-mux 流控增强

---

## 文档

- [架构说明](docs/ARCHITECTURE.md)
- [快速开始](docs/tutorial/getting-started.md)
- [配置详解](docs/tutorial/configuration.md)
- [部署指南](docs/tutorial/deployment.md)
- [故障排查](docs/tutorial/troubleshooting.md)
- [常见问题](docs/tutorial/faq.md)
- [性能报告](docs/performance-report.md)

---

## 许可证

[MIT](LICENSE)
