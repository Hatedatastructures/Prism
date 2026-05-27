# Prism 开发者文档

按源码模块分层的技术文档。每个模块对应 `include/prism/` 下的一个目录，复杂模块用子目录+文件，简单模块单文件。

---

## 核心模块

| 模块 | 文档 | 说明 |
|------|------|------|
| **instance** | [agent.md](agent.md) | 代理核心：front/listener、balancer、worker、session、dispatch、account |
| **recognition** | [recognition.md](recognition.md) | 协议智能识别：probe 探测、tls 信号分析、pipeline 执行 |
| **connect** | [channel.md](channel.md) | 传输层抽象：接口、连接池、Happy Eyeballs、健康检测 |
| **transport** | [channel.md](channel.md) | 传输实现：reliable(TCP)、encrypted(TLS)、unreliable(UDP)、preview(预读) |
| **resolve** | [resolve.md](resolve.md) | DNS 解析：resolver 接口、upstream 查询、detail 子模块 |
| **protocol** | [HTTP](protocol/http.md) · [SOCKS5](protocol/socks5.md) · [Trojan](protocol/trojan.md) · [VLESS](protocol/vless.md) · [SS2022](protocol/shadowsocks.md) | 各协议实现 |
| **stealth** | [Reality](stealth/reality.md) · [Restls](stealth/Restls.md) · [AnyTLS](stealth/AnyTLS.md) · [TrustTunnel](stealth/TrustTunnel.md) | TLS 伪装方案 |
| **multiplex** | [smux](multiplex/smux.md) · [yamux](multiplex/yamux.md) · [h2mux](multiplex/h2mux.md) | 多路复用 |

## 基础设施模块

| 模块 | 文档 | 说明 |
|------|------|------|
| **context** | — | 运行时上下文（server/worker/session context） |
| **stats** | — | 运行时统计（runtime/traffic/account/memory） |
| **memory** | [memory.md](memory.md) | PMR 容器、全局池、帧竞技场 |
| **crypto** | [crypto.md](crypto.md) | AEAD、SHA224、BLAKE3、X25519、HKDF、Base64 |
| **transformer** | — | JSON 序列化（glaze 映射） |
| **fault** | [fault.md](fault.md) | 错误码体系 |
| **exception** | [exception.md](exception.md) | 异常继承层次 |
| **pipeline** | [pipeline.md](pipeline.md) | 协议管道原语（概念文档，代码已分散至 connect/transport） |
| **性能** | [performance-report.md](performance-report.md) | 基准测试报告 |

---

## 按角色查找

- **新开发者**：→ 阅读 [教程目录](../tutorial/) 中的配置和部署指南
- **协议开发者**：→ [protocol/socks5.md](protocol/socks5.md)、[protocol/trojan.md](protocol/trojan.md) 等
- **核心开发者**：→ [agent.md](agent.md) → [recognition.md](recognition.md) → [channel.md](channel.md) → [resolve.md](resolve.md)
- **伪装方案开发者**：→ [stealth/reality.md](stealth/reality.md) → [stealth/Restls.md](stealth/Restls.md) → [stealth/AnyTLS.md](stealth/AnyTLS.md) → [stealth/TrustTunnel.md](stealth/TrustTunnel.md)