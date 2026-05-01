# Prism 开发者文档

按源码模块分层的技术文档。每个模块对应 `include/prism/` 下的一个目录，复杂模块用子目录+文件，简单模块单文件。

---

## 核心模块

| 模块 | 文档 | 说明 |
|------|------|------|
| **agent** | [agent.md](agent.md) | 代理核心：front/listener、balancer、worker、session、dispatch、account |
| **recognition** | [recognition.md](recognition.md) | 协议智能识别：probe 探测、arrival 分析、handshake 执行 |
| **channel** | [channel.md](channel.md) | 传输层抽象：接口、连接池、Happy Eyeballs、健康检测 |
| **resolve** | [resolve.md](resolve.md) | DNS 解析：resolver 接口、upstream 查询、detail 子模块 |
| **pipeline** | [pipeline.md](pipeline.md) | 协议管道：primitives、tunnel |
| **protocol** | [HTTP](protocol/http.md) · [SOCKS5](protocol/socks5.md) · [Trojan](protocol/trojan.md) · [VLESS](protocol/vless.md) · [SS2022](protocol/shadowsocks.md) | 各协议实现 |
| **stealth** | [Reality](stealth/reality.md) | TLS 伪装 |
| **multiplex** | [smux](multiplex/smux.md) · [yamux](multiplex/yamux.md) | 多路复用 |

## 基础设施模块

| 模块 | 文档 | 说明 |
|------|------|------|
| **memory** | [memory.md](memory.md) | PMR 容器、全局池、帧竞技场 |
| **crypto** | [crypto.md](crypto.md) | SHA224、Base64、AEAD、BLAKE3 |
| **fault** | [fault.md](fault.md) | 错误码体系 |
| **exception** | [exception.md](exception.md) | 异常继承层次 |
| **性能** | [performance-report.md](performance-report.md) | 基准测试报告 |

---

## 按角色查找

- **新开发者**：→ 阅读 [教程目录](../tutorial/) 中的配置和部署指南
- **协议开发者**：→ [protocol/socks5.md](protocol/socks5.md)、[protocol/trojan.md](protocol/trojan.md) 等
- **核心开发者**：→ [agent.md](agent.md) → [recognition.md](recognition.md) → [channel.md](channel.md) → [resolve.md](resolve.md)