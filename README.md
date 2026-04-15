<div align="center">

# Prism

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)


**高性能协程代理引擎** — C++23 纯协程架构，PMR 热路径零堆分配

</div>

---
## 概述

Prism 是一个从零构建的服务端代理引擎，用 **C++23 协程** 替代回调、用 **PMR 内存池** 消除堆分配、用 **零拷贝** 减少数据搬移。每个连接由独立协程驱动，per-worker 独占 `io_context` 全链路无锁，请求处理全程零 `malloc`。支持五种代理协议 + Reality TLS 伪装，兼容 Mihomo 内核客户端。


---

## 特性

**架构**
- **无锁协程** — C++23 `co_await` 全链路异步无锁，无回调嵌套
- **零堆分配** — PMR 全局池 + 线程独占池，热路径全程零 `malloc`
- **无锁设计** — per-worker 独占 `io_context`，吞吐随 CPU 核心数线性扩展
- **智能嗅探** — 首包协议检测 + TLS 透明剥离 + 二次探测，一个端口服务所有协议

**协议**
- *HTTP* — 正向代理 + `CONNECT` 隧道 + Basic 认证
- *SOCKS5* — RFC 1928 完整实现，TCP `CONNECT` + UDP `ASSOCIATE`
- *Trojan* — TLS + SHA224 凭据 + mux
- *VLESS* — UUID 认证 + mux
- *SS2022* — SIP022 AEAD（AES-128/256-GCM + XChaCha20-Poly1305），BLAKE3 密钥派生，TCP/UDP 中继 + 抗重放

**伪装**
- *Reality* — TLS 指纹伪装，X25519 密钥交换

**优化**
- **Happy Eyeballs** — 多服务器 DNS 竞速 + 多 IP 连接竞速（RFC 8305）
- **连接池** — 线程级连接复用 + 健康检查 + 自动回收
- **阶段 DNS** — 规则匹配 → 缓存 → 请求合并 → 上游查询（UDP/TCP/DoT/DoH）→ 黑名单 → TTL 钳制
- **负载均衡** — 加权评分调度 + 亲和性哈希 + 全局过载反压

---

## 快速开始

**环境要求：** GCC 13+ / CMake 3.23+，所有依赖自动拉取，无需手动安装。

```bash
git clone https://github.com/Hatedatastructures/Prism.git
cd Prism

cmake -B build_release -DCMAKE_BUILD_TYPE=Release
cmake --build build_release --config Release

# 启动（默认监听 0.0.0.0:8081）
./build_release/src/Prism.exe

# 测试
ctest --test-dir build_release --output-on-failure
```

**客户端配置（Clash客户端）：**

```yaml
proxies:
  - name: "Prism"
    type: trojan
    server: 192.168.x.x
    port: 8081
    password: "prism"
    udp: true
    skip-cert-verify: true
```

> 完整配置参考 [**clash配置**](docs/examples/clash/reference.yaml)

---

## 项目结构

```
Prism/
├── include/prism/
│   ├── agent/            # 代理核心（listener, balancer, worker, session）
│   ├── channel/          # 传输层（reliable, encrypted, connection pool, eyeball）
│   ├── crypto/           # 加密（AEAD, SHA224, BLAKE3, X25519, HKDF, Base64）
│   ├── fault/            # 错误码体系
│   ├── memory/           # PMR 内存管理（pool, arena, container）
│   ├── multiplex/        # 多路复用（smux, yamux, duct, parcel）
│   ├── pipeline/         # 协议管道（primitives, tunnel）
│   ├── protocol/         # 协议实现（http, socks5, trojan, vless, shadowsocks）
│   ├── stealth/          # TLS 伪装层（reality/）
│   └── resolve/          # DNS（router, recursor, cache, resolver, rules）
├── src/                  # 源文件 + 入口
├── tests/                # 单元测试（21 个）
├── benchmarks/           # 基准测试
├── stresses/             # 压力测试
├── docs/                 # 文档
└── scripts/              # 工具脚本
```

---

## 依赖项

全部通过 CMake FetchContent 自动拉取，首次拉取构建约 10 分钟，后续复用缓存。

| 依赖 | 用途 |
|------|------|
| Boost 1.89 (Asio) | 协程异步 I/O |
| BoringSSL | TLS（OpenSSL API 兼容） |
| spdlog 1.17 | 异步日志 |
| glaze 6.5 | JSON 序列化 |
| BLAKE3 1.8 | SS2022 密钥派生 |
| Google Benchmark 1.9 | 性能测试 |

---

## 协议状态

| 协议 | TCP | UDP | 认证 | Mux |
|------|:---:|:---:|------|:---:|
| *HTTP* | ✓ | — | Basic | — |
| *SOCKS5* | ✓ | ✓ | User/Pass | — |
| *Trojan* | ✓ | ✓ | SHA224 | ✓ |
| *VLESS* | ✓ | — | UUID | ✓ |
| *SS2022* | ✓ | ✓ | PSK/BLAKE3 | — |

| 伪装 | 状态 | 说明 |
|------|------|------|
| *Reality* | 已完成 | TLS 指纹伪装，X25519 密钥交换，可叠加任意内层协议 |

| Mux | 状态 | 说明 |
|-----|------|------|
| *smux* v1 | 已完成 | 兼容 Mihomo/xtaci，TCP + UDP |
| *yamux* | 已完成 | 窗口流量控制 |

---

## 开发路线

- [x] 五协议完整实现（*HTTP* / *SOCKS5* / *Trojan* / *VLESS* / *SS2022*）+ *Reality* TLS 伪装
- [x] TLS 透明剥离 + 二次协议探测
- [x] *smux* / *yamux* 多路复用
- [x] Happy Eyeballs（RFC 8305）
- [x] 7 阶段 DNS 管道（UDP/TCP/DoT/DoH + 缓存 + 规则）
- [x] 连接池 + 健康检查
- [x] 加权负载均衡 + 过载反压
- [x] 每用户连接数限制 + 凭据认证
- [ ] *QUIC* / *Hysteria2*
- [ ] *smux* v2
- [ ] *WebSocket*

---

## 文档

**教程**
- [快速开始](docs/tutorial/getting-started.md) · [配置详解](docs/tutorial/configuration.md) · [故障排除](docs/tutorial/troubleshooting.md) · [FAQ](docs/tutorial/faq.md)

**技术手册**
- [架构设计](docs/manual/architecture.md) · [模块设计](docs/manual/modules.md) · [运行时流程](docs/manual/runtime.md) · [路由与分发](docs/manual/routing.md)

**协议规范**
- [HTTP](docs/protocols/http.md) · [SOCKS5](docs/protocols/socks5.md) · [Trojan](docs/protocols/trojan.md) · [VLESS](docs/protocols/vless.md) · [SS2022](docs/protocols/shadowsocks.md) · [TLS](docs/protocols/tls.md)

**TLS 伪装**
- [Reality](docs/protocols/reality.md)

**参考资料**
- [配置结构体](docs/reference/config-structure.md) · [依赖关系](docs/reference/dependencies.md) · [多路复用](docs/multiplex/overview.md)

---

## 许可证

[MIT](LICENSE)
