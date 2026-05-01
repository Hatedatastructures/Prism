<div align="center">

# Prism

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

**高性能协程代理引擎** — C++23 纯协程架构，PMR 热路径零堆分配

</div>

---

## 概述

Prism 是从零构建的服务端代理引擎，用 C++23 协程替代回调、PMR 内存池消除堆分配、零拷贝减少数据搬移。每个连接由独立协程驱动，per-worker 独占 io_context 全链路无锁，热路径全程零 malloc。支持五种代理协议 + Reality TLS 伪装，兼容 Mihomo 客户端。

---

## 特性

**架构**
- C++23 `co_await` 全链路异步，无回调嵌套
- PMR 全局池 + 线程独占池，热路径零堆分配
- per-worker 独占 `io_context`，吞吐随核心数线性扩展
- 首包协议检测 + TLS 透明剥离 + 二次探测，单端口服务所有协议

**协议**
- **HTTP** — 正向代理 + CONNECT 隧道 + Basic 认证
- **SOCKS5** — RFC 1928，TCP CONNECT + UDP ASSOCIATE
- **Trojan** — TLS + SHA224 凭据 + mux
- **VLESS** — UUID 认证 + mux
- **SS2022** — SIP022 AEAD (AES-128/256-GCM + XChaCha20-Poly1305)，BLAKE3 密钥派生，抗重放

**伪装**
- **Reality** — TLS 指纹伪装，X25519 密钥交换

**优化**
- Happy Eyeballs (RFC 8305) — DNS 竞速 + 多 IP 连接竞速
- 连接池 — 线程级复用 + 健康检查 + 自动回收
- DNS 管道 — 规则匹配 → 缓存 → 合并 → 上游(UDP/TCP/DoT/DoH) → 黑名单 → TTL钳制
- 负载均衡 — 加权评分 + 亲和性哈希 + 过载反压

**多路复用**
- **smux v1** — 兼容 Mihomo/xtaci，TCP + UDP
- **yamux** — 窗口流量控制

---

## 快速开始

环境要求：C++23 / CMake 3.23+ / MinGW 或 GCC 工具链

```bash
git clone https://github.com/Hatedatastructures/Prism.git
cd Prism

# 构建
cmake -B build_release -DCMAKE_BUILD_TYPE=Release
cmake --build build_release --config Release -j

# 配置
cp src/configuration.json build_release/src/

# 启动
./build_release/src/prism.exe                    # 自动加载同目录配置
./build_release/src/prism.exe /path/to/config    # 指定配置路径

# 测试
ctest --test-dir build_release --output-on-failure
```

> 配置文件中的路径需改为绝对路径，详见 [配置详解](docs/tutorial/configuration.md)

**客户端示例**

```yaml
proxies:
  - name: "Prism-Trojan"
    type: trojan
    server: 192.168.x.x
    port: 8081
    password: "prism"
    udp: true
    skip-cert-verify: true
```

---

## 协议支持

| 协议 | TCP | UDP | 认证 | Mux | 伪装 |
|------|:---:|:---:|:-----|:---:|:----:|
| HTTP | ✓ | — | Basic | — | — |
| SOCKS5 | ✓ | ✓ | User/Pass | — | — |
| Trojan | ✓ | ✓ | SHA224 | ✓ | Reality |
| VLESS | ✓ | ✓ | UUID | ✓ | Reality |
| SS2022 | ✓ | ✓ | PSK/BLAKE3 | — | — |

| 伪装 | 状态 |
|------|------|
| Reality | 已完成 — TLS 指纹伪装，可叠加任意内层协议 |
| ShadowTLS v3 | 开发中 |
| RestLS | 开发中 |

---

## 性能

Intel i9-13900K + DDR4 64GB，Release (-O3)

**协议握手**

```
BenchmarkSS2022握手            560000     1.35 us/op    731.4 k/s   纯内存，无网络往返
BenchmarkTrojan握手              5600     131 us/op      7.63 k/s
BenchmarkVLESS握手               5600     138 us/op      7.17 k/s
BenchmarkSOCKS5握手              4480     146 us/op      6.83 k/s   双往返
BenchmarkHTTP握手                4480     170 us/op      6.10 k/s
```

**吞吐量**

```
Benchmark隧道传输/128KB          18667     49.5 us/op     7.11 Gi/s  接近内存带宽
BenchmarkAES256GCM加密           2358     298 us/op      225 Mi/s   64KB payload
BenchmarkAES256GCM解密           2358     307 us/op      205 Mi/s
BenchmarkReality握手            14452     47.6 us/op     22.6 k/s   X25519 占45.8%
BenchmarkBLAKE3密钥派生        2800000    269 ns/op      144 Mi/s   SS2022 EK派生
```

**内存分配**

```
BenchmarkFrameArena           112000000    9.24 ns/op     3.75 Gi/s  帧内临时对象
BenchmarkThreadLocalPool       37333333    17.7 ns/op     1.70 Gi/s  跨帧持久对象
BenchmarkGlobalPool             5600000    119 ns/op      260 Mi/s  全局共享
BenchmarkThreadLocal/4t        22300444    37.5 ns/op     103× vs Global  无竞争
```

[完整性能报告](docs/prism/performance-report.md)

---

## 项目结构

```
Prism/
├── include/prism/
│   ├── agent/          # listener · balancer · worker · session
│   ├── recognition/    # probe · clienthello · handshake
│   ├── channel/        # reliable · encrypted · connection · eyeball
│   ├── crypto/         # AEAD · SHA224 · BLAKE3 · X25519 · HKDF · Base64
│   ├── memory/         # pool · arena · container (PMR)
│   ├── multiplex/      # smux · yamux · duct · parcel
│   ├── protocol/       # http · socks5 · trojan · vless · shadowsocks
│   ├── stealth/        # reality · shadowtls · restls · native
│   ├── resolve/        # router · recursor · cache · rules · resolver
│   └── fault/          # 错误码体系
├── src/                # 模块实现 + 入口
├── tests/              # 单元测试 (42个)
├── benchmarks/         # 性能测试
├── stresses/           # 压力测试
├── docs/               # 文档
└── scripts/            # 工具脚本
```

---

## 依赖

全部通过 CMake FetchContent 自动拉取，首次构建约 10 分钟。

| 库 | 版本 | 用途 |
|:---|:----:|:-----|
| Boost.Asio | 1.89 | 协程异步 I/O |
| BoringSSL | — | TLS (OpenSSL API 兼容) |
| spdlog | 1.17 | 异步日志 |
| glaze | 6.5 | JSON 序列化 |
| BLAKE3 | 1.8 | SS2022 密钥派生 |
| Google Benchmark | 1.9.5 | 性能测试 |

---

## 开发路线

- [x] 五协议完整实现 (HTTP/SOCKS5/Trojan/VLESS/SS2022)
- [x] TLS 透明剥离 + 二次协议探测
- [x] Recognition 模块 (协议智能识别 + 伪装特征分析)
- [x] smux/yamux 多路复用
- [x] Happy Eyeballs (RFC 8305)
- [x] 7阶段 DNS 管道
- [x] 连接池 + 健康检查
- [x] 加权负载均衡 + 过载反压
- [x] Reality TLS 伪装
- [ ] ShadowTLS v3 / RestLS
- [ ] QUIC / Hysteria2
- [ ] smux v2
- [ ] WebSocket

---

## 文档

**新手教程**
[快速开始](docs/tutorial/getting-started.md) · [配置详解](docs/tutorial/configuration.md) · [部署指南](docs/tutorial/deployment.md) · [故障排查](docs/tutorial/troubleshooting.md) · [常见问题](docs/tutorial/faq.md)

**开发者文档**
[文档入口](docs/index.md) · [agent](docs/prism/agent.md) · [recognition](docs/prism/recognition.md) · [channel](docs/prism/channel.md) · [resolve](docs/prism/resolve.md) · [Trojan](docs/prism/protocol/trojan.md) · [VLESS](docs/prism/protocol/vless.md) · [smux](docs/prism/multiplex/smux.md) · [Reality](docs/prism/stealth/reality.md)

---

## 许可证

[MIT](LICENSE)