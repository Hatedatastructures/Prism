# Prism 性能基准测试

> 测试日期: 2026-05-01
> 测试平台: Intel Core i9-13900K (24核/32线程 @ 2995 MHz)
> 内存配置: DDR4 64GB
> 编译环境: MinGW GCC 13.1.0, C++23, Release (-O3)
> 完整日志: logs/forward.log

---

## 一、协议握手性能

协议握手延迟直接影响连接建立速度。SS2022 最快（纯内存操作），其他协议均需 TCP 往返。

### 握手延迟

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| HTTP握手 | 4480 | 170 us | 164 us | 6.10 k/s | |
| SOCKS5握手 | 4480 | 146 us | 146 us | 6.83 k/s | |
| Trojan握手 | 5600 | 131 us | 131 us | 7.63 k/s | |
| VLESS握手 | 5600 | 138 us | 140 us | 7.17 k/s | |
| SS2022握手 | 560000 | 1.35 us | 1.37 us | 731.4 k/s | 纯内存，无网络 |

### 握手流程对比

| 协议 | 流程分解 | 总耗时 | 往返次数 |
|:-----|:---------|:-------|:--------:|
| SS2022 | PSK Base64 解码 (142ns) → 密钥复制 (~1us) → 完成 | ~1.35 us | 0 |
| Trojan | TCP connect (~100us) → 认证发送 → 响应确认 → 完成 | ~131 us | 1 |
| VLESS | TCP connect (~100us) → UUID验证 (~18ns) → 完成 | ~138 us | 1 |
| SOCKS5 | TCP connect → 方法协商 → 连接请求 → 完成 | ~146 us | 2 |
| HTTP | TCP connect → CONNECT请求 → 200响应 → 完成 | ~170 us | 1 |

### 与竞品对比

| 实现名称 | 每次耗时 | 说明 |
|:---------|:--------:|:-----|
| Prism SS2022 | 1.35 us | 本测试 |
| shadowsocks-rust | 5-10 us | PSK 解析 + 密钥派生 |
| Prism Trojan | 131 us | 本测试 |
| trojan-gfw | 150-200 us | 社区反馈 |
| Prism VLESS | 138 us | 本测试 |
| Xray VLESS | 100-150 us | XTLS 文档 |

---

## 二、隧道吞吐量

### TCP 透传吞吐量

纯 TCP 零拷贝转发（无加密），测试大包场景的内存拷贝效率。

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| 隧道传输/16KB | 49778 | 21.8 us | 10.7 us | 2.86 Gi/s |
| 隧道传输/64KB | 56000 | 33.6 us | 19.8 us | 6.16 Gi/s |
| 隧道传输/128KB | 18667 | 49.5 us | 34.3 us | 7.11 Gi/s |

### 纯内存拷贝基准

用于对比 TCP 开销的理论极限。

| 测试项 | 运行次数 | 每次耗时 | 速率 |
|:-------|:--------:|:--------:|:----:|
| 内存拷贝/64B | 1238913581 | 0.75 ns | 157.5 Gi/s |
| 内存拷贝/1KB | 64000000 | 10.7 ns | 177.6 Gi/s |
| 内存拷贝/16KB | 7466667 | 111 ns | 275.2 Gi/s |
| 内存拷贝/64KB | 896000 | 959 ns | 127.3 Gi/s |
| 内存拷贝/128KB | 407273 | 1.88 us | 129.9 Gi/s |

**分析**: TCP 回环涉及内核上下文切换 + socket 缓冲区拷贝，小包场景系统开销占比极高 (>99%)。大包场景 TCP 吞吐达 7 Gi/s，接近内存带宽极限。

### 与竞品对比

| 实现名称 | 速率 | 说明 |
|:---------|:----:|:-----|
| Prism (TCP) | 7.11 Gi/s | 本地回环，128KB |
| WireGuard | ~4 Gi/s | 官方文档 |
| shadowsocks-rust | ~200-300 Mi/s | AES-NI 启用时 |
| Hysteria2 | ~500-800 Mi/s | 基于 QUIC，有加密开销 |

---

## 三、加密性能 (AEAD)

SS2022 是 Prism 中唯一在隧道期间持续加解密的协议。

### AES-GCM 连续吞吐量 (64KB payload)

| 测试项 | 运行次数 | 每次耗时 | 速率 |
|:-------|:--------:|:--------:|:----:|
| AES-128-GCM加密 | 2635 | 256 us | 245 Mi/s |
| AES-128-GCM解密 | 2800 | 258 us | 255 Mi/s |
| AES-256-GCM加密 | 2358 | 298 us | 225 Mi/s |
| AES-256-GCM解密 | 2358 | 307 us | 205 Mi/s |

**瓶颈**: AES-256-GCM 吞吐约 205 Mi/s，远低于 AES-NI 理论极限 (~2 Gi/s)。需确认 BoringSSL AES-NI 汇编优化启用状态。

### AES-256-GCM 加密多 Payload 大小

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| AEAD加密/16B | 746667 | 956 ns | 921 ns | 16.6 Mi/s |
| AEAD加密/64B | 640000 | 1011 ns | 1001 ns | 61.0 Mi/s |
| AEAD加密/256B | 497778 | 1959 ns | 1915 ns | 127.5 Mi/s |
| AEAD加密/1KB | 74667 | 8892 ns | 8161 ns | 119.7 Mi/s |
| AEAD加密/4KB | 22400 | 33324 ns | 32785 ns | 119.1 Mi/s |
| AEAD加密/16KB | 5600 | 275 us | 128 us | 121.7 Mi/s |
| AEAD加密/64KB | 1000 | 1054 us | 531 us | 117.6 Mi/s |

### AES-256-GCM 解密多 Payload 大小

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| AEAD解密/16B | 560000 | 2270 ns | 1200 ns | 12.7 Mi/s |
| AEAD解密/64B | 448000 | 1679 ns | 1430 ns | 42.7 Mi/s |
| AEAD解密/256B | 298667 | 3694 ns | 2616 ns | 93.3 Mi/s |
| AEAD解密/1KB | 112000 | 11825 ns | 8650 ns | 112.9 Mi/s |
| AEAD解密/4KB | 21333 | 38394 ns | 27100 ns | 144.1 Mi/s |
| AEAD解密/16KB | 5600 | 144 us | 109 us | 143.6 Mi/s |
| AEAD解密/64KB | 1000 | 624 us | 547 us | 114.3 Mi/s |

---

## 四、密钥交换 (X25519)

Reality 握手核心操作，直接影响 TLS 伪装连接建立延迟。

### X25519 操作性能

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 |
|:-------|:--------:|:--------:|:-------:|
| X25519密钥生成 | 21333 | 50704 ns | 43946 ns |
| X25519公钥派生 | 22400 | 33406 ns | 29994 ns |
| X25519密钥交换 | 11200 | 81482 ns | 53013 ns |

### Reality 握手分解

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| Reality完整握手 | 14452 | 47.6 us | 44.3 us | 22.6 k/s | |
| Reality仅X25519 | 15448 | 45.7 us | 44.5 us | 22.5 k/s | |
| Reality密钥生成 | 22400 | 52.9 us | 31.4 us | 31.9 k/s | |
| Reality公钥派生 | 49778 | 12.5 us | 12.6 us | 79.6 k/s | |
| Reality密钥交换 | 32000 | 21.8 us | 21.0 us | 47.6 k/s | 占45.8%，主要瓶颈 |
| Reality TLS Mock | 3446154 | 271 ns | 227 ns | 2.63 Gi/s | |
| Reality HKDF Ext | 1120000 | 665 ns | 628 ns | 1.59 M/s | |
| Reality HKDF Exp | 896000 | 676 ns | 663 ns | 1.51 M/s | |

---

## 五、密钥派生性能

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| BLAKE3密钥派生 | 2800000 | 269 ns | 212 ns | 144 Mi/s | SS2022 EK 派生 |
| HKDF Extract | 560000 | 1330 ns | 1116 ns | 27.3 Mi/s | TLS 1.3 extract |
| HKDF Expand | 497778 | 1490 ns | 1161 ns | 26.3 Mi/s | TLS 1.3 expand |
| HKDF ExpandLabel | 896000 | 1358 ns | 1081 ns | 14.1 Mi/s | TLS 1.3 label |
| Salt Pool重放检查 | 1000000 | 767 ns | 531 ns | 1.3 M/s | SS2022 重放保护 |

---

## 六、Hash 与编码性能

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| SHA224短消息 | 3200000 | 221 ns | 215 ns | 13.3 Mi/s | Trojan credential |
| SHA224长消息 | 248889 | 2760 ns | 2699 ns | 361.8 Mi/s | 大数据 hash |
| Base64解码短 | 20363636 | 33.6 ns | 33.8 ns | 226 Mi/s | PSK 解析 |
| Base64解码长 | 89600 | 6196 ns | 6104 ns | 218.8 Mi/s | 大数据解码 |
| Trojan Credential | 28000000 | 35.1 ns | 29.0 ns | 1.80 Gi/s | SHA224 hash |
| Trojan无效输入 | 154482759 | 4.66 ns | 3.94 ns | 13.2 Gi/s | 快速失败 |

---

## 七、内存分配性能

热路径零 `malloc` 是 Prism 核心设计目标。

### String 分配 (32B)

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| Frame Arena | 112000000 | 9.24 ns | 7.95 ns | 3.75 Gi/s | 最快 |
| ThreadLocal Pool | 37333333 | 17.7 ns | 17.6 ns | 1.70 Gi/s | 无竞争 |
| Global Pool | 5600000 | 119 ns | 117 ns | 260.4 Mi/s | 有竞争 |
| NewDelete | 23578947 | 27.9 ns | 27.8 ns | 1.07 Gi/s | |
| Std String | 32000000 | 21.5 ns | 21.5 ns | 1.39 Gi/s | |

### Vector 分配

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| Frame Arena | 112000000 | 5.70 ns | 5.44 ns | 10.96 Gi/s |
| ThreadLocal Pool | 40727273 | 17.5 ns | 17.6 ns | 3.38 Gi/s |
| Global Pool | 6400000 | 120 ns | 115 ns | 531.9 Mi/s |
| NewDelete | 20363636 | 25.7 ns | 24.6 ns | 2.43 Gi/s |

### 多线程竞争

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 说明 |
|:-------|:--------:|:--------:|:-------:|:-----|
| Global Pool 1线程 | 5600000 | 142 ns | 142 ns | baseline |
| Global Pool 2线程 | 746666 | 920 ns | 921 ns | 6.5× slower |
| Global Pool 4线程 | 256000 | 3767 ns | 3662 ns | 26.5× slower |
| Global Pool 8线程 | 44800 | 10422 ns | 11161 ns | 73× slower |
| ThreadLocal Pool4 | 22300444 | 37.5 ns | 36.4 ns | 103× faster vs Global |
| Global Pool 4线程 | 179200 | 3530 ns | 3052 ns | |

**关键发现**: ThreadLocal Pool 在 4 线程下比 Global Pool 快 103 倍，几乎无竞争开销。

### Frame Arena 批量分配

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 对象数/秒 |
|:-------|:--------:|:--------:|:-------:|:----:|:--------:|
| 批量/32×256B | 320000 | 2551 ns | 2246 ns | 3.40 Gi/s | 114 M/s |
| 批量/128×128B | 497778 | 1820 ns | 1444 ns | 10.57 Gi/s | 88.6 M/s |
| 批量/512×32B | 1000000 | 879 ns | 688 ns | 22.19 Gi/s | 46.5 M/s |
| Frame Arena重置 | 560000000 | 1.68 ns | 1.37 ns | 极快 | |

### 内存分配最佳实践

| 场景 | 推荐方案 | 耗时 | 特点 |
|:-----|:---------|:-----|:-----|
| 帧内临时对象 | Frame Arena | 6-11 ns | 无竞争，批量释放 |
| 跨帧持久对象 | ThreadLocal Pool | 17-75 ns | 多线程友好 |
| 全局共享数据 | Global Pool | ~120 ns | 需接受竞争开销 |
| 大块数据 (>64KB) | NewDelete | ~25 ns | 避免 pool fragmentation |

---

## 八、IO 与延迟分布

### TCP Echo 回环

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| TCP Echo 64B | 100000 | 20.1 us | 11.7 us | 10.4 Mi/s |
| TCP Echo 1KB | 89600 | 18.4 us | 9.24 us | 211.3 Mi/s |
| TCP Echo 16KB | 64000 | 21.7 us | 10.5 us | 2.91 Gi/s |
| TCP Echo 64KB | 32000 | 32.6 us | 20.5 us | 5.95 Gi/s |
| TCP Echo 128KB | 16000 | 65.3 us | 42.0 us | 5.81 Gi/s |

### 连接与隧道延迟分布

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 平均 | P50 | P90 | P99 |
|:-------|:--------:|:--------:|:-------:|:----:|:----:|:----:|:----:|
| 连接延迟 | 5600 | 135 us | 128 us | 110us | 95us | 141us | 336us |
| 隧道延迟/64B | 74667 | 18.7 us | 7.74 us | 18us | 17us | 18us | 47us |
| 隧道延迟/1KB | 64000 | 18.6 us | 10.0 us | 18us | 17us | 19us | 45us |
| 隧道延迟/16KB | 62916 | 22.5 us | 11.2 us | 22us | 20us | 22us | 64us |
| 隧道延迟/64KB | 29867 | 43.9 us | 22.0 us | 43us | 35us | 65us | 118us |
| 小包延迟 | 89600 | 20.5 us | 12.0 us | 20us | | | |
| 大包延迟 | 29867 | 32.9 us | 17.8 us | 32us | | | |

**P99 抖动**: 连接建立 P99 达 336 us (P50 的 3.5 倍)，可能由系统调度或内核缓冲区竞争导致。

---

## 九、多路复用性能

### Frame 序列化/反序列化

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| Smux Frame序列 | 7466666667 | 0.097 ns | 0.096 ns | 77.4 Gi/s | |
| Smux Frame反序列 | 746666667 | 0.951 ns | 0.900 ns | 8.28 Gi/s | 仅指针操作 |
| Yamux Frame序列 | 2986666667 | 0.221 ns | 0.204 ns | 54.8 Gi/s | |
| Yamux Frame反序列 | 746666667 | 0.943 ns | 0.921 ns | 12.1 Gi/s | |
| Smux序列/16KB | 2635294 | 325 ns | 308 ns | 49.5 Gi/s | |
| Smux反序列/16KB | 746666667 | 0.992 ns | 0.984 ns | 7.58 Gi/s | 仅指针操作 |
| Yamux序列/16KB | 2488889 | 302 ns | 295 ns | 51.8 Gi/s | |
| Yamux反序列/16KB | 746666667 | 2.18 ns | 1.40 ns | 7.97 Gi/s | |

### UDP Datagram 构建

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| Smux UDP/64B | 21333333 | 31.3 ns | 30.8 ns | 2.33 Gi/s |
| Smux UDP/512B | 14451613 | 48.9 ns | 48.7 ns | 10.05 Gi/s |
| Smux UDP/4KB | 8960000 | 86.9 ns | 87.2 ns | 43.9 Gi/s |
| Smux UDP/16KB | 2635294 | 262 ns | 261 ns | 58.5 Gi/s |

### 多流构建

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| Smux多流/4 | 407273 | 1.74 us | 1.69 us | 36.2 Gi/s |
| Smux多流/16 | 112000 | 6.77 us | 6.56 us | 37.3 Gi/s |
| Smux多流/64 | 32000 | 22.3 us | 21.5 us | 45.5 Gi/s |
| Yamux多流/4 | 448000 | 1.69 us | 1.64 us | 37.3 Gi/s |
| Yamux多流/16 | 100000 | 6.43 us | 6.41 us | 38.1 Gi/s |
| Yamux多流/64 | 37333 | 22.4 us | 22.2 us | 44.1 Gi/s |

---

## 十、协议解析性能

### HTTP Parser

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 |
|:-------|:--------:|:--------:|:-------:|:----:|
| HTTP解析GET | 5600000 | 139 ns | 131 ns | 2.54 Gi/s |
| HTTP解析CONNECT | 6400000 | 114 ns | 115 ns | 964 Mi/s |
| HTTP解析POST | 7466667 | 93.9 ns | 92.1 ns | 43.1 Gi/s |
| HTTP路径提取 | 203636364 | 3.40 ns | 3.30 ns | |

### 其他协议

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| Trojan验证 | 89600000 | 6.74 ns | 5.75 ns | | 验证 |
| Trojan UDP解析 | 11200000 | 57.4 ns | 54.4 ns | 192.8 Mi/s | UDP 解析 |
| Trojan UDP构建 | 4480000 | 172 ns | 174 ns | 21.9 Gi/s | UDP 构建 |
| SOCKS5 UDP解析 | 11200000 | 60.9 ns | 58.6 ns | 162.8 Mi/s | UDP 解析 |
| SOCKS5 UDP编码 | 112000000 | 8.56 ns | 7.81 ns | | UDP 编码 |
| SOCKS5响应构建 | 16592593 | 43.7 ns | 40.5 ns | | 响应构建 |
| VLESS IPv4解析 | 28000000 | 19.4 ns | 17.9 ns | 1.36 Gi/s | IPv4 解析 |
| VLESS Domain解析 | 497777778 | 1.67 ns | 1.44 ns | 20.0 Gi/s | 视图操作 |
| VLESS响应构建 | 7466666667 | 0.092 ns | 0.090 ns | 20.7 Gi/s | 响应构建 |
| SS PSK解析 | 4480000 | 142 ns | 140 ns | | PSK 解析 |

---

## 十一、DNS 与规则引擎

### DNS 操作

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 速率 | 说明 |
|:-------|:--------:|:--------:|:-------:|:----:|:-----|
| DNS查询构造 | 10000000 | 80.7 ns | 60.9 ns | | 查询构造 |
| DNS打包 | 4480000 | 130 ns | 129 ns | 473 Mi/s | 打包 |
| DNS解包 | 8960000 | 85.2 ns | 82.0 ns | 337 Mi/s | 解包 |
| DNS IP提取 | 10000000 | 54.8 ns | 53.1 ns | | IP 提取 |
| DNS最小TTL | 280000000 | 2.70 ns | 2.68 ns | | 最小 TTL |

### Domain Trie

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 说明 |
|:-------|:--------:|:--------:|:-------:|:-----|
| Domain Trie命中 | 4977778 | 145 ns | 144 ns | 精确命中 |
| Domain Trie通配符 | 3733333 | 187 ns | 188 ns | 通配符匹配 |
| Domain Trie未命中 | 4977778 | 134 ns | 129 ns | 未命中，快速失败 |
| Domain Trie大数据 | 4072727 | 170 ns | 173 ns | 10K 条目 |

### Rules Engine

| 测试项 | 运行次数 | 每次耗时 | CPU耗时 | 说明 |
|:-------|:--------:|:--------:|:-------:|:-----|
| 规则引擎匹配 | 2240000 | 349 ns | 342 ns | 规则匹配 |
| Credential Plain | 2986667 | 225 ns | 214 ns | Plain 验证 |
| Credential Hashed | 6400000 | 111 ns | 107 ns | Hashed 验证 |

---

## 十二、瓶颈分析与优化

### 当前瓶颈

| 模块名称 | 当前性能 | 理论极限 | 差距 | 原因 |
|:---------|:--------:|:--------:|:----:|:-----|
| AES-GCM 加密 | 205 Mi/s | AES-NI ~2G | 10× | AES-NI 未启用? |
| X25519密钥交换 | 81.5 us | 模拟 ~50us | 1.6× | BoringSSL 版本? |
| TCP 小包回环 | 20 us | 内存 0.1us | 200× | 系统开销 |

### 已验证优化

| 优化项 | 优化前 | 优化后 | 提升 |
|:-------|:------:|:------:|:----:|
| X25519 公钥派生 | ~35 us | 13.8 us | 60% |
| X25519 密钥交换 | ~35 us | 24.1 us | 31% |
| ThreadLocal vs Global | 3.77 us | 36.4 ns | 103× |

### 待优化项

| 模块名称 | 当前性能 | 目标性能 | 方案 |
|:---------|:--------:|:--------:|:-----|
| AES-256-GCM加密 | 225 Mi/s | 500+ Mi/s | 检查 AES-NI 启用 |
| AES-256-GCM解密 | 205 Mi/s | 500+ Mi/s | 同上 |
| Reality 握手 | 47.6 us | ~25 us | 预计算静态密钥 |
| 小包 TCP | 20 us | ~5 us | writev/coalesce |

---

## 十三、单线程吞吐能力

| 场景 | 瓶颈 | 速率 |
|:-----|:-----|:----:|
| SS2022 数据转发 | AEAD 加解密 | ~200 Mi/s |
| Reality 握手 | X25519 | ~22.6 k/s |
| 热路径内存分配 | FrameArena | ~6.4 Gi/s |
| 纯 TCP 透传 | MemoryCopy | ~7 Gi/s |

---

## 十四、测试方法

使用 Google Benchmark v1.8，输出格式说明：

| 字段 | 含义 |
|:-----|:-----|
| 运行次数 | 测试执行的总次数 |
| 每次耗时 | 从开始到结束的实际时间 |
| CPU耗时 | CPU 实际执行时间 |
| 速率 | 每秒处理的操作数或数据量 |

时间单位: `ns` = 纳秒, `us` = 微秒
速率单位: `k/s` = 千次/秒, `M/s` = 百万次/秒, `Mi/s` = MB/s, `Gi/s` = GB/s

运行命令：

```bash
cmake -B build_release -DCMAKE_BUILD_TYPE=Release -DPRISM_ENABLE_BENCHMARK=ON
cmake --build build_release --config Release

build_release/benchmarks/CodecBench.exe
build_release/benchmarks/CryptoBench.exe
build_release/benchmarks/IOBench.exe
build_release/benchmarks/LatencyBench.exe
build_release/benchmarks/MemoryBench.exe
build_release/benchmarks/MuxBench.exe
build_release/benchmarks/MuxConnBench.exe
build_release/benchmarks/ProtocolBench.exe
build_release/benchmarks/RealityBench.exe
build_release/benchmarks/ResourceBench.exe
build_release/benchmarks/ScaleBench.exe
build_release/benchmarks/SessionBench.exe
```

---

## 参考资源

- WireGuard Performance: https://www.wireguard.com/performance/
- Redis Benchmarks: https://redis.io/docs/latest/operate/oss_and_stack/management/optimization/benchmarks/
- TechEmpower Framework Benchmarks: https://tfb-status.techempower.com/
- Envoy Performance: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/performance
- Google Benchmark: https://github.com/google/benchmark

---

*报告生成: 2026-05-01*