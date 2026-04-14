# 性能基准文档

本文档说明 Prism 的基准测试和压力测试框架，包括测试场景说明和结果解读。

---

## 性能指标目标

| 指标 | 目标值 |
|------|--------|
| 代理转发延迟 | < 5ms（本地端到端） |
| 单核吞吐量 | > 10Gbps |
| 每连接内存占用 | < 8KB（PMR 策略下） |

---

## 构建与运行

```bash
# 默认启用基准和压力测试
cmake -B build_release -DCMAKE_BUILD_TYPE=Release
cmake --build build_release --config Release

# 禁用（减少编译时间）
cmake -B build_release -DCMAKE_BUILD_TYPE=Release \
    -DPRISM_ENABLE_BENCHMARK=OFF -DPRISM_ENABLE_STRESS=OFF
```

Google Benchmark 通过 FetchContent 自动拉取 v1.9.5。

### 运行基准测试

```bash
build_release/benchmarks/codec_bench.exe    # HTTP/SOCKS5/Trojan/VLESS/Shadowsocks/DNS/加密/协议分析
build_release/benchmarks/crypto_bench.exe   # AEAD seal/open、BLAKE3、Salt Pool
build_release/benchmarks/memory_bench.exe   # std vs PMR 多资源对比
build_release/benchmarks/mux_bench.exe      # smux/yamux 帧编解码、UDP 数据报
```

### 运行压力测试

```bash
build_release/stresses/memory_stress.exe         # 多线程内存分配
build_release/stresses/pool_contention_stress.exe # 内存池锁竞争
build_release/stresses/arena_overflow_stress.exe  # Frame Arena 重置延迟
build_release/stresses/mux_stress.exe             # 多路复用协议
```

### 常用 Google Benchmark 参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `--benchmark_filter=<regex>` | 筛选测试项 | `--benchmark_filter=BM_Http.*` |
| `--benchmark_format=<fmt>` | 输出格式：`console`/`json`/`csv` | `--benchmark_format=json` |
| `--benchmark_out=<file>` | 结果输出到文件 | `--benchmark_out=result.json` |
| `--benchmark_repetitions=<N>` | 重复次数 | `--benchmark_repetitions=3` |
| `--benchmark_min_time=<T>` | 每项最小运行时间（秒） | `--benchmark_min_time=5.0` |

---

## 基准测试场景说明

### CodecBench -- 编解码基准

源码：`benchmarks/CodecBench.cpp`

#### HTTP 协议解析

| 测试项 | 说明 | 参数化 |
|--------|------|--------|
| `BM_HttpParseProxyRequest_Get` | GET 请求解析 | -- |
| `BM_HttpParseProxyRequest_Connect` | CONNECT 隧道请求解析（含 Proxy-Authorization） | -- |
| `BM_HttpParseProxyRequest_PostBody` | POST 请求解析（含 body） | body：0/32/128/512/4096 字节 |
| `BM_HttpExtractRelativePath` | URL 相对路径提取 | -- |

#### SOCKS5 协议解析

| 测试项 | 说明 | 参数化 |
|--------|------|--------|
| `BM_Socks5DecodeHeader` | 4 字节请求头解析 | -- |
| `BM_Socks5DecodeIPv4` | IPv4 地址解析 | -- |
| `BM_Socks5DecodeDomain` | 域名地址解析（11 字节） | -- |
| `BM_Socks5DecodeIPv6` | IPv6 地址解析（16 字节） | -- |
| `BM_Socks5DecodeDomain_VarLen` | 域名地址解析（变长） | 域名长度：4/16/64/255 |
| `BM_Socks5DecodePort` | 端口解码 | -- |

#### Trojan 协议解析

| 测试项 | 说明 | 参数化 |
|--------|------|--------|
| `BM_TrojanDecodeCredential` | 56 字节 SHA224 凭据解析 | -- |
| `BM_TrojanDecodeCredential_Invalid` | 无效凭据快速失败 | -- |
| `BM_TrojanDecodeCrlf` | CRLF 分隔符解析 | -- |
| `BM_TrojanDecodeCmdAtyp` | 命令 + 地址类型 | -- |
| `BM_TrojanDecodeIPv4` | IPv4 地址解析 | -- |
| `BM_TrojanDecodeIPv6` | IPv6 地址解析 | -- |
| `BM_TrojanDecodeDomain_VarLen` | 域名地址解析（变长） | 域名长度：4/16/64/255 |
| `BM_TrojanDecodePort` | 端口解码 | -- |

#### VLESS / Shadowsocks 2022

| 测试项 | 说明 |
|--------|------|
| `BM_VlessParseRequest` | VLESS 请求头（版本 + UUID + 命令 + IPv4，26 字节） |
| `BM_ShadowsocksParseAddressPort` | SS2022 地址端口（IPv4，7 字节） |
| `BM_ShadowsocksDecodePsk` | Base64 PSK 解码 |

#### DNS 报文

| 测试项 | 说明 |
|--------|------|
| `BM_DnsMakeQuery` | 构造 DNS 查询消息 |
| `BM_DnsPackMessage` | DNS 消息序列化 |
| `BM_DnsUnpackMessage` | DNS 消息反序列化 |
| `BM_DnsExtractIps` | 提取 IP 地址列表 |
| `BM_DnsMinTtl` | 计算最低 TTL |

#### 密码学工具

| 测试项 | 说明 |
|--------|------|
| `BM_Sha224Short` / `BM_Sha224Long` | SHA-224（3 字节 / 1KB 输入） |
| `BM_Base64DecodeShort` / `BM_Base64DecodeLong` | Base64 解码（8 字节 / ~1KB） |
| `BM_NormalizeCredential_Plain` | 明文密码转 SHA224 |
| `BM_NormalizeCredential_Hashed` | 已哈希凭据直接使用 |

#### 协议分析引擎

| 测试项 | 说明 |
|--------|------|
| `BM_AnalysisResolveIPv4` / `BM_AnalysisResolveIPv6` | 地址:端口解析 |
| `BM_AnalysisDetectInnerHttp` | TLS 内层 HTTP 探测 |
| `BM_AnalysisDetectInnerTrojan` | TLS 内层 Trojan 探测 |
| `BM_AnalysisDetectInnerUndetermined` | TLS 内层未确定协议探测 |

#### DNS 规则引擎

| 测试项 | 说明 |
|--------|------|
| `BM_DomainTrieSearchHit` / `Wildcard` / `Miss` | 域名字典树匹配 |
| `BM_RulesEngineMatch` | 规则引擎综合匹配 |

---

### CryptoBench -- 加密基准

源码：`benchmarks/CryptoBench.cpp`

#### AEAD 加解密（1024 字节明文，BoringSSL EVP_AEAD）

| 测试项 | 说明 |
|--------|------|
| `BM_AeadSealAes128Gcm` / `BM_AeadOpenAes128Gcm` | AES-128-GCM 加密/解密 |
| `BM_AeadSealAes256Gcm` / `BM_AeadOpenAes256Gcm` | AES-256-GCM 加密/解密 |

> `Open` 操作每次迭代重新构造 `aead_context`，测量包含密钥调度的完整开销。

#### BLAKE3 / Salt Pool

| 测试项 | 说明 |
|--------|------|
| `BM_Blake3DeriveKey` | 32 字节密钥派生子密钥（SS2022 场景） |
| `BM_SaltPoolCheckAndInsert` | 随机 16 字节 salt 重放检查（容量 3600） |

---

### MemoryBench -- 内存分配基准

源码：`benchmarks/MemoryBench.cpp`

#### 基线

| 测试项 | 说明 |
|--------|------|
| `BM_EmptyLoop` | 空循环基线（框架开销） |
| `BM_PauseResumeOnly` | 计时器暂停/恢复开销 |

#### 字符串分配对比（参数化：0/8/32/128/512/4096 字节）

| 测试项 | 说明 |
|--------|------|
| `BM_StdStringAssign_Size` | `std::string` 赋值 |
| `BM_PmrStringAssign_DefaultResource_Size` | PMR + 全局池默认资源 |
| `BM_PmrStringAssign_NewDeleteResource_Size` | PMR + `new_delete_resource`（基准参照） |
| `BM_PmrStringAssign_GlobalPool_Size` | PMR + 全局池 |
| `BM_PmrStringAssign_ThreadLocalPool_Size` | PMR + 线程局部池 |
| `BM_PmrStringAssign_FrameArena_Size` | PMR + 帧竞技场 |

**关键对比**：`BM_PmrStringAssign_FrameArena_Size` vs `BM_StdStringAssign_Size`，帧竞技场应有数量级优势。

#### 向量分配对比（参数化：8/64/256/4096 个 uint64_t）

| 测试项 | 说明 |
|--------|------|
| `BM_StdVectorPush` | `std::vector` |
| `BM_PmrVectorPush_FrameArena` | PMR vector + 帧竞技场 |

#### 帧竞技场操作

| 测试项 | 说明 |
|--------|------|
| `BM_FrameArenaResetOnly` | 纯 reset 开销 |

---

### MuxBench -- 多路复用基准

源码：`benchmarks/MuxBench.cpp`

#### smux 帧头 / 地址解析

| 测试项 | 说明 | 参数化 |
|--------|------|--------|
| `BM_SmuxFrameDeserialize_PSH/SYN/FIN/NOP` | 帧头解析（8 字节） | -- |
| `BM_SmuxParseMuxAddress_IPv4` | IPv4（9 字节） | -- |
| `BM_SmuxParseMuxAddress_Domain` | 域名（"example.com"） | -- |
| `BM_SmuxParseMuxAddress_Domain_VarLen` | 变长域名 | 4/16/64/255 |

#### smux UDP 数据报

| 测试项 | 参数化 |
|--------|--------|
| `BM_SmuxParseUdpDatagram_IPv4` | -- |
| `BM_SmuxParseUdpLengthPrefixed` | -- |
| `BM_SmuxBuildUdpDatagram_IPv4` / `_Domain` | payload：0/64/512/4096 |
| `BM_SmuxBuildUdpLengthPrefixed` | payload：0/64/512/4096 |

#### yamux 帧操作

| 测试项 | 说明 |
|--------|------|
| `BM_YamuxBuildHeader` / `ParseHeader` | 帧头构建/解析（12 字节） |
| `BM_YamuxBuildWindowUpdateFrame` | 窗口更新帧 |
| `BM_YamuxBuildPingFrame` | Ping 帧 |
| `BM_YamuxBuildGoAwayFrame` | GoAway 帧 |

#### 跨协议帧解码对比

| 测试项 | 参数化 |
|--------|--------|
| `BM_MuxFrameDecode_Smux`（8 字节头） | payload：0/128/512/4096/65535 |
| `BM_MuxFrameDecode_Yamux`（12 字节头） | payload：0/128/512/4096/65535 |

---

## 压力测试说明

独立于 Google Benchmark 的多线程压力测试，验证极端条件下的稳定性。

### MemoryStress -- 多线程内存分配

源码：`stresses/MemoryStress.cpp`

| 参数 | 默认值 |
|------|--------|
| 线程数 | 4 |
| 持续时间 | 10 秒 |
| 最大内存 | 2 GB |
| 分配批次 | 1000 |
| 对象大小 | 64 - 65536 字节 |

每线程使用独立的 `thread_local_pool()` + `counting_resource` 统计，循环分配随机大小 `memory::string`，内存接近上限时自动收缩。

### PoolContentionStress -- 内存池锁竞争

源码：`stresses/PoolContentionStress.cpp`

| 参数 | 默认值 |
|------|--------|
| 线程数 | 4 |
| 持续时间 | 10 秒 |
| 分配大小 | 128 字节 |

所有线程共享 `global_pool()` 制造最大竞争，每轮 1000 次分配-赋值-释放。

### ArenaOverflowStress -- Frame Arena 重置延迟

源码：`stresses/ArenaOverflowStress.cpp`

| 参数 | 默认值 |
|------|--------|
| 迭代数 | 50000 |
| 每批分配数 | 128 |
| 对象大小 | 256 字节 |

每次迭代：`arena.reset()` -> 分配 N 个 `memory::string` -> 记录延迟 min/max/avg。

### MuxStress -- 多路复用协议

源码：`stresses/MuxStress.cpp`

| 参数 | 默认值 |
|------|--------|
| 线程数 | 4 |
| 持续时间 | 5 秒 |
| 单线程迭代 | 1000000 |
| 最大 payload | 4096 字节 |

| 场景 | 说明 |
|------|------|
| 帧解码风暴 | 单线程 100 万轮混合 smux/yamux 帧解码 |
| 并发编解码 | 多线程同时帧解码、地址解析、UDP 构建 |
| 地址解析覆盖 | IPv4/域名/长域名/IPv6 全类型验证 |
| UDP 数据报往返 | 构建 -> 解析 -> 比对，验证完整性 |

### 共享工具

所有压力测试使用 `psm::stress::counting_resource`（`stresses/CountingResource.hpp`）统计分配/释放次数、总字节数、峰值内存。

---

## 如何解读结果

### 基准测试输出

```
Benchmark                                    Time             CPU   Iterations
------------------------------------------------------------------------------
BM_HttpParseProxyRequest_Get              1204 ns         1204 ns       563422
BM_Socks5DecodeHeader                       12 ns           12 ns     56000000  329.022MB/s
```

| 列名 | 含义 |
|------|------|
| `Time` | 单次迭代实际耗时 |
| `CPU` | 单次迭代 CPU 时间 |
| `Iterations` | 最小时间窗口内迭代数 |
| `B/s` | 字节吞吐率 |
| `items/s` | 操作吞吐率 |

### 关键对比项

- `BM_StdStringAssign_Size` vs `BM_PmrStringAssign_FrameArena_Size`：PMR 帧竞技场优势
- `BM_AeadSealAes128Gcm` vs `BM_AeadSealAes256Gcm`：AES-128 与 AES-256 差异
- `BM_MuxFrameDecode_Smux` vs `BM_MuxFrameDecode_Yamux`：两种多路复用帧解码对比

### 压力测试关注点

| 指标 | 期望 |
|------|------|
| OOM 错误 | 无 |
| 错误数（MuxStress） | 0 |
| 吞吐量 | 纳秒级分配延迟，无突增 |

---

## 版本对比

```bash
# 导出 JSON 结果
build_release/benchmarks/codec_bench.exe --benchmark_format=json --benchmark_out=codec_vA.json

# 使用 compare.py 对比（位于 Google Benchmark 源码 tools/ 目录）
python3 compare.py benchmarks codec_vA.json codec_vB.json
```

对比时确保：硬件环境一致、使用 Release 构建、多次运行取中位数。

---

## 性能调优建议

以下按场景分类，详细参数说明参考 [配置详解](../tutorial/configuration.md)。

| 场景 | 关键参数 | 建议值 |
|------|----------|--------|
| 高并发短连接 | `pool.max_cache_per_endpoint` | 64-128 |
| | `pool.max_idle_seconds` | 60-120 |
| | `mux.buffer_size` | 32KB |
| 大文件下载 | `pool.recv/send_buffer_size` | 128KB-256KB |
| | `mux.buffer_size` | 64KB-128KB |
| | `mux.max_streams` | 64-128 |
| 低延迟敏感 | `pool.connect_timeout_ms` | 500-1000 |
| | `dns.timeout_ms` | 1000 |
| | `pool.tcp_nodelay` | true |
| 内存受限 | `pool.max_cache_per_endpoint` | 8-16 |
| | `mux.buffer_size` | 16KB-32KB |
| | `dns.cache_size` | 1000-2000 |
