# Preview Benchmark 基线

> 采集日期：2026-08-18 晚间
> 构建配置：`Release + PRISM_ENABLE_COVERAGE=ON`（MinGW，含 --coverage 插桩，性能略降）
> 用途：参考基线。ASAN/纯净 Release 重建后需重新采集对比。
> 机器：16 核（L1 48KiB×16 / L2 2MiB×16 / L3 36MiB）

## 2026-09-01 纯 Release 闭环采样

本节是 Preview migration local closure 的当前证据，不替代上面的历史 coverage
基线。采集窗口为 `2026-09-01 02:22:47` 至 `02:36:16 +08:00`，编译器为
`C:/msys64/ucrt64/bin/g++.exe`，CMake 配置为 `Release`、
`PRISM_ENABLE_BENCHMARK=ON`、`PRISM_ENABLE_STRESS=OFF`、coverage/ASAN 关闭，
使用现有 `build/`。运行环境输出为 32 logical CPUs @ 2995 MHz，L1D 48 KiB × 16、
L2 2 MiB × 16、L3 36 MiB × 1。

配置与构建命令：

```text
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DPRISM_ENABLE_BENCHMARK=ON -DPRISM_ENABLE_STRESS=OFF
cmake --build build --config Release --target PreviewCodecBench PreviewTransportBench PreviewRuntimeBench PreviewDnsBench CodecBench MuxBench ProtocolBench ResolveBench DnsMessageBench DnsCacheBench -j1
ctest --test-dir build -L perf -V -j1 --timeout 600
```

Preview perf CTest 共注册 `90` 项，实际运行 `65` 项全部通过，`25` 项因已有
`StealthNested2` 外部依赖门禁而 disabled，失败 `0`，退出码 `0`，总耗时 `15.01 s`。
Preview verbose raw 输出中的代表性值如下；带 `med` 的条目已经使用各自测试内的
三次运行中位数：

| Domain | Representative raw measurement |
|---|---|
| Codec | `vmess chunk Seal 16KB` 1336.36 ns/op；`ss2022 chunk Seal 16KB` 1462.34 ns/op |
| Transport | TCP raw 16KB: 2103.1 MB/s；TCP raw 256KB: 6816.2 MB/s |
| Runtime | `BM_AeadSeal16KB` 1004 ns；`BM_MemoryPoolAlloc` 23.9 ns |
| Mux | smux 1129.1 MB/s；yamux 1207.2 MB/s；h2mux 1178.3 MB/s |
| DNS | cache hit 126 ns/op；AnswerScan 52 ns/op；local UDP E2E 9521 QPS |

生产 Google Benchmark 使用 `--benchmark_min_time=0.05s`、
`--benchmark_repetitions=3`、`--benchmark_color=false`，同时输出 console 和 JSON。
JSON 中每个非 aggregate benchmark 都有 3 个 iteration，并生成 mean/median/stddev/cv
aggregate。代表性 `real_time` median（单位均为 ns）如下，完整值保存在对应 JSON：

| Executable | Benchmark | Median |
|---|---|---:|
| `CodecBench` | `BM_DnsPackMessage` | 145.38 |
| `CodecBench` | `BM_ShadowsocksDecodePsk` | 110.22 |
| `MuxBench` | `BM_SmuxBuildUdpDatagram_IPv4/512` | 51.68 |
| `ProtocolBench` | `BM_Socks5DecodeUdpHeader` | 12.97 |
| `ProtocolBench` | `BM_ShadowsocksParseAddressPort` | 8.11 |
| `ResolveBench` | `BM_Cache_Get_Hit100` | 77.92 |
| `DnsMessageBench` | `BM_DnsPackQuery` | 179.15 |
| `DnsCacheBench` | `BM_CacheGetHit` | 131.52 |

原始证据文件：`build/preview-perf-20260901-verbose.log`、
`build/preview-perf-20260901-rerun.log`，以及
`build/production-{CodecBench,MuxBench,ProtocolBench,ResolveBench,DnsMessageBench,DnsCacheBench}-20260901.{log,json}`。

### 比较边界与所有权影响

本次没有 production 与 Preview 之间“相同输入、相同协议实现边界、相同计量方式”
的可直接对拍 benchmark。Preview 的 domain perf 是本地 fake server 上的端到端传输、
手写计时或独立 Google Benchmark；production targets 是另一套编解码、cache 和
PMR/容器实现的微基准。因此本次没有合法的跨实现百分比，也没有声称“无性能回退”；
`>5%` 直接比较门禁在本批没有适用样本。上述数字用于记录可复现的当前量级和后续
同 harness 对比的锚点。

DNS OS resolver 为了跨挂起点保活，会复制规范化 name、executor 和 timeout；这引入
一次必要的 owned-string copy/allocation。`IdentityTraffic` 的已有 identity 路径只做
atomic snapshot load、查找和 `fetch_add`；首次 identity 才复制不可变表并分配 slot。
Mux writer 的完整写循环在底层 short write 时增加调用次数，但不允许牺牲帧完整性。

采样完成后已将同一 `build/` 恢复为正常的 `Release + PRISM_ENABLE_BENCHMARK=OFF +
PRISM_ENABLE_STRESS=OFF` 配置，并在恢复后重新构建功能 targets。

## Socks5FrameBench（帧编解码）

| Benchmark | Time | CPU |
|---|---|---|
| ParseHeader | 23.7 ns | 23.4 ns |
| DecodePort | 16.2 ns | 16.1 ns |
| EncodeHdr | 399 ns | 401 ns |
| DecodeHdr | 75.8 ns | 75.0 ns |
| ParsePwAuth | 24.4 ns | 24.0 ns |
| ParseIPv4 | 12.6 ns | 11.4 ns |
| ParseIPv6 | 9.95 ns | 9.84 ns |
| ParseDomain | 21.9 ns | 21.8 ns |
| UdpRoundtrip | 526 ns | 516 ns |

## RecognitionPipeBench（识别流水线）

| Benchmark | Time | CPU |
|---|---|---|
| BuildBitmap | 18.6 ns | 18.4 ns |
| HasFeature | 2.52 ns | 2.49 ns |
| TargetParse | 149 ns | 141 ns |
| TargetResolve | 216 ns | 207 ns |
| BitmapBatch | 44.1 ns | 43.0 ns |

## CodecBench（通用编解码/路由）

| Benchmark | Time | CPU | 吞吐 |
|---|---|---|---|
| Sha224Long | 1502 ns | 1507 ns | 648 Mi/s |
| Base64DecodeLong | 22325 ns | 22670 ns | 58.9 Mi/s |
| DomainTrieSearchHit | 1025 ns | 977 ns | — |
| DomainTrieSearchMiss | 960 ns | 942 ns | — |
| DomainTrie_LargeDataset/10000 | 1159 ns | 1144 ns | — |

## ProtocolBench（协议编解码）

| Benchmark | Time | CPU | 吞吐 |
|---|---|---|---|
| Socks5EncodeUdpHeader | 370 ns | 353 ns | — |
| Socks5DecodeUdpHeader | 80.0 ns | 80.2 ns | 118.9 Mi/s |
| VlessParseRequest_IPv4 | 80.1 ns | 80.2 ns | 309.1 Mi/s |
| VlessParseRequest_Domain | 85.5 ns | 85.8 ns | 344.6 Mi/s |
| VlessParseUdpPacket | 66.9 ns | 65.6 ns | — |
| VlessMakeResponse | 3.96 ns | 3.84 ns | 497.2 Mi/s |
| TrojanParseUdpPacket | 73.5 ns | 71.5 ns | 146.7 Mi/s |
| TrojanBuildUdpPacket/512 | 10516 ns | 10463 ns | 47.3 Mi/s |
| ShadowsocksParseAddressPort | 66.9 ns | 64.2 ns | 104.0 Mi/s |

## MuxBench（多路复用帧）

| Benchmark | Time | CPU | 吞吐 |
|---|---|---|---|
| SmuxFrameSerialization | 14.1 ns | 13.8 ns | 552.4 Mi/s |
| SmuxFrameDeserialization | 26.7 ns | 26.7 ns | 285.9 Mi/s |
| YamuxFrameSerialization | 15.8 ns | 15.3 ns | 745.7 Mi/s |
| YamuxFrameDeserialization | 35.0 ns | 34.5 ns | 331.4 Mi/s |
| SmuxBuildUdpDatagram_IPv4/512 | 6388 ns | 6417 ns | 78.0 Mi/s |

## LatencyBench（链路延迟）

| Benchmark | Time | CPU | 说明 |
|---|---|---|---|
| ConnectionLatency | 139 us | 138 us | p50=111us p99=234us |
| TunnelLatency/64 | 17.4 us | 8.93 us | 13.7 Mi/s |
| TunnelLatency/16384 | 23.1 us | 13.5 us | 2.26 Gi/s |
| TunnelLatency/65536 | 37.8 us | 25.5 us | 4.79 Gi/s |
| SmallPacketLatency | 19.3 us | 10.3 us | 11.8 Mi/s |
| LargePacketLatency | 36.3 us | 18.1 us | 6.76 Gi/s |

## 结论与注意

- 帧编解码/识别均在 ns 级，Tunnel 双向吞吐在 GiB/s 量级，架构无明显热点。
- 本基线下 coverage 插桩生效（debug 警告），数值比纯净 Release 略差；下次用无插桩 Release 重采一组作为正式基线。
- 与生产栈对标（perfcmp）已有历史记录（git log e755ce0），本次为 preview 库独立基线。
