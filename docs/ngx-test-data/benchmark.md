# Preview Benchmark 基线

> Gate D 状态（2026-09-07）：同一 harness 的 Preview/生产对拍尚未完成；本文件中的
> 独立数字不构成跨实现性能结论。可比较场景采用 `<=5%` 噪声、`5%-10%` 复核、
> `>10%` 阻止迁移的分级规则，待统一 runner 产出原始 JSON 后生效。

> 当前门禁证据（2026-09-11）：Release 全量构建 exit `0`；CTest `3982` 注册、
> deterministic/interop 之外的功能集合 `3855/3855` 通过、`25` Disabled；perf/stress 串行
> 实际运行 `94/94`，PerformanceContract `4/4`；`Perf_Recognition` `886.94s`，
> perf/stress 标签总墙钟 `905.22s`。这仍是 Preview
> 独立识别基线，不是 Preview 与生产 Prism 的百分比对拍。

本轮已增加唯一的 `tests/Contract/PerformanceContract.cpp` target。它使用相同的
payload、100 次预热、10000 次迭代和 3 次重复，输出生产/Preview 的 VLESS、SS2022
和 SOCKS5 codec 样本到 `PRISM_PERF_OUTPUT` 指定的路径（当前本地 artifact 为
`build/perf-contract-results.json`）；每条
记录包含 `sample_count`、median/p95/p99、MAD 和 CPU 时间字段。它仍是可复现的
 codec 级 Contract 证据，并额外包含固定 16 KiB payload 的 `transport.mock_write` 和
 `transport.tcp_loopback`，以及固定 1200 字节 datagram 的 `transport.udp_loopback`
  production/Preview 样本；TCP 记录额外输出 `bytes_per_second`，UDP 记录
  `packets_per_second`，两者均由同一批量样本的 median wall time 推导。TCP 场景经过
  本机 accept/connect、reliable wrapper、固定 warmup/iterations 和发送端 shutdown；
  UDP 场景经过本机双 socket、固定端点、逐报文校验和固定 warmup/iterations。Contract
  顶层 environment 现在额外记录进程 `peak_working_set_bytes`；这些 loopback 指标仍不
  等同于代理协议握手、外网吞吐或独立进程 RSS 对拍，真实网络/RSS harness 仍列为 Gate D 缺口。
  JSON schema 当前为 `prism.perf-contract.v2`；每份 JSON 顶层还记录 `environment.os`、
 `environment.compiler`、`environment.compiler_version`、`environment.pointer_bits`、
 `environment.hardware_threads` 和 `environment.peak_working_set_bytes`，用于 Windows/Linux
 结果复现和环境差异审查；每条
 指标同时保存 `samples_ns` 与 `cpu_samples_ns` 原始数组，聚合字段可由机器重新计算；
  顶层 `comparisons` 按 production/preview 配对输出 median/p95 相对变化，并按
  `noise`（不超过 5%）、`review`（5%-10%）和 `block`（超过 10%）分类。

外部互操作结果 JSON 现在也记录每个实际执行用例的 `wall_time_ms`、
`peak_working_set_bytes` 和 `metrics_available`；这提供进程级的启动/echo/RSS 证据，
并明确区分 blocked/not-run 与真实采样，但还不等同于统一的
代理握手延迟、持续吞吐、UDP pps 或多连接峰值 RSS harness。

2026-09-11 当前复核补充：普通确定性功能测试以 `-j8` 运行，`3855/3855` 通过；
性能和压力测试保持 `-j1`，`Perf_Recognition` `741.10s` 通过，其余 `97/97` 通过。
`Perf_MultiConnLinear` 初次暴露的段错误来自性能测试自身的 coroutine lambda 引用
捕获生命周期，改为命名协程后单项连续 3 次通过。生产 GoCompat 仍单独串行执行，
当前 `1/4` 通过，失败项属于生产识别/handler 前置，不作为 Preview 性能基线或外部
矩阵 PASS 计数。

随后对 Preview SOCKS5 IPv4 地址文本化移除了热路径 `snprintf`，改用 `to_chars`；
协议 focused 回归 `51/51` 通过，Contract 连续三轮 `4/4` 通过。最终
`socks5.parse_addr_port` median `+339.47%`/p95 `+321.49%` 仍为 `block`。
随后 SS2022 SessionKey 去除 Psk+Salt 中间 material 分配，focused SS2022 `34/34`
通过；最终 `ss2022.session_key` median `+12.86%`、p95 `+5.61%`，仍因 median
超过 10% 保持 `block`。这些优化不能被写成迁移门禁已解除；最终 Contract JSON 仍以
`build/perf-contract-results.json` 为准。

## 2026-09-05 Recognition 基线

`tests/preview/perf/RecognitionPerf.cpp` 是 Preview 识别策略的独立基线，不与
生产实现做百分比对拍。默认参数为 `1000` 次 warmup、`7` 个 sample、每个 sample
`10000` 次实际识别；随机 wire/profile 构造在计时外，分配由 executable-level
new/delete 计数器采集。Deterministic 的单候选兼容入口遵守 Profile 的单候选约束，
DeterministicRoute
固定测量两个候选，MixedTrial 测量候选数 `2/4/8`；确定性场景使用互不重叠的首字节，
MixedTrial 保留同样的候选规模；HTTP 与 VLESS 各有一组场景。

最终命令：

```text
ctest --test-dir build -L perf -R "^Perf_Recognition$" --output-on-failure -j 1 --timeout 1800
```

结果：`1/1` 通过；RecognitionPerf 的 CTest 专用 timeout 为 `1800s`，用于覆盖
不同机器负载下的长基线运行；2026-09-11 当前主机最新完整 perf/stress 运行在
`957.67s` 墙钟内通过，其中该场景耗时 `936.62s`。这些独立 Preview 数字只用于
记录环境和负载变化，不构成 Preview 与生产实现的百分比结论。每行 JSON 包含 `mode`、
`protocol`、`wire_size`、
`candidate_count`、`winner_index`、`trial_count`、`read_calls`、
`allocation_count`、`allocation_bytes`、`median_ns`、`p95_ns`、`p99_ns`、
`mad_ns` 和 `failures`。快速调试可用环境变量覆盖计数，但正式门禁使用上述默认值。

2026-09-08 ShadowTLS v3 标准首包/relay 增量后，正式默认运行仍为 `1/1`，历史 `Perf_Recognition` 耗时
`629.91s`；当前主机最新运行耗时 `1499.67s`。Deterministic 单候选兼容入口保持单候选，`DeterministicRoute` 使用双候选唯一首字节，
`MixedTrial` 使用 `2/4/8` 候选；2026-09-08 那次历史全量 CTest 墙钟为 `762.50s`，当前主机最新墙钟见上文。

2026-09-09：TLS ClientHello 识别改为直接读取稳定 `ProbeSnapshot` 的字节视图，去掉
`ReadClientHello`、Configured TLS 边界探测和 carrier candidate 解析中的临时字节复制；
wire、回注和认证语义不变，focused recognition `103/103` 及全量 CTest 均通过。

2026-09-10：legacy Pipeline 的取消/超时控制统一接入连接级 `ProbeBuffer`，并新增
`ReadSome` 窗口读取原语，避免控制修复将首包探测退化为逐字节读取；legacy 预取消、
partial-prefix 回放和窗口大小均有回归；协议认证标记和账户租约传递也已纳入 Session/Adapter
回归，认知 focused 与全量 CTest 均通过。

`Perf_VmessMultiThread` 运行在多线程 `io_context` 上，但每个 VMess 连接固定到独立
`strand`，并等待 server coroutine 退出；这样不会跨线程访问会话级非同步内存池。该目标
的 20 次重复回归全部通过，单次约 `5.6-5.9s`。

该基线只说明 Preview 识别路径的当前量级；它没有提供 Preview 与 psm 的同网络
payload、连接关闭和环境指纹对拍，因此不能用于迁移百分比或生产性能结论。

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
ctest --test-dir build -L perf -V -j1 --timeout 1800
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
