# Preview Benchmark 基线

> 采集日期：2026-08-18 晚间
> 构建配置：`Release + PRISM_ENABLE_COVERAGE=ON`（MinGW，含 --coverage 插桩，性能略降）
> 用途：参考基线。ASAN/纯净 Release 重建后需重新采集对比。
> 机器：16 核（L1 48KiB×16 / L2 2MiB×16 / L3 36MiB）

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
