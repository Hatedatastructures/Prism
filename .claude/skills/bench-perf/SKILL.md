---
name: bench-perf
description: 编写或修改性能基准测试、分析 benchmark 结果、优化热路径性能时触发。
---

# Skill: 性能基准

## 触发条件

编写 benchmark、分析性能回归、优化热路径、添加性能回归测试时。

## 基准测试框架

### Google Benchmark 模式

```
函数签名:  static void BM_Xxx(benchmark::State& state)
注册宏:    BENCHMARK(BM_Xxx)
入口宏:    BENCHMARK_MAIN()
参数化:    ->Arg(100)->Arg(1000)->Arg(10000)
防优化:    benchmark::DoNotOptimize(var)
字节统计:  state.SetBytesProcessed(iterations * bytes)
跳过错误:  state.SkipWithError("msg")
```

### 编译与运行

```bash
# 编译（需开启选项）
cmake -B build -DPRISM_ENABLE_BENCHMARK=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j 16

# 运行单个 benchmark
build/benchmarks/XxxBench.exe

# 运行并输出 JSON
build/benchmarks/XxxBench.exe --benchmark_format=json
```

### RegressionBench（无 Google Benchmark 依赖）

使用内部计时器，不链接 `benchmark::benchmark`。适合不需要框架基础设施的简单回归检测。

## Benchmark 文件索引

| 文件 | 测试子系统 |
|------|-----------|
| CodecBench | HTTP 解析、Trojan 凭证、DNS 报文、SHA224、Base64 |
| CryptoBench | 加密操作 |
| IOBench | I/O 吞吐量 |
| LatencyBench | 延迟测量 |
| MemoryBench | 内存分配性能 |
| MuxBench | Mux 连接吞吐（smux/yamux） |
| MuxConnBench | Mux 连接建立 |
| ProtocolBench | 协议级性能 |
| RealityBench | Reality TLS 握手 |
| RegressionBench | 回归检测（内部计时） |
| ResourceBench | 资源使用 |
| ScaleBench | 规模测试 |
| SessionBench | 会话性能 |

## 典型模式

### 计算密集型 benchmark

```cpp
static void BM_HttpParse(benchmark::State& state)
{
    proxy_request req;
    for (auto _ : state)
    {
        fault::code ec = parse_req(input, req);
        if (fault::failed(ec)) state.SkipWithError("parse failed");
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(state.iterations() * input.size());
}
BENCHMARK(BM_HttpParse);
```

### I/O 吞吐型 benchmark

使用 loopback `pipe_pair` 构造真实链路:
```cpp
struct pipe_pair
{
    net::io_context& io;
    net::ip::tcp::socket client;
    net::ip::tcp::socket server;
    pipe_pair(net::io_context& ioc)
    {
        // loopback accept + connect
    }
};
```

手动构造帧头，测量完整 round-trip 吞吐。

### 参数化 benchmark

```cpp
static void BM_Alloc(benchmark::State& state)
{
    for (auto _ : state)
    {
        // 使用 state.range(0) 作为分配大小
    }
}
BENCHMARK(BM_Alloc)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096);
```

## 编写规则

1. **Release 模式** — 必须在 `-O2` 以上编译运行，Debug 模式结果无意义
2. **防优化消除** — 热路径输出必须用 `DoNotOptimize`，否则编译器可能消除整个循环
3. **真实链路** — I/O benchmark 用 loopback pipe_pair，不用 MockTransport
4. **参数化** — 大对象、可变长度输入用 `state.range(0)` 参数化
5. **聚焦** — 每个 benchmark 文件聚焦单一子系统
6. **PMR 区分** — 内存分配 benchmark 必须区分 PMR 池分配 vs 系统 malloc 路径

## 分析模式

- **基线对比**: `XxxBench.exe --benchmark_format=json > baseline.json`，与历史对比
- **回归检测**: `RegressionBench` 使用内部计时（无 Google Benchmark 依赖）
- **瓶颈定位**: 先跑全量 bench → 定位慢路径 → 单点优化 → 再跑验证

## 压力测试

`PRISM_ENABLE_STRESS=ON` 编译后运行 `build/stresses/MuxStress.exe`。压力测试验证高并发下稳定性，非性能测量。
