/**
 * @file H2MuxBench.cpp
 * @brief h2mux 帧处理热路径基准测试
 * @details 测量 h2mux 多路复用中的关键数据结构操作性能：
 *          待处理流映射增删查、HTTP/2 头部字段匹配、
 *          h2_headers 结构体填充、nghttp2 会话生命周期。
 *          这些操作在每个流的建立和数据传输阶段被频繁调用。
 */

#include <benchmark/benchmark.h>
#include <prism/proto/multiplex/h2mux/craft.hpp>
#include <prism/foundation/memory/container.hpp>
#include <nghttp2/nghttp2.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace
{

using namespace psm::multiplex::h2mux;
namespace mem = psm::memory;

// ============================================================
// 测试辅助
// ============================================================

/// 创建预填充的待处理流映射
auto make_pending_map(std::size_t n)
    -> mem::unordered_map<std::uint32_t, h2_pending_entry>
{
    mem::unordered_map<std::uint32_t, h2_pending_entry> map;
    for (std::size_t i = 1; i <= n; ++i)
    {
        auto &entry = map[static_cast<std::uint32_t>(i)];
        entry.headers.stream_id = static_cast<std::int32_t>(i);
        entry.connecting = false;
    }
    return map;
}

/// 模拟 on_header 中的头部字段匹配逻辑（与 craft.cpp 热路径一致）
auto match_header(std::string_view name) -> int
{
    if (name == ":authority") return 0;
    if (name == "host" || name == "Host") return 1;
    if (name == "user-agent") return 2;
    if (name == "proxy-authorization") return 3;
    return -1;
}

/// 预构建的测试映射
const auto pending_10 = make_pending_map(10);
const auto pending_100 = make_pending_map(100);

// ============================================================
// h2_pending 映射操作基准测试
// ============================================================

void BM_H2_PendingMap_Insert(benchmark::State &state)
{
    const auto n = static_cast<std::size_t>(state.range(0));
    for (auto _ : state)
    {
        state.PauseTiming();
        mem::unordered_map<std::uint32_t, h2_pending_entry> map;
        state.ResumeTiming();

        for (std::size_t i = 1; i <= n; ++i)
        {
            auto &entry = map[static_cast<std::uint32_t>(i)];
            entry.headers.stream_id = static_cast<std::int32_t>(i);
            benchmark::DoNotOptimize(&entry);
        }
    }
    state.SetItemsProcessed(static_cast<std::int64_t>(n) * state.iterations());
}
BENCHMARK(BM_H2_PendingMap_Insert)->Arg(10)->Arg(100);

void BM_H2_PendingMap_Lookup_Hit(benchmark::State &state)
{
    const auto n = static_cast<std::size_t>(state.range(0));
    const mem::unordered_map<std::uint32_t, h2_pending_entry> *map = nullptr;
    if (n <= 10) { map = &pending_10; }
    else { map = &pending_100; }

    const auto key = static_cast<std::uint32_t>(n / 2);
    for (auto _ : state)
    {
        auto it = map->find(key);
        benchmark::DoNotOptimize(it);
    }
}
BENCHMARK(BM_H2_PendingMap_Lookup_Hit)->Arg(10)->Arg(100);

void BM_H2_PendingMap_Lookup_Miss(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto it = pending_100.find(9999);
        benchmark::DoNotOptimize(it);
    }
}
BENCHMARK(BM_H2_PendingMap_Lookup_Miss);

void BM_H2_PendingMap_Erase(benchmark::State &state)
{
    for (auto _ : state)
    {
        state.PauseTiming();
        auto map = make_pending_map(100);
        state.ResumeTiming();

        auto count = map.erase(50);
        benchmark::DoNotOptimize(count);
    }
}
BENCHMARK(BM_H2_PendingMap_Erase);

// ============================================================
// 头部字段匹配基准测试
// ============================================================

void BM_H2_HeaderMatch_Authority(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = match_header(":authority");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_H2_HeaderMatch_Authority);

void BM_H2_HeaderMatch_Host(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = match_header("host");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_H2_HeaderMatch_Host);

void BM_H2_HeaderMatch_UserAgent(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = match_header("user-agent");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_H2_HeaderMatch_UserAgent);

void BM_H2_HeaderMatch_ProxyAuth(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = match_header("proxy-authorization");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_H2_HeaderMatch_ProxyAuth);

void BM_H2_HeaderMatch_Miss(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = match_header("x-custom-header");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_H2_HeaderMatch_Miss);

// ============================================================
// h2_headers 填充基准测试
// ============================================================

void BM_H2_HeadersPopulate(benchmark::State &state)
{
    for (auto _ : state)
    {
        h2_headers hdrs;
        hdrs.stream_id = 1;
        hdrs.authority.assign("www.example.com:443");
        hdrs.host.assign("www.example.com");
        hdrs.user_agent.assign("curl/8.0");
        hdrs.proxy_auth.assign("Basic dXNlcjpwYXNz");
        benchmark::DoNotOptimize(hdrs.authority.data());
    }
}
BENCHMARK(BM_H2_HeadersPopulate);

// ============================================================
// nghttp2 会话开销基准测试
// ============================================================

void BM_H2_Nghttp2SessionCreate(benchmark::State &state)
{
    for (auto _ : state)
    {
        nghttp2_session *session = nullptr;
        nghttp2_session_server_new(&session, nullptr, nullptr);
        benchmark::DoNotOptimize(session);
        nghttp2_session_del(session);
    }
}
BENCHMARK(BM_H2_Nghttp2SessionCreate);

void BM_H2_RespondConnect(benchmark::State &state)
{
    for (auto _ : state)
    {
        state.PauseTiming();
        nghttp2_session *session = nullptr;
        nghttp2_session_server_new(&session, nullptr, nullptr);
        nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
        state.ResumeTiming();

        const auto sname = reinterpret_cast<const std::uint8_t *>(":status");
        const auto sval = reinterpret_cast<const std::uint8_t *>("200");
        nghttp2_nv hdr = {const_cast<std::uint8_t *>(sname),
                          const_cast<std::uint8_t *>(sval),
                          7, 3, NGHTTP2_FLAG_NONE};
        auto rv = nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE,
                                          1, nullptr, &hdr, 1, nullptr);
        benchmark::DoNotOptimize(rv);

        nghttp2_session_del(session);
    }
}
BENCHMARK(BM_H2_RespondConnect);

// ============================================================
// 完整流生命周期基准测试
// ============================================================

void BM_H2_ConnectStreamCycle(benchmark::State &state)
{
    mem::unordered_map<std::uint32_t, h2_pending_entry> pending;
    std::uint32_t stream_id = 1;

    for (auto _ : state)
    {
        // 1. on_begin_headers: 创建待处理条目
        {
            auto &entry = pending[stream_id];
            entry.headers.stream_id = static_cast<std::int32_t>(stream_id);
            entry.connecting = false;
        }

        // 2. on_header: 头部匹配 + 字符串赋值
        {
            auto it = pending.find(stream_id);
            if (it != pending.end())
            {
                auto &hdrs = it->second.headers;
                hdrs.authority.assign("www.example.com:443");
                hdrs.host.assign("www.example.com");
                hdrs.user_agent.assign("curl/8.0");
                hdrs.proxy_auth.assign("Basic dXNlcjpwYXNz");
            }
        }

        // 3. on_frame_recv: 查找待处理条目
        {
            auto it = pending.find(stream_id);
            benchmark::DoNotOptimize(it);
        }

        // 4. on_stream_close: 清理
        pending.erase(stream_id);
        ++stream_id;
    }
}
BENCHMARK(BM_H2_ConnectStreamCycle);

} // namespace

BENCHMARK_MAIN();
