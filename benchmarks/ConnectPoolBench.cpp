/**
 * @file ConnectPoolBench.cpp
 * @brief 连接池管理操作基准测试
 * @details 测量连接池基础设施操作的性能：
 *          endpoint 到 key 转换、endpoint 哈希计算、
 *          pooled_connection RAII 操作（valid/release/reset）、
 *          连接池统计与回收。
 *          池操作在每次上游连接建立和归还时被调用。
 */

#include <benchmark/benchmark.h>
#include <prism/connect/pool/pool.hpp>
#include <prism/memory/container.hpp>

#include <cstdint>

namespace
{

namespace conn = psm::connect;
namespace net = boost::asio;

// ============================================================
// 测试数据：预构造的端点
// ============================================================

const auto ep1 = net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), 443);
const auto ep2 = net::ip::tcp::endpoint(net::ip::make_address("10.0.0.1"), 8080);
const auto ep3 = net::ip::tcp::endpoint(net::ip::make_address("192.168.1.1"), 3306);

const auto key1 = conn::to_key(ep1);
const auto key2 = conn::to_key(ep2);
const auto key3 = conn::to_key(ep3);

// ============================================================
// to_key 转换基准测试
// ============================================================

/// @brief 测量 endpoint 到 key 转换性能
void BM_ConnPool_ToKey(benchmark::State &state)
{
    const auto &ep = (state.range(0) == 0) ? ep1 : (state.range(0) == 1) ? ep2 : ep3;
    for (auto _ : state)
    {
        auto k = conn::to_key(ep);
        benchmark::DoNotOptimize(k);
    }
}
BENCHMARK(BM_ConnPool_ToKey)->Arg(0)->Arg(1)->Arg(2);

// ============================================================
// endpoint_hash 仿函数基准测试
// ============================================================

/// @brief 测量 endpoint_key 哈希计算性能
void BM_ConnPool_EndpointHash(benchmark::State &state)
{
    const auto &key = (state.range(0) == 0) ? key1 : (state.range(0) == 1) ? key2 : key3;
    conn::endpoint_hash hasher;
    for (auto _ : state)
    {
        auto h = hasher(key);
        benchmark::DoNotOptimize(h);
    }
}
BENCHMARK(BM_ConnPool_EndpointHash)->Arg(0)->Arg(1)->Arg(2);

// ============================================================
// pooled_connection::valid() 基准测试
// ============================================================

/// @brief 测量 pooled_connection 有效性检查性能
void BM_ConnPool_PooledValid(benchmark::State &state)
{
    // 默认构造的 pooled_connection 为无效状态
    conn::pooled_connection pc;
    for (auto _ : state)
    {
        auto v = pc.valid();
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_ConnPool_PooledValid);

// ============================================================
// pooled_connection::release() 基准测试
// ============================================================

/// @brief 测量 pooled_connection 所有权释放性能
void BM_ConnPool_PooledRelease(benchmark::State &state)
{
    for (auto _ : state)
    {
        state.PauseTiming();
        conn::pooled_connection pc;
        state.ResumeTiming();

        auto *s = pc.release();
        benchmark::DoNotOptimize(s);
    }
}
BENCHMARK(BM_ConnPool_PooledRelease);

// ============================================================
// pooled_connection::reset() 基准测试
// ============================================================

/// @brief 测量 pooled_connection 重置性能
void BM_ConnPool_PooledReset(benchmark::State &state)
{
    for (auto _ : state)
    {
        state.PauseTiming();
        conn::pooled_connection pc;
        state.ResumeTiming();

        pc.reset();
        benchmark::DoNotOptimize(pc.valid());
    }
}
BENCHMARK(BM_ConnPool_PooledReset);

// ============================================================
// connection_pool::stats() 基准测试
// ============================================================

/// @brief 测量连接池统计信息获取性能
void BM_ConnPool_Stats(benchmark::State &state)
{
    net::io_context ioc;
    conn::connection_pool pool(ioc);
    for (auto _ : state)
    {
        auto s = pool.stats();
        benchmark::DoNotOptimize(s.idle_count);
        benchmark::DoNotOptimize(s.total_acquires);
    }
}
BENCHMARK(BM_ConnPool_Stats);

// ============================================================
// 不同 endpoint 的哈希分散性基准测试
// ============================================================

/// @brief 测量不同 endpoint 哈希分散性性能
void BM_ConnPool_EndpointHash_Diff(benchmark::State &state)
{
    conn::endpoint_hash hasher;

    // 构造多个不同端点的 key
    psm::memory::vector<conn::endpoint_key> keys(psm::memory::current_resource());
    keys.reserve(64);
    for (std::uint16_t port = 1; port <= 64; ++port)
    {
        const auto ep = net::ip::tcp::endpoint(net::ip::make_address("10.0.0.1"), port);
        keys.push_back(conn::to_key(ep));
    }

    std::size_t idx = 0;
    for (auto _ : state)
    {
        auto h = hasher(keys[idx % keys.size()]);
        benchmark::DoNotOptimize(h);
        ++idx;
    }
}
BENCHMARK(BM_ConnPool_EndpointHash_Diff);

// ============================================================
// endpoint_key 相等比较基准测试
// ============================================================

/// @brief 测量 endpoint_key 相等比较性能
void BM_ConnPool_KeyEqual(benchmark::State &state)
{
    // key1 == key1（相同） 和 key1 == key2（不同）
    for (auto _ : state)
    {
        auto same = (key1 == key1);
        auto diff = (key1 == key2);
        benchmark::DoNotOptimize(same);
        benchmark::DoNotOptimize(diff);
    }
}
BENCHMARK(BM_ConnPool_KeyEqual);

} // namespace

BENCHMARK_MAIN();
