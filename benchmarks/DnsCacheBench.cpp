/**
 * @file DnsCacheBench.cpp
 * @brief DNS 缓存 / 合并 / 编解码微基准
 * @details 聚焦 1.1-1.5 优化后的数据结构热点：
 *          - Cache 满容量持续插入（FIFO 淘汰）——O(1) 环形缓冲稳态吞吐
 *          - Cache 插入 + 命中查询混合（解析器真实访问模式）
 *          - Cache 命中查询（只读路径）
 *          - Coalescer FindCreate 同键复用（single-flight 热点）
 *          - Format Pack / Unpack 往返（压缩表构建与解析）
 * @note 与 DnsMessageBench 互补：本基准聚焦缓存与合并数据结构而非纯报文编解码。
 *       全部为内存操作，无网络依赖。
 */

#include <preview/Net/Dns/Cache.hpp>
#include <preview/Net/Dns/Coalescer.hpp>
#include <preview/Net/Dns/Format.hpp>

#include <benchmark/benchmark.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace
{
    using Preview::Network::Dns::Cache;
    using Preview::Network::Dns::CacheOptions;
    using Preview::Network::Dns::Coalescer;
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::PutInput;
    using Preview::Network::Dns::QType;
    using Preview::Network::Dns::Record;

    constexpr std::uint16_t QtA = 1;

    auto MakePut(const std::size_t i) -> PutInput
    {
        PutInput in;
        in.Domain = "host" + std::to_string(i) + ".example.com";
        in.QType = QtA;
        in.Ips = {boost::asio::ip::make_address("1.2.3.4")};
        in.Ttl = std::chrono::seconds(60);
        return in;
    }

    auto MakeKey(const std::size_t i) -> std::string
    {
        return "host" + std::to_string(i) + ".example.com";
    }
} // namespace

/// Cache：满容量持续插入（含 FIFO 淘汰）——验证 O(1) 淘汰的稳态吞吐
static void BM_CachePutSteadyState(benchmark::State &state)
{
    CacheOptions opts;
    opts.MaxEntries = static_cast<std::size_t>(state.range(0));
    Cache c(opts);
    std::size_t i = 0;
    for (auto _ : state)
    {
        c.Put(MakePut(i++));
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CachePutSteadyState)->Arg(1000)->Arg(10000);

/// Cache：插入 + 命中查询混合（写读各半，模拟解析器真实访问模式）
static void BM_CachePutGetMixed(benchmark::State &state)
{
    CacheOptions opts;
    const auto N = static_cast<std::size_t>(state.range(0));
    opts.MaxEntries = N;
    Cache c(opts);
    std::size_t i = 0;
    for (auto _ : state)
    {
        const auto Idx = i % N;
        c.Put(MakePut(Idx));
        (void)c.Get(MakeKey(Idx), QtA);
        ++i;
    }
    state.SetItemsProcessed(state.iterations() * 2);
}
BENCHMARK(BM_CachePutGetMixed)->Arg(10000);

/// Cache：命中查询（只读路径）
static void BM_CacheGetHit(benchmark::State &state)
{
    CacheOptions opts;
    Cache c(opts);
    constexpr std::size_t kKeys = 1024;
    for (std::size_t i = 0; i < kKeys; ++i)
    {
        c.Put(MakePut(i));
    }
    std::size_t i = 0;
    for (auto _ : state)
    {
        (void)c.Get(MakeKey(i++ % kKeys), QtA);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CacheGetHit);

/// Coalescer：FindCreate 同键复用（single-flight 热点）
static void BM_CoalescerFindCreate(benchmark::State &state)
{
    boost::asio::io_context ioc;
    Coalescer<std::vector<boost::asio::ip::address>> c(ioc.get_executor());
    auto [flight, isNew] = c.FindCreate("busy.example.com", QtA);
    (void)flight;
    (void)isNew;
    for (auto _ : state)
    {
        auto [f, n] = c.FindCreate("busy.example.com", QtA);
        (void)f;
        (void)n;
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CoalescerFindCreate);

/// Format：查询报文 Pack（含压缩表构建与分配）
static void BM_DnsPackQuery(benchmark::State &state)
{
    auto msg = Message::MakeQuery("www.example.com", QType::A);
    for (auto _ : state)
    {
        auto wire = msg.Pack();
        benchmark::DoNotOptimize(wire.size());
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DnsPackQuery);

/// Format：带回应的报文 Unpack（解析路径）
static void BM_DnsUnpack(benchmark::State &state)
{
    auto msg = Message::MakeQuery("www.example.com", QType::A);
    msg.Id = 0x1234;
    Record rec;
    rec.Name = "www.example.com";
    rec.Type = QType::A;
    rec.RClass = 1;
    rec.Ttl = 60;
    rec.Rdata = {1, 2, 3, 4};
    msg.Answers.push_back(rec);
    const auto wire = msg.Pack();
    for (auto _ : state)
    {
        auto parsed = Message::Unpack(wire);
        benchmark::DoNotOptimize(parsed.has_value());
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DnsUnpack);

BENCHMARK_MAIN();
