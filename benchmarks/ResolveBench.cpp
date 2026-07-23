/**
 * @file ResolveBench.cpp
 * @brief DNS 解析基础设施基准测试
 * @details 测量 DNS 解析管道中高频操作的性能：
 *          透明哈希（string_hash FNV-1a）和相等比较（string_equal）、
 *          DNS 缓存读写与淘汰、DNS 查询合并器。
 *          透明哈希在每次缓存查找时调用，缓存操作在每次 DNS 解析时执行。
 */

#include <benchmark/benchmark.h>
#include <prism/net/dns/detail/cache.hpp>
#include <prism/net/dns/detail/coalescer.hpp>
#include <prism/net/dns/detail/transparent.hpp>
#include <prism/net/dns/detail/format.hpp>
#include <prism/foundation/memory/container.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace
{

using namespace psm::dns::detail;
namespace mem = psm::memory;

// ============================================================
// 测试数据
// ============================================================

const auto test_domain = std::string("www.example.com");
const auto test_domain_pmr = mem::string(test_domain);
const auto test_short_domain = std::string("a.bc");
const auto test_long_domain = std::string("subdomain.deep.nested.very.long.domain.example.com");

// ============================================================
// string_hash 基准测试
// ============================================================

void BM_TransparentHash_StringView(benchmark::State &state)
{
    string_hash hasher;
    for (auto _ : state)
    {
        auto h = hasher(std::string_view(test_domain));
        benchmark::DoNotOptimize(h);
    }
}
BENCHMARK(BM_TransparentHash_StringView);

void BM_TransparentHash_PmrString(benchmark::State &state)
{
    string_hash hasher;
    for (auto _ : state)
    {
        auto h = hasher(test_domain_pmr);
        benchmark::DoNotOptimize(h);
    }
}
BENCHMARK(BM_TransparentHash_PmrString);

void BM_TransparentHash_Short(benchmark::State &state)
{
    string_hash hasher;
    for (auto _ : state)
    {
        auto h = hasher(std::string_view(test_short_domain));
        benchmark::DoNotOptimize(h);
    }
}
BENCHMARK(BM_TransparentHash_Short);

void BM_TransparentHash_Long(benchmark::State &state)
{
    string_hash hasher;
    for (auto _ : state)
    {
        auto h = hasher(std::string_view(test_long_domain));
        benchmark::DoNotOptimize(h);
    }
}
BENCHMARK(BM_TransparentHash_Long);

// ============================================================
// string_equal 基准测试
// ============================================================

void BM_TransparentEqual_SvSv(benchmark::State &state)
{
    string_equal eq;
    const std::string_view a(test_domain);
    const std::string_view b(test_domain);
    for (auto _ : state)
    {
        auto r = eq(a, b);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_TransparentEqual_SvSv);

void BM_TransparentEqual_SvPmr(benchmark::State &state)
{
    string_equal eq;
    const std::string_view a(test_domain);
    for (auto _ : state)
    {
        auto r = eq(a, test_domain_pmr);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_TransparentEqual_SvPmr);

// ============================================================
// cache 基准测试
// ============================================================

/// 构建含 N 条 A 记录的缓存
auto make_cache(std::size_t n) -> cache
{
    cache_options opts;
    opts.max_entries = n * 2;
    opts.ttl = std::chrono::seconds(300);
    cache c(opts);

    for (std::size_t i = 0; i < n; ++i)
    {
        auto name = std::string("domain-") + std::to_string(i) + ".example.com";
        mem::vector<boost::asio::ip::address> ips;
        ips.push_back(boost::asio::ip::make_address("127.0.0.1"));
        c.put({name, qtype::a, ips, 300});
    }
    return c;
}

void BM_Cache_Put_Single(benchmark::State &state)
{
    cache_options opts;
    opts.max_entries = 100;
    cache c(opts);
    mem::vector<boost::asio::ip::address> ips;
    ips.push_back(boost::asio::ip::make_address("10.0.0.1"));

    for (auto _ : state)
    {
        c.put({"test.example.com", qtype::a, ips, 300});
    }
}
BENCHMARK(BM_Cache_Put_Single);

void BM_Cache_Put_ManyIps(benchmark::State &state)
{
    cache_options opts;
    opts.max_entries = 100;
    cache c(opts);

    mem::vector<boost::asio::ip::address> ips;
    for (int i = 0; i < 8; ++i)
    {
        ips.push_back(boost::asio::ip::make_address(
            "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256)));
    }

    for (auto _ : state)
    {
        c.put({"multi-ip.example.com", qtype::a, ips, 300});
    }
}
BENCHMARK(BM_Cache_Put_ManyIps);

void BM_Cache_Get_Hit10(benchmark::State &state)
{
    auto c = make_cache(10);
    const auto key = std::string("domain-5.example.com");
    for (auto _ : state)
    {
        auto r = c.get(key, qtype::a);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Cache_Get_Hit10);

void BM_Cache_Get_Hit100(benchmark::State &state)
{
    auto c = make_cache(100);
    const auto key = std::string("domain-50.example.com");
    for (auto _ : state)
    {
        auto r = c.get(key, qtype::a);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Cache_Get_Hit100);

void BM_Cache_Get_Hit1000(benchmark::State &state)
{
    auto c = make_cache(1000);
    const auto key = std::string("domain-500.example.com");
    for (auto _ : state)
    {
        auto r = c.get(key, qtype::a);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Cache_Get_Hit1000);

void BM_Cache_Get_Miss(benchmark::State &state)
{
    auto c = make_cache(100);
    for (auto _ : state)
    {
        auto r = c.get("nonexistent.example.com", qtype::a);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Cache_Get_Miss);

void BM_Cache_EvictExpired(benchmark::State &state)
{
    for (auto _ : state)
    {
        state.PauseTiming();
        auto c = make_cache(100);
        state.ResumeTiming();

        c.evict_expired();
        benchmark::DoNotOptimize(&c);
    }
}
BENCHMARK(BM_Cache_EvictExpired);

void BM_Cache_PutNegative(benchmark::State &state)
{
    cache_options opts;
    opts.max_entries = 100;
    cache c(opts);

    for (auto _ : state)
    {
        c.put_negative("nx.example.com", qtype::aaaa, std::chrono::seconds(30));
    }
}
BENCHMARK(BM_Cache_PutNegative);

// ============================================================
// coalescer 基准测试
// ============================================================

void BM_Coalescer_MakeKey(benchmark::State &state)
{
    coalescer coal;
    for (auto _ : state)
    {
        auto key = coal.make_key("www.example.com", "443");
        benchmark::DoNotOptimize(key.data());
    }
}
BENCHMARK(BM_Coalescer_MakeKey);

void BM_Coalescer_FindCreate_New(benchmark::State &state)
{
    boost::asio::io_context ioc;
    for (auto _ : state)
    {
        state.PauseTiming();
        coalescer coal;
        state.ResumeTiming();

        auto key = coal.make_key("www.example.com", "443");
        auto result = coal.find_create(key, ioc.get_executor());
        benchmark::DoNotOptimize(result.second);
    }
}
BENCHMARK(BM_Coalescer_FindCreate_New);

void BM_Coalescer_FindCreate_Existing(benchmark::State &state)
{
    boost::asio::io_context ioc;
    coalescer coal;
    auto key = coal.make_key("www.example.com", "443");
    coal.find_create(key, ioc.get_executor());

    for (auto _ : state)
    {
        auto result = coal.find_create(key, ioc.get_executor());
        benchmark::DoNotOptimize(result.second);
    }
}
BENCHMARK(BM_Coalescer_FindCreate_Existing);

} // namespace

BENCHMARK_MAIN();
