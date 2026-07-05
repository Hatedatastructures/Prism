/**
 * @file DnsMessageBench.cpp
 * @brief DNS 报文处理热路径基准测试
 * @details 测量 DNS 查询编码、响应解码、IP 提取性能。
 */

#include <benchmark/benchmark.h>
#include <prism/foundation/foundation.hpp>
#include <prism/net/resolve/dns/detail/format.hpp>
#include <prism/net/resolve/dns/detail/cache.hpp>

#include <boost/asio.hpp>
#include <cstdint>

namespace
{
    namespace dns = psm::resolve::dns::detail;
    namespace mem = psm::memory;
    namespace net = boost::asio;

    // ─── DNS 查询编码 ───────────────────────────

    static void BM_DnsEncodeQueryA(benchmark::State &state)
    {
        for (auto _ : state)
        {
            auto msg = dns::message::make_query("example.com", dns::qtype::a);
            benchmark::DoNotOptimize(msg);
        }
    }
    BENCHMARK(BM_DnsEncodeQueryA);

    static void BM_DnsEncodeQueryAAAA(benchmark::State &state)
    {
        for (auto _ : state)
        {
            auto msg = dns::message::make_query("subdomain.example.com", dns::qtype::aaaa);
            benchmark::DoNotOptimize(msg);
        }
    }
    BENCHMARK(BM_DnsEncodeQueryAAAA);

    // ─── DNS 报文序列化 (pack) ──────────────────

    static void BM_DnsPackQuery(benchmark::State &state)
    {
        auto msg = dns::message::make_query("www.example.com", dns::qtype::a);
        for (auto _ : state)
        {
            auto bytes = msg.pack();
            benchmark::DoNotOptimize(bytes);
        }
    }
    BENCHMARK(BM_DnsPackQuery);

    // ─── DNS 报文反序列化 (unpack) ──────────────

    static void BM_DnsUnpackResponse(benchmark::State &state)
    {
        auto query = dns::message::make_query("example.com", dns::qtype::a);
        query.qr = true;
        query.ra = true;
        query.rcode = 0;

        dns::record rec;
        rec.name = "example.com";
        rec.type = dns::qtype::a;
        rec.rclass = 1;
        rec.ttl = 300;
        rec.rdata = {8, 8, 8, 8};
        query.answers.push_back(std::move(rec));

        auto wire = query.pack();

        for (auto _ : state)
        {
            auto result = dns::message::unpack(
                std::span<const std::uint8_t>(wire.data(), wire.size()));
            benchmark::DoNotOptimize(result);
        }
    }
    BENCHMARK(BM_DnsUnpackResponse);

    // ─── IP 提取 ────────────────────────────────

    static void BM_DnsExtractIps(benchmark::State &state)
    {
        dns::message msg;
        msg.qr = true;

        for (int i = 0; i < 4; ++i)
        {
            dns::record rec;
            rec.name = "example.com";
            rec.type = dns::qtype::a;
            rec.rclass = 1;
            rec.ttl = 300;
            rec.rdata = {static_cast<std::uint8_t>(192),
                         static_cast<std::uint8_t>(168),
                         static_cast<std::uint8_t>(1),
                         static_cast<std::uint8_t>(i + 1)};
            msg.answers.push_back(std::move(rec));
        }

        for (auto _ : state)
        {
            auto ips = msg.extract_ips();
            benchmark::DoNotOptimize(ips);
        }
    }
    BENCHMARK(BM_DnsExtractIps);

    // ─── DNS 缓存查找 ───────────────────────────

    static void BM_DnsCacheLookupHit(benchmark::State &state)
    {
        dns::cache_options opts;
        opts.max_entries = 1024;
        dns::cache c(opts);

        mem::vector<net::ip::address> ips;
        ips.push_back(net::ip::make_address("1.2.3.4"));
        dns::put_input input{
            .domain = "cached.example.com",
            .qt = dns::qtype::a,
            .ips = ips,
            .ttl_seconds = 300,
        };
        c.put(input);

        for (auto _ : state)
        {
            auto result = c.get("cached.example.com", dns::qtype::a);
            benchmark::DoNotOptimize(result);
        }
    }
    BENCHMARK(BM_DnsCacheLookupHit);

    static void BM_DnsCacheLookupMiss(benchmark::State &state)
    {
        dns::cache_options opts;
        opts.max_entries = 1024;
        dns::cache c(opts);

        for (auto _ : state)
        {
            auto result = c.get("miss.example.com", dns::qtype::a);
            benchmark::DoNotOptimize(result);
        }
    }
    BENCHMARK(BM_DnsCacheLookupMiss);

} // namespace

BENCHMARK_MAIN();
