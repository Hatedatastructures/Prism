/**
 * @file CodecBench.cpp
 * @brief 协议编解码基准测试
 * @details 测量 HTTP 代理请求解析、DNS 报文处理、
 *          加密工具（SHA224、Base64）、DNS 规则引擎等性能指标。
 * @note 已移除无参考价值的单字节解析测试（static constexpr 导致编译器常量折叠）
 */

#include <benchmark/benchmark.h>
#include <prism/protocol/http/parser.hpp>
#include <prism/protocol/trojan/format.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/resolve/dns/detail/format.hpp>
#include <prism/resolve/dns/detail/rules.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <array>
#include <span>
#include <string>
#include <string_view>

using namespace psm;

namespace psm::resolve
{
    using dns::detail::message;
    using dns::detail::qtype;
    using dns::detail::domain_trie;
    using dns::detail::rules_engine;
    using dns::detail::rule_result;
    using dns::detail::record;
    using dns::detail::question;
}

// ============================================================
// HTTP 协议基准测试
// 测试 HTTP 代理请求解析（GET/CONNECT/POST）和相对路径提取性能
// ============================================================

static const std::string http_get_request =
    "GET /index.html HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    "Accept-Encoding: gzip, deflate, sdch\r\n"
    "Accept-Language: en-US,en;q=0.8\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

static const std::string http_connect_request =
    "CONNECT www.example.com:443 HTTP/1.1\r\n"
    "Host: www.example.com:443\r\n"
    "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
    "\r\n";

static std::string make_http_post_request(std::size_t body_size)
{
    std::string body(body_size, 'x');
    std::string request;
    request.reserve(256 + body.size());
    request.append("POST /submit HTTP/1.1\r\n");
    request.append("Host: www.example.com\r\n");
    request.append("User-Agent: ForwardEngine-Bench\r\n");
    request.append("Content-Type: application/octet-stream\r\n");
    request.append("Content-Length: ");
    request.append(std::to_string(body.size()));
    request.append("\r\n");
    request.append("Connection: keep-alive\r\n");
    request.append("\r\n");
    request.append(body);
    return request;
}

static void BM_HttpParseProxyRequest_Get(benchmark::State &state)
{
    protocol::http::proxy_request req;
    for (auto _ : state)
    {
        fault::code ec = protocol::http::parse_proxy_request(http_get_request, req);
        if (fault::failed(ec))
        {
            state.SkipWithError("HTTP Parsing failed");
        }
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(http_get_request.size()));
}

static void BM_HttpParseProxyRequest_Connect(benchmark::State &state)
{
    protocol::http::proxy_request req;
    for (auto _ : state)
    {
        const fault::code ec = protocol::http::parse_proxy_request(http_connect_request, req);
        if (fault::failed(ec))
        {
            state.SkipWithError("HTTP Parsing failed");
        }
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(http_connect_request.size()));
}

static void BM_HttpParseProxyRequest_PostBody(benchmark::State &state)
{
    const auto payload = make_http_post_request(static_cast<std::size_t>(state.range(0)));
    protocol::http::proxy_request req;
    for (auto _ : state)
    {
        fault::code ec = protocol::http::parse_proxy_request(payload, req);
        if (fault::failed(ec))
        {
            state.SkipWithError("HTTP Parsing failed");
        }
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.size()));
}

static void BM_HttpExtractRelativePath(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = protocol::http::extract_relative_path("http://www.example.com/path/to/resource?q=1#frag");
        benchmark::DoNotOptimize(result);
    }
}

// ============================================================
// Trojan 协议基准测试
// 测试 Trojan 凭据解析（56 字节 SHA224 哈希比对）性能
// ============================================================

static void BM_TrojanDecodeCredential(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 56> buffer =
        {
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};

    for (auto _ : state)
    {
        auto [ec, credential] = protocol::trojan::format::parse_credential(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("Trojan user credential parsing failed");
        }
        benchmark::DoNotOptimize(credential);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_TrojanDecodeCredential_Invalid(benchmark::State &state)
{
    std::array<std::uint8_t, 56> buffer{};
    buffer.fill('a');
    buffer[7] = 'g';
    for (auto _ : state)
    {
        auto [ec, credential] = protocol::trojan::format::parse_credential(buffer);
        benchmark::DoNotOptimize(ec);
        benchmark::DoNotOptimize(credential);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

// ============================================================
// DNS 报文基准测试
// 测试 DNS 查询构建、报文打包/解包、IP 提取、TTL 计算性能
// ============================================================

static void BM_DnsMakeQuery(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto msg = resolve::message::make_query("example.com", resolve::qtype::a);
        benchmark::DoNotOptimize(msg);
    }
}

static void BM_DnsPackMessage(benchmark::State &state)
{
    auto msg = resolve::message::make_query("example.com", resolve::qtype::a);
    for (auto _ : state)
    {
        auto wire = msg.pack();
        benchmark::DoNotOptimize(wire);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64);
}

static void BM_DnsUnpackMessage(benchmark::State &state)
{
    auto msg = resolve::message::make_query("example.com", resolve::qtype::a);
    auto wire = msg.pack();
    for (auto _ : state)
    {
        auto opt = resolve::message::unpack(std::span<const std::uint8_t>(wire.data(), wire.size()));
        benchmark::DoNotOptimize(opt);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(wire.size()));
}

static void BM_DnsExtractIps(benchmark::State &state)
{
    resolve::message msg;
    {
        resolve::record ans;
        ans.type = resolve::qtype::a;
        ans.ttl = 300;
        ans.rdata = {8, 8, 8, 8};
        msg.answers.push_back(std::move(ans));
    }
    {
        resolve::record ans;
        ans.type = resolve::qtype::aaaa;
        ans.ttl = 300;
        ans.rdata = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        msg.answers.push_back(std::move(ans));
    }
    for (auto _ : state)
    {
        auto ips = msg.extract_ips();
        benchmark::DoNotOptimize(ips);
    }
}

static void BM_DnsMinTtl(benchmark::State &state)
{
    resolve::message msg;
    for (int i = 0; i < 10; ++i)
    {
        resolve::record r;
        r.ttl = static_cast<std::uint32_t>(300 + i * 60);
        msg.answers.push_back(std::move(r));
    }
    for (auto _ : state)
    {
        auto ttl = msg.min_ttl();
        benchmark::DoNotOptimize(ttl);
    }
}

// ============================================================
// 加密工具基准测试
// 测试 SHA224 哈希、Base64 解码、凭据规范化性能
// ============================================================

static void BM_Sha224Short(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto hash = crypto::sha224("abc");
        benchmark::DoNotOptimize(hash);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 3);
}

static void BM_Sha224Long(benchmark::State &state)
{
    std::string input(1024, 'x');
    for (auto _ : state)
    {
        auto hash = crypto::sha224(input);
        benchmark::DoNotOptimize(hash);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(input.size()));
}

static void BM_Base64DecodeShort(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto decoded = crypto::base64_decode("Zm9vYmFy");
        benchmark::DoNotOptimize(decoded);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 8);
}

static void BM_Base64DecodeLong(benchmark::State &state)
{
    std::string b64_input(1400, 'A');
    for (auto _ : state)
    {
        auto decoded = crypto::base64_decode(b64_input);
        benchmark::DoNotOptimize(decoded);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(b64_input.size()));
}

static void BM_NormalizeCredential_Plain(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = crypto::normalize_credential("my_password");
        benchmark::DoNotOptimize(result);
    }
}

static void BM_NormalizeCredential_Hashed(benchmark::State &state)
{
    std::string already_hashed(56, 'a');
    for (auto _ : state)
    {
        auto result = crypto::normalize_credential(already_hashed);
        benchmark::DoNotOptimize(result);
    }
}

// ============================================================
// DNS 规则引擎基准测试
// 测试域名前缀树查找（精确匹配/通配符/未命中）、规则引擎匹配性能
// ============================================================

static void BM_DomainTrieSearchHit(benchmark::State &state)
{
    resolve::domain_trie trie;
    trie.insert("example.com", 42);
    for (auto _ : state)
    {
        auto result = trie.search("example.com");
        benchmark::DoNotOptimize(result);
    }
}

static void BM_DomainTrieSearchWildcard(benchmark::State &state)
{
    resolve::domain_trie trie;
    trie.insert("*.example.com", 100);
    for (auto _ : state)
    {
        auto result = trie.search("www.example.com");
        benchmark::DoNotOptimize(result);
    }
}

static void BM_DomainTrieSearchMiss(benchmark::State &state)
{
    resolve::domain_trie trie;
    trie.insert("example.com", 42);
    for (auto _ : state)
    {
        auto result = trie.search("other.com");
        benchmark::DoNotOptimize(result);
    }
}

static void BM_RulesEngineMatch(benchmark::State &state)
{
    resolve::rules_engine engine;
    {
        namespace net = boost::asio;
        memory::vector<net::ip::address> ips;
        ips.push_back(net::ip::make_address("1.2.3.4"));
        engine.add_address_rule("blocked.com", ips);
    }
    engine.add_cname_rule("alias.com", "real.com");
    engine.add_negative_rule("evil.com");
    for (auto _ : state)
    {
        auto result = engine.match("alias.com");
        benchmark::DoNotOptimize(result);
    }
}

// ============================================================
// 大规模 DomainTrie 测试
// 测试不同规则数量下的查找性能
// ============================================================

static void BM_DomainTrie_LargeDataset(benchmark::State &state)
{
    const auto rule_count = static_cast<std::size_t>(state.range(0));
    resolve::domain_trie trie;

    for (std::size_t i = 0; i < rule_count; ++i)
    {
        std::string domain = "domain" + std::to_string(i) + ".com";
        trie.insert(domain, static_cast<std::uint64_t>(i));
    }

    std::string query_domain = "domain" + std::to_string(rule_count / 2) + ".com";
    for (auto _ : state)
    {
        auto result = trie.search(query_domain);
        benchmark::DoNotOptimize(result);
    }
}

static void BM_DomainTrie_WildcardLarge(benchmark::State &state)
{
    const auto rule_count = static_cast<std::size_t>(state.range(0));
    resolve::domain_trie trie;

    for (std::size_t i = 0; i < rule_count; ++i)
    {
        std::string domain = "*.domain" + std::to_string(i) + ".com";
        trie.insert(domain, static_cast<std::uint64_t>(i));
    }

    std::string query_domain = "www.domain" + std::to_string(rule_count / 2) + ".com";
    for (auto _ : state)
    {
        auto result = trie.search(query_domain);
        benchmark::DoNotOptimize(result);
    }
}

// ============================================================
// Shadowsocks SS2022 协议基准测试
// 测试 PSK Base64 解码性能
// ============================================================

static void BM_ShadowsocksDecodePsk(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto [ec, psk] = protocol::shadowsocks::format::decode_psk("AAAAAAAAAAAAAAAAAAAAAA==");
        benchmark::DoNotOptimize(psk);
    }
}

// ============================================================
// BENCHMARK 注册
// ============================================================

// HTTP
BENCHMARK(BM_HttpParseProxyRequest_Get);
BENCHMARK(BM_HttpParseProxyRequest_Connect);
BENCHMARK(BM_HttpParseProxyRequest_PostBody)->Arg(0)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_HttpExtractRelativePath);

// Trojan
BENCHMARK(BM_TrojanDecodeCredential);
BENCHMARK(BM_TrojanDecodeCredential_Invalid);

// DNS Packet
BENCHMARK(BM_DnsMakeQuery);
BENCHMARK(BM_DnsPackMessage);
BENCHMARK(BM_DnsUnpackMessage);
BENCHMARK(BM_DnsExtractIps);
BENCHMARK(BM_DnsMinTtl);

// Crypto
BENCHMARK(BM_Sha224Short);
BENCHMARK(BM_Sha224Long);
BENCHMARK(BM_Base64DecodeShort);
BENCHMARK(BM_Base64DecodeLong);
BENCHMARK(BM_NormalizeCredential_Plain);
BENCHMARK(BM_NormalizeCredential_Hashed);

// DNS Rules
BENCHMARK(BM_DomainTrieSearchHit);
BENCHMARK(BM_DomainTrieSearchWildcard);
BENCHMARK(BM_DomainTrieSearchMiss);
BENCHMARK(BM_RulesEngineMatch);

// DNS Rules 大规模测试
BENCHMARK(BM_DomainTrie_LargeDataset)->Arg(100)->Arg(1000)->Arg(10000);
BENCHMARK(BM_DomainTrie_WildcardLarge)->Arg(100)->Arg(1000);

// Shadowsocks
BENCHMARK(BM_ShadowsocksDecodePsk);

BENCHMARK_MAIN();
