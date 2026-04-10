#include <benchmark/benchmark.h>
#include <prism/protocol/http/parser.hpp>
#include <prism/protocol/socks5/wire.hpp>
#include <prism/protocol/trojan/format.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/resolve/packet.hpp>
#include <prism/resolve/rules.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/memory/pool.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

using namespace psm;

// HTTP Benchmark
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
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(http_get_request.size()));
}

static void BM_HttpParseProxyRequest_Connect(benchmark::State &state)
{
    protocol::http::proxy_request req;
    for (auto _ : state)
    {
        fault::code ec = protocol::http::parse_proxy_request(http_connect_request, req);
        if (fault::failed(ec))
        {
            state.SkipWithError("HTTP Parsing failed");
        }
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(http_connect_request.size()));
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

// SOCKS5 Benchmark（纯解析)
static void BM_Socks5DecodeHeader(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 4> buffer = {0x05, 0x01, 0x00, 0x01};
    for (auto _ : state)
    {
        auto [ec, header] = protocol::socks5::wire::parse_header(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("SOCKS5 header parsing failed");
        }
        benchmark::DoNotOptimize(header);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_Socks5DecodeIPv4(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 4> buffer = {192, 168, 1, 1};
    for (auto _ : state)
    {
        auto [ec, addr] = protocol::socks5::wire::parse_ipv4(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("SOCKS5 ipv4 parsing failed");
        }
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_Socks5DecodeDomain(benchmark::State &state)
{
    std::array<std::uint8_t, 12> buffer{};
    buffer[0] = 11;
    buffer[1] = 'e';
    buffer[2] = 'x';
    buffer[3] = 'a';
    buffer[4] = 'm';
    buffer[5] = 'p';
    buffer[6] = 'l';
    buffer[7] = 'e';
    buffer[8] = '.';
    buffer[9] = 'c';
    buffer[10] = 'o';
    buffer[11] = 'm';

    for (auto _ : state)
    {
        auto [ec, addr] = protocol::socks5::wire::parse_domain(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("SOCKS5 domain parsing failed");
        }
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_Socks5DecodeIPv6(benchmark::State &state)
{
    std::array<std::uint8_t, 16> buffer{};
    for (std::size_t i = 0; i < buffer.size(); ++i)
    {
        buffer[i] = static_cast<std::uint8_t>(i);
    }
    for (auto _ : state)
    {
        auto [ec, addr] = protocol::socks5::wire::parse_ipv6(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("SOCKS5 ipv6 parsing failed");
        }
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_Socks5DecodeDomain_VarLen(benchmark::State &state)
{
    const std::size_t len = static_cast<std::size_t>(state.range(0));
    std::array<std::uint8_t, 256> buffer{};
    buffer[0] = static_cast<std::uint8_t>(len);
    for (std::size_t i = 0; i < len; ++i)
    {
        buffer[1 + i] = static_cast<std::uint8_t>('a' + (i % 26));
    }

    const auto view = std::span<const std::uint8_t>(buffer.data(), 1 + len);
    for (auto _ : state)
    {
        auto [ec, addr] = protocol::socks5::wire::parse_domain(view);
        if (fault::failed(ec))
        {
            state.SkipWithError("SOCKS5 domain parsing failed");
        }
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(view.size()));
}

static void BM_Socks5DecodePort(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 2> buffer = {0x1F, 0x90}; // 8080
    for (auto _ : state)
    {
        auto [ec, port] = protocol::socks5::wire::decode_port(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("SOCKS5 port parsing failed");
        }
        benchmark::DoNotOptimize(port);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

// Trojan Benchmark（纯解析）
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

static void BM_TrojanDecodeCrlf(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 2> buffer = {'\r', '\n'};
    for (auto _ : state)
    {
        auto ec = protocol::trojan::format::parse_crlf(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("Trojan CRLF parsing failed");
        }
        benchmark::DoNotOptimize(ec);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_TrojanDecodeCmdAtyp(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 2> buffer = {0x01, 0x01}; // CONNECT + IPv4
    for (auto _ : state)
    {
        auto [ec, header] = protocol::trojan::format::parse_cmd_atyp(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("Trojan cmd/atyp parsing failed");
        }
        benchmark::DoNotOptimize(header);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_TrojanDecodeIPv4(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 4> buffer = {127, 0, 0, 1};
    for (auto _ : state)
    {
        auto [ec, addr] = protocol::trojan::format::parse_ipv4(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("Trojan ipv4 parsing failed");
        }
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_TrojanDecodeIPv6(benchmark::State &state)
{
    std::array<std::uint8_t, 16> buffer{};
    for (std::size_t i = 0; i < buffer.size(); ++i)
    {
        buffer[i] = static_cast<std::uint8_t>(0xF0u ^ static_cast<std::uint8_t>(i));
    }
    for (auto _ : state)
    {
        auto [ec, addr] = protocol::trojan::format::parse_ipv6(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("Trojan ipv6 parsing failed");
        }
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_TrojanDecodeDomain_VarLen(benchmark::State &state)
{
    const std::size_t len = static_cast<std::size_t>(state.range(0));
    std::array<std::uint8_t, 256> buffer{};
    buffer[0] = static_cast<std::uint8_t>(len);
    for (std::size_t i = 0; i < len; ++i)
    {
        buffer[1 + i] = static_cast<std::uint8_t>('b' + (i % 25));
    }

    const auto view = std::span<const std::uint8_t>(buffer.data(), 1 + len);
    for (auto _ : state)
    {
        auto [ec, addr] = protocol::trojan::format::parse_domain(view);
        if (fault::failed(ec))
        {
            state.SkipWithError("Trojan domain parsing failed");
        }
        benchmark::DoNotOptimize(addr);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(view.size()));
}

static void BM_TrojanDecodePort(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 2> buffer = {0x00, 0x50}; // 80
    for (auto _ : state)
    {
        auto [ec, port] = protocol::trojan::format::parse_port(buffer);
        if (fault::failed(ec))
        {
            state.SkipWithError("Trojan port parsing failed");
        }
        benchmark::DoNotOptimize(port);
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
// DNS Packet Benchmark
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
// Crypto Benchmark
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
    // 构建 ~1KB base64 输入
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
// Protocol Analysis Benchmark
// ============================================================

static void BM_AnalysisResolveIPv4(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto t = protocol::analysis::resolve("192.168.1.1:443");
        benchmark::DoNotOptimize(t);
    }
}

static void BM_AnalysisResolveIPv6(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto t = protocol::analysis::resolve("[::1]:443");
        benchmark::DoNotOptimize(t);
    }
}

static void BM_AnalysisDetectInnerHttp(benchmark::State &state)
{
    std::string http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    for (auto _ : state)
    {
        auto result = protocol::analysis::detect_inner(http_request);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(http_request.size()));
}

static void BM_AnalysisDetectInnerTrojan(benchmark::State &state)
{
    std::string trojan_like(60, 'a');
    trojan_like[56] = '\r';
    trojan_like[57] = '\n';
    trojan_like[58] = 0x01;
    trojan_like[59] = 0x01;
    for (auto _ : state)
    {
        auto result = protocol::analysis::detect_inner(trojan_like);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(trojan_like.size()));
}

static void BM_AnalysisDetectInnerUndetermined(benchmark::State &state)
{
    std::string short_data(30, 'a');
    for (auto _ : state)
    {
        auto result = protocol::analysis::detect_inner(short_data);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(short_data.size()));
}

// ============================================================
// DNS Rules Engine Benchmark
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
// BENCHMARK 注册
// ============================================================

// HTTP
BENCHMARK(BM_HttpParseProxyRequest_Get);
BENCHMARK(BM_HttpParseProxyRequest_Connect);
BENCHMARK(BM_HttpParseProxyRequest_PostBody)->Arg(0)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_HttpExtractRelativePath);

// SOCKS5
BENCHMARK(BM_Socks5DecodeHeader);
BENCHMARK(BM_Socks5DecodeIPv4);
BENCHMARK(BM_Socks5DecodeDomain);
BENCHMARK(BM_Socks5DecodeIPv6);
BENCHMARK(BM_Socks5DecodeDomain_VarLen)->Arg(4)->Arg(16)->Arg(64)->Arg(255);
BENCHMARK(BM_Socks5DecodePort);

// Trojan
BENCHMARK(BM_TrojanDecodeCredential);
BENCHMARK(BM_TrojanDecodeCredential_Invalid);
BENCHMARK(BM_TrojanDecodeCrlf);
BENCHMARK(BM_TrojanDecodeCmdAtyp);
BENCHMARK(BM_TrojanDecodeIPv4);
BENCHMARK(BM_TrojanDecodeIPv6);
BENCHMARK(BM_TrojanDecodeDomain_VarLen)->Arg(4)->Arg(16)->Arg(64)->Arg(255);
BENCHMARK(BM_TrojanDecodePort);

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

// Protocol Analysis
BENCHMARK(BM_AnalysisResolveIPv4);
BENCHMARK(BM_AnalysisResolveIPv6);
BENCHMARK(BM_AnalysisDetectInnerHttp);
BENCHMARK(BM_AnalysisDetectInnerTrojan);
BENCHMARK(BM_AnalysisDetectInnerUndetermined);

// DNS Rules
BENCHMARK(BM_DomainTrieSearchHit);
BENCHMARK(BM_DomainTrieSearchWildcard);
BENCHMARK(BM_DomainTrieSearchMiss);
BENCHMARK(BM_RulesEngineMatch);

BENCHMARK_MAIN();
