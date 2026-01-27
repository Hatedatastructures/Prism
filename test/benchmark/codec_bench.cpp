#include <benchmark/benchmark.h>
#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/socks5/wire.hpp>
#include <forward-engine/protocol/trojan/wire.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/gist.hpp>
#include <array>
#include <span>
#include <string>
#include <string_view>

using namespace ngx;

// HTTP Benchmark（纯解析）
static const std::string http_get_request =
    "GET /index.html HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    "Accept-Encoding: gzip, deflate, sdch\r\n"
    "Accept-Language: en-US,en;q=0.8\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

static std::string make_http_post_request_with_body(std::size_t body_size)
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

static std::string make_http_response_with_body(std::size_t body_size)
{
    std::string body(body_size, 'y');
    std::string response;
    response.reserve(256 + body.size());
    response.append("HTTP/1.1 200 OK\r\n");
    response.append("Server: ForwardEngine-Bench\r\n");
    response.append("Content-Type: application/octet-stream\r\n");
    response.append("Content-Length: ");
    response.append(std::to_string(body.size()));
    response.append("\r\n");
    response.append("Connection: keep-alive\r\n");
    response.append("\r\n");
    response.append(body);
    return response;
}

static void BM_HttpDeserialize(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    protocol::http::request req(arena.get());

    for (auto _ : state)
    {
        req.clear();
        gist::code ec = protocol::http::deserialize(http_get_request, req);
        if (ec != gist::code::success)
        {
            state.SkipWithError("HTTP Parsing failed");
        }
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(http_get_request.size()));
}

static void BM_HttpDeserialize_PostBody(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    protocol::http::request req(arena.get());
    const auto payload = make_http_post_request_with_body(static_cast<std::size_t>(state.range(0)));

    for (auto _ : state)
    {
        req.clear();
        gist::code ec = protocol::http::deserialize(payload, req);
        if (ec != gist::code::success)
        {
            state.SkipWithError("HTTP Parsing failed");
        }
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.size()));
}

static void BM_HttpDeserialize_Response(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    protocol::http::response resp(arena.get());
    const auto payload = make_http_response_with_body(static_cast<std::size_t>(state.range(0)));

    for (auto _ : state)
    {
        resp.clear();
        gist::code ec = protocol::http::deserialize(payload, resp);
        if (ec != gist::code::success)
        {
            state.SkipWithError("HTTP Parsing failed");
        }
        benchmark::DoNotOptimize(resp);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(payload.size()));
}

static void BM_HttpSerialize_Request(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::unsynchronized_pool pool;
    auto mr = &pool;
    protocol::http::request req(mr);
    req.method(protocol::http::verb::get);
    req.target("/index.html");
    req.version(11);
    req.set(protocol::http::field::host, "www.example.com");
    req.set(protocol::http::field::user_agent, "ForwardEngine-Bench");
    req.set(protocol::http::field::accept, "*/*");
    req.keep_alive(true);

    const auto sample = protocol::http::serialize(req, mr);
    const auto bytes_per_iter = static_cast<std::int64_t>(sample.size());

    for (auto _ : state)
    {
        auto out = protocol::http::serialize(req, mr);
        benchmark::DoNotOptimize(out);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * bytes_per_iter);
}

static void BM_HttpSerialize_Response(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::unsynchronized_pool pool;
    auto mr = &pool;
    protocol::http::response resp(mr);
    resp.version(11);
    resp.status(200);
    resp.reason("OK");
    resp.set(protocol::http::field::server, "ForwardEngine-Bench");
    resp.set(protocol::http::field::content_type, "text/plain");
    resp.body(std::string_view{"hello"});
    resp.keep_alive(true);

    const auto sample = protocol::http::serialize(resp, mr);
    const auto bytes_per_iter = static_cast<std::int64_t>(sample.size());

    for (auto _ : state)
    {
        auto out = protocol::http::serialize(resp, mr);
        benchmark::DoNotOptimize(out);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * bytes_per_iter);
}

// SOCKS5 Benchmark（纯解析）
static void BM_Socks5DecodeHeader(benchmark::State &state)
{
    // VER(1) | CMD(1) | RSV(1) | ATYP(1)
    static constexpr std::array<std::uint8_t, 4> buffer = {0x05, 0x01, 0x00, 0x01};
    for (auto _ : state)
    {
        auto [ec, header] = protocol::socks5::wire::decode_header(buffer);
        if (ec != gist::code::success)
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
        auto [ec, addr] = protocol::socks5::wire::decode_ipv4(buffer);
        if (ec != gist::code::success)
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
        auto [ec, addr] = protocol::socks5::wire::decode_domain(buffer);
        if (ec != gist::code::success)
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
        auto [ec, addr] = protocol::socks5::wire::decode_ipv6(buffer);
        if (ec != gist::code::success)
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
        auto [ec, addr] = protocol::socks5::wire::decode_domain(view);
        if (ec != gist::code::success)
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
        if (ec != gist::code::success)
        {
            state.SkipWithError("SOCKS5 port parsing failed");
        }
        benchmark::DoNotOptimize(port);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

// Trojan Benchmark（纯解析）
static void BM_TrojanDecodeHash(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 56> buffer =
        {
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};

    for (auto _ : state)
    {
        auto [ec, hash] = protocol::trojan::wire::decode_hash(buffer);
        if (ec != gist::code::success)
        {
            state.SkipWithError("Trojan hash parsing failed");
        }
        benchmark::DoNotOptimize(hash);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_TrojanDecodeCrlf(benchmark::State &state)
{
    static constexpr std::array<std::uint8_t, 2> buffer = {'\r', '\n'};
    for (auto _ : state)
    {
        auto ec = protocol::trojan::wire::decode_crlf(buffer);
        if (ec != gist::code::success)
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
        auto [ec, header] = protocol::trojan::wire::decode_cmd_atyp(buffer);
        if (ec != gist::code::success)
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
        auto [ec, addr] = protocol::trojan::wire::decode_ipv4(buffer);
        if (ec != gist::code::success)
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
        auto [ec, addr] = protocol::trojan::wire::decode_ipv6(buffer);
        if (ec != gist::code::success)
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
        auto [ec, addr] = protocol::trojan::wire::decode_domain(view);
        if (ec != gist::code::success)
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
        auto [ec, port] = protocol::trojan::wire::decode_port(buffer);
        if (ec != gist::code::success)
        {
            state.SkipWithError("Trojan port parsing failed");
        }
        benchmark::DoNotOptimize(port);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

static void BM_TrojanDecodeHash_Invalid(benchmark::State &state)
{
    std::array<std::uint8_t, 56> buffer{};
    buffer.fill('a');
    buffer[7] = 'g';
    for (auto _ : state)
    {
        auto [ec, hash] = protocol::trojan::wire::decode_hash(buffer);
        benchmark::DoNotOptimize(ec);
        benchmark::DoNotOptimize(hash);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

BENCHMARK(BM_HttpDeserialize);
BENCHMARK(BM_HttpDeserialize_PostBody)->Arg(0)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_HttpDeserialize_Response)->Arg(0)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_HttpSerialize_Request);
BENCHMARK(BM_HttpSerialize_Response);
BENCHMARK(BM_Socks5DecodeHeader);
BENCHMARK(BM_Socks5DecodeIPv4);
BENCHMARK(BM_Socks5DecodeDomain);
BENCHMARK(BM_Socks5DecodeIPv6);
BENCHMARK(BM_Socks5DecodeDomain_VarLen)->Arg(4)->Arg(16)->Arg(64)->Arg(255);
BENCHMARK(BM_Socks5DecodePort);
BENCHMARK(BM_TrojanDecodeHash);
BENCHMARK(BM_TrojanDecodeHash_Invalid);
BENCHMARK(BM_TrojanDecodeCrlf);
BENCHMARK(BM_TrojanDecodeCmdAtyp);
BENCHMARK(BM_TrojanDecodeIPv4);
BENCHMARK(BM_TrojanDecodeIPv6);
BENCHMARK(BM_TrojanDecodeDomain_VarLen)->Arg(4)->Arg(16)->Arg(64)->Arg(255);
BENCHMARK(BM_TrojanDecodePort);

BENCHMARK_MAIN();
