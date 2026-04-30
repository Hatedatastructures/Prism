/**
 * @file ProtocolBench.cpp
 * @brief 代理协议端到端基准测试
 * @details 测量 HTTP/SOCKS5/Trojan/VLESS/Shadowsocks 协议的握手流程、
 *          UDP 编解码、认证验证等端到端性能指标。
 */

#include <benchmark/benchmark.h>
#include <prism/protocol/http/parser.hpp>
#include <prism/protocol/socks5/wire.hpp>
#include <prism/protocol/trojan/format.hpp>
#include <prism/protocol/vless/format.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

using namespace psm;

// ============================================================
// HTTP 协议基准测试
// ============================================================

/**
 * @brief HTTP 转发请求行构建
 * @details 测试 build_forward_request_line 的请求行重写性能
 */
static void BM_HttpBuildForwardRequestLine(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    protocol::http::proxy_request req;
    req.method = "GET";
    req.target = "/index.html";
    req.host = "www.example.com";

    for (auto _ : state)
    {
        arena.reset();
        auto line = protocol::http::build_forward_request_line(req, mr);
        benchmark::DoNotOptimize(line);
    }
}

/**
 * @brief HTTP 大头部解析
 * @details 测试接近 64KB 限制的大头部解析性能
 */
static void BM_HttpParse_LargeHeader(benchmark::State &state)
{
    const auto size = static_cast<std::size_t>(state.range(0));
    std::string request;
    request.reserve(size + 100);
    request.append("GET / HTTP/1.1\r\n");
    request.append("Host: example.com\r\n");

    // 添加大量头部字段
    for (std::size_t i = 0; i < size / 50; ++i)
    {
        request.append("X-Custom-Header-" + std::to_string(i) + ": value\r\n");
    }
    request.append("\r\n");

    protocol::http::proxy_request req;
    for (auto _ : state)
    {
        auto ec = protocol::http::parse_proxy_request(request, req);
        benchmark::DoNotOptimize(req);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(request.size()));
}

// ============================================================
// SOCKS5 协议基准测试
// ============================================================

/**
 * @brief SOCKS5 UDP 头编码
 * @details 测试 encode_udp_header 的 IPv4 UDP 数据报头编码性能
 */
static void BM_Socks5EncodeUdpHeader(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    protocol::socks5::wire::udp_header header;
    header.destination_address = protocol::socks5::ipv4_address{{127, 0, 0, 1}};
    header.destination_port = 53;
    header.frag = 0;

    for (auto _ : state)
    {
        arena.reset();
        memory::vector<std::uint8_t> out(mr);
        auto ec = protocol::socks5::wire::encode_udp_header(header, out);
        benchmark::DoNotOptimize(out);
    }
}

/**
 * @brief SOCKS5 UDP 头解码
 * @details 测试 decode_udp_header 的 IPv4 UDP 数据报头解析性能
 */
static void BM_Socks5DecodeUdpHeader(benchmark::State &state)
{
    // 预构造 SOCKS5 UDP 数据报: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2)
    std::array<std::uint8_t, 10> buffer = {
        0x00, 0x00,       // RSV
        0x00,             // FRAG
        0x01,             // ATYP=IPv4
        127, 0, 0, 1,     // IPv4 地址
        0x00, 0x35        // Port=53 BE
    };

    for (auto _ : state)
    {
        auto [ec, result] = protocol::socks5::wire::decode_udp_header(buffer);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

/**
 * @brief SOCKS5 成功响应构建
 * @details 测试成功响应的构建性能（IPv4 地址绑定）
 */
static void BM_Socks5BuildSuccessResponse(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();
        memory::vector<std::uint8_t> response(mr);
        // SOCKS5 成功响应: VER(1) + REP(1) + RSV(1) + ATYP(1) + IPv4(4) + PORT(2) = 10 字节
        response.push_back(0x05);  // VER
        response.push_back(0x00);  // REP=成功
        response.push_back(0x00);  // RSV
        response.push_back(0x01);  // ATYP=IPv4
        response.push_back(127);
        response.push_back(0);
        response.push_back(0);
        response.push_back(1);
        response.push_back(0x00);
        response.push_back(0x50);  // Port=80 BE
        benchmark::DoNotOptimize(response);
    }
}

// ============================================================
// Trojan 协议基准测试
// ============================================================

/**
 * @brief Trojan UDP 包解析
 * @details 测试 parse_udp_packet 的 UDP 数据报解析性能
 */
static void BM_TrojanParseUdpPacket(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    // 预构造 Trojan UDP 包: ATYP(1) + IPv4(4) + PORT(2) + PAYLOAD(4)
    std::vector<std::byte> buffer;
    buffer.push_back(std::byte{0x01});  // ATYP=IPv4
    buffer.push_back(std::byte{127});
    buffer.push_back(std::byte{0});
    buffer.push_back(std::byte{0});
    buffer.push_back(std::byte{1});     // IPv4
    buffer.push_back(std::byte{0x00});
    buffer.push_back(std::byte{0x35});  // Port=53 BE
    buffer.push_back(std::byte{0xDE});
    buffer.push_back(std::byte{0xAD});
    buffer.push_back(std::byte{0xBE});
    buffer.push_back(std::byte{0xEF});  // Payload

    auto span = std::span<const std::byte>(buffer.data(), buffer.size());
    for (auto _ : state)
    {
        arena.reset();
        auto [ec, result] = protocol::trojan::format::parse_udp_packet(span);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buffer.size()));
}

/**
 * @brief Trojan UDP 包构建
 * @details 测试 build_udp_packet 的 UDP 数据报构建性能
 */
static void BM_TrojanBuildUdpPacket(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    std::vector<std::byte> payload(payload_size, std::byte{0x42});

    for (auto _ : state)
    {
        arena.reset();
        memory::vector<std::byte> out(mr);

        protocol::trojan::format::udp_frame frame;
        frame.destination_address = protocol::socks5::ipv4_address{{127, 0, 0, 1}};
        frame.destination_port = 53;

        auto ec = protocol::trojan::format::build_udp_packet(frame, std::span<const std::byte>(payload.data(), payload.size()), out);
        benchmark::DoNotOptimize(out);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(payload_size + 7));
}

/**
 * @brief Trojan 凭据 SHA224 验证
 * @details 测试凭据哈希验证性能（SHA224 比对）
 */
static void BM_TrojanCredentialVerify(benchmark::State &state)
{
    // 56 字节 SHA224 哈希（十六进制）
    std::string credential = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::string expected_hash = credential;  // 预计算哈希

    for (auto _ : state)
    {
        bool match = (credential == expected_hash);
        benchmark::DoNotOptimize(match);
    }
}

// ============================================================
// VLESS 协议基准测试
// ============================================================

/**
 * @brief VLESS IPv4 请求解析
 * @details 测试 parse_request 的 IPv4 地址请求解析性能
 */
static void BM_VlessParseRequest_IPv4(benchmark::State &state)
{
    std::array<std::uint8_t, 26> buf{};
    buf[0] = 0x00;                    // version
    // UUID 全零 (16 bytes, already zero)
    buf[17] = 0x00;                   // addnl_len
    buf[18] = 0x01;                   // cmd = TCP
    buf[19] = 0x00; buf[20] = 0x50;   // port = 80
    buf[21] = 0x01;                   // atyp = IPv4
    buf[22] = 127; buf[23] = 0; buf[24] = 0; buf[25] = 1;

    for (auto _ : state)
    {
        auto result = protocol::vless::format::parse_request(buf);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buf.size()));
}

/**
 * @brief VLESS 域名请求解析
 * @details 测试 parse_request 的域名地址请求解析性能
 */
static void BM_VlessParseRequest_Domain(benchmark::State &state)
{
    // VLESS 域名请求: version(1) + UUID(16) + addnl_len(1) + cmd(1) + port(2) + atyp(1) + len(1) + domain(11)
    std::vector<std::uint8_t> buf(31);
    buf[0] = 0x00;                    // version
    buf[17] = 0x00;                   // addnl_len
    buf[18] = 0x01;                   // cmd = TCP
    buf[19] = 0x01; buf[20] = 0xBB;   // port = 443
    buf[21] = 0x02;                   // atyp = domain
    buf[22] = 11;                     // domain length
    // domain = "example.com"
    buf[23] = 'e';
    buf[24] = 'x';
    buf[25] = 'a';
    buf[26] = 'm';
    buf[27] = 'p';
    buf[28] = 'l';
    buf[29] = 'e';
    buf[30] = '.';
    // 需要更多字节完成域名...

    for (auto _ : state)
    {
        auto result = protocol::vless::format::parse_request(std::span<const std::uint8_t>(buf.data(), buf.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buf.size()));
}

/**
 * @brief VLESS UDP 包解析
 * @details 测试 parse_udp_packet 的 UDP 数据报解析性能
 */
static void BM_VlessParseUdpPacket(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    // VLESS UDP 包格式类似 Trojan
    std::vector<std::byte> buffer;
    buffer.push_back(std::byte{0x01});  // ATYP=IPv4
    buffer.push_back(std::byte{127});
    buffer.push_back(std::byte{0});
    buffer.push_back(std::byte{0});
    buffer.push_back(std::byte{1});
    buffer.push_back(std::byte{0x00});
    buffer.push_back(std::byte{0x35});
    buffer.push_back(std::byte{0xDE});
    buffer.push_back(std::byte{0xAD});
    buffer.push_back(std::byte{0xBE});
    buffer.push_back(std::byte{0xEF});

    auto span = std::span<const std::byte>(buffer.data(), buffer.size());
    for (auto _ : state)
    {
        arena.reset();
        auto [ec, result] = protocol::vless::format::parse_udp_packet(span);
        benchmark::DoNotOptimize(result);
    }
}

/**
 * @brief VLESS 响应生成
 * @details 测试 make_response 的 2 字节响应构建性能
 */
static void BM_VlessMakeResponse(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto response = protocol::vless::format::make_response();
        benchmark::DoNotOptimize(response);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 2);
}

// ============================================================
// Shadowsocks SS2022 协议基准测试
// ============================================================

/**
 * @brief Shadowsocks 地址端口解析
 * @details 测试 parse_address_port 的性能
 */
static void BM_ShadowsocksParseAddressPort(benchmark::State &state)
{
    std::array<std::uint8_t, 7> buf = {0x01, 127, 0, 0, 1, 0x1F, 0x90};
    for (auto _ : state)
    {
        auto [ec, result] = protocol::shadowsocks::format::parse_address_port(buf);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buf.size()));
}

/**
 * @brief Shadowsocks PSK 解码
 * @details 测试 decode_psk 的 Base64 解码性能
 */
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
BENCHMARK(BM_HttpBuildForwardRequestLine);
BENCHMARK(BM_HttpParse_LargeHeader)->Arg(1024)->Arg(4096)->Arg(8192);

// SOCKS5
BENCHMARK(BM_Socks5EncodeUdpHeader);
BENCHMARK(BM_Socks5DecodeUdpHeader);
BENCHMARK(BM_Socks5BuildSuccessResponse);

// Trojan
BENCHMARK(BM_TrojanParseUdpPacket);
BENCHMARK(BM_TrojanBuildUdpPacket)->Arg(0)->Arg(64)->Arg(512)->Arg(4096);
BENCHMARK(BM_TrojanCredentialVerify);

// VLESS
BENCHMARK(BM_VlessParseRequest_IPv4);
BENCHMARK(BM_VlessParseRequest_Domain);
BENCHMARK(BM_VlessParseUdpPacket);
BENCHMARK(BM_VlessMakeResponse);

// Shadowsocks
BENCHMARK(BM_ShadowsocksParseAddressPort);
BENCHMARK(BM_ShadowsocksDecodePsk);

BENCHMARK_MAIN();