/**
 * @file TunnelBench.cpp
 * @brief 代理协议隧道握手基准测试
 * @details 测量各协议握手阶段（解析请求、构建响应）的性能。
 *          纯透传协议（HTTP/SOCKS5/Trojan/VLESS）握手后数据
 *          转发由系统网络 I/O 决定，无法在内存中模拟。
 *          SS2022 是唯一在隧道期间持续 AEAD 加解密的协议。
 */

#include <benchmark/benchmark.h>
#include <prism/protocol/http/parser.hpp>
#include <prism/protocol/socks5/wire.hpp>
#include <prism/protocol/trojan/format.hpp>
#include <prism/protocol/vless/format.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

using namespace psm;

// ============================================================
// HTTP 协议握手：解析请求 + 构建转发请求行
// ============================================================

static void BM_HttpHandshake(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    std::string http_request =
        "CONNECT www.example.com:443 HTTP/1.1\r\n"
        "Host: www.example.com:443\r\n"
        "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
        "\r\n";

    for (auto _ : state)
    {
        arena.reset();

        // 解析请求
        protocol::http::proxy_request req;
        auto ec = protocol::http::parse_proxy_request(http_request, req);
        if (fault::failed(ec))
            state.SkipWithError("HTTP parsing failed");

        // 构建转发请求行
        auto line = protocol::http::build_forward_request_line(req, mr);
        benchmark::DoNotOptimize(line);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(http_request.size()));
}

// ============================================================
// SOCKS5 协议握手：解析头部 + 构建成功响应
// ============================================================

static void BM_Socks5Handshake(benchmark::State &state)
{
    // 预构造 SOCKS5 请求：VER(1) + NMETHODS(1) + METHODS(1) + CMD(1) + RSV(1) + ATYP(1) + DST ADDR(4) + DST PORT(2)
    std::array<std::uint8_t, 12> request = {
        0x05,       // VER
        0x01,       // NMETHODS
        0x00,       // METHOD=NO AUTH
        0x01,       // CMD=CONNECT
        0x00,       // RSV
        0x01,       // ATYP=IPv4
        127, 0, 0, 1, // DST.ADDR
        0x01, 0xBB    // DST.PORT=443 BE
    };

    for (auto _ : state)
    {
        // 解析头部
        auto [ec, header] = protocol::socks5::wire::parse_header(request);
        if (fault::failed(ec))
            state.SkipWithError("SOCKS5 header parsing failed");

        // 解析地址
        std::span<const std::uint8_t> addr_buf(request.data() + 5, 4);
        auto [addr_ec, addr] = protocol::socks5::wire::parse_ipv4(addr_buf);
        if (fault::failed(addr_ec))
            state.SkipWithError("SOCKS5 address parsing failed");

        // 解析端口
        auto [port_ec, port] = protocol::socks5::wire::decode_port(
            std::span<const std::uint8_t>(request.data() + 9, 2));
        if (fault::failed(port_ec))
            state.SkipWithError("SOCKS5 port parsing failed");

        benchmark::DoNotOptimize(header);
        benchmark::DoNotOptimize(addr);
        benchmark::DoNotOptimize(port);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(request.size()));
}

// ============================================================
// Trojan 协议握手：解析凭据 + 解析地址
// ============================================================

static void BM_TrojanHandshake(benchmark::State &state)
{
    // 预构造 Trojan 握手数据：56B 凭据 + CRLF + CMD(1) + ATYP(1) + IPv4(4) + PORT(2)
    std::array<std::uint8_t, 66> data{};
    for (std::size_t i = 0; i < 56; ++i)
        data[i] = static_cast<std::uint8_t>('a');
    data[56] = static_cast<std::uint8_t>('\r');
    data[57] = static_cast<std::uint8_t>('\n');
    data[58] = 0x01; // CMD=CONNECT
    data[59] = 0x01; // ATYP=IPv4
    data[60] = 127;
    data[61] = 0;
    data[62] = 0;
    data[63] = 1;
    data[64] = 0x01;
    data[65] = 0xBB;

    for (auto _ : state)
    {
        // 解析 56 字节凭据
        auto cred_view = std::span<const std::uint8_t>(data.data(), 56);
        auto [cred_ec, credential] = protocol::trojan::format::parse_credential(cred_view);
        if (fault::failed(cred_ec))
            state.SkipWithError("Trojan credential parsing failed");

        // 解析 CRLF
        auto crlf_view = std::span<const std::uint8_t>(data.data() + 56, 2);
        auto crlf_ec = protocol::trojan::format::parse_crlf(crlf_view);
        if (fault::failed(crlf_ec))
            state.SkipWithError("Trojan CRLF parsing failed");

        // 解析命令 + 地址类型
        auto cmd_view = std::span<const std::uint8_t>(data.data() + 58, 2);
        auto [cmd_ec, cmd_atyp] = protocol::trojan::format::parse_cmd_atyp(cmd_view);
        if (fault::failed(cmd_ec))
            state.SkipWithError("Trojan cmd/atyp parsing failed");

        // 解析 IPv4 地址
        auto addr_view = std::span<const std::uint8_t>(data.data() + 60, 4);
        auto [addr_ec, addr] = protocol::trojan::format::parse_ipv4(addr_view);
        if (fault::failed(addr_ec))
            state.SkipWithError("Trojan address parsing failed");

        // 解析端口
        auto port_view = std::span<const std::uint8_t>(data.data() + 64, 2);
        auto [port_ec, port] = protocol::trojan::format::parse_port(port_view);
        if (fault::failed(port_ec))
            state.SkipWithError("Trojan port parsing failed");

        benchmark::DoNotOptimize(credential);
        benchmark::DoNotOptimize(cmd_atyp);
        benchmark::DoNotOptimize(addr);
        benchmark::DoNotOptimize(port);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(data.size()));
}

// ============================================================
// VLESS 协议握手：解析请求
// ============================================================

static void BM_VlessHandshake(benchmark::State &state)
{
    // 预构造 VLESS 请求：version(1) + UUID(16) + addnl_len(1) + cmd(1) + port(2) + atyp(1) + IPv4(4)
    std::array<std::uint8_t, 26> request{};
    request[0] = 0x00;                    // version
    // UUID 全零 (16 bytes)
    request[17] = 0x00;                   // addnl_len
    request[18] = 0x01;                   // cmd = TCP
    request[19] = 0x01; request[20] = 0xBB; // port = 443
    request[21] = 0x01;                   // atyp = IPv4
    request[22] = 127; request[23] = 0; request[24] = 0; request[25] = 1;

    for (auto _ : state)
    {
        auto result = protocol::vless::format::parse_request(
            std::span<const std::uint8_t>(request.data(), request.size()));
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(request.size()));
}

// ============================================================
// SS2022 协议握手：PSK 解码 + 密钥派生
// ============================================================

static void BM_Ss2022Handshake(benchmark::State &state)
{
    for (auto _ : state)
    {
        // PSK Base64 解码
        auto [ec, psk] = protocol::shadowsocks::format::decode_psk("AAAAAAAAAAAAAAAAAAAAAA==");
        if (fault::failed(ec))
            state.SkipWithError("SS2022 PSK decode failed");
        benchmark::DoNotOptimize(psk);
    }
}

// ============================================================
// BENCHMARK 注册
// ============================================================

// 协议握手
BENCHMARK(BM_HttpHandshake);
BENCHMARK(BM_Socks5Handshake);
BENCHMARK(BM_TrojanHandshake);
BENCHMARK(BM_VlessHandshake);
BENCHMARK(BM_Ss2022Handshake);

BENCHMARK_MAIN();
