/**
 * @file Socks5FrameBench.cpp
 * @brief SOCKS5 协议帧操作基准测试
 * @details 测量 SOCKS5 协议帧操作性能：
 *          握手头解析、UDP 头编解码、端口解析、
 *          用户名/密码认证解析与响应构建、
 *          通用地址解析（IPv4/IPv6/域名/端口）。
 *          帧操作在每次 SOCKS5 代理连接的握手和转发中被调用。
 */

#include <benchmark/benchmark.h>
#include <prism/protocol/socks5/framing.hpp>
#include <prism/protocol/common/framing.hpp>
#include <prism/foundation/memory/container.hpp>

#include <cstdint>

namespace
{

namespace wire = psm::protocol::socks5::wire;
namespace cframing = psm::protocol::common::framing;
namespace common = psm::protocol::common;

// ============================================================
// 测试数据
// ============================================================

/// SOCKS5 请求头：version=5, cmd=connect, rsv=0, atyp=ipv4
const psm::memory::vector<std::uint8_t> socks5_header_data = {
    0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50};

/// 端口数据：80（大端序）
const psm::memory::vector<std::uint8_t> port_data = {0x00, 0x50};

/// IPv4 数据：127.0.0.1
const psm::memory::vector<std::uint8_t> ipv4_data = {127, 0, 0, 1};

/// IPv6 数据：::1（环回地址）
const psm::memory::vector<std::uint8_t> ipv6_data = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

/// 域名数据：长度前缀 + "example.com"
const psm::memory::vector<std::uint8_t> domain_data = {
    11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};

/// 用户名/密码认证：version=1, username="user", password="pass"
const psm::memory::vector<std::uint8_t> pw_auth_data = {
    0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'};

/// 非法版本号：version=4（非 SOCKS5）
const psm::memory::vector<std::uint8_t> invalid_version_data = {0x04, 0x01, 0x00, 0x01};

/// SOCKS5 UDP 数据报（IPv4）：RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2)
const psm::memory::vector<std::uint8_t> udp_hdr_data = {
    0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50};

// ============================================================
// 基准测试
// ============================================================

/// @brief 测量 SOCKS5 请求头解析性能
void BM_Socks5Frame_ParseHeader(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = wire::parse_header(socks5_header_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_ParseHeader);

/// @brief 测量 SOCKS5 端口解码性能
void BM_Socks5Frame_DecodePort(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = wire::decode_port(port_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_DecodePort);

/// @brief 测量 SOCKS5 UDP 头编码性能
void BM_Socks5Frame_EncodeHdr(benchmark::State &state)
{
    common::ipv4_address addr{};
    addr.bytes = {127, 0, 0, 1};
    const wire::udp_header hdr{
        .destination_address = addr,
        .destination_port = 80,
        .frag = 0,
    };

    for (auto _ : state)
    {
        psm::memory::vector<std::uint8_t> out;
        const auto ec = wire::encode_hdr(hdr, out);
        benchmark::DoNotOptimize(ec);
        benchmark::DoNotOptimize(out.data());
    }
}
BENCHMARK(BM_Socks5Frame_EncodeHdr);

/// @brief 测量 SOCKS5 UDP 头解码性能
void BM_Socks5Frame_DecodeHdr(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = wire::decode_hdr(udp_hdr_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_DecodeHdr);

/// @brief 测量 SOCKS5 用户名/密码认证解析性能
void BM_Socks5Frame_ParsePwAuth(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = wire::parse_pw_auth(pw_auth_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_ParsePwAuth);

/// @brief 测量 SOCKS5 用户名/密码认证响应构建性能
void BM_Socks5Frame_BuildPwAuthResp(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto resp = wire::build_pw_auth_response(wire::auth_result::success);
        benchmark::DoNotOptimize(resp);
    }
}
BENCHMARK(BM_Socks5Frame_BuildPwAuthResp);

/// @brief 测量通用 IPv4 地址解析性能
void BM_Socks5Frame_ParseIPv4(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = cframing::parse_ipv4(ipv4_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_ParseIPv4);

/// @brief 测量通用 IPv6 地址解析性能
void BM_Socks5Frame_ParseIPv6(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = cframing::parse_ipv6(ipv6_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_ParseIPv6);

/// @brief 测量通用域名解析性能
void BM_Socks5Frame_ParseDomain(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = cframing::parse_domain(domain_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_ParseDomain);

/// @brief 测量通用端口解析性能
void BM_Socks5Frame_ParsePort(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = cframing::parse_port(port_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_ParsePort);

/// @brief 测量非法版本号输入的请求头解析性能
void BM_Socks5Frame_ParseHeader_Invalid(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto result = wire::parse_header(invalid_version_data);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Socks5Frame_ParseHeader_Invalid);

/// @brief 测量 SOCKS5 UDP 头编解码完整往返性能
void BM_Socks5Frame_UdpRoundtrip(benchmark::State &state)
{
    common::ipv4_address addr{};
    addr.bytes = {127, 0, 0, 1};
    const wire::udp_header hdr{
        .destination_address = addr,
        .destination_port = 80,
        .frag = 0,
    };

    for (auto _ : state)
    {
        psm::memory::vector<std::uint8_t> out;
        const auto enc_ec = wire::encode_hdr(hdr, out);
        benchmark::DoNotOptimize(enc_ec);

        const auto dec_result = wire::decode_hdr(out);
        benchmark::DoNotOptimize(dec_result);
    }
}
BENCHMARK(BM_Socks5Frame_UdpRoundtrip);

} // namespace

BENCHMARK_MAIN();
