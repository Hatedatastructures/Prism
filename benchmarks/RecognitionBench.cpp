/**
 * @file RecognitionBench.cpp
 * @brief 协议识别基准测试
 * @details 测量外层协议探测（probe::detect）、TLS 内层协议识别（detect_tls）、
 *          HTTP 方法检测（is_http_request）和 ClientHello 特征解析（parse_client_hello）性能。
 *          这些函数位于每条新连接的识别热路径上，延迟直接影响连接建立吞吐。
 */

#include <benchmark/benchmark.h>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/recognition/tls/signal.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/memory/container.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

using namespace psm;

// ============================================================
// 测试数据
// ============================================================

/// SOCKS5 握手首字节 0x05 + 01 + 00（无认证）
static const std::string socks5_data = std::string("\x05\x01\x00", 3);

/// TLS ClientHello 前缀（0x16 0x03 0x01 + 长度占位）
static const std::string tls_data =
    std::string("\x16\x03\x01", 3) + std::string(128, '\x00');

/// HTTP GET 请求
static const std::string http_get_data = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

/// HTTP CONNECT 请求
static const std::string http_connect_data = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";

/// Shadowsocks 类数据（随机首字节，非 SOCKS5/TLS/HTTP）
static const std::string ss_data = std::string("\x37\xa4\xb2\xc1\xd0\xe5\xf6\x01\x23\x45\x67\x89\xab\xcd\xef", 16);

/// 未知数据
static const std::string unknown_data = std::string("\x00\x01\x02\x03\x04\x05\x06\x07", 8);

/// 空数据
static const std::string empty_data;

// TLS 内层协议测试数据

/// TLS 内层 HTTP 数据
static const std::string tls_inner_http = "POST /api/v1/data HTTP/1.1\r\nContent-Length: 100\r\n\r\n";

/// TLS 内层 VLESS 数据（version=0, uuid 16B, addon_len=0, cmd=0x01, 预留2B, atype=0x01）
static std::string make_vless_data()
{
    std::string d(22, '\x00');
    d[0] = 0x00;   // version
    // byte 1-16: uuid (全零)
    d[17] = 0x00;  // additional info length
    d[18] = 0x01;  // command: tcp
    // byte 19-20: port
    d[21] = 0x01;  // address type: ipv4
    return d;
}
static const std::string tls_inner_vless = make_vless_data();

/// TLS 内层 Trojan 数据（56 字节十六进制密码 + CRLF + cmd + atype）
static std::string make_trojan_data()
{
    std::string d(60, '\x00');
    for (int i = 0; i < 56; ++i)
        d[i] = "0123456789abcdef"[i % 16];
    d[56] = '\r';
    d[57] = '\n';
    d[58] = 0x01;  // command: connect
    d[59] = 0x01;  // address type: ipv4
    return d;
}
static const std::string tls_inner_trojan = make_trojan_data();

/// TLS 内层未知数据
static const std::string tls_inner_unknown(80, '\xAA');

// ============================================================
// 构造合法 TLS ClientHello 记录用于 parse_client_hello 测试
// ============================================================

/**
 * @brief 构造一个最小但有效的 TLS 1.3 ClientHello 记录
 * @details 包含 SNI、supported_versions、key_share (X25519) 扩展，
 *          使 parse_client_hello 能走完所有解析路径。
 */
static auto build_client_hello_record(std::string_view sni) -> memory::vector<uint8_t>
{
    memory::vector<uint8_t> hello;
    namespace tls_ns = protocol::tls;

    // ClientHello body 先构建
    memory::vector<uint8_t> body;

    // protocol version (TLS 1.2 兼容)
    body.push_back(0x03);
    body.push_back(0x03);

    // random (32 bytes)
    for (int i = 0; i < 32; ++i)
        body.push_back(static_cast<uint8_t>(i));

    // session_id (32 bytes)
    body.push_back(32);
    for (int i = 0; i < 32; ++i)
        body.push_back(static_cast<uint8_t>(i + 0x10));

    // cipher_suites (2 suites)
    body.push_back(0x00);
    body.push_back(0x04);
    tls_ns::write_u16(body, tls_ns::CIPHER_AES_128_GCM_SHA256);
    tls_ns::write_u16(body, 0x1302);

    // compression methods
    body.push_back(0x01);
    body.push_back(0x00);

    // === extensions ===
    memory::vector<uint8_t> exts;

    // SNI extension
    {
        memory::vector<uint8_t> sni_ext;
        tls_ns::write_u16(sni_ext, tls_ns::EXT_SERVER_NAME);
        memory::vector<uint8_t> sni_list;
        sni_list.push_back(tls_ns::SNAME_TYPE_HOSTNAME);
        tls_ns::write_u16(sni_list, static_cast<uint16_t>(sni.size()));
        for (auto c : sni)
            sni_list.push_back(static_cast<uint8_t>(c));
        tls_ns::write_u16(sni_ext, static_cast<uint16_t>(sni_list.size()));
        exts.insert(exts.end(), sni_ext.begin(), sni_ext.end());
        exts.insert(exts.end(), sni_list.begin(), sni_list.end());
    }

    // supported_versions extension
    {
        tls_ns::write_u16(exts, tls_ns::EXT_SUPPORTED_VERSIONS);
        exts.push_back(0x03);
        exts.push_back(0x02);
        tls_ns::write_u16(exts, tls_ns::VERSION_TLS13);
        tls_ns::write_u16(exts, 2);
    }

    // key_share extension (X25519)
    {
        tls_ns::write_u16(exts, tls_ns::EXT_KEY_SHARE);
        memory::vector<uint8_t> ks_data;
        tls_ns::write_u16(ks_data, tls_ns::GROUP_X25519);
        tls_ns::write_u16(ks_data, 32);
        for (int i = 0; i < 32; ++i)
            ks_data.push_back(static_cast<uint8_t>(i));
        tls_ns::write_u16(exts, static_cast<uint16_t>(ks_data.size() + 2));
        exts.push_back(static_cast<uint8_t>(ks_data.size() >> 8));
        exts.push_back(static_cast<uint8_t>(ks_data.size() & 0xFF));
        exts.insert(exts.end(), ks_data.begin(), ks_data.end());
    }

    // extensions length prefix
    tls_ns::write_u16(body, static_cast<uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    // handshake header: type(1) + length(3)
    hello.push_back(tls_ns::HS_CLIENT_HELLO);
    tls_ns::write_u24(hello, body.size());
    hello.insert(hello.end(), body.begin(), body.end());

    // TLS record header
    memory::vector<uint8_t> record;
    record.push_back(tls_ns::CT_HANDSHAKE);
    record.push_back(0x03);
    record.push_back(0x01);
    tls_ns::write_u16(record, static_cast<uint16_t>(hello.size()));
    record.insert(record.end(), hello.begin(), hello.end());

    return record;
}

// 预构建的 ClientHello 记录
static const auto ch_record_short = build_client_hello_record("e.cn");
static const auto ch_record_long = build_client_hello_record("www.example.com");
static const auto ch_record_none = build_client_hello_record("");

// ============================================================
// probe::detect() — 外层协议探测
// ============================================================

static void BM_Probe_Detect_Socks5(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect(socks5_data);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_Detect_Socks5);

static void BM_Probe_Detect_Tls(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect(tls_data);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_Detect_Tls);

static void BM_Probe_Detect_HttpGet(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect(http_get_data);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_Detect_HttpGet);

static void BM_Probe_Detect_HttpConnect(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect(http_connect_data);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_Detect_HttpConnect);

static void BM_Probe_Detect_Shadowsocks(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect(ss_data);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_Detect_Shadowsocks);

static void BM_Probe_Detect_Empty(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect(empty_data);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_Detect_Empty);

// ============================================================
// probe::detect_tls() — TLS 内层协议探测
// ============================================================

static void BM_Probe_DetectTls_Http(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect_tls(tls_inner_http);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_DetectTls_Http);

static void BM_Probe_DetectTls_Vless(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect_tls(tls_inner_vless);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_DetectTls_Vless);

static void BM_Probe_DetectTls_Trojan(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect_tls(tls_inner_trojan);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_DetectTls_Trojan);

static void BM_Probe_DetectTls_Unknown(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect_tls(tls_inner_unknown);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_DetectTls_Unknown);

static void BM_Probe_DetectTls_ShortData(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::detect_tls(ss_data);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_DetectTls_ShortData);

// ============================================================
// probe::is_http_request() — HTTP 方法前缀检测
// ============================================================

static void BM_Probe_IsHttp_Get(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::is_http_request("GET / HTTP/1.1\r\n");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_IsHttp_Get);

static void BM_Probe_IsHttp_Connect(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::is_http_request("CONNECT host:443 HTTP/1.1\r\n");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_IsHttp_Connect);

static void BM_Probe_IsHttp_Patch(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::is_http_request("PATCH /api HTTP/1.1\r\n");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_IsHttp_Patch);

static void BM_Probe_IsHttp_Negative(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::probe::is_http_request("HELLO world this is not http");
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Probe_IsHttp_Negative);

// ============================================================
// tls::parse_client_hello() — ClientHello 特征解析
// ============================================================

static void BM_Tls_ParseClientHello_ShortSni(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::tls::parse_client_hello(ch_record_short);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Tls_ParseClientHello_ShortSni);

static void BM_Tls_ParseClientHello_LongSni(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::tls::parse_client_hello(ch_record_long);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Tls_ParseClientHello_LongSni);

static void BM_Tls_ParseClientHello_NoSni(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = recognition::tls::parse_client_hello(ch_record_none);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Tls_ParseClientHello_NoSni);

BENCHMARK_MAIN();
