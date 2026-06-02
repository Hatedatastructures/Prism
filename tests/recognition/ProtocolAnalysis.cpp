/**
 * @file ProtocolAnalysis.cpp
 * @brief 协议分析模块单元测试
 * @details 测试 recognition::probe::detect() 和 psm::recognition::probe::detect_tls() 函数，
 * 覆盖 SOCKS5/TLS/HTTP/VLESS/Trojan/Shadowsocks 各协议的探测路径、
 * 边界条件和排除法 fallback 逻辑。
 */

#include <prism/protocol/types.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/recognition/target.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace protocol = psm::protocol;
using psm::protocol::protocol_type;

/**
 * @brief 测试 recognition::probe::detect() 外层协议探测
 */
TEST(ProtocolAnalysis, Detect)
{
    // 空数据 -> unknown
    EXPECT_TRUE(psm::recognition::probe::detect("") == protocol_type::unknown)
        << "detect: empty data -> unknown";

    // SOCKS5 (0x05)
    std::string socks5_data = "\x05\x01\x00";
    EXPECT_TRUE(psm::recognition::probe::detect(socks5_data) == protocol_type::socks5)
        << "detect: 0x05 -> socks5";

    // TLS (0x16 0x03)
    std::string tls_data = "\x16\x03\x01\x00\x05";
    EXPECT_TRUE(psm::recognition::probe::detect(tls_data) == protocol_type::tls)
        << "detect: 0x16 0x03 -> tls";

    // 单字节 0x16（非 TLS，需 2 字节验证） -> shadowsocks fallback
    std::string not_tls = "\x16\x00";
    EXPECT_TRUE(psm::recognition::probe::detect(not_tls) == protocol_type::shadowsocks)
        << "detect: 0x16 0x00 -> shadowsocks (not TLS)";

    // HTTP GET
    EXPECT_TRUE(psm::recognition::probe::detect("GET / HTTP/1.1\r\n") == protocol_type::http)
        << "detect: GET -> http";

    // HTTP POST
    EXPECT_TRUE(psm::recognition::probe::detect("POST /api HTTP/1.1\r\n") == protocol_type::http)
        << "detect: POST -> http";

    // HTTP CONNECT
    EXPECT_TRUE(psm::recognition::probe::detect("CONNECT host:443 HTTP/1.1\r\n") == protocol_type::http)
        << "detect: CONNECT -> http";

    // 随机字节 -> shadowsocks fallback
    std::string random_data = "\x42\x00\xFF\xAB\xCD";
    EXPECT_TRUE(psm::recognition::probe::detect(random_data) == protocol_type::shadowsocks)
        << "detect: random bytes -> shadowsocks fallback";
}

/**
 * @brief 测试 analysis::detect_tls() TLS 内层协议探测
 */
TEST(ProtocolAnalysis, DetectTls)
{
    // HTTP over TLS
    EXPECT_TRUE(psm::recognition::probe::detect_tls("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") == protocol_type::http)
        << "detect_tls: HTTP GET -> http";

    // HTTP 最短前缀 "GET "
    EXPECT_TRUE(psm::recognition::probe::detect_tls("GET ") == protocol_type::http)
        << "detect_tls: minimal GET -> http";

    // VLESS TCP: version=0x00, UUID(16)=zeros, addnl_len=0x00, cmd=0x01, port=0x00 0x50, atyp=0x01, ipv4=127.0.0.1
    {
        std::string vless_data(22, '\0');
        vless_data[0] = 0x00;  // version
        // byte[1..16] = UUID (zeros)
        vless_data[17] = 0x00; // addnl_len
        vless_data[18] = 0x01; // cmd = tcp
        vless_data[19] = 0x00; // port high
        vless_data[20] = 0x50; // port low (80)
        vless_data[21] = 0x01; // atyp = ipv4
        EXPECT_TRUE(psm::recognition::probe::detect_tls(vless_data) == protocol_type::vless)
            << "detect_tls: valid VLESS -> vless";
    }

    // VLESS invalid version
    {
        std::string vless_data(22, '\0');
        vless_data[0] = 0x01; // invalid version
        vless_data[18] = 0x01; // cmd
        vless_data[21] = 0x01; // atyp
        EXPECT_TRUE(psm::recognition::probe::detect_tls(vless_data) != protocol_type::vless)
            << "detect_tls: invalid version -> not vless";
    }

    // VLESS invalid command
    {
        std::string vless_data(22, '\0');
        vless_data[18] = 0x05; // invalid cmd
        vless_data[21] = 0x01; // atyp
        EXPECT_TRUE(psm::recognition::probe::detect_tls(vless_data) != protocol_type::vless)
            << "detect_tls: invalid cmd -> not vless";
    }

    // Trojan: 56 hex chars + CRLF + cmd + atyp
    {
        std::string trojan_data(60, 'a');
        trojan_data[56] = '\r';
        trojan_data[57] = '\n';
        trojan_data[58] = 0x01; // cmd = connect
        trojan_data[59] = 0x01; // atyp = ipv4
        EXPECT_TRUE(psm::recognition::probe::detect_tls(trojan_data) == protocol_type::trojan)
            << "detect_tls: valid Trojan -> trojan";
    }

    // Trojan with non-hex chars
    {
        std::string trojan_data(60, 'a');
        trojan_data[30] = 'Z'; // non-hex
        trojan_data[56] = '\r';
        trojan_data[57] = '\n';
        trojan_data[58] = 0x01;
        trojan_data[59] = 0x01;
        EXPECT_TRUE(psm::recognition::probe::detect_tls(trojan_data) != protocol_type::trojan)
            << "detect_tls: non-hex char -> not trojan";
    }

    // Trojan invalid cmd
    {
        std::string trojan_data(60, 'a');
        trojan_data[56] = '\r';
        trojan_data[57] = '\n';
        trojan_data[58] = 0x02; // invalid cmd
        trojan_data[59] = 0x01;
        EXPECT_TRUE(psm::recognition::probe::detect_tls(trojan_data) != protocol_type::trojan)
            << "detect_tls: invalid cmd -> not trojan";
    }

    // Short data < 22 bytes -> unknown
    {
        std::string short_data(10, 'x');
        EXPECT_TRUE(psm::recognition::probe::detect_tls(short_data) == protocol_type::unknown)
            << "detect_tls: 10 bytes -> unknown";
    }

    // 22-59 bytes, no match -> unknown
    {
        std::string mid_data(30, 'y');
        EXPECT_TRUE(psm::recognition::probe::detect_tls(mid_data) == protocol_type::unknown)
            << "detect_tls: 30 bytes no match -> unknown";
    }

    // 60+ bytes, no match -> unknown (callers decide fallback)
    {
        std::string long_data(70, 'z');
        EXPECT_TRUE(psm::recognition::probe::detect_tls(long_data) == protocol_type::unknown)
            << "detect_tls: 70 bytes no match -> unknown";
    }
}

/**
 * @brief 测试 analysis::resolve() HTTP 目标地址解析
 */
TEST(ProtocolAnalysis, Resolve)
{
    // CONNECT host:port
    {
        protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com:443";
        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve: CONNECT host";
        EXPECT_TRUE(t.port == "443") << "resolve: CONNECT port";
        EXPECT_TRUE(t.positive == true) << "resolve: CONNECT positive";
    }

    // Absolute URI
    {
        protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "http://example.com:8080/path";
        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve: absolute URI host";
        EXPECT_TRUE(t.port == "8080") << "resolve: absolute URI port";
        EXPECT_TRUE(t.positive == true) << "resolve: absolute URI positive";
    }

    // CONNECT without port (default 443)
    {
        protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com";
        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.port == "443") << "resolve: CONNECT no port -> 443";
    }
}
