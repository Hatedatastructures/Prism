/**
 * @file ProbeAnalyzerPure.cpp
 * @brief 协议检测纯函数测试 — detect/is_http_request/detect_tls
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/stealth/recognition/probe/analyzer.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace
{
    using psm::connect::protocol_type;
    using psm::recognition::probe::detect;
    using psm::recognition::probe::detect_tls;
    using psm::recognition::probe::is_http_request;

    // ─── detect() ──────────────────────────────────

    TEST(ProbeAnalyzerPure, DetectEmpty)
    {
        EXPECT_TRUE(detect("") == protocol_type::unknown)
            << "detect: empty -> unknown";
    }

    TEST(ProbeAnalyzerPure, DetectSocks5)
    {
        const char data[] = "\x05\x01\x00";
        EXPECT_TRUE(detect({data, 3}) == protocol_type::socks5)
            << "detect: 0x05 -> socks5";
    }

    TEST(ProbeAnalyzerPure, DetectTls)
    {
        const char data[] = "\x16\x03\x01";
        EXPECT_TRUE(detect({data, 3}) == protocol_type::tls)
            << "detect: 0x16 0x03 -> tls";
    }

    TEST(ProbeAnalyzerPure, DetectTlsSingleByte)
    {
        const char data[] = "\x16";
        // 单字节 0x16 不够两字节 → 不是 TLS，也不是 HTTP/SOCKS5 → shadowsocks
        EXPECT_TRUE(detect({data, 1}) == protocol_type::shadowsocks)
            << "detect: 0x16 alone -> shadowsocks";
    }

    TEST(ProbeAnalyzerPure, DetectHttp)
    {
        EXPECT_TRUE(detect("GET / HTTP/1.1\r\n") == protocol_type::http)
            << "detect: GET -> http";
        EXPECT_TRUE(detect("POST /api HTTP/1.1\r\n") == protocol_type::http)
            << "detect: POST -> http";
        EXPECT_TRUE(detect("CONNECT example.com:443 HTTP/1.1\r\n") == protocol_type::http)
            << "detect: CONNECT -> http";
    }

    TEST(ProbeAnalyzerPure, DetectShadowsocks)
    {
        // 任意不匹配已知协议的数据
        const char data[] = "\x01\x02\x03\x04";
        EXPECT_TRUE(detect({data, 4}) == protocol_type::shadowsocks)
            << "detect: random bytes -> shadowsocks";
    }

    // ─── is_http_request() ─────────────────────────

    TEST(ProbeAnalyzerPure, IsHttpRequestMethods)
    {
        EXPECT_TRUE(is_http_request("GET /")) << "is_http: GET";
        EXPECT_TRUE(is_http_request("POST /")) << "is_http: POST";
        EXPECT_TRUE(is_http_request("HEAD /")) << "is_http: HEAD";
        EXPECT_TRUE(is_http_request("PUT /")) << "is_http: PUT";
        EXPECT_TRUE(is_http_request("DELETE /")) << "is_http: DELETE";
        EXPECT_TRUE(is_http_request("CONNECT host:443")) << "is_http: CONNECT";
        EXPECT_TRUE(is_http_request("OPTIONS /")) << "is_http: OPTIONS";
        EXPECT_TRUE(is_http_request("TRACE /")) << "is_http: TRACE";
        EXPECT_TRUE(is_http_request("PATCH /")) << "is_http: PATCH";
    }

    TEST(ProbeAnalyzerPure, IsHttpRequestNegative)
    {
        EXPECT_TRUE(!is_http_request("")) << "is_http: empty=false";
        EXPECT_TRUE(!is_http_request("GE")) << "is_http: too short=false";
        EXPECT_TRUE(!is_http_request("get /")) << "is_http: lowercase=false";
    }

    // ─── detect_tls() ──────────────────────────────

    TEST(ProbeAnalyzerPure, DetectTlsInnerHttp)
    {
        EXPECT_TRUE(detect_tls("GET / HTTP/1.1\r\n") == protocol_type::http)
            << "detect_tls: GET -> http";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerVless)
    {
        // VLESS: byte[0]=0x00, byte[17]=0x00, byte[18]=0x01(cmd), byte[21]=0x01(atyp)
        std::string buf(22, '\0');
        buf[18] = 0x01; // command: tcp
        buf[21] = 0x01; // address type: ipv4
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::vless)
            << "detect_tls: vless pattern";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerVlessUdp)
    {
        std::string buf(22, '\0');
        buf[18] = 0x02; // command: udp
        buf[21] = 0x03; // address type: domain
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::vless)
            << "detect_tls: vless udp+domain";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerVlessMux)
    {
        std::string buf(22, '\0');
        buf[18] = static_cast<char>(0x7F); // command: mux
        buf[21] = 0x02;                    // address type: ipv6
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::vless)
            << "detect_tls: vless mux+ipv6";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerVlessBadVersion)
    {
        std::string buf(22, '\0');
        buf[0] = 0x01; // 非零版本
        buf[18] = 0x01;
        buf[21] = 0x01;
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown)
            << "detect_tls: bad version -> unknown";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerVlessBadCommand)
    {
        std::string buf(22, '\0');
        // buf[18] = 0x00 (invalid command)
        buf[21] = 0x01;
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown)
            << "detect_tls: bad command -> unknown";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerTrojan)
    {
        // Trojan: 56 hex bytes + \r\n + cmd(0x01) + atyp(0x01)
        std::string buf(60, 'a'); // 56 个 hex 字符
        buf[56] = '\r';
        buf[57] = '\n';
        buf[58] = static_cast<char>(0x01); // tcp
        buf[59] = static_cast<char>(0x01); // ipv4
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::trojan)
            << "detect_tls: trojan pattern";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerTrojanBadHex)
    {
        std::string buf(60, 'a');
        buf[30] = '\x01'; // 非 hex 字符
        buf[56] = '\r';
        buf[57] = '\n';
        buf[58] = static_cast<char>(0x01);
        buf[59] = static_cast<char>(0x01);
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown)
            << "detect_tls: trojan bad hex -> unknown";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerTrojanBadCRLF)
    {
        std::string buf(60, 'a');
        buf[56] = '\n'; // 缺少 \r
        buf[57] = '\n';
        buf[58] = static_cast<char>(0x01);
        buf[59] = static_cast<char>(0x01);
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown)
            << "detect_tls: trojan bad crlf -> unknown";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerShortData)
    {
        EXPECT_TRUE(detect_tls("") == protocol_type::unknown)
            << "detect_tls: empty -> unknown";
        EXPECT_TRUE(detect_tls("\x00") == protocol_type::unknown)
            << "detect_tls: 1 byte -> unknown";
    }

    TEST(ProbeAnalyzerPure, DetectTlsInnerSixtyPlusUnknown)
    {
        // 60+ 字节不匹配任何模式
        std::string buf(64, '\xFF');
        EXPECT_TRUE(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown)
            << "detect_tls: 60+ garbage -> unknown";
    }
} // namespace
