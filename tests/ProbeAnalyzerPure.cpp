/**
 * @file ProbeAnalyzerPure.cpp
 * @brief 协议检测纯函数测试 — detect/is_http_request/detect_tls
 */

#include <prism/memory.hpp>
#include <prism/protocol/types.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::protocol::protocol_type;
    using psm::recognition::probe::detect;
    using psm::recognition::probe::detect_tls;
    using psm::recognition::probe::is_http_request;

    // ─── detect() ──────────────────────────────────

    void TestDetectEmpty(TestRunner &runner)
    {
        runner.Check(detect("") == protocol_type::unknown,
                     "detect: empty -> unknown");
    }

    void TestDetectSocks5(TestRunner &runner)
    {
        const char data[] = "\x05\x01\x00";
        runner.Check(detect({data, 3}) == protocol_type::socks5,
                     "detect: 0x05 -> socks5");
    }

    void TestDetectTls(TestRunner &runner)
    {
        const char data[] = "\x16\x03\x01";
        runner.Check(detect({data, 3}) == protocol_type::tls,
                     "detect: 0x16 0x03 -> tls");
    }

    void TestDetectTlsSingleByte(TestRunner &runner)
    {
        const char data[] = "\x16";
        // 单字节 0x16 不够两字节 → 不是 TLS，也不是 HTTP/SOCKS5 → shadowsocks
        runner.Check(detect({data, 1}) == protocol_type::shadowsocks,
                     "detect: 0x16 alone -> shadowsocks");
    }

    void TestDetectHttp(TestRunner &runner)
    {
        runner.Check(detect("GET / HTTP/1.1\r\n") == protocol_type::http,
                     "detect: GET -> http");
        runner.Check(detect("POST /api HTTP/1.1\r\n") == protocol_type::http,
                     "detect: POST -> http");
        runner.Check(detect("CONNECT example.com:443 HTTP/1.1\r\n") == protocol_type::http,
                     "detect: CONNECT -> http");
    }

    void TestDetectShadowsocks(TestRunner &runner)
    {
        // 任意不匹配已知协议的数据
        const char data[] = "\x01\x02\x03\x04";
        runner.Check(detect({data, 4}) == protocol_type::shadowsocks,
                     "detect: random bytes -> shadowsocks");
    }

    // ─── is_http_request() ─────────────────────────

    void TestIsHttpRequestMethods(TestRunner &runner)
    {
        runner.Check(is_http_request("GET /"), "is_http: GET");
        runner.Check(is_http_request("POST /"), "is_http: POST");
        runner.Check(is_http_request("HEAD /"), "is_http: HEAD");
        runner.Check(is_http_request("PUT /"), "is_http: PUT");
        runner.Check(is_http_request("DELETE /"), "is_http: DELETE");
        runner.Check(is_http_request("CONNECT host:443"), "is_http: CONNECT");
        runner.Check(is_http_request("OPTIONS /"), "is_http: OPTIONS");
        runner.Check(is_http_request("TRACE /"), "is_http: TRACE");
        runner.Check(is_http_request("PATCH /"), "is_http: PATCH");
    }

    void TestIsHttpRequestNegative(TestRunner &runner)
    {
        runner.Check(!is_http_request(""), "is_http: empty=false");
        runner.Check(!is_http_request("GE"), "is_http: too short=false");
        runner.Check(!is_http_request("get /"), "is_http: lowercase=false");
    }

    // ─── detect_tls() ──────────────────────────────

    void TestDetectTlsInnerHttp(TestRunner &runner)
    {
        runner.Check(detect_tls("GET / HTTP/1.1\r\n") == protocol_type::http,
                     "detect_tls: GET -> http");
    }

    void TestDetectTlsInnerVless(TestRunner &runner)
    {
        // VLESS: byte[0]=0x00, byte[17]=0x00, byte[18]=0x01(cmd), byte[21]=0x01(atyp)
        std::string buf(22, '\0');
        buf[18] = 0x01; // command: tcp
        buf[21] = 0x01; // address type: ipv4
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::vless,
                     "detect_tls: vless pattern");
    }

    void TestDetectTlsInnerVlessUdp(TestRunner &runner)
    {
        std::string buf(22, '\0');
        buf[18] = 0x02; // command: udp
        buf[21] = 0x03; // address type: domain
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::vless,
                     "detect_tls: vless udp+domain");
    }

    void TestDetectTlsInnerVlessMux(TestRunner &runner)
    {
        std::string buf(22, '\0');
        buf[18] = static_cast<char>(0x7F); // command: mux
        buf[21] = 0x02;                    // address type: ipv6
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::vless,
                     "detect_tls: vless mux+ipv6");
    }

    void TestDetectTlsInnerVlessBadVersion(TestRunner &runner)
    {
        std::string buf(22, '\0');
        buf[0] = 0x01; // 非零版本
        buf[18] = 0x01;
        buf[21] = 0x01;
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown,
                     "detect_tls: bad version -> unknown");
    }

    void TestDetectTlsInnerVlessBadCommand(TestRunner &runner)
    {
        std::string buf(22, '\0');
        // buf[18] = 0x00 (invalid command)
        buf[21] = 0x01;
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown,
                     "detect_tls: bad command -> unknown");
    }

    void TestDetectTlsInnerTrojan(TestRunner &runner)
    {
        // Trojan: 56 hex bytes + \r\n + cmd(0x01) + atyp(0x01)
        std::string buf(60, 'a'); // 56 个 hex 字符
        buf[56] = '\r';
        buf[57] = '\n';
        buf[58] = static_cast<char>(0x01); // tcp
        buf[59] = static_cast<char>(0x01); // ipv4
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::trojan,
                     "detect_tls: trojan pattern");
    }

    void TestDetectTlsInnerTrojanBadHex(TestRunner &runner)
    {
        std::string buf(60, 'a');
        buf[30] = '\x01'; // 非 hex 字符
        buf[56] = '\r';
        buf[57] = '\n';
        buf[58] = static_cast<char>(0x01);
        buf[59] = static_cast<char>(0x01);
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown,
                     "detect_tls: trojan bad hex -> unknown");
    }

    void TestDetectTlsInnerTrojanBadCRLF(TestRunner &runner)
    {
        std::string buf(60, 'a');
        buf[56] = '\n'; // 缺少 \r
        buf[57] = '\n';
        buf[58] = static_cast<char>(0x01);
        buf[59] = static_cast<char>(0x01);
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown,
                     "detect_tls: trojan bad crlf -> unknown");
    }

    void TestDetectTlsInnerShortData(TestRunner &runner)
    {
        runner.Check(detect_tls("") == protocol_type::unknown,
                     "detect_tls: empty -> unknown");
        runner.Check(detect_tls("\x00") == protocol_type::unknown,
                     "detect_tls: 1 byte -> unknown");
    }

    void TestDetectTlsInnerSixtyPlusUnknown(TestRunner &runner)
    {
        // 60+ 字节不匹配任何模式
        std::string buf(64, '\xFF');
        runner.Check(detect_tls({buf.data(), buf.size()}) == protocol_type::unknown,
                     "detect_tls: 60+ garbage -> unknown");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ProbeAnalyzerPure");

    TestDetectEmpty(runner);
    TestDetectSocks5(runner);
    TestDetectTls(runner);
    TestDetectTlsSingleByte(runner);
    TestDetectHttp(runner);
    TestDetectShadowsocks(runner);

    TestIsHttpRequestMethods(runner);
    TestIsHttpRequestNegative(runner);

    TestDetectTlsInnerHttp(runner);
    TestDetectTlsInnerVless(runner);
    TestDetectTlsInnerVlessUdp(runner);
    TestDetectTlsInnerVlessMux(runner);
    TestDetectTlsInnerVlessBadVersion(runner);
    TestDetectTlsInnerVlessBadCommand(runner);
    TestDetectTlsInnerTrojan(runner);
    TestDetectTlsInnerTrojanBadHex(runner);
    TestDetectTlsInnerTrojanBadCRLF(runner);
    TestDetectTlsInnerShortData(runner);
    TestDetectTlsInnerSixtyPlusUnknown(runner);

    return runner.Summary();
}
