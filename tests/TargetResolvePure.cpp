/**
 * @file TargetResolvePure.cpp
 * @brief 目标地址解析测试 — parse/resolve 各分支覆盖
 */

#include <prism/memory.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/recognition/target.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    // ─── parse ────────────────────────────────────

    void TestParseEmpty(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("", host, port);
        runner.Check(host.empty(), "parse: empty -> host empty");
        runner.Check(port.empty(), "parse: empty -> port empty");
    }

    void TestParseHostPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com:443", host, port);
        runner.Check(host == "example.com", "parse: host=example.com");
        runner.Check(port == "443", "parse: port=443");
    }

    void TestParseHostOnly(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com", host, port);
        runner.Check(host == "example.com", "parse: host-only host");
        runner.Check(port.empty(), "parse: host-only port empty");
    }

    void TestParseIPv6WithPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]:8080", host, port);
        runner.Check(host == "::1", "parse: ipv6 host=::1");
        runner.Check(port == "8080", "parse: ipv6 port=8080");
    }

    void TestParseIPv6NoPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]", host, port);
        runner.Check(host == "::1", "parse: ipv6 no-port host=::1");
        runner.Check(port == "80", "parse: ipv6 no-port default=80");
    }

    void TestParseIPv6NoBracket(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1", host, port);
        runner.Check(host == "[::1", "parse: unclosed bracket host");
    }

    void TestParseMultipleColons(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("::1", host, port);
        runner.Check(host == "::1", "parse: bare ipv6 host");
        runner.Check(port == "80", "parse: bare ipv6 default port=80");
    }

    void TestParseHostEmptyPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com:", host, port);
        runner.Check(host == "example.com", "parse: empty port host");
        runner.Check(port == "80", "parse: empty port default=80");
    }

    void TestParseIpv4WithPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("192.168.1.1:443", host, port);
        runner.Check(host == "192.168.1.1", "parse: IPv4 host");
        runner.Check(port == "443", "parse: IPv4 port");
    }

    void TestParseIpv6Scoped(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[fe80::1%eth0]:8080", host, port);
        runner.Check(host == "fe80::1%eth0", "parse: IPv6 scoped host");
        runner.Check(port == "8080", "parse: IPv6 scoped port");
    }

    // ─── resolve(string_view) ────────────────────

    void TestResolveHostPort(TestRunner &runner)
    {
        auto t = psm::recognition::resolve("example.com:8080");
        runner.Check(t.positive, "resolve sv: positive=true");
        runner.Check(t.host == "example.com", "resolve sv: host=example.com");
        runner.Check(t.port == "8080", "resolve sv: port=8080");
    }

    void TestResolveHostOnly(TestRunner &runner)
    {
        auto t = psm::recognition::resolve("example.com");
        runner.Check(t.positive, "resolve sv: host-only positive=true");
        runner.Check(t.host == "example.com", "resolve sv: host-only host");
    }

    void TestResolveIpv6(TestRunner &runner)
    {
        auto t = psm::recognition::resolve("[::1]:443");
        runner.Check(t.host == "::1", "resolve sv: IPv6 host");
        runner.Check(t.port == "443", "resolve sv: IPv6 port");
    }

    // ─── resolve(proxy_request) — CONNECT ────────

    void TestResolveConnect(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com:443";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.positive, "resolve: CONNECT positive=true");
        runner.Check(t.host == "example.com", "resolve: CONNECT host");
        runner.Check(t.port == "443", "resolve: CONNECT port=443");
    }

    void TestResolveConnectIPv6(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "[::1]:443";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "::1", "resolve: CONNECT ipv6 host");
        runner.Check(t.port == "443", "resolve: CONNECT ipv6 port");
    }

    void TestResolveConnectNoPort(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve: CONNECT no-port host");
        runner.Check(t.port == "443", "resolve: CONNECT no-port default=443");
    }

    void TestResolveConnectIPv6NoPort(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "[::1]";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "::1", "resolve: CONNECT IPv6 no-port host");
        runner.Check(t.port == "443", "resolve: CONNECT IPv6 no-port default=443");
    }

    // ─── resolve(proxy_request) — absolute URI ───

    void TestResolveAbsoluteHttp(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "http://example.com/path";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.positive, "resolve: http:// positive=true");
        runner.Check(t.host == "example.com", "resolve: http:// host");
        runner.Check(t.port == "80", "resolve: http:// default port=80");
    }

    void TestResolveAbsoluteHttps(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "https://example.com:8443/api";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve: https:// host");
        runner.Check(t.port == "8443", "resolve: https:// port=8443");
    }

    void TestResolveAbsoluteHttpsDefaultPort(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "POST";
        req.target = "https://example.com/submit";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve: https default port host");
        runner.Check(t.port == "443", "resolve: https default port=443");
    }

    void TestResolveAbsoluteNoPath(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "http://example.com";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve: http no path host");
        runner.Check(t.port == "80", "resolve: http no path port=80");
    }

    // ─── resolve(proxy_request) — relative path ──

    void TestResolveRelativePath(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "/index.html";
        req.host = "backend.example.com:8080";

        auto t = psm::recognition::resolve(req);
        runner.Check(!t.positive, "resolve: relative path positive=false");
        runner.Check(t.host == "backend.example.com", "resolve: relative host");
        runner.Check(t.port == "8080", "resolve: relative port");
    }

    void TestResolveRelativeHostOnly(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "/index.html";
        req.host = "backend.local";

        auto t = psm::recognition::resolve(req);
        runner.Check(!t.positive, "resolve: relative host only positive=false");
        runner.Check(t.host == "backend.local", "resolve: relative host only host");
        runner.Check(t.port == "80", "resolve: relative host only default port");
    }

    void TestResolveProxyBadScheme(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "ftp://example.com/";
        req.host = "fallback.com:9090";
        auto t = psm::recognition::resolve(req);
        runner.Check(!t.positive, "resolve: bad scheme positive=false");
        runner.Check(t.host == "fallback.com", "resolve: bad scheme fallback host");
        runner.Check(t.port == "9090", "resolve: bad scheme fallback port");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TargetResolvePure");

    TestParseEmpty(runner);
    TestParseHostPort(runner);
    TestParseHostOnly(runner);
    TestParseIPv6WithPort(runner);
    TestParseIPv6NoPort(runner);
    TestParseIPv6NoBracket(runner);
    TestParseMultipleColons(runner);
    TestParseHostEmptyPort(runner);
    TestParseIpv4WithPort(runner);
    TestParseIpv6Scoped(runner);

    TestResolveHostPort(runner);
    TestResolveHostOnly(runner);
    TestResolveIpv6(runner);

    TestResolveConnect(runner);
    TestResolveConnectIPv6(runner);
    TestResolveConnectNoPort(runner);
    TestResolveConnectIPv6NoPort(runner);

    TestResolveAbsoluteHttp(runner);
    TestResolveAbsoluteHttps(runner);
    TestResolveAbsoluteHttpsDefaultPort(runner);
    TestResolveAbsoluteNoPath(runner);

    TestResolveRelativePath(runner);
    TestResolveRelativeHostOnly(runner);
    TestResolveProxyBadScheme(runner);

    return runner.Summary();
}
