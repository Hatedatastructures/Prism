/**
 * @file TargetResolvePure.cpp
 * @brief 目标地址解析测试 — parse/resolve 各分支覆盖
 */

#include <prism/foundation/foundation.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/stealth/recognition/target.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

namespace
{
    // ─── parse ────────────────────────────────────

    TEST(TargetResolvePure, ParseEmpty)
    {
        psm::memory::string host, port;
        psm::recognition::parse("", host, port);
        EXPECT_TRUE(host.empty()) << "parse: empty -> host empty";
        EXPECT_TRUE(port.empty()) << "parse: empty -> port empty";
    }

    TEST(TargetResolvePure, ParseHostPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com:443", host, port);
        EXPECT_TRUE(host == "example.com") << "parse: host=example.com";
        EXPECT_TRUE(port == "443") << "parse: port=443";
    }

    TEST(TargetResolvePure, ParseHostOnly)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com", host, port);
        EXPECT_TRUE(host == "example.com") << "parse: host-only host";
        EXPECT_TRUE(port.empty()) << "parse: host-only port empty";
    }

    TEST(TargetResolvePure, ParseIPv6WithPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]:8080", host, port);
        EXPECT_TRUE(host == "::1") << "parse: ipv6 host=::1";
        EXPECT_TRUE(port == "8080") << "parse: ipv6 port=8080";
    }

    TEST(TargetResolvePure, ParseIPv6NoPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]", host, port);
        EXPECT_TRUE(host == "::1") << "parse: ipv6 no-port host=::1";
        EXPECT_TRUE(port == "80") << "parse: ipv6 no-port default=80";
    }

    TEST(TargetResolvePure, ParseIPv6NoBracket)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1", host, port);
        EXPECT_TRUE(host == "[::1") << "parse: unclosed bracket host";
    }

    TEST(TargetResolvePure, ParseMultipleColons)
    {
        psm::memory::string host, port;
        psm::recognition::parse("::1", host, port);
        EXPECT_TRUE(host == "::1") << "parse: bare ipv6 host";
        EXPECT_TRUE(port == "80") << "parse: bare ipv6 default port=80";
    }

    TEST(TargetResolvePure, ParseHostEmptyPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com:", host, port);
        EXPECT_TRUE(host == "example.com") << "parse: empty port host";
        EXPECT_TRUE(port == "80") << "parse: empty port default=80";
    }

    TEST(TargetResolvePure, ParseIpv4WithPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("192.168.1.1:443", host, port);
        EXPECT_TRUE(host == "192.168.1.1") << "parse: IPv4 host";
        EXPECT_TRUE(port == "443") << "parse: IPv4 port";
    }

    TEST(TargetResolvePure, ParseIpv6Scoped)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[fe80::1%eth0]:8080", host, port);
        EXPECT_TRUE(host == "fe80::1%eth0") << "parse: IPv6 scoped host";
        EXPECT_TRUE(port == "8080") << "parse: IPv6 scoped port";
    }

    // ─── resolve(string_view) ────────────────────

    TEST(TargetResolvePure, ResolveHostPort)
    {
        auto t = psm::recognition::resolve("example.com:8080");
        EXPECT_TRUE(t.positive) << "resolve sv: positive=true";
        EXPECT_TRUE(t.host == "example.com") << "resolve sv: host=example.com";
        EXPECT_TRUE(t.port == "8080") << "resolve sv: port=8080";
    }

    TEST(TargetResolvePure, ResolveHostOnly)
    {
        auto t = psm::recognition::resolve("example.com");
        EXPECT_TRUE(t.positive) << "resolve sv: host-only positive=true";
        EXPECT_TRUE(t.host == "example.com") << "resolve sv: host-only host";
    }

    TEST(TargetResolvePure, ResolveIpv6)
    {
        auto t = psm::recognition::resolve("[::1]:443");
        EXPECT_TRUE(t.host == "::1") << "resolve sv: IPv6 host";
        EXPECT_TRUE(t.port == "443") << "resolve sv: IPv6 port";
    }

    // ─── resolve(proxy_request) — CONNECT ────────

    TEST(TargetResolvePure, ResolveConnect)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com:443";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.positive) << "resolve: CONNECT positive=true";
        EXPECT_TRUE(t.host == "example.com") << "resolve: CONNECT host";
        EXPECT_TRUE(t.port == "443") << "resolve: CONNECT port=443";
    }

    TEST(TargetResolvePure, ResolveConnectIPv6)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "[::1]:443";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "::1") << "resolve: CONNECT ipv6 host";
        EXPECT_TRUE(t.port == "443") << "resolve: CONNECT ipv6 port";
    }

    TEST(TargetResolvePure, ResolveConnectNoPort)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve: CONNECT no-port host";
        EXPECT_TRUE(t.port == "443") << "resolve: CONNECT no-port default=443";
    }

    TEST(TargetResolvePure, ResolveConnectIPv6NoPort)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "[::1]";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "::1") << "resolve: CONNECT IPv6 no-port host";
        EXPECT_TRUE(t.port == "443") << "resolve: CONNECT IPv6 no-port default=443";
    }

    // ─── resolve(proxy_request) — absolute URI ───

    TEST(TargetResolvePure, ResolveAbsoluteHttp)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "http://example.com/path";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.positive) << "resolve: http:// positive=true";
        EXPECT_TRUE(t.host == "example.com") << "resolve: http:// host";
        EXPECT_TRUE(t.port == "80") << "resolve: http:// default port=80";
    }

    TEST(TargetResolvePure, ResolveAbsoluteHttps)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "https://example.com:8443/api";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve: https:// host";
        EXPECT_TRUE(t.port == "8443") << "resolve: https:// port=8443";
    }

    TEST(TargetResolvePure, ResolveAbsoluteHttpsDefaultPort)
    {
        psm::protocol::http::proxy_request req;
        req.method = "POST";
        req.target = "https://example.com/submit";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve: https default port host";
        EXPECT_TRUE(t.port == "443") << "resolve: https default port=443";
    }

    TEST(TargetResolvePure, ResolveAbsoluteNoPath)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "http://example.com";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve: http no path host";
        EXPECT_TRUE(t.port == "80") << "resolve: http no path port=80";
    }

    // ─── resolve(proxy_request) — relative path ──

    TEST(TargetResolvePure, ResolveRelativePath)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "/index.html";
        req.host = "backend.example.com:8080";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(!t.positive) << "resolve: relative path positive=false";
        EXPECT_TRUE(t.host == "backend.example.com") << "resolve: relative host";
        EXPECT_TRUE(t.port == "8080") << "resolve: relative port";
    }

    TEST(TargetResolvePure, ResolveRelativeHostOnly)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "/index.html";
        req.host = "backend.local";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(!t.positive) << "resolve: relative host only positive=false";
        EXPECT_TRUE(t.host == "backend.local") << "resolve: relative host only host";
        EXPECT_TRUE(t.port == "80") << "resolve: relative host only default port";
    }

    TEST(TargetResolvePure, ResolveProxyBadScheme)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "ftp://example.com/";
        req.host = "fallback.com:9090";
        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(!t.positive) << "resolve: bad scheme positive=false";
        EXPECT_TRUE(t.host == "fallback.com") << "resolve: bad scheme fallback host";
        EXPECT_TRUE(t.port == "9090") << "resolve: bad scheme fallback port";
    }
} // namespace
