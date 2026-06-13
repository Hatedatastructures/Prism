/**
 * @file Target.cpp
 * @brief 目标地址解析单元测试
 * @details 测试 recognition::parse、resolve(proxy_request)、resolve(host:port) 等函数。
 */

#include <prism/core/core.hpp>
#include <prism/stealth/recognition/target.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <string_view>

namespace
{
    using memory_string = psm::memory::string;

    TEST(Target, ParseIPv4WithPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("192.168.1.1:8080", host, port);
        EXPECT_TRUE(host == "192.168.1.1") << "parse IPv4 host";
        EXPECT_TRUE(port == "8080") << "parse IPv4 port";
    }

    TEST(Target, ParseIPv4NoPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("192.168.1.1", host, port);
        EXPECT_TRUE(host == "192.168.1.1") << "parse IPv4 no port host";
        // No colon → port stays empty or default
    }

    TEST(Target, ParseIPv6WithPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]:443", host, port);
        EXPECT_TRUE(host == "::1") << "parse IPv6 host";
        EXPECT_TRUE(port == "443") << "parse IPv6 port";
    }

    TEST(Target, ParseIPv6NoPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]", host, port);
        EXPECT_TRUE(host == "::1") << "parse IPv6 no port host";
        EXPECT_TRUE(port == "80") << "parse IPv6 no port default 80";
    }

    TEST(Target, ParseIPv6NoClosingBracket)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1", host, port);
        EXPECT_TRUE(host == "[::1") << "parse IPv6 unclosed bracket → raw host";
    }

    TEST(Target, ParseDomainWithPort)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com:443", host, port);
        EXPECT_TRUE(host == "example.com") << "parse domain host";
        EXPECT_TRUE(port == "443") << "parse domain port";
    }

    TEST(Target, ParseEmpty)
    {
        psm::memory::string host, port;
        psm::recognition::parse("", host, port);
        EXPECT_TRUE(host.empty()) << "parse empty → empty host";
    }

    TEST(Target, ParseMultipleColons)
    {
        // Multiple colons without brackets → treated as IPv6 literal, port defaults to 80
        psm::memory::string host, port;
        psm::recognition::parse("::1:8080:9090", host, port);
        // first_colon != last_colon → whole string is host, port = "80"
        EXPECT_TRUE(!host.empty()) << "multi-colon host not empty";
    }

    TEST(Target, ParsePortOnly)
    {
        psm::memory::string host, port;
        psm::recognition::parse(":8080", host, port);
        EXPECT_TRUE(host.empty()) << "parse port-only → empty host";
        EXPECT_TRUE(port == "8080") << "parse port-only port";
    }

    TEST(Target, ResolveHostPort)
    {
        auto t = psm::recognition::resolve("example.com:443");
        EXPECT_TRUE(t.host == "example.com") << "resolve host:port host";
        EXPECT_TRUE(t.port == "443") << "resolve host:port port";
        EXPECT_TRUE(t.positive == true) << "resolve host:port positive";
    }

    TEST(Target, ResolveConnect)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com:443";
        req.host = "example.com:443";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve CONNECT host";
        EXPECT_TRUE(t.port == "443") << "resolve CONNECT port";
        EXPECT_TRUE(t.positive == true) << "resolve CONNECT positive";
    }

    TEST(Target, ResolveConnectNoExplicitPort)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com";
        req.host = "example.com";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve CONNECT no explicit port host";
        EXPECT_TRUE(t.port == "443") << "resolve CONNECT no explicit port defaults 443";
    }

    TEST(Target, ResolveAbsoluteUriHttp)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "http://example.com:8080/path";
        req.host = "example.com:8080";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve absolute URI host";
        EXPECT_TRUE(t.port == "8080") << "resolve absolute URI port";
        EXPECT_TRUE(t.positive == true) << "resolve absolute URI positive";
    }

    TEST(Target, ResolveAbsoluteUriHttps)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "https://example.com/path";
        req.host = "example.com";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve HTTPS URI host";
        EXPECT_TRUE(t.port == "443") << "resolve HTTPS URI default port";
        EXPECT_TRUE(t.positive == true) << "resolve HTTPS URI positive";
    }

    TEST(Target, ResolveRelativePath)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "/index.html";
        req.host = "example.com:8080";

        auto t = psm::recognition::resolve(req);
        EXPECT_TRUE(t.host == "example.com") << "resolve relative path host";
        EXPECT_TRUE(t.port == "8080") << "resolve relative path port";
        EXPECT_TRUE(t.positive == false) << "resolve relative path NOT positive";
    }
} // namespace
