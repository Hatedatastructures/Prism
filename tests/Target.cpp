/**
 * @file Target.cpp
 * @brief 目标地址解析单元测试
 * @details 测试 recognition::parse、resolve(proxy_request)、resolve(host:port) 等函数。
 */

#include <prism/memory.hpp>
#include <prism/recognition/target.hpp>
#include <prism/trace/spdlog.hpp>

#include <string_view>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;
using memory_string = psm::memory::string;

namespace
{
    void TestParseIPv4WithPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("192.168.1.1:8080", host, port);
        runner.Check(host == "192.168.1.1", "parse IPv4 host");
        runner.Check(port == "8080", "parse IPv4 port");
    }

    void TestParseIPv4NoPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("192.168.1.1", host, port);
        runner.Check(host == "192.168.1.1", "parse IPv4 no port host");
        // No colon → port stays empty or default
    }

    void TestParseIPv6WithPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]:443", host, port);
        runner.Check(host == "::1", "parse IPv6 host");
        runner.Check(port == "443", "parse IPv6 port");
    }

    void TestParseIPv6NoPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1]", host, port);
        runner.Check(host == "::1", "parse IPv6 no port host");
        runner.Check(port == "80", "parse IPv6 no port default 80");
    }

    void TestParseIPv6NoClosingBracket(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("[::1", host, port);
        runner.Check(host == "[::1", "parse IPv6 unclosed bracket → raw host");
    }

    void TestParseDomainWithPort(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("example.com:443", host, port);
        runner.Check(host == "example.com", "parse domain host");
        runner.Check(port == "443", "parse domain port");
    }

    void TestParseEmpty(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse("", host, port);
        runner.Check(host.empty(), "parse empty → empty host");
    }

    void TestParseMultipleColons(TestRunner &runner)
    {
        // Multiple colons without brackets → treated as IPv6 literal, port defaults to 80
        psm::memory::string host, port;
        psm::recognition::parse("::1:8080:9090", host, port);
        // first_colon != last_colon → whole string is host, port = "80"
        runner.Check(!host.empty(), "multi-colon host not empty");
    }

    void TestParsePortOnly(TestRunner &runner)
    {
        psm::memory::string host, port;
        psm::recognition::parse(":8080", host, port);
        runner.Check(host.empty(), "parse port-only → empty host");
        runner.Check(port == "8080", "parse port-only port");
    }

    void TestResolveHostPort(TestRunner &runner)
    {
        auto t = psm::recognition::resolve("example.com:443");
        runner.Check(t.host == "example.com", "resolve host:port host");
        runner.Check(t.port == "443", "resolve host:port port");
        runner.Check(t.positive == true, "resolve host:port positive");
    }

    void TestResolveConnect(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com:443";
        req.host = "example.com:443";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve CONNECT host");
        runner.Check(t.port == "443", "resolve CONNECT port");
        runner.Check(t.positive == true, "resolve CONNECT positive");
    }

    void TestResolveConnectNoExplicitPort(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "CONNECT";
        req.target = "example.com";
        req.host = "example.com";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve CONNECT no explicit port host");
        runner.Check(t.port == "443", "resolve CONNECT no explicit port defaults 443");
    }

    void TestResolveAbsoluteUriHttp(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "http://example.com:8080/path";
        req.host = "example.com:8080";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve absolute URI host");
        runner.Check(t.port == "8080", "resolve absolute URI port");
        runner.Check(t.positive == true, "resolve absolute URI positive");
    }

    void TestResolveAbsoluteUriHttps(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "https://example.com/path";
        req.host = "example.com";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve HTTPS URI host");
        runner.Check(t.port == "443", "resolve HTTPS URI default port");
        runner.Check(t.positive == true, "resolve HTTPS URI positive");
    }

    void TestResolveRelativePath(TestRunner &runner)
    {
        psm::protocol::http::proxy_request req;
        req.method = "GET";
        req.target = "/index.html";
        req.host = "example.com:8080";

        auto t = psm::recognition::resolve(req);
        runner.Check(t.host == "example.com", "resolve relative path host");
        runner.Check(t.port == "8080", "resolve relative path port");
        runner.Check(t.positive == false, "resolve relative path NOT positive");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("Target");

    TestParseIPv4WithPort(runner);
    TestParseIPv4NoPort(runner);
    TestParseIPv6WithPort(runner);
    TestParseIPv6NoPort(runner);
    TestParseIPv6NoClosingBracket(runner);
    TestParseDomainWithPort(runner);
    TestParseEmpty(runner);
    TestParseMultipleColons(runner);
    TestParsePortOnly(runner);
    TestResolveHostPort(runner);
    TestResolveConnect(runner);
    TestResolveConnectNoExplicitPort(runner);
    TestResolveAbsoluteUriHttp(runner);
    TestResolveAbsoluteUriHttps(runner);
    TestResolveRelativePath(runner);

    return runner.Summary();
}
