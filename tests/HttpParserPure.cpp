/**
 * @file HttpParserPure.cpp
 * @brief HTTP parser 纯函数测试
 * @details 测试 parse_req/rel_path/build_fwd 全分支
 */

#include <prism/memory.hpp>
#include <prism/protocol/http/parser.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::protocol::http::parse_req;
    using psm::protocol::http::rel_path;
    using psm::protocol::http::build_fwd;
    using psm::protocol::http::proxy_request;

    void TestParseReqBasicGet(TestRunner &runner)
    {
        const char *raw = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success, "parse_req GET: success");
        runner.Check(req.method == "GET", "parse_req GET: method");
        runner.Check(req.target == "http://example.com/path", "parse_req GET: target");
        runner.Check(req.version == "HTTP/1.1", "parse_req GET: version");
        runner.Check(req.host == "example.com", "parse_req GET: host");
    }

    void TestParseReqConnect(TestRunner &runner)
    {
        const char *raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success, "parse_req CONNECT: success");
        runner.Check(req.method == "CONNECT", "parse_req CONNECT: method");
        runner.Check(req.target == "example.com:443", "parse_req CONNECT: target");
    }

    void TestParseReqWithProxyAuth(TestRunner &runner)
    {
        const char *raw = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success, "parse_req auth: success");
        runner.Check(req.authorization == "Basic dGVzdDp0ZXN0", "parse_req auth: authorization");
    }

    void TestParseReqNoCrlf(TestRunner &runner)
    {
        const char *raw = "GET / HTTP/1.1";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::parse_error, "parse_req: no CRLF");
    }

    void TestParseReqNoSecondSpace(TestRunner &runner)
    {
        const char *raw = "GET /HTTP/1.1\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::parse_error, "parse_req: no second space");
    }

    void TestParseReqNoHeaderEnd(TestRunner &runner)
    {
        const char *raw = "GET / HTTP/1.1\r\nHost: test";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::parse_error, "parse_req: no \\r\\n\\r\\n");
    }

    void TestParseReqEmptyHeader(TestRunner &runner)
    {
        const char *raw = "GET / HTTP/1.1\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success, "parse_req: empty headers -> success");
        runner.Check(req.host.empty(), "parse_req: host empty");
    }

    void TestParseReqCaseInsensitiveHeaders(TestRunner &runner)
    {
        const char *raw = "GET / HTTP/1.1\r\nhOsT: example.com\r\nproxy-AUTHORIZATION: Basic abc\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success, "parse_req case: success");
        runner.Check(req.host == "example.com", "parse_req case: host found");
        runner.Check(req.authorization == "Basic abc", "parse_req case: auth found");
    }

    void TestParseReqOffsets(TestRunner &runner)
    {
        const char *raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success, "parse_req offset: success");
        runner.Check(req.line_end == 16, "parse_req offset: line_end=16");
        runner.Check(req.hdr_end == 27, "parse_req offset: hdr_end=27");
    }

    void TestRelPathHttp(TestRunner &runner)
    {
        runner.Check(rel_path("http://example.com/path?q=1") == "/path?q=1", "rel_path: http -> path");
    }

    void TestRelPathHttps(TestRunner &runner)
    {
        runner.Check(rel_path("https://example.com/abc") == "/abc", "rel_path: https -> path");
    }

    void TestRelPathNoScheme(TestRunner &runner)
    {
        runner.Check(rel_path("/relative/path") == "/relative/path", "rel_path: no scheme -> original");
    }

    void TestRelPathNoPath(TestRunner &runner)
    {
        runner.Check(rel_path("http://example.com") == "/", "rel_path: no path -> /");
    }

    void TestRelPathHttpsNoPath(TestRunner &runner)
    {
        runner.Check(rel_path("https://example.com") == "/", "rel_path: https no path -> /");
    }

    void TestBuildFwd(TestRunner &runner)
    {
        proxy_request req;
        req.method = "GET";
        req.target = "http://example.com/path";
        req.version = "HTTP/1.1";

        auto line = build_fwd(req, psm::memory::current_resource());
        runner.Check(line == "GET /path HTTP/1.1\r\n", "build_fwd: basic rewrite");
    }

    void TestBuildFwdRelativePath(TestRunner &runner)
    {
        proxy_request req;
        req.method = "POST";
        req.target = "/api/data";
        req.version = "HTTP/1.1";

        auto line = build_fwd(req, psm::memory::current_resource());
        runner.Check(line == "POST /api/data HTTP/1.1\r\n", "build_fwd: relative unchanged");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("HttpParserPure");

    TestParseReqBasicGet(runner);
    TestParseReqConnect(runner);
    TestParseReqWithProxyAuth(runner);
    TestParseReqNoCrlf(runner);
    TestParseReqNoSecondSpace(runner);
    TestParseReqNoHeaderEnd(runner);
    TestParseReqEmptyHeader(runner);
    TestParseReqCaseInsensitiveHeaders(runner);
    TestParseReqOffsets(runner);
    TestRelPathHttp(runner);
    TestRelPathHttps(runner);
    TestRelPathNoScheme(runner);
    TestRelPathNoPath(runner);
    TestRelPathHttpsNoPath(runner);
    TestBuildFwd(runner);
    TestBuildFwdRelativePath(runner);

    return runner.Summary();
}
