/**
 * @file HttpParserPure.cpp
 * @brief HTTP parser 纯函数测试
 * @details 测试 parse_req/rel_path/build_fwd 全分支
 */

#include <prism/foundation/foundation.hpp>
#include <prism/proto/protocol/http/parser.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

namespace
{
    using psm::protocol::http::parse_req;
    using psm::protocol::http::rel_path;
    using psm::protocol::http::build_fwd;
    using psm::protocol::http::proxy_request;

    TEST(HttpParserPure, ParseReqBasicGet)
    {
        const char *raw = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_req GET: success";
        EXPECT_TRUE(req.method == "GET") << "parse_req GET: method";
        EXPECT_TRUE(req.target == "http://example.com/path") << "parse_req GET: target";
        EXPECT_TRUE(req.version == "HTTP/1.1") << "parse_req GET: version";
        EXPECT_TRUE(req.host == "example.com") << "parse_req GET: host";
    }

    TEST(HttpParserPure, ParseReqConnect)
    {
        const char *raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_req CONNECT: success";
        EXPECT_TRUE(req.method == "CONNECT") << "parse_req CONNECT: method";
        EXPECT_TRUE(req.target == "example.com:443") << "parse_req CONNECT: target";
    }

    TEST(HttpParserPure, ParseReqWithProxyAuth)
    {
        const char *raw = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_req auth: success";
        EXPECT_TRUE(req.authorization == "Basic dGVzdDp0ZXN0") << "parse_req auth: authorization";
    }

    TEST(HttpParserPure, ParseReqNoCrlf)
    {
        const char *raw = "GET / HTTP/1.1";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::parse_error) << "parse_req: no CRLF";
    }

    TEST(HttpParserPure, ParseReqNoSecondSpace)
    {
        const char *raw = "GET /HTTP/1.1\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::parse_error) << "parse_req: no second space";
    }

    TEST(HttpParserPure, ParseReqNoHeaderEnd)
    {
        const char *raw = "GET / HTTP/1.1\r\nHost: test";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::parse_error) << "parse_req: no \\r\\n\\r\\n";
    }

    TEST(HttpParserPure, ParseReqEmptyHeader)
    {
        const char *raw = "GET / HTTP/1.1\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_req: empty headers -> success";
        EXPECT_TRUE(req.host.empty()) << "parse_req: host empty";
    }

    TEST(HttpParserPure, ParseReqCaseInsensitiveHeaders)
    {
        const char *raw = "GET / HTTP/1.1\r\nhOsT: example.com\r\nproxy-AUTHORIZATION: Basic abc\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_req case: success";
        EXPECT_TRUE(req.host == "example.com") << "parse_req case: host found";
        EXPECT_TRUE(req.authorization == "Basic abc") << "parse_req case: auth found";
    }

    TEST(HttpParserPure, ParseReqOffsets)
    {
        const char *raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_req offset: success";
        EXPECT_TRUE(req.line_end == 16) << "parse_req offset: line_end=16";
        EXPECT_TRUE(req.hdr_end == 27) << "parse_req offset: hdr_end=27";
    }

    TEST(HttpParserPure, RelPathHttp)
    {
        EXPECT_TRUE(rel_path("http://example.com/path?q=1") == "/path?q=1") << "rel_path: http -> path";
    }

    TEST(HttpParserPure, RelPathHttps)
    {
        EXPECT_TRUE(rel_path("https://example.com/abc") == "/abc") << "rel_path: https -> path";
    }

    TEST(HttpParserPure, RelPathNoScheme)
    {
        EXPECT_TRUE(rel_path("/relative/path") == "/relative/path") << "rel_path: no scheme -> original";
    }

    TEST(HttpParserPure, RelPathNoPath)
    {
        EXPECT_TRUE(rel_path("http://example.com") == "/") << "rel_path: no path -> /";
    }

    TEST(HttpParserPure, RelPathHttpsNoPath)
    {
        EXPECT_TRUE(rel_path("https://example.com") == "/") << "rel_path: https no path -> /";
    }

    TEST(HttpParserPure, BuildFwd)
    {
        proxy_request req;
        req.method = "GET";
        req.target = "http://example.com/path";
        req.version = "HTTP/1.1";

        auto line = build_fwd(req, psm::memory::current_resource());
        EXPECT_TRUE(line == "GET /path HTTP/1.1\r\n") << "build_fwd: basic rewrite";
    }

    TEST(HttpParserPure, BuildFwdRelativePath)
    {
        proxy_request req;
        req.method = "POST";
        req.target = "/api/data";
        req.version = "HTTP/1.1";

        auto line = build_fwd(req, psm::memory::current_resource());
        EXPECT_TRUE(line == "POST /api/data HTTP/1.1\r\n") << "build_fwd: relative unchanged";
    }
} // namespace
