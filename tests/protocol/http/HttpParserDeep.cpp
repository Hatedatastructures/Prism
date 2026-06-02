/**
 * @file HttpParserDeep.cpp
 * @brief HTTP parser 深度测试
 * @details 测试 parser.cpp 中匿名命名空间的纯函数：
 *          to_lower、iequals、trim、iequals_prefix，
 *          以及 parse_req 的边缘分支。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

// #include 源文件增加覆盖率计数
#include "../../src/prism/protocol/http/parser.cpp"

namespace
{
    using namespace psm::protocol::http;

    // ─── to_lower ──────────────────────────────────

    TEST(HttpParserDeep, ToLowerUppercase)
    {
        EXPECT_TRUE(to_lower('A') == 'a') << "to_lower: A -> a";
        EXPECT_TRUE(to_lower('Z') == 'z') << "to_lower: Z -> z";
        EXPECT_TRUE(to_lower('M') == 'm') << "to_lower: M -> m";
    }

    TEST(HttpParserDeep, ToLowerAlreadyLower)
    {
        EXPECT_TRUE(to_lower('a') == 'a') << "to_lower: a -> a";
        EXPECT_TRUE(to_lower('z') == 'z') << "to_lower: z -> z";
    }

    TEST(HttpParserDeep, ToLowerDigit)
    {
        EXPECT_TRUE(to_lower('0') == '0') << "to_lower: 0 unchanged";
        EXPECT_TRUE(to_lower('9') == '9') << "to_lower: 9 unchanged";
    }

    TEST(HttpParserDeep, ToLowerSpecial)
    {
        EXPECT_TRUE(to_lower('-') == '-') << "to_lower: - unchanged";
        EXPECT_TRUE(to_lower('_') == '_') << "to_lower: _ unchanged";
        EXPECT_TRUE(to_lower(' ') == ' ') << "to_lower: space unchanged";
    }

    // ─── iequals ───────────────────────────────────

    TEST(HttpParserDeep, IequalsSame)
    {
        EXPECT_TRUE(iequals("hello", "hello")) << "iequals: same strings";
        EXPECT_TRUE(iequals("", "")) << "iequals: both empty";
    }

    TEST(HttpParserDeep, IequalsCaseInsensitive)
    {
        EXPECT_TRUE(iequals("Hello", "hello")) << "iequals: case insensitive";
        EXPECT_TRUE(iequals("HOST", "host")) << "iequals: HOST == host";
        EXPECT_TRUE(iequals("Proxy-Authorization", "proxy-authorization"))
            << "iequals: mixed case header";
    }

    TEST(HttpParserDeep, IequalsDifferentLength)
    {
        EXPECT_TRUE(!iequals("abc", "ab")) << "iequals: different length";
        EXPECT_TRUE(!iequals("", "a")) << "iequals: empty vs non-empty";
    }

    TEST(HttpParserDeep, IequalsDifferentContent)
    {
        EXPECT_TRUE(!iequals("abc", "abd")) << "iequals: different content";
        EXPECT_TRUE(!iequals("host", "post")) << "iequals: host != post";
    }

    // ─── trim ──────────────────────────────────────

    TEST(HttpParserDeep, TrimNoWhitespace)
    {
        EXPECT_TRUE(trim("hello") == "hello") << "trim: no whitespace";
        EXPECT_TRUE(trim("") == "") << "trim: empty string";
    }

    TEST(HttpParserDeep, TrimLeadingSpaces)
    {
        EXPECT_TRUE(trim("  hello") == "hello") << "trim: leading spaces";
        EXPECT_TRUE(trim("   hello world") == "hello world") << "trim: leading multi-space";
    }

    TEST(HttpParserDeep, TrimTrailingSpaces)
    {
        EXPECT_TRUE(trim("hello  ") == "hello") << "trim: trailing spaces";
        EXPECT_TRUE(trim("hello world  ") == "hello world") << "trim: trailing multi-space";
    }

    TEST(HttpParserDeep, TrimTabs)
    {
        EXPECT_TRUE(trim("\thello") == "hello") << "trim: leading tab";
        EXPECT_TRUE(trim("hello\t") == "hello") << "trim: trailing tab";
        EXPECT_TRUE(trim("\t \t") == "") << "trim: only whitespace -> empty";
    }

    TEST(HttpParserDeep, TrimBothSides)
    {
        EXPECT_TRUE(trim("  hello  ") == "hello") << "trim: both sides";
        EXPECT_TRUE(trim("\t value \t") == "value") << "trim: both sides with tabs";
    }

    // ─── iequals_prefix ────────────────────────────

    TEST(HttpParserDeep, IequalsPrefixMatch)
    {
        EXPECT_TRUE(iequals_prefix("Basic abc", "Basic "))
            << "iequals_prefix: Basic match";
        EXPECT_TRUE(iequals_prefix("basic dGVzdDp0ZXN0", "basic "))
            << "iequals_prefix: lowercase basic match";
        EXPECT_TRUE(iequals_prefix("BASIC test", "Basic "))
            << "iequals_prefix: BASIC match";
    }

    TEST(HttpParserDeep, IequalsPrefixSameSize)
    {
        EXPECT_TRUE(!iequals_prefix("Basic", "Basic"))
            << "iequals_prefix: same size -> false (str must be > prefix)";
        EXPECT_TRUE(!iequals_prefix("abc", "abc"))
            << "iequals_prefix: equal length -> false";
    }

    TEST(HttpParserDeep, IequalsPrefixShorterStr)
    {
        EXPECT_TRUE(!iequals_prefix("Basi", "Basic "))
            << "iequals_prefix: shorter str -> false";
        EXPECT_TRUE(!iequals_prefix("", "Basic "))
            << "iequals_prefix: empty str -> false";
    }

    TEST(HttpParserDeep, IequalsPrefixMismatch)
    {
        EXPECT_TRUE(!iequals_prefix("Digest user", "Basic "))
            << "iequals_prefix: different scheme -> false";
        EXPECT_TRUE(!iequals_prefix("NTLM token", "Basic "))
            << "iequals_prefix: NTLM != Basic -> false";
    }

    // ─── parse_req 边缘分支 ───────────────────────

    TEST(HttpParserDeep, ParseReqNoSpaceAtAll)
    {
        // 无空格，first_space == npos
        const char *raw = "NOSPACE\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::parse_error)
            << "parse_req: no space at all -> parse_error";
    }

    TEST(HttpParserDeep, ParseReqSpaceAfterLineEnd)
    {
        // 第一个空格在 \r\n 之后，first_space >= line_end
        const char *raw = "TEST\r\n X\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::parse_error)
            << "parse_req: space after line_end -> parse_error";
    }

    TEST(HttpParserDeep, ParseReqSecondSpaceAfterLineEnd)
    {
        // 第一个空格在请求行内，第二个空格在 \r\n 之后
        const char *raw = "GET /\r\n \r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::parse_error)
            << "parse_req: second space after line_end -> parse_error";
    }

    TEST(HttpParserDeep, ParseReqHeaderNoColon)
    {
        // 头字段无冒号，应跳过
        const char *raw = "GET / HTTP/1.1\r\nX-BadHeader\r\nHost: ok\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success)
            << "parse_req: header no colon -> success";
        EXPECT_TRUE(req.host == "ok")
            << "parse_req: header no colon -> host still parsed";
    }

    TEST(HttpParserDeep, ParseReqHeaderEmptyLineMidBlock)
    {
        // 头部中间空行，应 continue 跳过
        const char *raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success)
            << "parse_req: empty mid line -> success";
        EXPECT_TRUE(req.host == "x")
            << "parse_req: empty mid line -> host still parsed";
    }

    TEST(HttpParserDeep, ParseReqSingleHeaderNoCrlfAfter)
    {
        // 最后一个 header 后直接到 \r\n\r\n，block.find("\r\n") 返回 npos
        const char *raw = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success)
            << "parse_req: single header -> success";
        EXPECT_TRUE(req.host == "test")
            << "parse_req: single header -> host";
    }

    TEST(HttpParserDeep, ParseReqMultipleHeaders)
    {
        const char *raw = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                          "Proxy-Authorization: Basic abc\r\n"
                          "User-Agent: test\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success)
            << "parse_req: multiple headers -> success";
        EXPECT_TRUE(req.host == "example.com")
            << "parse_req: multi header -> host";
        EXPECT_TRUE(req.authorization == "Basic abc")
            << "parse_req: multi header -> auth";
    }

    TEST(HttpParserDeep, ParseReqHeaderWhitespaceTrim)
    {
        // 值前后有空格和 tab
        const char *raw = "GET / HTTP/1.1\r\nHost: \t example.com \t\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        EXPECT_TRUE(ec == psm::fault::code::success)
            << "parse_req: whitespace trim -> success";
        EXPECT_TRUE(req.host == "example.com")
            << "parse_req: whitespace trim -> host trimmed";
    }

    // ─── rel_path 额外分支 ─────────────────────────

    TEST(HttpParserDeep, RelPathHttpsWithPathAndQuery)
    {
        EXPECT_TRUE(rel_path("https://host/path?query=1#frag") == "/path?query=1#frag")
            << "rel_path: https with path+query+frag";
    }

    TEST(HttpParserDeep, RelPathHttpRoot)
    {
        EXPECT_TRUE(rel_path("http://host/") == "/")
            << "rel_path: http root path";
    }

    TEST(HttpParserDeep, RelPathRelativeWithSlash)
    {
        EXPECT_TRUE(rel_path("/already/relative") == "/already/relative")
            << "rel_path: already relative -> unchanged";
    }

    TEST(HttpParserDeep, RelPathBarePathNoSlash)
    {
        EXPECT_TRUE(rel_path("nothttp://host/path") == "nothttp://host/path")
            << "rel_path: non-http scheme -> original";
    }

} // namespace
