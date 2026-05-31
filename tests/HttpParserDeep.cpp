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

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数
#include "../src/prism/protocol/http/parser.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::protocol::http;

    // ─── to_lower ──────────────────────────────────

    void TestToLowerUppercase(TestRunner &runner)
    {
        runner.Check(to_lower('A') == 'a', "to_lower: A -> a");
        runner.Check(to_lower('Z') == 'z', "to_lower: Z -> z");
        runner.Check(to_lower('M') == 'm', "to_lower: M -> m");
    }

    void TestToLowerAlreadyLower(TestRunner &runner)
    {
        runner.Check(to_lower('a') == 'a', "to_lower: a -> a");
        runner.Check(to_lower('z') == 'z', "to_lower: z -> z");
    }

    void TestToLowerDigit(TestRunner &runner)
    {
        runner.Check(to_lower('0') == '0', "to_lower: 0 unchanged");
        runner.Check(to_lower('9') == '9', "to_lower: 9 unchanged");
    }

    void TestToLowerSpecial(TestRunner &runner)
    {
        runner.Check(to_lower('-') == '-', "to_lower: - unchanged");
        runner.Check(to_lower('_') == '_', "to_lower: _ unchanged");
        runner.Check(to_lower(' ') == ' ', "to_lower: space unchanged");
    }

    // ─── iequals ───────────────────────────────────

    void TestIequalsSame(TestRunner &runner)
    {
        runner.Check(iequals("hello", "hello"), "iequals: same strings");
        runner.Check(iequals("", ""), "iequals: both empty");
    }

    void TestIequalsCaseInsensitive(TestRunner &runner)
    {
        runner.Check(iequals("Hello", "hello"), "iequals: case insensitive");
        runner.Check(iequals("HOST", "host"), "iequals: HOST == host");
        runner.Check(iequals("Proxy-Authorization", "proxy-authorization"),
                     "iequals: mixed case header");
    }

    void TestIequalsDifferentLength(TestRunner &runner)
    {
        runner.Check(!iequals("abc", "ab"), "iequals: different length");
        runner.Check(!iequals("", "a"), "iequals: empty vs non-empty");
    }

    void TestIequalsDifferentContent(TestRunner &runner)
    {
        runner.Check(!iequals("abc", "abd"), "iequals: different content");
        runner.Check(!iequals("host", "post"), "iequals: host != post");
    }

    // ─── trim ──────────────────────────────────────

    void TestTrimNoWhitespace(TestRunner &runner)
    {
        runner.Check(trim("hello") == "hello", "trim: no whitespace");
        runner.Check(trim("") == "", "trim: empty string");
    }

    void TestTrimLeadingSpaces(TestRunner &runner)
    {
        runner.Check(trim("  hello") == "hello", "trim: leading spaces");
        runner.Check(trim("   hello world") == "hello world", "trim: leading multi-space");
    }

    void TestTrimTrailingSpaces(TestRunner &runner)
    {
        runner.Check(trim("hello  ") == "hello", "trim: trailing spaces");
        runner.Check(trim("hello world  ") == "hello world", "trim: trailing multi-space");
    }

    void TestTrimTabs(TestRunner &runner)
    {
        runner.Check(trim("\thello") == "hello", "trim: leading tab");
        runner.Check(trim("hello\t") == "hello", "trim: trailing tab");
        runner.Check(trim("\t \t") == "", "trim: only whitespace → empty");
    }

    void TestTrimBothSides(TestRunner &runner)
    {
        runner.Check(trim("  hello  ") == "hello", "trim: both sides");
        runner.Check(trim("\t value \t") == "value", "trim: both sides with tabs");
    }

    // ─── iequals_prefix ────────────────────────────

    void TestIequalsPrefixMatch(TestRunner &runner)
    {
        runner.Check(iequals_prefix("Basic abc", "Basic "),
                     "iequals_prefix: Basic match");
        runner.Check(iequals_prefix("basic dGVzdDp0ZXN0", "basic "),
                     "iequals_prefix: lowercase basic match");
        runner.Check(iequals_prefix("BASIC test", "Basic "),
                     "iequals_prefix: BASIC match");
    }

    void TestIequalsPrefixSameSize(TestRunner &runner)
    {
        runner.Check(!iequals_prefix("Basic", "Basic"),
                     "iequals_prefix: same size → false (str must be > prefix)");
        runner.Check(!iequals_prefix("abc", "abc"),
                     "iequals_prefix: equal length → false");
    }

    void TestIequalsPrefixShorterStr(TestRunner &runner)
    {
        runner.Check(!iequals_prefix("Basi", "Basic "),
                     "iequals_prefix: shorter str → false");
        runner.Check(!iequals_prefix("", "Basic "),
                     "iequals_prefix: empty str → false");
    }

    void TestIequalsPrefixMismatch(TestRunner &runner)
    {
        runner.Check(!iequals_prefix("Digest user", "Basic "),
                     "iequals_prefix: different scheme → false");
        runner.Check(!iequals_prefix("NTLM token", "Basic "),
                     "iequals_prefix: NTLM != Basic → false");
    }

    // ─── parse_req 边缘分支 ───────────────────────

    void TestParseReqNoSpaceAtAll(TestRunner &runner)
    {
        // 无空格，first_space == npos
        const char *raw = "NOSPACE\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::parse_error,
                     "parse_req: no space at all → parse_error");
    }

    void TestParseReqSpaceAfterLineEnd(TestRunner &runner)
    {
        // 第一个空格在 \r\n 之后，first_space >= line_end
        const char *raw = "TEST\r\n X\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::parse_error,
                     "parse_req: space after line_end → parse_error");
    }

    void TestParseReqSecondSpaceAfterLineEnd(TestRunner &runner)
    {
        // 第一个空格在请求行内，第二个空格在 \r\n 之后
        const char *raw = "GET /\r\n \r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::parse_error,
                     "parse_req: second space after line_end → parse_error");
    }

    void TestParseReqHeaderNoColon(TestRunner &runner)
    {
        // 头字段无冒号，应跳过
        const char *raw = "GET / HTTP/1.1\r\nX-BadHeader\r\nHost: ok\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success,
                     "parse_req: header no colon → success");
        runner.Check(req.host == "ok",
                     "parse_req: header no colon → host still parsed");
    }

    void TestParseReqHeaderEmptyLineMidBlock(TestRunner &runner)
    {
        // 头部中间空行，应 continue 跳过
        const char *raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success,
                     "parse_req: empty mid line → success");
        runner.Check(req.host == "x",
                     "parse_req: empty mid line → host still parsed");
    }

    void TestParseReqSingleHeaderNoCrlfAfter(TestRunner &runner)
    {
        // 最后一个 header 后直接到 \r\n\r\n，block.find("\r\n") 返回 npos
        const char *raw = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success,
                     "parse_req: single header → success");
        runner.Check(req.host == "test",
                     "parse_req: single header → host");
    }

    void TestParseReqMultipleHeaders(TestRunner &runner)
    {
        const char *raw = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                          "Proxy-Authorization: Basic abc\r\n"
                          "User-Agent: test\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success,
                     "parse_req: multiple headers → success");
        runner.Check(req.host == "example.com",
                     "parse_req: multi header → host");
        runner.Check(req.authorization == "Basic abc",
                     "parse_req: multi header → auth");
    }

    void TestParseReqHeaderWhitespaceTrim(TestRunner &runner)
    {
        // 值前后有空格和 tab
        const char *raw = "GET / HTTP/1.1\r\nHost: \t example.com \t\r\n\r\n";
        proxy_request req;
        auto ec = parse_req(raw, req);
        runner.Check(ec == psm::fault::code::success,
                     "parse_req: whitespace trim → success");
        runner.Check(req.host == "example.com",
                     "parse_req: whitespace trim → host trimmed");
    }

    // ─── rel_path 额外分支 ─────────────────────────

    void TestRelPathHttpsWithPathAndQuery(TestRunner &runner)
    {
        runner.Check(rel_path("https://host/path?query=1#frag") == "/path?query=1#frag",
                     "rel_path: https with path+query+frag");
    }

    void TestRelPathHttpRoot(TestRunner &runner)
    {
        runner.Check(rel_path("http://host/") == "/",
                     "rel_path: http root path");
    }

    void TestRelPathRelativeWithSlash(TestRunner &runner)
    {
        runner.Check(rel_path("/already/relative") == "/already/relative",
                     "rel_path: already relative → unchanged");
    }

    void TestRelPathBarePathNoSlash(TestRunner &runner)
    {
        runner.Check(rel_path("nothttp://host/path") == "nothttp://host/path",
                     "rel_path: non-http scheme → original");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("HttpParserDeep");

    // to_lower
    TestToLowerUppercase(runner);
    TestToLowerAlreadyLower(runner);
    TestToLowerDigit(runner);
    TestToLowerSpecial(runner);

    // iequals
    TestIequalsSame(runner);
    TestIequalsCaseInsensitive(runner);
    TestIequalsDifferentLength(runner);
    TestIequalsDifferentContent(runner);

    // trim
    TestTrimNoWhitespace(runner);
    TestTrimLeadingSpaces(runner);
    TestTrimTrailingSpaces(runner);
    TestTrimTabs(runner);
    TestTrimBothSides(runner);

    // iequals_prefix
    TestIequalsPrefixMatch(runner);
    TestIequalsPrefixSameSize(runner);
    TestIequalsPrefixShorterStr(runner);
    TestIequalsPrefixMismatch(runner);

    // parse_req 边缘分支
    TestParseReqNoSpaceAtAll(runner);
    TestParseReqSpaceAfterLineEnd(runner);
    TestParseReqSecondSpaceAfterLineEnd(runner);
    TestParseReqHeaderNoColon(runner);
    TestParseReqHeaderEmptyLineMidBlock(runner);
    TestParseReqSingleHeaderNoCrlfAfter(runner);
    TestParseReqMultipleHeaders(runner);
    TestParseReqHeaderWhitespaceTrim(runner);

    // rel_path 额外分支
    TestRelPathHttpsWithPathAndQuery(runner);
    TestRelPathHttpRoot(runner);
    TestRelPathRelativeWithSlash(runner);
    TestRelPathBarePathNoSlash(runner);

    return runner.Summary();
}
