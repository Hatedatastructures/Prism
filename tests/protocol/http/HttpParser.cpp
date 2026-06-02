/**
 * @file HttpParser.cpp
 * @brief HTTP 代理请求解析器单元测试
 * @details 测试 psm::protocol::http::parse_req() 和
 * psm::protocol::http::rel_path() 的正确性，覆盖基本请求解析、
 * CONNECT 方法、POST 方法、Proxy-Authorization 头、大小写不敏感、
 * 空白修剪、畸形输入、偏移量精度、路径提取等场景。
 */

#include <prism/protocol/http/parser.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <string>
#include <string_view>


#include <gtest/gtest.h>

/**
 * @brief 测试基本 GET 请求解析
 */
TEST(HttpParser, BasicGetRequest)
{
    // 构造标准 GET 请求，验证各字段完整提取
    const std::string raw = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    // 解析成功是后续断言的前提
    ASSERT_TRUE(result == psm::fault::code::success) << "parse_req should return success for valid GET request";
    // 验证方法字段被正确提取
    EXPECT_TRUE(req.method == "GET") << "method should be 'GET'";
    // 验证请求目标为路径形式
    EXPECT_TRUE(req.target == "/index.html") << "target should be '/index.html'";
    // 验证 HTTP 版本号
    EXPECT_TRUE(req.version == "HTTP/1.1") << "version should be 'HTTP/1.1'";
    // 验证 Host 头值被正确提取
    EXPECT_TRUE(req.host == "www.example.com") << "host should be 'www.example.com'";
    // line_end 标记请求行末尾，用于定位头部起始
    EXPECT_TRUE(req.line_end != 0) << "line_end should not be 0";
    // header_end 标记头部终止符之后的位置
    EXPECT_TRUE(req.hdr_end != 0) << "header_end should not be 0";
}

/**
 * @brief 测试 CONNECT 请求解析
 */
TEST(HttpParser, ConnectRequest)
{
    // CONNECT 方法的 target 是 authority 形式，非路径
    const std::string raw = "CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed for CONNECT request";
    // 验证方法为 CONNECT
    EXPECT_TRUE(req.method == "CONNECT") << "method should be 'CONNECT'";
    // CONNECT 目标应保留 host:port 原始形式
    EXPECT_TRUE(req.target == "www.example.com:443") << "target should be 'www.example.com:443'";
}

/**
 * @brief 测试 POST 请求解析
 */
TEST(HttpParser, PostRequest)
{
    // POST 请求带 Content-Length 头，验证不影响核心字段解析
    const std::string raw = "POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 100\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed for POST request";
    // 验证方法为 POST
    EXPECT_TRUE(req.method == "POST") << "method should be 'POST'";
    // 验证 Host 正确，无关头部不干扰
    EXPECT_TRUE(req.host == "api.example.com") << "host should be 'api.example.com'";
}

/**
 * @brief 测试 Proxy-Authorization 头解析
 */
TEST(HttpParser, ProxyAuthorization)
{
    // 验证 Basic 认证凭据被完整提取（含 scheme 和 token）
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";
    // dXNlcjpwYXNz 是 "user:pass" 的 Base64 编码
    EXPECT_TRUE(req.authorization == "Basic dXNlcjpwYXNz") << "authorization should be 'Basic dXNlcjpwYXNz'";
}

/**
 * @brief 测试同时包含 Host 和 Proxy-Authorization 的请求
 */
TEST(HttpParser, BothAuthAndHost)
{
    // Host 和 Proxy-Authorization 同时存在时均应被提取
    const std::string raw = "GET /secret HTTP/1.1\r\nHost: secure.example.com\r\nProxy-Authorization: Bearer token123\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";
    // Host 头不应被认证头覆盖
    EXPECT_TRUE(req.host == "secure.example.com") << "host should be 'secure.example.com'";
    // Bearer 类型认证也应正确识别
    EXPECT_TRUE(req.authorization == "Bearer token123") << "authorization should be 'Bearer token123'";
}

/**
 * @brief 测试大小写不敏感的头字段名
 */
TEST(HttpParser, CaseInsensitiveHeaders)
{
    // HOST 全大写：验证头字段名大小写不敏感
    {
        const std::string raw = "GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
        psm::protocol::http::proxy_request req{};
        auto result = psm::protocol::http::parse_req(raw, req);

        EXPECT_TRUE(result == psm::fault::code::success && req.host == "example.com")
            << "HOST (uppercase) should be parsed as host";
    }

    // hOsT 混合大小写：模拟非规范客户端
    {
        const std::string raw = "GET / HTTP/1.1\r\nhOsT: mixed.com\r\n\r\n";
        psm::protocol::http::proxy_request req{};
        auto result = psm::protocol::http::parse_req(raw, req);

        EXPECT_TRUE(result == psm::fault::code::success && req.host == "mixed.com")
            << "hOsT (mixed case) should be parsed as host";
    }

    // proxy-AUTHORIZATION 混合大小写：认证头也须不敏感
    {
        const std::string raw = "GET / HTTP/1.1\r\nHost: x.com\r\nproxy-AUTHORIZATION: Basic abc\r\n\r\n";
        psm::protocol::http::proxy_request req{};
        auto result = psm::protocol::http::parse_req(raw, req);

        EXPECT_TRUE(result == psm::fault::code::success && req.authorization == "Basic abc")
            << "proxy-AUTHORIZATION (mixed case) should be parsed";
    }
}

/**
 * @brief 测试头字段值的空白修剪
 */
TEST(HttpParser, HeaderWhitespaceTrim)
{
    // Host 值前后含多余空白，验证自动修剪
    const std::string raw = "GET / HTTP/1.1\r\nHost:  example.com \r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";
    // 前导和尾部空白均应被去除
    EXPECT_TRUE(req.host == "example.com") << "host should be trimmed to 'example.com'";
}

/**
 * @brief 测试缺少冒号的畸形头字段行
 */
TEST(HttpParser, MalformedHeaderNoColon)
{
    // 畸形头行缺少冒号分隔符，解析器应静默跳过
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Bad-Header\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    // 解析不应因畸形行失败
    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed despite malformed header line (silently skipped)";
    // 有效头部应仍被正确提取
    EXPECT_TRUE(req.host == "example.com") << "host should still be 'example.com'";
}

/**
 * @brief 测试带 body 数据的请求
 */
TEST(HttpParser, RequestWithBodyData)
{
    // 请求附带 body，验证 header_end 定位到 body 起始
    const std::string raw = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";

    // header_end 应指向 \r\n\r\n 之后、body 之前
    const std::size_t expected_header_end = raw.find("\r\n\r\n") + 4;
    EXPECT_TRUE(req.hdr_end == expected_header_end) << "header_end should point to body start";
}

/**
 * @brief 测试请求行和头部结束偏移量的精确值
 */
TEST(HttpParser, ReqLineAndHeaderEndOffsets)
{
    // 精确构造已知请求，手动计算字节偏移量
    // "GET / HTTP/1.1\r\n" = 16 字节
    // "Host: x.com\r\n" = 13 字节
    // "\r\n" = 2 字节
    // line_end = 16, header_end = 16 + 13 + 2 = 31
    const std::string raw = "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";

    // 请求行结束位置：第一个 \r\n 之后
    const std::size_t expected_line_end = raw.find("\r\n") + 2; // 16
    EXPECT_TRUE(req.line_end == expected_line_end) << "line_end offset incorrect";

    // 头部结束位置：\r\n\r\n 之后
    const std::size_t expected_header_end = raw.find("\r\n\r\n") + 4; // 31
    EXPECT_TRUE(req.hdr_end == expected_header_end) << "header_end offset incorrect";
}

/**
 * @brief 测试缺少头部终止符的请求
 */
TEST(HttpParser, MissingHeaderTerminator)
{
    // 缺少 \r\n\r\n 终止符，报文不完整
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    // 必须返回解析错误
    EXPECT_TRUE(result == psm::fault::code::parse_error) << "should return parse_error when \\r\\n\\r\\n is missing";
}

/**
 * @brief 测试缺少请求行 CRLF 的请求
 */
TEST(HttpParser, MissingRequestLineCrlf)
{
    // 请求行缺少 CRLF，无法定位行尾
    const std::string raw = "GET / HTTP/1.1";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    EXPECT_TRUE(result == psm::fault::code::parse_error) << "should return parse_error when request line has no CRLF";
}

/**
 * @brief 测试空输入
 */
TEST(HttpParser, EmptyInput)
{
    // 空输入边界条件
    const std::string raw = "";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    EXPECT_TRUE(result == psm::fault::code::parse_error) << "should return parse_error for empty input";
}

/**
 * @brief 测试从绝对 URI 中提取相对路径
 */
TEST(HttpParser, ExtractPathFromAbsoluteUri)
{
    // 带 query 和 fragment 的完整 URI，提取路径部分
    {
        auto path = psm::protocol::http::rel_path("http://example.com/path?q=1#frag");
        EXPECT_TRUE(path == "/path?q=1#frag") << "http://example.com/path?q=1#frag should extract '/path?q=1#frag'";
    }

    // HTTPS 协议也应正确去除 authority 部分
    {
        auto path = psm::protocol::http::rel_path("https://example.com/api");
        EXPECT_TRUE(path == "/api") << "https://example.com/api should extract '/api'";
    }
}

/**
 * @brief 测试 URI 无路径分量时返回根路径
 */
TEST(HttpParser, ExtractPathNoPathComponent)
{
    // URI 无路径时默认返回根路径 "/"
    {
        auto path = psm::protocol::http::rel_path("http://example.com");
        EXPECT_TRUE(path == "/") << "http://example.com should extract '/'";
    }

    {
        auto path = psm::protocol::http::rel_path("https://example.com");
        EXPECT_TRUE(path == "/") << "https://example.com should extract '/'";
    }
}

/**
 * @brief 测试已经是相对路径的目标保持不变
 */
TEST(HttpParser, ExtractPathAlreadyRelative)
{
    // 已经是相对路径的输入应原样返回
    {
        auto path = psm::protocol::http::rel_path("/path?q=1");
        EXPECT_TRUE(path == "/path?q=1") << "'/path?q=1' should be returned as-is";
    }

    // CONNECT 风格的 host:port 不应被误判为路径
    {
        auto path = psm::protocol::http::rel_path("host:443");
        EXPECT_TRUE(path == "host:443") << "'host:443' should be returned as-is";
    }
}

/**
 * @brief 测试最小合法请求（无任何头部字段）
 */
TEST(HttpParser, MinimalRequest)
{
    // 仅请求行 + 空头部，host 应为空
    const std::string raw = "GET / HTTP/1.1\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed for minimal request";
    EXPECT_TRUE(req.method == "GET") << "method should be 'GET'";
    EXPECT_TRUE(req.target == "/") << "target should be '/'";
    EXPECT_TRUE(req.host.empty()) << "host should be empty when no Host header present";
}

/**
 * @brief 测试 HTTP/1.0 版本解析
 */
TEST(HttpParser, Http10Version)
{
    const std::string raw = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed for HTTP/1.0";
    EXPECT_TRUE(req.version == "HTTP/1.0") << "version should be 'HTTP/1.0'";
    EXPECT_TRUE(req.host == "example.com") << "host should be 'example.com'";
}

/**
 * @brief 测试带端口的 Host 头
 */
TEST(HttpParser, HostWithPort)
{
    // Host 值含端口号，应完整保留
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";
    EXPECT_TRUE(req.host == "example.com:8080") << "host should be 'example.com:8080'";
}

/**
 * @brief 测试 Tab 作为头部字段值分隔符
 */
TEST(HttpParser, TabSeparator)
{
    // RFC 7230 允许冒号后使用 OWS（空格或 tab），验证 tab 被正确修剪
    const std::string raw = "GET / HTTP/1.1\r\nHost:\texample.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed with tab separator";
    EXPECT_TRUE(req.host == "example.com") << "host should be 'example.com' (tab trimmed)";
}

/**
 * @brief 测试多个 Host 行（应取最后一个）
 */
TEST(HttpParser, MultipleHostHeaders)
{
    // 多个 Host 头：解析器逐行覆盖，最终保留最后一个
    const std::string raw = "GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";
    EXPECT_TRUE(req.host == "second.com") << "host should be 'second.com' (last Host wins)";
}

/**
 * @brief 测试其他头字段不干扰核心字段提取
 */
TEST(HttpParser, OtherHeadersIgnored)
{
    // 大量无关头部，仅 Host 和 Proxy-Authorization 应被提取
    const std::string raw = "GET / HTTP/1.1\r\n"
                            "Host: example.com\r\n"
                            "Content-Length: 42\r\n"
                            "Content-Type: application/json\r\n"
                            "User-Agent: test/1.0\r\n"
                            "Accept: */*\r\n"
                            "Proxy-Authorization: Basic abc123\r\n"
                            "Connection: keep-alive\r\n"
                            "\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_req(raw, req);

    ASSERT_TRUE(result == psm::fault::code::success) << "parse should succeed";
    EXPECT_TRUE(req.host == "example.com") << "host should be 'example.com'";
    EXPECT_TRUE(req.authorization == "Basic abc123") << "authorization should be 'Basic abc123'";
}

/**
 * @brief 测试 rel_path 带端口
 */
TEST(HttpParser, ExtractPathWithPort)
{
    // URI 带非标准端口，路径提取不受端口影响
    {
        auto path = psm::protocol::http::rel_path("http://example.com:8080/path");
        EXPECT_TRUE(path == "/path") << "http://example.com:8080/path should extract '/path'";
    }

    {
        auto path = psm::protocol::http::rel_path("https://example.com:443/api?q=1");
        EXPECT_TRUE(path == "/api?q=1") << "https://example.com:443/api?q=1 should extract '/api?q=1'";
    }
}
