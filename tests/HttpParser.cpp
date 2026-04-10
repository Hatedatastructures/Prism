/**
 * @file HttpParser.cpp
 * @brief HTTP 代理请求解析器单元测试
 * @details 测试 psm::protocol::http::parse_proxy_request() 和
 * psm::protocol::http::extract_relative_path() 的正确性，覆盖基本请求解析、
 * CONNECT 方法、POST 方法、Proxy-Authorization 头、大小写不敏感、
 * 空白修剪、畸形输入、偏移量精度、路径提取等场景。
 */

#include <prism/protocol/http/parser.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <string>
#include <string_view>

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    auto log_info(const std::string_view msg) -> void
    {
        psm::trace::info("[HttpParser] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    auto log_pass(const std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[HttpParser] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    auto log_fail(const std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[HttpParser] FAIL: {}", msg);
    }
}

/**
 * @brief 测试基本 GET 请求解析
 */
void TestBasicGetRequest()
{
    log_info("=== TestBasicGetRequest ===");

    // 构造标准 GET 请求，验证各字段完整提取
    const std::string raw = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    // 解析成功是后续断言的前提
    if (result != psm::fault::code::success)
    {
        log_fail("parse_proxy_request should return success for valid GET request");
        return;
    }
    // 验证方法字段被正确提取
    if (req.method != "GET")
    {
        log_fail("method should be 'GET'");
        return;
    }
    // 验证请求目标为路径形式
    if (req.target != "/index.html")
    {
        log_fail("target should be '/index.html'");
        return;
    }
    // 验证 HTTP 版本号
    if (req.version != "HTTP/1.1")
    {
        log_fail("version should be 'HTTP/1.1'");
        return;
    }
    // 验证 Host 头值被正确提取
    if (req.host != "www.example.com")
    {
        log_fail("host should be 'www.example.com'");
        return;
    }
    // req_line_end 标记请求行末尾，用于定位头部起始
    if (req.req_line_end == 0)
    {
        log_fail("req_line_end should not be 0");
        return;
    }
    // header_end 标记头部终止符之后的位置
    if (req.header_end == 0)
    {
        log_fail("header_end should not be 0");
        return;
    }

    log_pass("BasicGetRequest");
}

/**
 * @brief 测试 CONNECT 请求解析
 */
void TestConnectRequest()
{
    log_info("=== TestConnectRequest ===");

    // CONNECT 方法的 target 是 authority 形式，非路径
    const std::string raw = "CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed for CONNECT request");
        return;
    }
    // 验证方法为 CONNECT
    if (req.method != "CONNECT")
    {
        log_fail("method should be 'CONNECT'");
        return;
    }
    // CONNECT 目标应保留 host:port 原始形式
    if (req.target != "www.example.com:443")
    {
        log_fail("target should be 'www.example.com:443'");
        return;
    }

    log_pass("ConnectRequest");
}

/**
 * @brief 测试 POST 请求解析
 */
void TestPostRequest()
{
    log_info("=== TestPostRequest ===");

    // POST 请求带 Content-Length 头，验证不影响核心字段解析
    const std::string raw = "POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 100\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed for POST request");
        return;
    }
    // 验证方法为 POST
    if (req.method != "POST")
    {
        log_fail("method should be 'POST'");
        return;
    }
    // 验证 Host 正确，无关头部不干扰
    if (req.host != "api.example.com")
    {
        log_fail("host should be 'api.example.com'");
        return;
    }

    log_pass("PostRequest");
}

/**
 * @brief 测试 Proxy-Authorization 头解析
 */
void TestProxyAuthorization()
{
    log_info("=== TestProxyAuthorization ===");

    // 验证 Basic 认证凭据被完整提取（含 scheme 和 token）
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }
    // dXNlcjpwYXNz 是 "user:pass" 的 Base64 编码
    if (req.authorization != "Basic dXNlcjpwYXNz")
    {
        log_fail("authorization should be 'Basic dXNlcjpwYXNz'");
        return;
    }

    log_pass("ProxyAuthorization");
}

/**
 * @brief 测试同时包含 Host 和 Proxy-Authorization 的请求
 */
void TestBothAuthAndHost()
{
    log_info("=== TestBothAuthAndHost ===");

    // Host 和 Proxy-Authorization 同时存在时均应被提取
    const std::string raw = "GET /secret HTTP/1.1\r\nHost: secure.example.com\r\nProxy-Authorization: Bearer token123\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }
    // Host 头不应被认证头覆盖
    if (req.host != "secure.example.com")
    {
        log_fail("host should be 'secure.example.com'");
        return;
    }
    // Bearer 类型认证也应正确识别
    if (req.authorization != "Bearer token123")
    {
        log_fail("authorization should be 'Bearer token123'");
        return;
    }

    log_pass("BothAuthAndHost");
}

/**
 * @brief 测试大小写不敏感的头字段名
 */
void TestCaseInsensitiveHeaders()
{
    log_info("=== TestCaseInsensitiveHeaders ===");

    // HOST 全大写：验证头字段名大小写不敏感
    {
        const std::string raw = "GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
        psm::protocol::http::proxy_request req{};
        auto result = psm::protocol::http::parse_proxy_request(raw, req);

        if (result != psm::fault::code::success || req.host != "example.com")
        {
            log_fail("HOST (uppercase) should be parsed as host");
            return;
        }
    }

    // hOsT 混合大小写：模拟非规范客户端
    {
        const std::string raw = "GET / HTTP/1.1\r\nhOsT: mixed.com\r\n\r\n";
        psm::protocol::http::proxy_request req{};
        auto result = psm::protocol::http::parse_proxy_request(raw, req);

        if (result != psm::fault::code::success || req.host != "mixed.com")
        {
            log_fail("hOsT (mixed case) should be parsed as host");
            return;
        }
    }

    // proxy-AUTHORIZATION 混合大小写：认证头也须不敏感
    {
        const std::string raw = "GET / HTTP/1.1\r\nHost: x.com\r\nproxy-AUTHORIZATION: Basic abc\r\n\r\n";
        psm::protocol::http::proxy_request req{};
        auto result = psm::protocol::http::parse_proxy_request(raw, req);

        if (result != psm::fault::code::success || req.authorization != "Basic abc")
        {
            log_fail("proxy-AUTHORIZATION (mixed case) should be parsed");
            return;
        }
    }

    log_pass("CaseInsensitiveHeaders");
}

/**
 * @brief 测试头字段值的空白修剪
 */
void TestHeaderWhitespaceTrim()
{
    log_info("=== TestHeaderWhitespaceTrim ===");

    // Host 值前后含多余空白，验证自动修剪
    const std::string raw = "GET / HTTP/1.1\r\nHost:  example.com \r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }
    // 前导和尾部空白均应被去除
    if (req.host != "example.com")
    {
        log_fail("host should be trimmed to 'example.com'");
        return;
    }

    log_pass("HeaderWhitespaceTrim");
}

/**
 * @brief 测试缺少冒号的畸形头字段行
 */
void TestMalformedHeaderNoColon()
{
    log_info("=== TestMalformedHeaderNoColon ===");

    // 畸形头行缺少冒号分隔符，解析器应静默跳过
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Bad-Header\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    // 解析不应因畸形行失败
    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed despite malformed header line (silently skipped)");
        return;
    }
    // 有效头部应仍被正确提取
    if (req.host != "example.com")
    {
        log_fail("host should still be 'example.com'");
        return;
    }

    log_pass("MalformedHeaderNoColon");
}

/**
 * @brief 测试带 body 数据的请求
 */
void TestRequestWithBodyData()
{
    log_info("=== TestRequestWithBodyData ===");

    // 请求附带 body，验证 header_end 定位到 body 起始
    const std::string raw = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }

    // header_end 应指向 \r\n\r\n 之后、body 之前
    const std::size_t expected_header_end = raw.find("\r\n\r\n") + 4;
    if (req.header_end != expected_header_end)
    {
        log_fail("header_end should point to body start");
        return;
    }

    log_pass("RequestWithBodyData");
}

/**
 * @brief 测试请求行和头部结束偏移量的精确值
 */
void TestReqLineAndHeaderEndOffsets()
{
    log_info("=== TestReqLineAndHeaderEndOffsets ===");

    // 精确构造已知请求，手动计算字节偏移量
    // "GET / HTTP/1.1\r\n" = 16 字节
    // "Host: x.com\r\n" = 13 字节
    // "\r\n" = 2 字节
    // req_line_end = 16, header_end = 16 + 13 + 2 = 31
    const std::string raw = "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }

    // 请求行结束位置：第一个 \r\n 之后
    const std::size_t expected_req_line_end = raw.find("\r\n") + 2; // 16
    if (req.req_line_end != expected_req_line_end)
    {
        log_fail("req_line_end offset incorrect");
        return;
    }

    // 头部结束位置：\r\n\r\n 之后
    const std::size_t expected_header_end = raw.find("\r\n\r\n") + 4; // 31
    if (req.header_end != expected_header_end)
    {
        log_fail("header_end offset incorrect");
        return;
    }

    log_pass("ReqLineAndHeaderEndOffsets");
}

/**
 * @brief 测试缺少头部终止符的请求
 */
void TestMissingHeaderTerminator()
{
    log_info("=== TestMissingHeaderTerminator ===");

    // 缺少 \r\n\r\n 终止符，报文不完整
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    // 必须返回解析错误
    if (result != psm::fault::code::parse_error)
    {
        log_fail("should return parse_error when \\r\\n\\r\\n is missing");
        return;
    }

    log_pass("MissingHeaderTerminator");
}

/**
 * @brief 测试缺少请求行 CRLF 的请求
 */
void TestMissingRequestLineCrlf()
{
    log_info("=== TestMissingRequestLineCrlf ===");

    // 请求行缺少 CRLF，无法定位行尾
    const std::string raw = "GET / HTTP/1.1";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::parse_error)
    {
        log_fail("should return parse_error when request line has no CRLF");
        return;
    }

    log_pass("MissingRequestLineCrlf");
}

/**
 * @brief 测试空输入
 */
void TestEmptyInput()
{
    log_info("=== TestEmptyInput ===");

    // 空输入边界条件
    const std::string raw = "";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::parse_error)
    {
        log_fail("should return parse_error for empty input");
        return;
    }

    log_pass("EmptyInput");
}

/**
 * @brief 测试从绝对 URI 中提取相对路径
 */
void TestExtractPathFromAbsoluteUri()
{
    log_info("=== TestExtractPathFromAbsoluteUri ===");

    // 带 query 和 fragment 的完整 URI，提取路径部分
    {
        auto path = psm::protocol::http::extract_relative_path("http://example.com/path?q=1#frag");
        if (path != "/path?q=1#frag")
        {
            log_fail("http://example.com/path?q=1#frag should extract '/path?q=1#frag'");
            return;
        }
    }

    // HTTPS 协议也应正确去除 authority 部分
    {
        auto path = psm::protocol::http::extract_relative_path("https://example.com/api");
        if (path != "/api")
        {
            log_fail("https://example.com/api should extract '/api'");
            return;
        }
    }

    log_pass("ExtractPathFromAbsoluteUri");
}

/**
 * @brief 测试 URI 无路径分量时返回根路径
 */
void TestExtractPathNoPathComponent()
{
    log_info("=== TestExtractPathNoPathComponent ===");

    // URI 无路径时默认返回根路径 "/"
    {
        auto path = psm::protocol::http::extract_relative_path("http://example.com");
        if (path != "/")
        {
            log_fail("http://example.com should extract '/'");
            return;
        }
    }

    {
        auto path = psm::protocol::http::extract_relative_path("https://example.com");
        if (path != "/")
        {
            log_fail("https://example.com should extract '/'");
            return;
        }
    }

    log_pass("ExtractPathNoPathComponent");
}

/**
 * @brief 测试已经是相对路径的目标保持不变
 */
void TestExtractPathAlreadyRelative()
{
    log_info("=== TestExtractPathAlreadyRelative ===");

    // 已经是相对路径的输入应原样返回
    {
        auto path = psm::protocol::http::extract_relative_path("/path?q=1");
        if (path != "/path?q=1")
        {
            log_fail("'/path?q=1' should be returned as-is");
            return;
        }
    }

    // CONNECT 风格的 host:port 不应被误判为路径
    {
        auto path = psm::protocol::http::extract_relative_path("host:443");
        if (path != "host:443")
        {
            log_fail("'host:443' should be returned as-is");
            return;
        }
    }

    log_pass("ExtractPathAlreadyRelative");
}

/**
 * @brief 测试最小合法请求（无任何头部字段）
 */
void TestMinimalRequest()
{
    log_info("=== TestMinimalRequest ===");

    // 仅请求行 + 空头部，host 应为空
    const std::string raw = "GET / HTTP/1.1\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed for minimal request");
        return;
    }
    if (req.method != "GET")
    {
        log_fail("method should be 'GET'");
        return;
    }
    if (req.target != "/")
    {
        log_fail("target should be '/'");
        return;
    }
    if (!req.host.empty())
    {
        log_fail("host should be empty when no Host header present");
        return;
    }

    log_pass("MinimalRequest");
}

/**
 * @brief 测试 HTTP/1.0 版本解析
 */
void TestHttp10Version()
{
    log_info("=== TestHttp10Version ===");

    const std::string raw = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed for HTTP/1.0");
        return;
    }
    if (req.version != "HTTP/1.0")
    {
        log_fail("version should be 'HTTP/1.0'");
        return;
    }
    if (req.host != "example.com")
    {
        log_fail("host should be 'example.com'");
        return;
    }

    log_pass("Http10Version");
}

/**
 * @brief 测试带端口的 Host 头
 */
void TestHostWithPort()
{
    log_info("=== TestHostWithPort ===");

    // Host 值含端口号，应完整保留
    const std::string raw = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }
    if (req.host != "example.com:8080")
    {
        log_fail("host should be 'example.com:8080'");
        return;
    }

    log_pass("HostWithPort");
}

/**
 * @brief 测试 Tab 作为头部字段值分隔符
 */
void TestTabSeparator()
{
    log_info("=== TestTabSeparator ===");

    // RFC 7230 允许冒号后使用 OWS（空格或 tab），验证 tab 被正确修剪
    const std::string raw = "GET / HTTP/1.1\r\nHost:\texample.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed with tab separator");
        return;
    }
    if (req.host != "example.com")
    {
        log_fail("host should be 'example.com' (tab trimmed)");
        return;
    }

    log_pass("TabSeparator");
}

/**
 * @brief 测试多个 Host 行（应取最后一个）
 */
void TestMultipleHostHeaders()
{
    log_info("=== TestMultipleHostHeaders ===");

    // 多个 Host 头：解析器逐行覆盖，最终保留最后一个
    const std::string raw = "GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n";
    psm::protocol::http::proxy_request req{};
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }
    if (req.host != "second.com")
    {
        log_fail("host should be 'second.com' (last Host wins)");
        return;
    }

    log_pass("MultipleHostHeaders");
}

/**
 * @brief 测试其他头字段不干扰核心字段提取
 */
void TestOtherHeadersIgnored()
{
    log_info("=== TestOtherHeadersIgnored ===");

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
    auto result = psm::protocol::http::parse_proxy_request(raw, req);

    if (result != psm::fault::code::success)
    {
        log_fail("parse should succeed");
        return;
    }
    if (req.host != "example.com")
    {
        log_fail("host should be 'example.com'");
        return;
    }
    if (req.authorization != "Basic abc123")
    {
        log_fail("authorization should be 'Basic abc123'");
        return;
    }

    log_pass("OtherHeadersIgnored");
}

/**
 * @brief 测试 extract_relative_path 带端口
 */
void TestExtractPathWithPort()
{
    log_info("=== TestExtractPathWithPort ===");

    // URI 带非标准端口，路径提取不受端口影响
    {
        auto path = psm::protocol::http::extract_relative_path("http://example.com:8080/path");
        if (path != "/path")
        {
            log_fail("http://example.com:8080/path should extract '/path'");
            return;
        }
    }

    {
        auto path = psm::protocol::http::extract_relative_path("https://example.com:443/api?q=1");
        if (path != "/api?q=1")
        {
            log_fail("https://example.com:443/api?q=1 should extract '/api?q=1'");
            return;
        }
    }

    log_pass("ExtractPathWithPort");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行 HTTP 代理请求解析和路径提取
 *          全部测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化全局 PMR 内存池，测试中使用的容器依赖此池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统，无自定义配置
    psm::trace::init({});

    log_info("Starting HTTP parser tests...");

    // parse_proxy_request 测试
    TestBasicGetRequest();
    TestConnectRequest();
    TestPostRequest();
    TestProxyAuthorization();
    TestBothAuthAndHost();
    TestCaseInsensitiveHeaders();
    TestHeaderWhitespaceTrim();
    TestMalformedHeaderNoColon();
    TestRequestWithBodyData();
    TestReqLineAndHeaderEndOffsets();
    TestMissingHeaderTerminator();
    TestMissingRequestLineCrlf();
    TestEmptyInput();

    // extract_relative_path 测试
    TestExtractPathFromAbsoluteUri();
    TestExtractPathNoPathComponent();
    TestExtractPathAlreadyRelative();
    TestExtractPathWithPort();

    // 边界用例
    TestMinimalRequest();
    TestHttp10Version();
    TestHostWithPort();
    TestTabSeparator();
    TestMultipleHostHeaders();
    TestOtherHeadersIgnored();

    log_info("HTTP parser tests completed.");
    psm::trace::info("[HttpParser] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
