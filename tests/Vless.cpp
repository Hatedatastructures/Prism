/**
 * @file Vless.cpp
 * @brief VLESS 协议单元测试与集成测试
 * @details 测试 VLESS 协议的请求解析、响应生成和完整握手流程，覆盖
 * IPv4/IPv6/域名地址解析、命令字识别、无效输入处理以及协程集成握手。
 */

#include <prism/protocol/vless.hpp>
#include <prism/protocol/vless/format.hpp>
#include <prism/protocol/vless/message.hpp>
#include <prism/protocol/vless/constants.hpp>
#include <prism/protocol/vless/relay.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>
#include <boost/asio.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace net = boost::asio;
namespace protocol = psm::protocol;
namespace transport = psm::channel::transport;
using tcp = net::ip::tcp;

namespace
{
    int passed = 0;
    int failed = 0;

    void log_info(const std::string_view msg)
    {
        psm::trace::info("[Vless] {}", msg);
    }

    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[Vless] PASS: {}", msg);
    }

    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[Vless] FAIL: {}", msg);
    }
}

// ============================================================================
// 单元测试
// ============================================================================

/**
 * @brief 测试 VLESS 请求解析 — IPv4 地址
 */
void TestVlessParseRequestIPv4()
{
    log_info("=== TestVlessParseRequestIPv4 ===");

    // [Version 1B][UUID 16B][AddnlLen 1B][Cmd 1B][Port 2B BE][Atyp 1B][Addr 4B]
    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);                                         // version
    buf.insert(buf.end(), 16, 0x00);                             // UUID (全零)
    buf.push_back(0x00);                                         // addnl_len = 0
    buf.push_back(0x01);                                         // cmd = tcp
    buf.push_back(0x00); buf.push_back(0x50);                    // port = 80 (big-endian)
    buf.push_back(0x01);                                         // atyp = IPv4
    buf.push_back(127); buf.push_back(0); buf.push_back(0); buf.push_back(1); // 127.0.0.1

    auto result = protocol::vless::format::parse_request(buf);
    if (!result)
    {
        log_fail("parse_request returned nullopt for valid IPv4 request");
        return;
    }

    if (result->cmd != protocol::vless::command::tcp)
    {
        log_fail("cmd should be tcp");
        return;
    }

    if (result->port != 80)
    {
        log_fail("port should be 80, got " + std::to_string(result->port));
        return;
    }

    auto *ipv4 = std::get_if<protocol::vless::ipv4_address>(&result->destination_address);
    if (!ipv4)
    {
        log_fail("address type should be IPv4");
        return;
    }

    std::array<std::uint8_t, 4> expected = {127, 0, 0, 1};
    if (ipv4->bytes != expected)
    {
        log_fail("IPv4 address mismatch");
        return;
    }

    log_pass("VlessParseRequestIPv4");
}

/**
 * @brief 测试 VLESS 请求解析 — 域名地址
 */
void TestVlessParseRequestDomain()
{
    log_info("=== TestVlessParseRequestDomain ===");

    const std::string domain = "example.com";

    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);                                         // version
    buf.insert(buf.end(), 16, 0x00);                             // UUID
    buf.push_back(0x00);                                         // addnl_len = 0
    buf.push_back(0x01);                                         // cmd = tcp
    buf.push_back(0x01); buf.push_back(0xBB);                    // port = 443 (big-endian)
    buf.push_back(0x02);                                         // atyp = domain
    buf.push_back(static_cast<std::uint8_t>(domain.size()));     // domain length
    buf.insert(buf.end(), domain.begin(), domain.end());          // domain content

    auto result = protocol::vless::format::parse_request(buf);
    if (!result)
    {
        log_fail("parse_request returned nullopt for valid domain request");
        return;
    }

    if (result->port != 443)
    {
        log_fail("port should be 443");
        return;
    }

    auto *dom = std::get_if<protocol::vless::domain_address>(&result->destination_address);
    if (!dom)
    {
        log_fail("address type should be domain");
        return;
    }

    if (dom->length != domain.size())
    {
        log_fail("domain length mismatch");
        return;
    }

    log_pass("VlessParseRequestDomain");
}

/**
 * @brief 测试 VLESS 请求解析 — IPv6 地址
 */
void TestVlessParseRequestIPv6()
{
    log_info("=== TestVlessParseRequestIPv6 ===");

    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);                                         // version
    buf.insert(buf.end(), 16, 0x00);                             // UUID
    buf.push_back(0x00);                                         // addnl_len = 0
    buf.push_back(0x01);                                         // cmd = tcp
    buf.push_back(0x20); buf.push_back(0xFB);                    // port = 8443 (big-endian)
    buf.push_back(0x03);                                         // atyp = IPv6
    // ::1 — 15 个零 + 1
    buf.insert(buf.end(), 15, 0x00);
    buf.push_back(0x01);

    auto result = protocol::vless::format::parse_request(buf);
    if (!result)
    {
        log_fail("parse_request returned nullopt for valid IPv6 request");
        return;
    }

    if (result->port != 8443)
    {
        log_fail("port should be 8443, got " + std::to_string(result->port));
        return;
    }

    auto *ipv6 = std::get_if<protocol::vless::ipv6_address>(&result->destination_address);
    if (!ipv6)
    {
        log_fail("address type should be IPv6");
        return;
    }

    log_pass("VlessParseRequestIPv6");
}

/**
 * @brief 测试 mux 命令识别
 */
void TestVlessParseRequestMuxCommand()
{
    log_info("=== TestVlessParseRequestMuxCommand ===");

    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);
    buf.insert(buf.end(), 16, 0x00);
    buf.push_back(0x00);
    buf.push_back(0x7F);                                         // cmd = mux (0x7F)
    buf.push_back(0x00); buf.push_back(0x50);
    buf.push_back(0x01);
    buf.insert(buf.end(), 4, 0x00);

    auto result = protocol::vless::format::parse_request(buf);
    if (!result)
    {
        log_fail("parse_request returned nullopt");
        return;
    }

    if (result->cmd != protocol::vless::command::mux)
    {
        log_fail("cmd should be mux");
        return;
    }

    log_pass("VlessParseRequestMuxCommand");
}

/**
 * @brief 测试无效版本号
 */
void TestVlessParseRequestInvalidVersion()
{
    log_info("=== TestVlessParseRequestInvalidVersion ===");

    std::vector<std::uint8_t> buf;
    buf.push_back(0x01);                                         // version = 1 (invalid)
    buf.insert(buf.end(), 16, 0x00);
    buf.push_back(0x00);
    buf.push_back(0x01);
    buf.push_back(0x00); buf.push_back(0x50);
    buf.push_back(0x01);
    buf.insert(buf.end(), 4, 0x00);

    auto result = protocol::vless::format::parse_request(buf);
    if (result.has_value())
    {
        log_fail("invalid version should return nullopt");
        return;
    }

    log_pass("VlessParseRequestInvalidVersion");
}

/**
 * @brief 测试截断缓冲区
 */
void TestVlessParseRequestTruncated()
{
    log_info("=== TestVlessParseRequestTruncated ===");

    std::array<std::uint8_t, 5> short_buf = {0x00, 0x00, 0x00, 0x00, 0x00};

    auto result = protocol::vless::format::parse_request(short_buf);
    if (result.has_value())
    {
        log_fail("truncated buffer should return nullopt");
        return;
    }

    log_pass("VlessParseRequestTruncated");
}

/**
 * @brief 测试非零附加信息长度
 */
void TestVlessParseRequestNonZeroAddnl()
{
    log_info("=== TestVlessParseRequestNonZeroAddnl ===");

    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);                                         // version
    buf.insert(buf.end(), 16, 0x00);                             // UUID
    buf.push_back(0x05);                                         // addnl_len = 5 (non-zero, unsupported)

    auto result = protocol::vless::format::parse_request(buf);
    if (result.has_value())
    {
        log_fail("non-zero addnl_len should return nullopt");
        return;
    }

    log_pass("VlessParseRequestNonZeroAddnl");
}

/**
 * @brief 测试 make_response
 */
void TestVlessMakeResponse()
{
    log_info("=== TestVlessMakeResponse ===");

    auto resp = protocol::vless::format::make_response();

    if (resp.size() != 2)
    {
        log_fail("response should be 2 bytes");
        return;
    }

    if (resp[0] != std::byte{0x00} || resp[1] != std::byte{0x00})
    {
        log_fail("response should be {0x00, 0x00}");
        return;
    }

    log_pass("VlessMakeResponse");
}

// ============================================================================
// 集成测试（协程）
// ============================================================================

/**
 * @brief VLESS 测试服务器协程
 */
net::awaitable<void> DoVlessServer(tcp::acceptor &acceptor)
{
    try
    {
        log_info("Server coroutine started, waiting for connection...");
        auto socket = co_await acceptor.async_accept(net::use_awaitable);

        // UUID 验证器：接受全零 UUID
        auto verifier = [](std::string_view uuid) -> bool
        {
            log_info(std::format("Verifying UUID: {}", uuid));
            return !uuid.empty();
        };

        auto trans = transport::make_reliable(std::move(socket));
        auto vless = protocol::vless::make_relay(std::move(trans), {}, verifier);

        log_info("Server starting VLESS handshake...");
        auto [ec, req] = co_await vless->handshake();
        if (psm::fault::failed(ec))
        {
            log_fail(std::format("Server handshake failed: {}", std::string_view(psm::fault::describe(ec))));
            co_return;
        }
        log_info("Server handshake success");

        // Echo 测试
        std::array<char, 1024> buffer;
        try
        {
            std::size_t n = co_await transport::async_read_some(vless, net::buffer(buffer), net::use_awaitable);
            std::string received(buffer.data(), n);
            log_info(std::format("Server received: {}", received));

            co_await transport::async_write_some(vless, net::buffer(received), net::use_awaitable);
        }
        catch (const std::exception &e)
        {
            log_fail(std::format("Data echo error: {}", e.what()));
        }

        vless->close();
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("Server exception: {}", e.what()));
    }
}

/**
 * @brief VLESS 测试客户端协程
 */
net::awaitable<void> DoVlessClient(tcp::endpoint endpoint, const std::string &test_msg)
{
    try
    {
        tcp::socket socket(co_await net::this_coro::executor);
        co_await socket.async_connect(endpoint, net::use_awaitable);

        // 构造 VLESS 请求：[Version 1B][UUID 16B][AddnlLen 1B][Cmd 1B][Port 2B BE][Atyp 1B][Addr 4B]
        std::vector<std::uint8_t> req;
        req.push_back(0x00);                                         // version
        req.insert(req.end(), 16, 0x00);                             // UUID (全零)
        req.push_back(0x00);                                         // addnl_len = 0
        req.push_back(0x01);                                         // cmd = tcp
        req.push_back(0x00); req.push_back(0x50);                    // port = 80
        req.push_back(0x01);                                         // atyp = IPv4
        req.push_back(127); req.push_back(0); req.push_back(0); req.push_back(1); // 127.0.0.1

        co_await net::async_write(socket, net::buffer(req), net::use_awaitable);

        // 读取 2 字节响应
        std::array<std::uint8_t, 2> resp;
        co_await net::async_read(socket, net::buffer(resp), net::use_awaitable);

        // 发送测试消息
        co_await net::async_write(socket, net::buffer(test_msg), net::use_awaitable);

        // 读取回显
        std::array<char, 1024> buffer;
        std::size_t n = co_await socket.async_read_some(net::buffer(buffer), net::use_awaitable);
        std::string received(buffer.data(), n);

        if (received != test_msg)
        {
            throw std::runtime_error("echo mismatch");
        }

        log_info(std::format("Client test success: {}", test_msg));

        boost::system::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("Client exception: {}", e.what()));
    }
}

/**
 * @brief 测试 VLESS 完整握手与数据回显
 */
void TestVlessRelayHandshake()
{
    log_info("=== TestVlessRelayHandshake ===");

    net::io_context ioc;

    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    auto bound_endpoint = acceptor.local_endpoint();

    log_info(std::format("Test server listening on: {}:{}", bound_endpoint.address().to_string(), bound_endpoint.port()));

    const std::string test_message = "Hello VLESS";
    auto client_ok = std::make_shared<bool>(false);

    net::co_spawn(ioc, DoVlessServer(acceptor), net::detached);
    net::co_spawn(
        ioc,
        [endpoint = bound_endpoint, &test_message, client_ok]() -> net::awaitable<void>
        {
            try
            {
                co_await DoVlessClient(endpoint, test_message);
                *client_ok = true;
            }
            catch (const std::exception &e)
            {
                log_fail(std::format("Client wrapper exception: {}", e.what()));
            }
        },
        [&](const std::exception_ptr &)
        { ioc.stop(); });

    ioc.run();

    if (*client_ok)
    {
        log_pass("Vless relay handshake and echo");
    }
}

// ============================================================================
// 测试入口
// ============================================================================

/**
 * @brief 测试入口
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    log_info("Starting VLESS tests...");

    // 单元测试
    TestVlessParseRequestIPv4();
    TestVlessParseRequestDomain();
    TestVlessParseRequestIPv6();
    TestVlessParseRequestMuxCommand();
    TestVlessParseRequestInvalidVersion();
    TestVlessParseRequestTruncated();
    TestVlessParseRequestNonZeroAddnl();
    TestVlessMakeResponse();

    // 集成测试
    try
    {
        TestVlessRelayHandshake();
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("TestVlessRelayHandshake threw exception: {}", e.what()));
    }

    psm::trace::info("[Vless] Results: {} passed, {} failed", passed, failed);
    psm::trace::shutdown();

    return failed > 0 ? 1 : 0;
}
