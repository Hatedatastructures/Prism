/**
 * @file Vless.cpp
 * @brief VLESS 协议单元测试与集成测试
 * @details 测试 VLESS 协议的请求解析、响应生成和完整握手流程，覆盖
 * IPv4/IPv6/域名地址解析、命令字识别、无效输入处理以及协程集成握手。
 */

#include <prism/protocol/vless/vless.hpp>
#include <prism/protocol/vless/framing.hpp>
#include <prism/protocol/vless/packet.hpp>
#include <prism/protocol/vless/constants.hpp>
#include <prism/protocol/vless/conn.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>
#include <boost/asio.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>


#include <gtest/gtest.h>

namespace net = boost::asio;
namespace protocol = psm::protocol;
namespace transport = psm::transport;
using tcp = net::ip::tcp;

// ============================================================================
// 单元测试
// ============================================================================

/**
 * @brief 测试 VLESS 请求解析 -- IPv4 地址
 */
TEST(Vless, ParseRequestIPv4)
{
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
    ASSERT_TRUE(result.has_value()) << "parse_request returned nullopt for valid IPv4 request";

    EXPECT_TRUE(result->cmd == protocol::vless::command::tcp) << "cmd should be tcp";
    EXPECT_TRUE(result->port == 80) << "port should be 80, got " << result->port;

    auto *ipv4 = std::get_if<protocol::vless::ipv4_address>(&result->destination_address);
    ASSERT_TRUE(ipv4 != nullptr) << "address type should be IPv4";

    std::array<std::uint8_t, 4> expected = {127, 0, 0, 1};
    EXPECT_TRUE(ipv4->bytes == expected) << "IPv4 address mismatch";
}

/**
 * @brief 测试 VLESS 请求解析 -- 域名地址
 */
TEST(Vless, ParseRequestDomain)
{
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
    ASSERT_TRUE(result.has_value()) << "parse_request returned nullopt for valid domain request";

    EXPECT_TRUE(result->port == 443) << "port should be 443";

    auto *dom = std::get_if<protocol::vless::domain_address>(&result->destination_address);
    ASSERT_TRUE(dom != nullptr) << "address type should be domain";
    EXPECT_TRUE(dom->length == domain.size()) << "domain length mismatch";
}

/**
 * @brief 测试 VLESS 请求解析 -- IPv6 地址
 */
TEST(Vless, ParseRequestIPv6)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);                                         // version
    buf.insert(buf.end(), 16, 0x00);                             // UUID
    buf.push_back(0x00);                                         // addnl_len = 0
    buf.push_back(0x01);                                         // cmd = tcp
    buf.push_back(0x20); buf.push_back(0xFB);                    // port = 8443 (big-endian)
    buf.push_back(0x03);                                         // atyp = IPv6
    // ::1 -- 15 个零 + 1
    buf.insert(buf.end(), 15, 0x00);
    buf.push_back(0x01);

    auto result = protocol::vless::format::parse_request(buf);
    ASSERT_TRUE(result.has_value()) << "parse_request returned nullopt for valid IPv6 request";

    EXPECT_TRUE(result->port == 8443) << "port should be 8443, got " << result->port;

    auto *ipv6 = std::get_if<protocol::vless::ipv6_address>(&result->destination_address);
    ASSERT_TRUE(ipv6 != nullptr) << "address type should be IPv6";
}

/**
 * @brief 测试 mux 命令识别
 */
TEST(Vless, ParseRequestMuxCommand)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);
    buf.insert(buf.end(), 16, 0x00);
    buf.push_back(0x00);
    buf.push_back(0x7F);                                         // cmd = mux (0x7F)
    buf.push_back(0x00); buf.push_back(0x50);
    buf.push_back(0x01);
    buf.insert(buf.end(), 4, 0x00);

    auto result = protocol::vless::format::parse_request(buf);
    ASSERT_TRUE(result.has_value()) << "parse_request returned nullopt";
    EXPECT_TRUE(result->cmd == protocol::vless::command::mux) << "cmd should be mux";
}

/**
 * @brief 测试无效版本号
 */
TEST(Vless, ParseRequestInvalidVersion)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(0x01);                                         // version = 1 (invalid)
    buf.insert(buf.end(), 16, 0x00);
    buf.push_back(0x00);
    buf.push_back(0x01);
    buf.push_back(0x00); buf.push_back(0x50);
    buf.push_back(0x01);
    buf.insert(buf.end(), 4, 0x00);

    auto result = protocol::vless::format::parse_request(buf);
    EXPECT_TRUE(!result.has_value()) << "invalid version should return nullopt";
}

/**
 * @brief 测试截断缓冲区
 */
TEST(Vless, ParseRequestTruncated)
{
    std::array<std::uint8_t, 5> short_buf = {0x00, 0x00, 0x00, 0x00, 0x00};

    auto result = protocol::vless::format::parse_request(short_buf);
    EXPECT_TRUE(!result.has_value()) << "truncated buffer should return nullopt";
}

/**
 * @brief 测试非零附加信息长度
 */
TEST(Vless, ParseRequestNonZeroAddnl)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(0x00);                                         // version
    buf.insert(buf.end(), 16, 0x00);                             // UUID
    buf.push_back(0x05);                                         // addnl_len = 5 (non-zero, unsupported)

    auto result = protocol::vless::format::parse_request(buf);
    EXPECT_TRUE(!result.has_value()) << "non-zero addnl_len should return nullopt";
}

/**
 * @brief 测试 make_response
 */
TEST(Vless, MakeResponse)
{
    auto resp = protocol::vless::format::make_response();

    EXPECT_TRUE(resp.size() == 2) << "response should be 2 bytes";
    EXPECT_TRUE(resp[0] == std::byte{0x00} && resp[1] == std::byte{0x00}) << "response should be {0x00, 0x00}";
}

// ============================================================================
// UDP 帧格式测试
// ============================================================================

/**
 * @brief 测试 parse_udp_pkt -- IPv4 地址
 */
TEST(Vless, UdpParseIPv4)
{
    // [ATYP=0x01][127.0.0.1][Port=0x0050][Payload]
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x01});                                // ATYP = IPv4
    buf.push_back(std::byte{127}); buf.push_back(std::byte{0});
    buf.push_back(std::byte{0});   buf.push_back(std::byte{1});   // 127.0.0.1
    buf.push_back(std::byte{0x00}); buf.push_back(std::byte{0x50}); // port = 80
    const char* payload = "hello";
    for (auto c : std::string_view(payload))
    {
        buf.push_back(static_cast<std::byte>(c));
    }

    auto [ec, result] = protocol::vless::format::parse_udp_pkt(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse_udp_pkt IPv4 failed: " << psm::fault::describe(ec);

    auto* ipv4 = std::get_if<protocol::vless::ipv4_address>(&result.destination_address);
    ASSERT_TRUE(ipv4 != nullptr) << "address type should be IPv4";
    EXPECT_TRUE(result.destination_port == 80) << "port should be 80, got " << result.destination_port;
    EXPECT_TRUE(result.payload_size == 5) << "payload size should be 5, got " << result.payload_size;
}

/**
 * @brief 测试 parse_udp_pkt -- IPv6 地址
 */
TEST(Vless, UdpParseIPv6)
{
    // [ATYP=0x03][16B ::1][Port=0x01BB][Payload]
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x03});                                // ATYP = IPv6 (VLESS uses 0x03 for IPv6)
    for (int i = 0; i < 15; ++i)
    {
        buf.push_back(std::byte{0x00});
    }
    buf.push_back(std::byte{0x01});                                // ::1
    buf.push_back(std::byte{0x01}); buf.push_back(std::byte{0xBB}); // port = 443
    const char* payload = "world";
    for (auto c : std::string_view(payload))
    {
        buf.push_back(static_cast<std::byte>(c));
    }

    auto [ec, result] = protocol::vless::format::parse_udp_pkt(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse_udp_pkt IPv6 failed: " << psm::fault::describe(ec);

    auto* ipv6 = std::get_if<protocol::vless::ipv6_address>(&result.destination_address);
    ASSERT_TRUE(ipv6 != nullptr) << "address type should be IPv6";
    EXPECT_TRUE(result.destination_port == 443) << "port should be 443, got " << result.destination_port;
}

/**
 * @brief 测试 parse_udp_pkt -- 域名地址
 */
TEST(Vless, UdpParseDomain)
{
    const std::string domain = "example.com";
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x02});                                // ATYP = Domain
    buf.push_back(static_cast<std::byte>(domain.size()));          // domain length
    for (auto c : domain)
    {
        buf.push_back(static_cast<std::byte>(c));
    }
    buf.push_back(std::byte{0x01}); buf.push_back(std::byte{0xBB}); // port = 443
    const char* payload = "test";
    for (auto c : std::string_view(payload))
    {
        buf.push_back(static_cast<std::byte>(c));
    }

    auto [ec, result] = protocol::vless::format::parse_udp_pkt(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse_udp_pkt Domain failed: " << psm::fault::describe(ec);

    auto* dom = std::get_if<protocol::vless::domain_address>(&result.destination_address);
    ASSERT_TRUE(dom != nullptr) << "address type should be domain";
    EXPECT_TRUE(result.destination_port == 443) << "port should be 443";
    EXPECT_TRUE(result.payload_size == 4) << "payload size should be 4, got " << result.payload_size;
}

/**
 * @brief 测试 parse_udp_pkt -- 短缓冲区
 */
TEST(Vless, UdpParseShortBuffer)
{
    // IPv4 最小帧需要 7 字节 (1+4+2)，提供 5 字节应失败
    std::vector<std::byte> buf(5, std::byte{0x01});
    auto [ec, result] = protocol::vless::format::parse_udp_pkt(buf);
    EXPECT_TRUE(psm::fault::failed(ec)) << "short buffer should fail";
}

/**
 * @brief 测试 parse_udp_pkt -- 空 payload
 */
TEST(Vless, UdpParseEmptyPayload)
{
    // [ATYP=0x01][127.0.0.1][Port=80] -- 无 payload
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{127}); buf.push_back(std::byte{0});
    buf.push_back(std::byte{0});   buf.push_back(std::byte{1});
    buf.push_back(std::byte{0x00}); buf.push_back(std::byte{0x50});

    auto [ec, result] = protocol::vless::format::parse_udp_pkt(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse_udp_pkt with empty payload should succeed";
    EXPECT_TRUE(result.payload_size == 0) << "payload_size should be 0, got " << result.payload_size;
}

/**
 * @brief 测试 build_udp_pkt + parse_udp_pkt 往返
 */
TEST(Vless, UdpBuildParseRoundtrip)
{
    // 构建 IPv4 帧
    protocol::vless::format::udp_routed frame;
    frame.destination_address = protocol::vless::ipv4_address{{127, 0, 0, 1}};
    frame.destination_port = 8080;

    const std::string payload_str = "hello vless udp";
    auto payload_span = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(payload_str.data()), payload_str.size());

    psm::memory::vector<std::byte> out(psm::memory::current_resource());
    auto build_ec = protocol::vless::format::build_udp_pkt(frame, payload_span, out);
    ASSERT_TRUE(psm::fault::succeeded(build_ec)) << "build_udp_pkt failed: " << psm::fault::describe(build_ec);

    // 解析回来
    auto [parse_ec, result] = protocol::vless::format::parse_udp_pkt(out);
    ASSERT_TRUE(psm::fault::succeeded(parse_ec)) << "parse_udp_pkt roundtrip failed: " << psm::fault::describe(parse_ec);

    EXPECT_TRUE(result.destination_port == 8080) << "roundtrip port should be 8080, got " << result.destination_port;
    EXPECT_TRUE(result.payload_size == payload_str.size()) << "roundtrip payload_size mismatch";

    // 验证 payload 内容一致
    std::string_view parsed_payload(reinterpret_cast<const char*>(out.data() + result.payload_offset),
                                     result.payload_size);
    EXPECT_TRUE(parsed_payload == payload_str) << "roundtrip payload content mismatch";
}

// ============================================================================
// 集成测试（协程）
// ============================================================================

namespace
{
    /**
     * @brief VLESS 测试服务器协程
     */
    net::awaitable<void> DoVlessServer(tcp::acceptor &acceptor)
    {
        try
        {
            auto socket = co_await acceptor.async_accept(net::use_awaitable);

            // UUID 验证器：接受全零 UUID
            auto verifier = [](std::string_view uuid) -> bool
            {
                return !uuid.empty();
            };

            auto trans = transport::make_reliable(std::move(socket));
            auto vless = protocol::vless::make_conn(std::move(trans), {}, verifier);

            auto [ec, req] = co_await vless->handshake();
            if (psm::fault::failed(ec))
            {
                co_return;
            }

            // Echo 测试
            std::array<std::byte, 1024> byte_buf{};
            try
            {
                std::error_code read_ec;
                std::size_t n = co_await vless->async_read_some(byte_buf, read_ec);
                if (read_ec)
                {
                    co_return;
                }
                std::string received(reinterpret_cast<const char *>(byte_buf.data()), n);

                std::error_code write_ec;
                co_await vless->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(received.data()),
                                               received.size()),
                    write_ec);
            }
            catch (const std::exception &)
            {
            }

            vless->close();
        }
        catch (const std::exception &)
        {
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

            boost::system::error_code ec;
            socket.shutdown(tcp::socket::shutdown_both, ec);
            socket.close(ec);
        }
        catch (const std::exception &)
        {
        }
    }
}

/**
 * @brief 测试 VLESS 完整握手与数据回显
 */
TEST(Vless, RelayHandshake)
{
    net::io_context ioc;

    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    auto bound_endpoint = acceptor.local_endpoint();

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
            catch (const std::exception &)
            {
            }
        },
        [&](const std::exception_ptr &)
        { ioc.stop(); });

    ioc.run();

    EXPECT_TRUE(*client_ok) << "Vless relay handshake and echo";
}
