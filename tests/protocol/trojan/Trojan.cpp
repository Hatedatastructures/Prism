/**
 * @file Trojan.cpp
 * @brief Trojan 协议中继握手测试
 * @details 验证 Trojan 协议完整握手流程和数据回显功能，包括：
 * 1. 凭据读取与验证
 * 2. 协议头部解析 (CMD + ATYP + ADDR + PORT)
 * 3. 数据双向传输 (Echo)
 */

#include <prism/proto/protocol/trojan.hpp>
#include <prism/proto/protocol/trojan/framing.hpp>
#include <prism/core/exception/network.hpp>
#include <prism/core/fault/code.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <memory>
#include <cstring>
#include <array>


#include <gtest/gtest.h>

namespace net = boost::asio;
namespace protocol = psm::protocol;
namespace transport = psm::transport;
using tcp = net::ip::tcp;

namespace
{
    /**
     * @brief Trojan 测试服务器协程
     * @details 接受一个连接，使用凭据验证器校验客户端发送的 56 字节 SHA224 哈希，
     *          完成协议握手后读取数据并原样回显，最后关闭连接。
     * @param acceptor TCP 接收器引用
     * @param expected_credential 期望的用户凭据（56 字节十六进制字符串）
     * @return net::awaitable<void>
     */
    net::awaitable<void> DoTrojanServer(tcp::acceptor &acceptor, const std::string &expected_credential)
    {
        try
        {
            // 异步等待客户端连接
            auto socket = co_await acceptor.async_accept(net::use_awaitable);

            // 凭据验证回调：比对客户端发送的 SHA224 哈希与期望值
            auto user_credential_verifier = [expected_credential](std::string_view user_credential) -> bool
            {
                return user_credential == expected_credential;
            };

            // 将 TCP socket 包装为可靠传输层
            auto trans = psm::transport::make_reliable(std::move(socket));
            // 基于传输层和凭据验证器创建 Trojan 中继实例
            auto trojan = psm::protocol::trojan::make_conn(std::move(trans), {}, user_credential_verifier);

            // 执行 Trojan 握手（读取凭据 + 解析 CMD/ATYP/ADDR/PORT）
            auto [ec, req] = co_await trojan->handshake();
            if (psm::fault::failed(ec))
            {
                co_return;
            }

            // Echo 测试：读取客户端载荷并原样回显
            try
            {
                // 从 Trojan 隧道中异步读取客户端发送的数据
                std::array<std::byte, 1024> byte_buf{};
                std::error_code read_ec;
                std::size_t n = co_await trojan->async_read_some(byte_buf, read_ec);
                if (read_ec)
                {
                    co_return;
                }
                std::string received_msg(reinterpret_cast<const char *>(byte_buf.data()), n);

                // 将收到的数据通过同一 Trojan 隧道回写给客户端
                std::error_code write_ec;
                co_await trojan->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(received_msg.data()),
                                               received_msg.size()),
                    write_ec);
            }
            catch (const std::exception &)
            {
            }

            // 测试完成，关闭 Trojan 中继连接
            trojan->close();
        }
        catch (const std::exception &)
        {
        }
        co_return;
    }

    /**
     * @brief Trojan 测试客户端协程
     * @details 按 Trojan 协议规范构造请求：56 字节凭据 + CRLF + CMD + ATYP + 地址 + 端口 + CRLF，
     *          发送后写入测试消息，读取回显并比对。
     * @param endpoint 服务端端点
     * @param credential 用户凭据（56 字节十六进制字符串）
     * @param host 目标域名
     * @param port 目标端口号
     * @param test_msg 测试载荷
     * @return net::awaitable<void>
     */
    net::awaitable<void> DoTrojanClient(tcp::endpoint endpoint, const std::string &credential, const std::string &host,
                                        uint16_t port, const std::string &test_msg)
    {
        try
        {
            // 获取当前协程的执行器并创建 TCP socket
            tcp::socket socket(co_await net::this_coro::executor);
            // 异步连接到 Trojan 测试服务端
            co_await socket.async_connect(endpoint, net::use_awaitable);

            // 按 Trojan 协议规范构造请求字节流
            // 格式: 56字节SHA224哈希 + CRLF + CMD(1) + ATYP(1) + ADDR + PORT(2) + CRLF
            std::string req;
            // 写入用户凭据（56 字节十六进制 SHA224 哈希）
            req.append(credential);
            // CRLF 分隔凭据与命令字段
            req.append("\r\n");
            req.push_back(0x01); // CMD=0x01 表示 CONNECT 命令
            req.push_back(0x03); // ATYP=0x03 表示域名类型
            req.push_back(static_cast<char>(host.length())); // 域名长度字节
            req.append(host);    // 域名内容
            // 端口号转为网络字节序（大端）并写入 2 字节
            uint16_t net_port = htons(port);
            req.append(reinterpret_cast<const char *>(&net_port), 2);
            // 头部以 CRLF 结尾
            req.append("\r\n");

            // 发送完整的 Trojan 协议头
            co_await net::async_write(socket, net::buffer(req), net::use_awaitable);

            // 协议头发送后立即写入测试载荷
            co_await net::async_write(socket, net::buffer(test_msg), net::use_awaitable);

            // 读取服务端回显的数据
            std::array<char, 1024> buffer;
            std::size_t n = co_await socket.async_read_some(net::buffer(buffer), net::use_awaitable);
            std::string received_msg(buffer.data(), n);

            // 验证回显内容与发送内容一致
            if (received_msg != test_msg)
            {
                throw psm::exception::network(psm::fault::code::generic_error);
            }

            // 优雅关闭 socket 的读写两端
            boost::system::error_code ec;
            socket.shutdown(tcp::socket::shutdown_both, ec);
            socket.close(ec);
        }
        catch (const std::exception &)
        {
        }
        co_return;
    }
}

// ============================================================================
// UDP 帧格式测试
// ============================================================================

/**
 * @brief 测试 Trojan parse_udp_packet -- IPv4 地址
 */
TEST(Trojan, UdpParseIPv4)
{
    // Trojan UDP: [ATYP=0x01][IPv4 4B][Port 2B][Length 2B][CRLF 2B][Payload]
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x01});                                // ATYP = IPv4
    buf.push_back(std::byte{127}); buf.push_back(std::byte{0});
    buf.push_back(std::byte{0});   buf.push_back(std::byte{1});   // 127.0.0.1
    buf.push_back(std::byte{0x00}); buf.push_back(std::byte{0x50}); // port = 80
    buf.push_back(std::byte{0x00}); buf.push_back(std::byte{0x05}); // length = 5
    buf.push_back(std::byte{0x0D}); buf.push_back(std::byte{0x0A}); // CRLF
    const char* payload = "hello";
    for (auto c : std::string_view(payload))
    {
        buf.push_back(static_cast<std::byte>(c));
    }

    auto [ec, result] = protocol::trojan::format::parse_udp_pkt(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse_udp_packet IPv4 failed: " << psm::fault::describe(ec);

    auto* ipv4 = std::get_if<protocol::trojan::ipv4_address>(&result.destination_address);
    ASSERT_TRUE(ipv4 != nullptr) << "address type should be IPv4";
    EXPECT_TRUE(result.destination_port == 80) << "port should be 80, got " << result.destination_port;
    EXPECT_TRUE(result.payload_size == 5) << "payload size should be 5, got " << result.payload_size;
}

/**
 * @brief 测试 Trojan parse_udp_packet -- 域名地址
 */
TEST(Trojan, UdpParseDomain)
{
    const std::string domain = "example.com";
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x03});                                // ATYP = Domain
    buf.push_back(static_cast<std::byte>(domain.size()));          // domain length
    for (auto c : domain)
    {
        buf.push_back(static_cast<std::byte>(c));
    }
    buf.push_back(std::byte{0x01}); buf.push_back(std::byte{0x0BB}); // port = 443
    buf.push_back(std::byte{0x00}); buf.push_back(std::byte{0x04}); // length = 4
    buf.push_back(std::byte{0x0D}); buf.push_back(std::byte{0x0A}); // CRLF
    const char* payload = "test";
    for (auto c : std::string_view(payload))
    {
        buf.push_back(static_cast<std::byte>(c));
    }

    auto [ec, result] = protocol::trojan::format::parse_udp_pkt(buf);
    ASSERT_TRUE(psm::fault::succeeded(ec)) << "parse_udp_packet Domain failed: " << psm::fault::describe(ec);

    auto* dom = std::get_if<protocol::trojan::domain_address>(&result.destination_address);
    ASSERT_TRUE(dom != nullptr) << "address type should be domain";
    EXPECT_TRUE(result.destination_port == 443) << "port should be 443";
}

/**
 * @brief 测试 Trojan build_udp_packet + parse_udp_packet 往返
 */
TEST(Trojan, UdpBuildParseRoundtrip)
{
    protocol::trojan::format::udp_routed frame;
    frame.destination_address = protocol::trojan::ipv4_address{{127, 0, 0, 1}};
    frame.destination_port = 8080;

    const std::string payload_str = "hello trojan udp";
    auto payload_span = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(payload_str.data()), payload_str.size());

    psm::memory::vector<std::byte> out(psm::memory::current_resource());
    auto build_ec = protocol::trojan::format::build_udp_pkt(frame, payload_span, out);
    ASSERT_TRUE(psm::fault::succeeded(build_ec)) << "build_udp_packet failed: " << psm::fault::describe(build_ec);

    auto [parse_ec, result] = protocol::trojan::format::parse_udp_pkt(out);
    ASSERT_TRUE(psm::fault::succeeded(parse_ec)) << "parse_udp_packet roundtrip failed: " << psm::fault::describe(parse_ec);

    EXPECT_TRUE(result.destination_port == 8080) << "roundtrip port should be 8080, got " << result.destination_port;
    EXPECT_TRUE(result.payload_size == payload_str.size()) << "roundtrip payload_size mismatch";

    std::string_view parsed_payload(reinterpret_cast<const char*>(out.data() + result.payload_offset),
                                     result.payload_size);
    EXPECT_TRUE(parsed_payload == payload_str) << "roundtrip payload content mismatch";
}

/**
 * @brief 测试 Trojan 协议完整握手与数据回显
 */
TEST(Trojan, RelayHandshake)
{
    // 创建 io_context 驱动异步事件循环
    net::io_context ioc;

    // 绑定到本地回环地址，端口 0 由操作系统自动分配
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    // 获取实际分配的端口号，供客户端连接使用
    auto bound_endpoint = acceptor.local_endpoint();

    // 构造测试凭据：56 个 'a' 模拟 SHA224 哈希输出
    const std::string test_user_credential(56, 'a');
    const std::string test_host = "example.com";
    const uint16_t test_port = 80;
    const std::string test_message = "Hello Trojan";

    // 用 shared_ptr 标记客户端是否完成全部测试
    auto client_ok = std::make_shared<bool>(false);

    // 启动服务端协程：接受连接并进行 Trojan 握手及回显
    net::co_spawn(ioc, DoTrojanServer(acceptor, test_user_credential), net::detached);
    // 启动客户端协程：连接服务端并执行完整的 Trojan 握手 + Echo 测试
    auto client_task = [endpoint = bound_endpoint, &test_user_credential, &test_host, test_port, &test_message, client_ok]() -> net::awaitable<void>
    {
                      try
                      {
                          co_await DoTrojanClient(endpoint, test_user_credential, test_host, test_port, test_message);
                          *client_ok = true;
                      }
                      catch (const std::exception &)
                      {
                      }
                  };
    net::co_spawn(ioc, std::move(client_task), [&](const std::exception_ptr &)
                  { ioc.stop(); });

    // 阻塞运行事件循环，直到所有异步操作完成
    ioc.run();

    // 根据客户端标记判定整体测试结果
    EXPECT_TRUE(*client_ok) << "Trojan relay handshake and echo";
}
