/**
 * @file Trojan.cpp
 * @brief Trojan 协议中继握手测试
 * @details 验证 Trojan 协议完整握手流程和数据回显功能，包括：
 * 1. 凭据读取与验证
 * 2. 协议头部解析 (CMD + ATYP + ADDR + PORT)
 * 3. 数据双向传输 (Echo)
 */

#include <prism/protocol/trojan.hpp>
#include <prism/exception/network.hpp>
#include <prism/fault/code.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <memory>
#include <cstring>
#include <array>

namespace net = boost::asio;
namespace protocol = psm::protocol;
namespace transport = psm::channel::transport;
using tcp = net::ip::tcp;

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    void log_info(const std::string_view msg)
    {
        psm::trace::info("[Trojan] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[Trojan] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[Trojan] FAIL: {}", msg);
    }
}

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
        log_info("Server coroutine started, waiting for connection...");
        // 异步等待客户端连接
        auto socket = co_await acceptor.async_accept(net::use_awaitable);

        // 凭据验证回调：比对客户端发送的 SHA224 哈希与期望值
        auto user_credential_verifier = [expected_credential](std::string_view user_credential) -> bool
        {
            log_info(std::format("Verifying user credential: {}", user_credential));
            return user_credential == expected_credential;
        };

        // 将 TCP socket 包装为可靠传输层
        auto trans = psm::channel::transport::make_reliable(std::move(socket));
        // 基于传输层和凭据验证器创建 Trojan 中继实例
        auto trojan = psm::protocol::trojan::make_relay(std::move(trans), {}, user_credential_verifier);

        // 执行 Trojan 握手（读取凭据 + 解析 CMD/ATYP/ADDR/PORT）
        log_info("Server starting Trojan handshake...");
        auto [ec, req] = co_await trojan->handshake();
        if (psm::fault::failed(ec))
        {
            log_fail(std::format("Server handshake failed: {}", std::string_view(psm::fault::describe(ec))));
            co_return;
        }
        log_info("Server handshake success");

        // 将目标地址转为可读字符串用于日志输出
        auto host_str = psm::protocol::trojan::to_string(req.destination_address);
        log_info(std::format("Trojan server received request: CMD={}, ADDR={}, PORT={}",
                             static_cast<int>(req.cmd), host_str, req.port));

        // Echo 测试：读取客户端载荷并原样回显
        std::array<char, 1024> buffer;
        auto buf = net::buffer(buffer);

        try
        {
            // 从 Trojan 隧道中异步读取客户端发送的数据
            std::size_t n = co_await psm::channel::transport::async_read_some(trojan, buf, net::use_awaitable);
            std::string received_msg(buffer.data(), n);

            log_info(std::format("Server received message: {}", received_msg));

            // 将收到的数据通过同一 Trojan 隧道回写给客户端
            co_await psm::channel::transport::async_write_some(trojan, net::buffer(received_msg), net::use_awaitable);
        }
        catch (const std::exception &e)
        {
            log_fail(std::format("Data transmission error: {}", e.what()));
        }

        // 测试完成，关闭 Trojan 中继连接
        log_info("Server test complete, closing connection");
        trojan->close();
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("Server exception: {}", e.what()));
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

        log_info(std::format("Client test success: {}", test_msg));

        // 优雅关闭 socket 的读写两端
        boost::system::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close(ec);
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("Client exception: {}", e.what()));
    }
    co_return;
}

/**
 * @brief 测试 Trojan 协议完整握手与数据回显
 */
void TestTrojanRelayHandshake()
{
    log_info("=== Testing Trojan relay handshake ===");

    // 创建 io_context 驱动异步事件循环
    net::io_context ioc;

    // 绑定到本地回环地址，端口 0 由操作系统自动分配
    tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 0);
    tcp::acceptor acceptor(ioc, endpoint);
    // 获取实际分配的端口号，供客户端连接使用
    auto bound_endpoint = acceptor.local_endpoint();

    log_info(std::format("Test server listening on: {}:{}", bound_endpoint.address().to_string(), bound_endpoint.port()));

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
    net::co_spawn(ioc, [endpoint = bound_endpoint, &test_user_credential, &test_host, test_port, &test_message, client_ok]() -> net::awaitable<void>
                  {
                      try
                      {
                          co_await DoTrojanClient(endpoint, test_user_credential, test_host, test_port, test_message);
                          *client_ok = true;
                      }
                      catch (const std::exception &e)
                      {
                          log_fail(std::format("Client wrapper exception: {}", e.what()));
                      } }, [&](const std::exception_ptr &)
                  { ioc.stop(); });

    // 阻塞运行事件循环，直到所有异步操作完成
    ioc.run();

    // 根据客户端标记判定整体测试结果
    if (*client_ok)
    {
        log_pass("Trojan relay handshake and echo");
    }
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，在 WIN32 平台设置控制台 UTF-8 输出，
 *          运行 Trojan 协议握手与回显测试，关闭日志系统后输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    // 设置控制台输出为 UTF-8 编码，确保中文日志正常显示
    SetConsoleOutputCP(CP_UTF8);
#endif
    // 初始化全局 PMR 内存池，供热路径容器使用
    psm::memory::system::enable_global_pooling();
    // 初始化 spdlog 日志系统
    psm::trace::init({});

    log_info("Starting Trojan tests...");

    try
    {
        TestTrojanRelayHandshake();
    }
    catch (const std::exception &e)
    {
        log_fail(std::format("TestTrojanRelayHandshake threw exception: {}", e.what()));
    }

    psm::trace::info("[Trojan] Results: {} passed, {} failed", passed, failed);
    // 关闭日志系统，刷新所有挂起的日志输出
    psm::trace::shutdown();

    return failed > 0 ? 1 : 0;
}
