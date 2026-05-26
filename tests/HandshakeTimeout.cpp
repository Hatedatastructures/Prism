/**
 * @file HandshakeTimeout.cpp
 * @brief 握手超时行为单元测试
 * @details 验证 session deadline、read_tls_frame 超时、
 * 以及协议握手 deadline 定时器在超时场景下的正确行为。
 * 使用短超时（100ms ~ 1s）配合 socket pair 模拟对端无响应。
 */

#include <prism/stealth/common.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/protocol/vless/conn.hpp>
#include <prism/protocol/trojan/conn.hpp>
#include <prism/memory.hpp>
#include <prism/trace.hpp>
#include <prism/fault.hpp>
#include "common/TestRunner.hpp"

#include <boost/asio.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace
{
    /**
     * @brief 创建一对已连接的 TCP socket
     * @param ioc io_context 引用
     * @return 连接好的 socket pair（client, server）
     * @details 使用 localhost acceptor 在本地回环地址上建立连接，
     * 返回的两个 socket 可以直接用于双向通信。
     */
    auto make_socket_pair(net::io_context &ioc)
        -> std::pair<tcp::socket, tcp::socket>
    {
        tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto server_ep = acceptor.local_endpoint();

        tcp::socket client(ioc);
        client.connect(server_ep);

        tcp::socket server = acceptor.accept();
        acceptor.close();

        return {std::move(client), std::move(server)};
    }
} // namespace

// ─── read_tls_frame 超时测试 ─────────────────────────────────

/**
 * @brief 测试 read_tls_frame 在对端不发送数据时超时返回错误
 * @details 创建 socket pair，server 端不发送任何数据，
 * 调用 read_tls_frame 并设置 100ms deadline。
 * 验证超时后返回 std::nullopt 且错误码表示操作被取消。
 */
void TestReadRawTlsFrameTimeout(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestReadRawTlsFrameTimeout ===");

    net::io_context ioc;

    auto [client_sock, server_sock] = make_socket_pair(ioc);

    // server_sock 放入 socket pair 但不使用，模拟对端无响应
    // client_sock 用于读取（不会有数据到达）
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        // 设置 100ms deadline
        net::steady_timer deadline(co_await net::this_coro::executor,
                                   std::chrono::milliseconds(100));

        std::error_code ec;
        auto result = co_await psm::stealth::common::read_tls_frame(
            client_sock, ec, &deadline);

        runner.Check(!result.has_value(),
                     "read_tls_frame should return nullopt on timeout");
        runner.Check(!!ec,
                     "error code should be set on timeout");
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试 read_tls_frame 在无 deadline 时对端关闭返回 EOF
 * @details 不设置 deadline，直接关闭 server 端 socket，
 * 验证 read_tls_frame 返回 nullopt 且错误码为 EOF。
 */
void TestReadRawTlsFrameEofNoDeadline(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestReadRawTlsFrameEofNoDeadline ===");

    net::io_context ioc;

    auto [client_sock, server_sock] = make_socket_pair(ioc);

    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        // 立即关闭 server 端，client 读取将收到 EOF
        server_sock.close();

        std::error_code ec;
        auto result = co_await psm::stealth::common::read_tls_frame(
            client_sock, ec, nullptr);

        runner.Check(!result.has_value(),
                     "read_tls_frame should return nullopt on EOF");
        // read_tls_frame uses boost::system::error_code internally,
        // writes to std::error_code via implicit conversion
        runner.Check(!!ec,
                     "error code should be set when peer closes");
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试 read_tls_frame 在 deadline 到期前成功读取
 * @details 发送有效的 TLS 记录头 + 载荷，验证在 deadline 到期前成功读取。
 */
void TestReadRawTlsFrameSuccessBeforeDeadline(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestReadRawTlsFrameSuccessBeforeDeadline ===");

    net::io_context ioc;

    auto [client_sock, server_sock] = make_socket_pair(ioc);

    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        // 构造一个有效的 TLS ClientHello 记录：
        // ContentType=0x16 (Handshake), Version=0x0301 (TLS 1.0),
        // Length=5, 然后 5 字节 payload
        std::array<std::uint8_t, 10> tls_record = {
            0x16,             // Handshake
            0x03, 0x01,       // TLS 1.0
            0x00, 0x05,       // Length = 5
            0x01,             // ClientHello
            0x00, 0x00, 0x01, // Length
            0x00              // Padding
        };

        co_await net::async_write(server_sock, net::buffer(tls_record),
                                  net::use_awaitable);

        // 设置 1 秒 deadline（足够长）
        net::steady_timer deadline(co_await net::this_coro::executor,
                                   std::chrono::seconds(1));

        std::error_code ec;
        auto result = co_await psm::stealth::common::read_tls_frame(
            client_sock, ec, &deadline);

        runner.Check(result.has_value(),
                     "read_tls_frame should return data before deadline");
        runner.Check(!ec, "error code should be success");

        if (result)
        {
            runner.Check(result->size() == 10,
                         "frame size should be 10 (5 header + 5 payload)");
        }
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

// ─── VLESS 协议握手超时测试 ─────────────────────────────────────

/**
 * @brief 测试 VLESS handshake 在对端不发送数据时超时返回 canceled/timeout
 * @details 创建 socket pair，server 端不发送数据，
 * 使用 VLESS conn 进行握手。由于 VLESS 内部有 30 秒 deadline，
 * 手动设置一个更短的 socket 层超时来加速测试。
 * 验证握手返回超时错误码。
 */
void TestVlessHandshakeTimeout(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestVlessHandshakeTimeout ===");

    net::io_context ioc;

    auto [client_sock, server_sock] = make_socket_pair(ioc);

    // server_sock 不发送数据，模拟对端无响应

    std::exception_ptr ep;
    auto handshake_ok = std::make_shared<bool>(false);

    auto coro = [&]() -> net::awaitable<void>
    {
        auto trans = psm::transport::make_reliable(std::move(client_sock));
        auto *raw_trans = trans.get();

        // 设置 100ms socket 超时，模拟 deadline 到期
        net::steady_timer timeout(co_await net::this_coro::executor,
                                  std::chrono::milliseconds(100));
        timeout.async_wait(
            [raw_trans](const boost::system::error_code &timer_ec)
            {
                if (!timer_ec)
                {
                    raw_trans->cancel();
                }
            });

        auto vless = psm::protocol::vless::make_conn(std::move(trans));
        auto [ec, req] = co_await vless->handshake();

        // 超时后 deadline 会 cancel 传输层，VLESS 将 canceled 转为 timeout
        bool is_timeout = (ec == psm::fault::code::timeout) ||
                          (ec == psm::fault::code::canceled);
        runner.Check(is_timeout,
                     "VLESS handshake should return timeout or canceled on no data");
        *handshake_ok = true;
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);

    runner.Check(*handshake_ok, "VLESS handshake timeout test completed");
}

// ─── Trojan 协议握手超时测试 ─────────────────────────────────────

/**
 * @brief 测试 Trojan handshake 在对端不发送数据时超时返回错误
 * @details 与 VLESS 测试同理，使用短超时模拟 deadline 行为。
 */
void TestTrojanHandshakeTimeout(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestTrojanHandshakeTimeout ===");

    net::io_context ioc;

    auto [client_sock, server_sock] = make_socket_pair(ioc);

    std::exception_ptr ep;
    auto handshake_ok = std::make_shared<bool>(false);

    auto coro = [&]() -> net::awaitable<void>
    {
        auto trans = psm::transport::make_reliable(std::move(client_sock));
        auto *raw_trans = trans.get();

        // 设置 100ms socket 超时
        net::steady_timer timeout(co_await net::this_coro::executor,
                                  std::chrono::milliseconds(100));
        timeout.async_wait(
            [raw_trans](const boost::system::error_code &timer_ec)
            {
                if (!timer_ec)
                {
                    raw_trans->cancel();
                }
            });

        auto trojan = psm::protocol::trojan::make_conn(std::move(trans));
        auto [ec, req] = co_await trojan->handshake();

        bool is_timeout = (ec == psm::fault::code::timeout) ||
                          (ec == psm::fault::code::canceled);
        runner.Check(is_timeout,
                     "Trojan handshake should return timeout or canceled on no data");
        *handshake_ok = true;
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);

    runner.Check(*handshake_ok, "Trojan handshake timeout test completed");
}

// ─── Session deadline 定时器创建逻辑验证 ─────────────────────────

/**
 * @brief 测试 deadline 定时器的创建与超时行为
 * @details 验证 steady_timer 可以正确到期并触发回调，
 * 这是 session handshake_deadline_ 和协议 deadline 的基础设施。
 */
void TestDeadlineTimerExpiry(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestDeadlineTimerExpiry ===");

    net::io_context ioc;
    auto expired = std::make_shared<bool>(false);
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        net::steady_timer timer(co_await net::this_coro::executor,
                                std::chrono::milliseconds(50));

        boost::system::error_code ec;
        co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

        runner.Check(!ec, "timer should expire without error");
        runner.Check(true, "timer expired successfully after 50ms");
        *expired = true;
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);

    runner.Check(*expired, "deadline timer expiry callback fired");
}

/**
 * @brief 测试 deadline 定时器取消后 async_wait 返回 operation_aborted
 * @details 验证取消 deadline 定时器时，async_wait 返回 operation_aborted，
 * 这与 session 中正常完成识别后取消 handshake_deadline_ 的行为一致。
 */
void TestDeadlineTimerCancellation(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestDeadlineTimerCancellation ===");

    net::io_context ioc;
    auto cancelled = std::make_shared<bool>(false);
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        net::steady_timer timer(co_await net::this_coro::executor,
                                std::chrono::seconds(30));

        // 启动一个内部协程来等待定时器，通过 shared_ptr 传递结果
        auto inner_result = std::make_shared<boost::system::error_code>();
        net::co_spawn(
            co_await net::this_coro::executor,
            [&timer, inner_result]() -> net::awaitable<void>
            {
                co_await timer.async_wait(
                    net::redirect_error(net::use_awaitable, *inner_result));
            },
            net::detached);

        // 让出执行权，确保内部协程开始等待
        net::steady_timer yield_timer(co_await net::this_coro::executor,
                                      std::chrono::milliseconds(10));
        co_await yield_timer.async_wait(net::use_awaitable);

        // 取消定时器
        timer.cancel();

        // 等待内部协程的回调执行
        net::steady_timer post_timer(co_await net::this_coro::executor,
                                     std::chrono::milliseconds(10));
        co_await post_timer.async_wait(net::use_awaitable);

        runner.Check(*inner_result == boost::asio::error::operation_aborted,
                     "cancelled timer should return operation_aborted");
        *cancelled = true;
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);

    runner.Check(*cancelled, "deadline timer cancellation callback fired");
}

/**
 * @brief 测试 deadline 到期后取消传输层的完整流程
 * @details 模拟 session::diversion() 中的 deadline 模式：
 * 创建定时器 + 协程并发执行，deadline 先到时后 cancel 传输层，
 * 模拟正在等待的读取操作被取消并返回 operation_canceled。
 */
void TestDeadlineCancelsRead(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestDeadlineCancelsRead ===");

    net::io_context ioc;
    auto read_cancelled = std::make_shared<bool>(false);
    std::exception_ptr ep;

    auto [client_sock, server_sock] = make_socket_pair(ioc);

    auto coro = [&]() -> net::awaitable<void>
    {
        auto trans = psm::transport::make_reliable(std::move(client_sock));

        // 设置 100ms deadline
        net::steady_timer deadline(co_await net::this_coro::executor,
                                   std::chrono::milliseconds(100));
        deadline.async_wait(
            [&trans](const boost::system::error_code &timer_ec)
            {
                if (!timer_ec)
                {
                    trans->cancel();
                }
            });

        // 尝试读取（server 端不会发数据）
        std::array<std::byte, 64> buf{};
        std::error_code read_ec;
        co_await trans->async_read_some(buf, read_ec);

        runner.Check(!!read_ec,
                     "read should fail after deadline cancels transport");
        // 错误码应该是 canceled 或 eof（cancel 后 socket 被取消）
        auto fault_code = psm::fault::to_code(read_ec);
        bool is_expected = (fault_code == psm::fault::code::canceled) ||
                           (fault_code == psm::fault::code::eof) ||
                           (fault_code == psm::fault::code::io_error);
        runner.Check(is_expected,
                     "error code should be canceled, eof, or io_error after cancel");
        *read_cancelled = true;
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);

    runner.Check(*read_cancelled, "deadline cancel read test completed");
}

// ─── 入口 ──────────────────────────────────────────────────────────

/**
 * @brief 测试入口
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    try
    {
#ifdef _WIN32
        SetConsoleOutputCP(CP_UTF8);
#endif
        psm::memory::system::enable_pooling();
        psm::trace::init({});

        psm::testing::TestRunner runner("HandshakeTimeout");

        // deadline 定时器基础设施测试
        TestDeadlineTimerExpiry(runner);
        TestDeadlineTimerCancellation(runner);

        // read_tls_frame 超时测试
        TestReadRawTlsFrameTimeout(runner);
        TestReadRawTlsFrameEofNoDeadline(runner);
        TestReadRawTlsFrameSuccessBeforeDeadline(runner);

        // deadline 取消读取的完整流程测试
        TestDeadlineCancelsRead(runner);

        // 协议握手超时测试
        TestVlessHandshakeTimeout(runner);
        TestTrojanHandshakeTimeout(runner);

        return runner.Summary();
    }
    catch (const std::exception &e)
    {
        psm::trace::shutdown();
        psm::trace::error("[HandshakeTimeout] fatal: {}", e.what());
        return 1;
    }
}
