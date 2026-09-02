/**
 * @file ListenerE2ETest.cpp
 * @brief TCP listener 骨架测试（T4-3）
 * @details 覆盖：
 *          - 亲和性分发：同 key 稳定 / 分布均匀
 *          - 全链路 E2E：Client → listener → 会话识别 → Dial → echo 上游 → 回显
 *          - Stop 后不再接受连接
 *          - 连接风暴：并发多连接全部 echo 成功
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Runtime/Listener.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using namespace Preview;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::RunCoro;

    /// 构造可识别首包（socks5 Greeting）
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    TEST(AffinityBalancer, StableAndUniform)
    {
        Preview::Runtime::AffinityBalancer balancer(4);
        // 相同 key 稳定
        EXPECT_EQ(balancer.Select("1.2.3.4"), balancer.Select("1.2.3.4"));
        EXPECT_EQ(balancer.Select("10.0.0.1"), balancer.Select("10.0.0.1"));
        // 分布覆盖全部 worker
        std::array<std::size_t, 4> buckets{};
        for (int i = 1; i <= 64; ++i)
        {
            ++buckets[balancer.Select("192.168.0." + std::to_string(i))];
        }
        for (const auto b : buckets)
        {
            EXPECT_GT(b, 0);
        }
        // 单 worker 恒为 0
        Preview::Runtime::AffinityBalancer single(1);
        EXPECT_EQ(single.Select("any"), 0);
    }

    TEST(TcpListener, FullChainE2E)
    {
        net::io_context ioc;

        // 真实 echo 上游
        auto echo_acceptor = std::make_shared<Tcp::acceptor>(
            ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor->local_endpoint().port();
        net::co_spawn(
            ioc.get_executor(),
            [echo_acceptor, executor = ioc.get_executor()]() -> net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor->async_accept(
                        net::redirect_error(net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    net::co_spawn(executor, TcpEchoServer(std::move(sock)), net::detached);
                }
            },
            net::detached);

        // listener：会话（识别 socks5 + Dial 到 echo 上游）
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](Preview::SharedTransmission Inbound, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                opts.RelayIdleTimeout = std::chrono::milliseconds(200);
                opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                                  Preview::Middleware::Context &ctx) -> net::awaitable<Preview::Fault::Code>
                {
                    ctx.Target.positive = true;
                    ctx.Target.Host = "127.0.0.1";
                    ctx.Target.Port = "0"; // 由 Dial 捕获端口替换
                    co_return Preview::Fault::Code::Success;
                };
                opts.Dial = [&](const Preview::Network::Target &t) -> net::awaitable<
                    std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    std::error_code ec;
                    Preview::Network::Dialer::Dialer d(ioc.get_executor());
                    auto Conn = co_await d.Connect("127.0.0.1", echo_port, ec);
                    if (ec)
                    {
                        co_return std::pair{Preview::Fault::Code::Unreachable, nullptr};
                    }
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Conn)};
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(opts));
            },
            2);

        // 单 RunCoro：Start + 客户端流程（避免 ioc.stop() 杀死挂起协程）
        std::string echo_back;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto start_rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                     if (ec || !Conn)
                     {
                         co_return;
                     }
                     const auto payload = socks5_greeting();
                     co_await Conn->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await Conn->async_read_some(buf, ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                     Conn->Close();
                     listener.Stop();
                     boost::system::error_code close_ec;
                     echo_acceptor->close(close_ec);
                 });
        EXPECT_EQ(echo_back, socks5_greeting());
    }

    TEST(TcpListener, StopStopsAccepting)
    {
        net::io_context ioc;
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [](Preview::SharedTransmission, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
            { return nullptr; });

        Preview::Fault::Code start_rc = Preview::Fault::Code::Success;
        bool connected = false;
        bool refused = false;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     start_rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                     const auto listen_port = listener.LocalEndpoint().port();

                     // 首次连接成功（Accept 循环工作）
                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                     connected = !ec;
                     if (Conn)
                     {
                         Conn->Close();
                     }

                     // 停止后连接被拒绝
                     listener.Stop();
                     std::error_code ec2;
                     auto conn2 = co_await d.Connect("127.0.0.1", listen_port, ec2);
                     refused = ec2 || conn2 == nullptr;
                     if (conn2)
                     {
                         conn2->Close();
                     }
                 });
        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
        EXPECT_TRUE(connected);
        EXPECT_TRUE(refused);
    }

    TEST(TcpListener, DestroyAfterStopKeepsAcceptLoopStateAlive)
    {
        net::io_context ioc;
        Preview::Fault::Code start_result = Preview::Fault::Code::GenericError;
        {
            auto listener = std::make_unique<Preview::Runtime::TcpListener>(
                ioc.get_executor(),
                [](Preview::SharedTransmission, std::size_t)
                    -> std::shared_ptr<Preview::Runtime::Session>
                { return nullptr; });
            RunCoro(ioc,
                    [&]() -> net::awaitable<void>
                    {
                        start_result = co_await listener->Start(
                            net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                        listener->Stop();
                    });
        }

        // Stop 的 accept completion 可能尚未被调度；共享 Lifetime 必须独立完成。
        ioc.restart();
        ioc.run();
        EXPECT_EQ(start_result, Preview::Fault::Code::Success);
        SUCCEED();
    }

    TEST(TcpListener, ConnectionStorm)
    {
        net::io_context ioc;

        auto echo_acceptor = std::make_shared<Tcp::acceptor>(
            ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor->local_endpoint().port();
        net::co_spawn(
            ioc.get_executor(),
            [echo_acceptor, executor = ioc.get_executor()]() -> net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor->async_accept(
                        net::redirect_error(net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    net::co_spawn(executor, TcpEchoServer(std::move(sock)), net::detached);
                }
            },
            net::detached);

        constexpr int conn_count = 20;
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](Preview::SharedTransmission, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                opts.RelayIdleTimeout = std::chrono::milliseconds(300);
                opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                                  Preview::Middleware::Context &ctx) -> net::awaitable<Preview::Fault::Code>
                {
                    ctx.Target.positive = true;
                    ctx.Target.Host = "127.0.0.1";
                    ctx.Target.Port = "0";
                    co_return Preview::Fault::Code::Success;
                };
                opts.Dial = [&](const Preview::Network::Target &) -> net::awaitable<
                    std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    std::error_code ec;
                    Preview::Network::Dialer::Dialer d(ioc.get_executor());
                    auto Conn = co_await d.Connect("127.0.0.1", echo_port, ec);
                    if (ec)
                    {
                        co_return std::pair{Preview::Fault::Code::Unreachable, nullptr};
                    }
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Conn)};
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(opts));
            },
            4);

        Preview::Fault::Code start_rc = Preview::Fault::Code::Success;
        // 并发连接：全部 echo 成功
        int success = 0;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     start_rc = co_await listener.Start(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::atomic<int> Done{0};
                     const auto payload = socks5_greeting();
                     for (int i = 0; i < conn_count; ++i)
                     {
                         net::co_spawn(
                             ioc.get_executor(),
                             [&, i]() -> net::awaitable<void>
                             {
                                 std::error_code ec;
                                 Preview::Network::Dialer::Dialer d(ioc.get_executor());
                                 auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                                 if (ec)
                                 {
                                     ++Done;
                                     co_return;
                                 }
                                 co_await Conn->async_write_some(
                                     std::span<const std::byte>(
                                         reinterpret_cast<const std::byte *>(payload.data()),
                                         payload.size()),
                                     ec);
                                 std::array<std::byte, 64> buf{};
                                 const auto n = co_await Conn->async_read_some(buf, ec);
                                 if (!ec && std::string_view(reinterpret_cast<const char *>(buf.data()), n) ==
                                                payload)
                                 {
                                     ++success;
                                 }
                                 Conn->Close();
                                 ++Done;
                             },
                             net::detached);
                     }
                     while (Done < conn_count)
                     {
                         net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(10));
                         co_await t.async_wait(net::use_awaitable);
                     }
                     listener.Stop();
                     boost::system::error_code close_ec;
                     echo_acceptor->close(close_ec);
                 });
        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
        EXPECT_EQ(success, conn_count);
    }

} // namespace
