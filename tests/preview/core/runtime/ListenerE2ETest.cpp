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
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <stdexcept>
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

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::RunCoro;

    /// 构造可识别首包（socks5 Greeting）
    auto Socks5Greeting() -> std::string
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
        Net::io_context ioc;

        // 真实 echo 上游
        auto echo_acceptor = std::make_shared<Tcp::acceptor>(
            ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor->local_endpoint().port();
        Net::co_spawn(
            ioc.get_executor(),
            [echo_acceptor, executor = ioc.get_executor()]() -> Net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor->async_accept(
                        Net::redirect_error(Net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    Net::co_spawn(executor, TcpEchoServer(std::move(sock)), Net::detached);
                }
            },
            Net::detached);

        // listener：会话（识别 socks5 + Dial 到 echo 上游）
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](Preview::SharedTransmission Inbound, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                opts.RelayIdleTimeout = std::chrono::milliseconds(200);
                opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                                  Preview::Middleware::Context &ctx) -> Net::awaitable<Preview::Fault::Code>
                {
                    ctx.Target.Positive = true;
                    ctx.Target.Host = "127.0.0.1";
                    ctx.Target.Port = "0"; // 由 Dial 捕获端口替换
                    co_return Preview::Fault::Code::Success;
                };
                opts.Dial = [&](const Preview::Network::Target &t) -> Net::awaitable<
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
                 [&]() -> Net::awaitable<void>
                 {
                     const auto start_rc = co_await listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Conn = co_await d.Connect("127.0.0.1", listen_port, ec);
                     if (ec || !Conn)
                     {
                         co_return;
                     }
                     const auto Payload = Socks5Greeting();
                     co_await Conn->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                                    Payload.size()),
                         ec);
                     std::array<std::byte, 64> buf{};
                     const auto n = co_await Conn->async_read_some(buf, ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                     Conn->Close();
                     listener.Stop();
                     boost::system::error_code close_ec;
                     echo_acceptor->close(close_ec);
                 });
        EXPECT_EQ(echo_back, Socks5Greeting());
    }

    TEST(TcpListener, StopStopsAccepting)
    {
        Net::io_context ioc;
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [](Preview::SharedTransmission, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
            { return nullptr; });

        Preview::Fault::Code start_rc = Preview::Fault::Code::Success;
        bool connected = false;
        bool refused = false;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     start_rc = co_await listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
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

    TEST(TcpListener, MaxConnectionsRejectsAdditionalSessions)
    {
        Net::io_context ioc;
        std::size_t FactoryCalls = 0;
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&FactoryCalls](Preview::SharedTransmission, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                ++FactoryCalls;
                return std::make_shared<Preview::Runtime::Session>(Preview::Runtime::SessionOptions{});
            },
            1, 1);

        Preview::Fault::Code start_rc = Preview::Fault::Code::GenericError;
        RunCoro(ioc,
                [&]() -> Net::awaitable<void>
                {
                    start_rc = co_await listener.Start(
                        Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                    EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                    if (start_rc != Preview::Fault::Code::Success)
                    {
                        co_return;
                    }
                    const auto Port = listener.LocalEndpoint().port();
                    std::error_code Error;
                    Preview::Network::Dialer::Dialer Dialer(ioc.get_executor());
                    auto First = co_await Dialer.Connect("127.0.0.1", Port, Error);
                    EXPECT_FALSE(Error);
                    EXPECT_NE(First, nullptr);
                    if (Error || !First)
                    {
                        listener.Stop();
                        co_return;
                    }

                    Net::steady_timer Ready(ioc);
                    Ready.expires_after(std::chrono::milliseconds(10));
                    co_await Ready.async_wait(Net::use_awaitable);
                    EXPECT_EQ(FactoryCalls, 1U);

                    auto Second = co_await Dialer.Connect("127.0.0.1", Port, Error);
                    EXPECT_FALSE(Error);
                    if (Second)
                    {
                        Second->Close();
                    }
                    Net::steady_timer Rejected(ioc);
                    Rejected.expires_after(std::chrono::milliseconds(10));
                    co_await Rejected.async_wait(Net::use_awaitable);
                    EXPECT_EQ(FactoryCalls, 1U);

                    First->Close();
                    listener.Stop();
                });
        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
    }

    TEST(TcpListener, FactoryRejectClosesAcceptedTransport)
    {
        Net::io_context ioc;
        std::shared_ptr<Preview::SharedTransmission> Accepted;
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&Accepted](Preview::SharedTransmission Transport, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Accepted = std::make_shared<Preview::SharedTransmission>(std::move(Transport));
                return nullptr;
            });

        Preview::Fault::Code start_rc = Preview::Fault::Code::GenericError;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     start_rc = co_await listener.Start(
                         Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     if (start_rc != Preview::Fault::Code::Success)
                     {
                         co_return;
                     }
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Client = co_await d.Connect("127.0.0.1", listen_port, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_NE(Client, nullptr);
                     if (ec || !Client)
                     {
                         co_return;
                     }

                     Net::steady_timer Tick(ioc);
                     Tick.expires_after(std::chrono::milliseconds(10));
                     co_await Tick.async_wait(Net::use_awaitable);
                     EXPECT_NE(Accepted, nullptr);
                     if (!Accepted)
                     {
                         Client->Close();
                         listener.Stop();
                         co_return;
                     }
                     EXPECT_FALSE((*Accepted)->IsOpen());

                     Client->Close();
                     listener.Stop();
                 });

        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
    }

    TEST(TcpListener, SessionExceptionClosesAcceptedTransport)
    {
        Net::io_context ioc;
        std::shared_ptr<Preview::SharedTransmission> Accepted;
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&Accepted](Preview::SharedTransmission Transport, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Accepted = std::make_shared<Preview::SharedTransmission>(Transport);
                Preview::Runtime::SessionOptions Options;
                Options.AcceptProtocol = [](Preview::SharedTransmission &, Preview::Middleware::Context &)
                    -> Net::awaitable<Preview::Fault::Code>
                {
                    throw std::runtime_error("accept failure");
                    co_return Preview::Fault::Code::Success;
                };
                return std::make_shared<Preview::Runtime::Session>(std::move(Options));
            });

        Preview::Fault::Code start_rc = Preview::Fault::Code::GenericError;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     start_rc = co_await listener.Start(
                         Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                     EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
                     if (start_rc != Preview::Fault::Code::Success)
                     {
                         co_return;
                     }
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::error_code ec;
                     Preview::Network::Dialer::Dialer d(ioc.get_executor());
                     auto Client = co_await d.Connect("127.0.0.1", listen_port, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_NE(Client, nullptr);
                     if (ec || !Client)
                     {
                         co_return;
                     }

                     const auto Greeting = Socks5Greeting();
                     co_await Client->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                                    Greeting.size()),
                         ec);
                     Net::steady_timer Tick(ioc);
                     Tick.expires_after(std::chrono::milliseconds(10));
                     co_await Tick.async_wait(Net::use_awaitable);
                     EXPECT_NE(Accepted, nullptr);
                     if (Accepted)
                     {
                         EXPECT_FALSE((*Accepted)->IsOpen());
                     }
                     Client->Close();
                     listener.Stop();
                 });

        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
    }

    TEST(TcpListener, DestroyAfterStopKeepsAcceptLoopStateAlive)
    {
        Net::io_context ioc;
        Preview::Fault::Code start_result = Preview::Fault::Code::GenericError;
        {
            auto listener = std::make_unique<Preview::Runtime::TcpListener>(
                ioc.get_executor(),
                [](Preview::SharedTransmission, std::size_t)
                    -> std::shared_ptr<Preview::Runtime::Session>
                { return nullptr; });
            RunCoro(ioc,
                    [&]() -> Net::awaitable<void>
                    {
                        start_result = co_await listener->Start(
                            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                        listener->Stop();
                    });
        }

        // Stop 的 accept completion 可能尚未被调度；共享 Lifetime 必须独立完成。
        ioc.restart();
        ioc.run();
        EXPECT_EQ(start_result, Preview::Fault::Code::Success);
        SUCCEED();
    }

    TEST(TcpListener, DestructorStopsAccepting)
    {
        // P-H13：不显式 Stop()，listener 析构必须关闭 acceptor，
        // 且残留的 accept completion 不得再进入会话工厂。
        Net::io_context ioc;
        Tcp::endpoint bound;
        std::atomic<int> factory_calls{0};
        {
            Preview::Runtime::TcpListener listener(
                ioc.get_executor(),
                [&factory_calls](Preview::SharedTransmission, std::size_t)
                    -> std::shared_ptr<Preview::Runtime::Session>
                {
                    factory_calls.fetch_add(1, std::memory_order_relaxed);
                    return nullptr;
                });
            Preview::Fault::Code start_rc = Preview::Fault::Code::IoError;
            RunCoro(ioc,
                    [&]() -> Net::awaitable<void>
                    {
                        start_rc = co_await listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                        bound = listener.LocalEndpoint();
                    });
            EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
            // 不调用 Stop()，直接让 listener 离开作用域
        }

        Tcp::socket probe(ioc);
        boost::system::error_code ec;
        const Tcp::endpoint Target(Net::ip::make_address("127.0.0.1"), bound.port());
        probe.connect(Target, ec);
        const bool refused = static_cast<bool>(ec);
        if (!ec)
        {
            probe.close();
        }
        EXPECT_TRUE(refused) << "listener 析构后 acceptor 仍接受连接";

        // 让可能残留的 accept completion 有机会被调度
        ioc.restart();
        RunCoro(ioc,
                []() -> Net::awaitable<void>
                {
                    Net::steady_timer t(co_await Net::this_coro::executor);
                    t.expires_after(std::chrono::milliseconds(50));
                    boost::system::error_code tec;
                    co_await t.async_wait(Net::redirect_error(Net::use_awaitable, tec));
                });
        EXPECT_EQ(factory_calls.load(std::memory_order_relaxed), 0) << "析构后仍有会话进入工厂";
    }

    TEST(TcpListener, ConnectionStorm)
    {
        Net::io_context ioc;

        auto echo_acceptor = std::make_shared<Tcp::acceptor>(
            ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto echo_port = echo_acceptor->local_endpoint().port();
        Net::co_spawn(
            ioc.get_executor(),
            [echo_acceptor, executor = ioc.get_executor()]() -> Net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto sock = co_await echo_acceptor->async_accept(
                        Net::redirect_error(Net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    Net::co_spawn(executor, TcpEchoServer(std::move(sock)), Net::detached);
                }
            },
            Net::detached);

        constexpr int conn_count = 20;
        Preview::Runtime::TcpListener listener(
            ioc.get_executor(),
            [&](Preview::SharedTransmission, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions opts;
                opts.RelayIdleTimeout = std::chrono::milliseconds(300);
                opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                                  Preview::Middleware::Context &ctx) -> Net::awaitable<Preview::Fault::Code>
                {
                    ctx.Target.Positive = true;
                    ctx.Target.Host = "127.0.0.1";
                    ctx.Target.Port = "0";
                    co_return Preview::Fault::Code::Success;
                };
                opts.Dial = [&](const Preview::Network::Target &) -> Net::awaitable<
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
                 [&]() -> Net::awaitable<void>
                 {
                     start_rc = co_await listener.Start(Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                     const auto listen_port = listener.LocalEndpoint().port();

                     std::atomic<int> Done{0};
                     const auto Payload = Socks5Greeting();
                     for (int i = 0; i < conn_count; ++i)
                     {
                         Net::co_spawn(
                             ioc.get_executor(),
                             [&, i]() -> Net::awaitable<void>
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
                                         reinterpret_cast<const std::byte *>(Payload.data()),
                                         Payload.size()),
                                     ec);
                                 std::array<std::byte, 64> buf{};
                                 const auto n = co_await Conn->async_read_some(buf, ec);
                                 if (!ec && std::string_view(reinterpret_cast<const char *>(buf.data()), n) ==
                                                Payload)
                                 {
                                     ++success;
                                 }
                                 Conn->Close();
                                 ++Done;
                             },
                             Net::detached);
                     }
                     while (Done < conn_count)
                     {
                         Net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(10));
                         co_await t.async_wait(Net::use_awaitable);
                     }
                     listener.Stop();
                     boost::system::error_code close_ec;
                     echo_acceptor->close(close_ec);
                 });
        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
        EXPECT_EQ(success, conn_count);
    }

} // namespace
