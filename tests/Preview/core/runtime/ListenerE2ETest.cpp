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
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Process.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/WorkerGroup.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Preview::Testing::TcpEchoServer;
    using Preview::Testing::RunCoro;

    class WorkerGroupRunner final
    {
    public:
        explicit WorkerGroupRunner(Preview::Runtime::WorkerGroup &GroupValue)
            : Group_(&GroupValue)
        {
            Threads_.reserve(Group_->Size());
            for (std::size_t Index = 0; Index < Group_->Size(); ++Index)
            {
                auto *WorkerValue = Group_->Find(Preview::WorkerId{
                    static_cast<std::uint64_t>(Index + 1)});
                if (WorkerValue)
                {
                    Threads_.emplace_back([WorkerValue] { WorkerValue->Run(); });
                }
            }
        }

        ~WorkerGroupRunner() noexcept
        {
            Group_->Stop();
            for (auto &Thread : Threads_)
            {
                if (Thread.joinable())
                {
                    Thread.join();
                }
            }
        }

        WorkerGroupRunner(const WorkerGroupRunner &) = delete;
        auto operator=(const WorkerGroupRunner &) -> WorkerGroupRunner & = delete;

    private:
        Preview::Runtime::WorkerGroup *Group_;
        std::vector<std::thread> Threads_;
    };

    /// 构造可识别首包（socks5 Greeting）
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    using SessionIdentityEvents =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    struct SessionIdentityCapture final
    {
        std::array<std::atomic<std::uint64_t>, 2> Values{};
    };

    struct SessionIdentityProbeResult final
    {
        Preview::Fault::Code FirstStart{Preview::Fault::Code::GenericError};
        Preview::Fault::Code SecondStart{Preview::Fault::Code::GenericError};
        bool FirstConnected{false};
        bool SecondConnected{false};
        bool GreetingsWritten{false};
        std::size_t EventsReceived{0};
    };

    struct SessionIdentityProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::TcpListener> First;
        std::shared_ptr<Preview::Runtime::TcpListener> Second;
        std::shared_ptr<SessionIdentityEvents> Events;
        std::shared_ptr<SessionIdentityProbeResult> Result;
    };

    auto MakeSessionIdentityFactory(
        const std::shared_ptr<SessionIdentityEvents> &Events,
        const std::shared_ptr<SessionIdentityCapture> &Captured,
        const std::size_t ListenerIndex) -> Preview::Runtime::TcpListener::SessionFactory
    {
        return [Events, Captured, ListenerIndex](Preview::SharedTransmission, std::size_t)
                   -> std::shared_ptr<Preview::Runtime::Session>
        {
            Preview::Runtime::SessionOptions Options;
            Options.AcceptProtocol = [Events, Captured, ListenerIndex](
                                         Preview::SharedTransmission &,
                                         Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                Captured->Values[ListenerIndex].store(
                    Context.TaskIdentity.SessionId.Value(), std::memory_order_release);
                (void)Events->try_send(boost::system::error_code{});
                co_return Preview::Fault::Code::ProtocolError;
            };
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        };
    }

    auto RunSessionIdentityProbe(SessionIdentityProbeRequest Request) -> Net::awaitable<void>
    {
        auto &Result = *Request.Result;
        Result.FirstStart = co_await Request.First->Start(Tcp::endpoint(Tcp::v4(), 0));
        if (Result.FirstStart != Preview::Fault::Code::Success)
        {
            co_return;
        }
        Result.SecondStart = co_await Request.Second->Start(Tcp::endpoint(Tcp::v4(), 0));
        if (Result.SecondStart != Preview::Fault::Code::Success)
        {
            co_await Request.First->Shutdown();
            co_return;
        }

        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        std::error_code FirstError;
        auto FirstClient = co_await Dialer.Connect(
            "127.0.0.1", Request.First->LocalEndpoint().port(), FirstError);
        Result.FirstConnected = !FirstError && static_cast<bool>(FirstClient);
        if (!Result.FirstConnected)
        {
            co_await Request.First->Shutdown();
            co_await Request.Second->Shutdown();
            co_return;
        }

        std::error_code SecondError;
        auto SecondClient = co_await Dialer.Connect(
            "127.0.0.1", Request.Second->LocalEndpoint().port(), SecondError);
        Result.SecondConnected = !SecondError && static_cast<bool>(SecondClient);
        if (!Result.SecondConnected)
        {
            FirstClient->Close();
            co_await Request.First->Shutdown();
            co_await Request.Second->Shutdown();
            co_return;
        }

        const auto Greeting = Socks5Greeting();
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size());
        std::error_code FirstWriteError;
        const auto FirstWritten = co_await FirstClient->async_write_some(Bytes, FirstWriteError);
        std::error_code SecondWriteError;
        const auto SecondWritten = co_await SecondClient->async_write_some(Bytes, SecondWriteError);
        Result.GreetingsWritten = !FirstWriteError && !SecondWriteError &&
                                  FirstWritten == Greeting.size() &&
                                  SecondWritten == Greeting.size();
        if (!Result.GreetingsWritten)
        {
            FirstClient->Close();
            SecondClient->Close();
            co_await Request.First->Shutdown();
            co_await Request.Second->Shutdown();
            co_return;
        }

        co_await Request.Events->async_receive(Net::use_awaitable);
        ++Result.EventsReceived;
        co_await Request.Events->async_receive(Net::use_awaitable);
        ++Result.EventsReceived;
        FirstClient->Close();
        SecondClient->Close();
        co_await Request.First->Shutdown();
        co_await Request.Second->Shutdown();
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
            EXPECT_GT(b, std::size_t{0});
        }
        // 单 worker 恒为 0
        Preview::Runtime::AffinityBalancer single(1);
        EXPECT_EQ(single.Select("any"), std::size_t{0});
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

        std::atomic<bool> FactoryCalled{false};
        std::atomic<bool> PrepareCalled{false};
        std::atomic<bool> DialCalled{false};
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{11};
        ProcessOptions.Generation = Preview::GenerationId{21};
        ProcessOptions.WorkerCount = 2;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        // listener：会话（识别 socks5 + Dial 到 echo 上游）
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Factory =
            [&](Preview::SharedTransmission, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
            {
                FactoryCalled.store(true, std::memory_order_release);
                Preview::Runtime::SessionOptions opts;
                opts.RelayIdleTimeout = std::chrono::milliseconds(200);
                opts.Prepare = [&PrepareCalled](const Preview::Recognition::RecognizeResult &,
                                                Preview::Middleware::Context &ctx)
                    -> Net::awaitable<Preview::Fault::Code>
                {
                    PrepareCalled.store(true, std::memory_order_release);
                    ctx.Target.Positive = true;
                    ctx.Target.Host = "127.0.0.1";
                    ctx.Target.Port = "0"; // 由 Dial 捕获端口替换
                    co_return Preview::Fault::Code::Success;
                };
                opts.Dial = [&](const Preview::Network::Target &t) -> Net::awaitable<
                    std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    (void)t;
                    DialCalled.store(true, std::memory_order_release);
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
            };
        Preview::Runtime::TcpListener listener(std::move(ListenerOptions));

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
                     const auto n = co_await Preview::Testing::TailReadGuarded(Conn, buf, ec);
                     echo_back.assign(reinterpret_cast<const char *>(buf.data()), n);
                     Conn->Close();
                     co_await listener.Shutdown();
                     boost::system::error_code close_ec;
                     echo_acceptor->close(close_ec);
                 });
        EXPECT_TRUE(FactoryCalled.load(std::memory_order_acquire));
        EXPECT_TRUE(PrepareCalled.load(std::memory_order_acquire));
        EXPECT_TRUE(DialCalled.load(std::memory_order_acquire));
        EXPECT_EQ(echo_back, Socks5Greeting());
    }

    TEST(TcpListener, StopStopsAccepting)
    {
        Net::io_context ioc;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{12};
        ProcessOptions.Generation = Preview::GenerationId{22};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Factory =
            [](Preview::SharedTransmission, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
        { return nullptr; };
        Preview::Runtime::TcpListener listener(std::move(ListenerOptions));

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

    TEST(TcpListener, StartAfterStopIsRejected)
    {
        Net::io_context Ioc;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{33};
        ProcessOptions.Generation = Preview::GenerationId{49};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Factory =
            [](Preview::SharedTransmission, std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
        { return nullptr; };
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        Preview::Fault::Code FirstResult = Preview::Fault::Code::GenericError;
        Preview::Fault::Code SecondResult = Preview::Fault::Code::GenericError;
        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                FirstResult = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                Listener.Stop();
                SecondResult = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            });

        EXPECT_EQ(FirstResult, Preview::Fault::Code::Success);
        EXPECT_EQ(SecondResult, Preview::Fault::Code::InvalidArgument);
    }

    TEST(TcpListener, MaxConnectionsRejectsAdditionalSessions)
    {
        Net::io_context ioc;
        std::atomic<std::size_t> FactoryCalls{0};
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{13};
        ProcessOptions.Generation = Preview::GenerationId{23};
        ProcessOptions.WorkerCount = 1;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.MaxConnections = 1;
        ListenerOptions.Factory =
            [&FactoryCalls](Preview::SharedTransmission, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
        {
            FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            return std::make_shared<Preview::Runtime::Session>(Preview::Runtime::SessionOptions{});
        };
        Preview::Runtime::TcpListener listener(std::move(ListenerOptions));

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
                    EXPECT_EQ(FactoryCalls.load(std::memory_order_acquire), std::size_t{1});

                    auto Second = co_await Dialer.Connect("127.0.0.1", Port, Error);
                    EXPECT_FALSE(Error);
                    if (Second)
                    {
                        Second->Close();
                    }
                    Net::steady_timer Rejected(ioc);
                    Rejected.expires_after(std::chrono::milliseconds(10));
                    co_await Rejected.async_wait(Net::use_awaitable);
                    EXPECT_EQ(FactoryCalls.load(std::memory_order_acquire), std::size_t{1});

                    First->Close();
                    co_await listener.Shutdown();
                });
        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
    }

    TEST(TcpListener, FactoryRejectClosesAcceptedTransport)
    {
        Net::io_context ioc;
        std::atomic<Preview::SharedTransmission> Accepted;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{14};
        ProcessOptions.Generation = Preview::GenerationId{24};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Factory =
            [&Accepted](Preview::SharedTransmission Transport, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
        {
            Accepted.store(std::move(Transport), std::memory_order_release);
            return nullptr;
        };
        Preview::Runtime::TcpListener listener(std::move(ListenerOptions));

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
                     const auto AcceptedTransport = Accepted.load(std::memory_order_acquire);
                     EXPECT_NE(AcceptedTransport, nullptr);
                     if (!AcceptedTransport)
                     {
                         Client->Close();
                         listener.Stop();
                         co_return;
                     }
                     EXPECT_FALSE(AcceptedTransport->IsOpen());

                     Client->Close();
                     listener.Stop();
                 });

        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
    }

    TEST(TcpListener, SessionExceptionClosesAcceptedTransport)
    {
        Net::io_context ioc;
        std::atomic<Preview::SharedTransmission> Accepted;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{15};
        ProcessOptions.Generation = Preview::GenerationId{25};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Factory =
            [&Accepted](Preview::SharedTransmission Transport, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
        {
            Accepted.store(Transport, std::memory_order_release);
            Preview::Runtime::SessionOptions Options;
            Options.AcceptProtocol =
                [](Preview::SharedTransmission &, Preview::Middleware::Context &)
                -> Net::awaitable<Preview::Fault::Code>
            {
                throw std::runtime_error("accept failure");
                co_return Preview::Fault::Code::Success;
            };
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        };
        Preview::Runtime::TcpListener listener(std::move(ListenerOptions));

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
                     const auto AcceptedTransport = Accepted.load(std::memory_order_acquire);
                     EXPECT_NE(AcceptedTransport, nullptr);
                     if (AcceptedTransport)
                     {
                         EXPECT_FALSE(AcceptedTransport->IsOpen());
                     }
                     Client->Close();
                     co_await listener.Shutdown();
                 });

        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
    }

    TEST(TcpListener, DestroyAfterStopKeepsAcceptLoopStateAlive)
    {
        Net::io_context ioc;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{16};
        ProcessOptions.Generation = Preview::GenerationId{26};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());
        Preview::Fault::Code start_result = Preview::Fault::Code::GenericError;
        {
            Preview::Runtime::TcpListener::Options ListenerOptions;
            ListenerOptions.Executor = ioc.get_executor();
            ListenerOptions.Workers = &ProcessValue.Workers();
            ListenerOptions.Factory =
                [](Preview::SharedTransmission, std::size_t)
                    -> std::shared_ptr<Preview::Runtime::Session>
            { return nullptr; };
            auto listener = std::make_unique<Preview::Runtime::TcpListener>(
                std::move(ListenerOptions));
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
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{17};
        ProcessOptions.Generation = Preview::GenerationId{27};
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());
        Tcp::endpoint bound;
        std::atomic<int> factory_calls{0};
        {
            Preview::Runtime::TcpListener::Options ListenerOptions;
            ListenerOptions.Executor = ioc.get_executor();
            ListenerOptions.Workers = &ProcessValue.Workers();
            ListenerOptions.Factory =
                [&factory_calls](Preview::SharedTransmission, std::size_t)
                    -> std::shared_ptr<Preview::Runtime::Session>
            {
                factory_calls.fetch_add(1, std::memory_order_relaxed);
                return nullptr;
            };
            Preview::Runtime::TcpListener listener(std::move(ListenerOptions));
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
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{18};
        ProcessOptions.Generation = Preview::GenerationId{28};
        ProcessOptions.WorkerCount = 4;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Factory =
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
            };
        Preview::Runtime::TcpListener listener(std::move(ListenerOptions));

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
                     co_await listener.Shutdown();
                     boost::system::error_code close_ec;
                     echo_acceptor->close(close_ec);
                 });
        EXPECT_EQ(start_rc, Preview::Fault::Code::Success);
        EXPECT_EQ(success, conn_count);
    }

    TEST(TcpListener, AdmissionUsesWorkerExecutorAndPreservesIdentity)
    {
        Net::io_context ListenerIo;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{31};
        ProcessOptions.Generation = Preview::GenerationId{47};
        ProcessOptions.WorkerCount = 1;
        ProcessOptions.MailboxCapacity = 4;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        auto &Workers = ProcessValue.Workers();
        auto *WorkerValue = Workers.Find(Preview::WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        WorkerGroupRunner Runner(Workers);

        const auto ListenerThread =
            static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        std::atomic<bool> FactoryOnWorker{false};
        std::atomic<bool> SessionOnWorker{false};
        std::atomic<std::uint64_t> FactoryThread{0};
        std::atomic<std::uint64_t> SessionThread{0};
        std::atomic<std::uint64_t> ObservedSession{0};
        std::atomic<std::uint64_t> ObservedWorker{0};
        std::atomic<std::uint64_t> ObservedGeneration{0};

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ListenerIo.get_executor();
        ListenerOptions.Workers = &Workers;
        ListenerOptions.Factory =
            [&Workers, &FactoryOnWorker, &FactoryThread, &SessionOnWorker, &SessionThread,
             &ObservedSession, &ObservedWorker, &ObservedGeneration](
                Preview::SharedTransmission, std::size_t WorkerIndex)
                -> std::shared_ptr<Preview::Runtime::Session>
        {
            auto *Selected = Workers.Find(Preview::WorkerId{WorkerIndex + 1});
            FactoryOnWorker.store(Selected && Selected->IsOnExecutor(), std::memory_order_release);
            FactoryThread.store(
                static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())),
                std::memory_order_release);

            Preview::Runtime::SessionOptions Options;
            Options.AcceptProtocol =
                [Selected, &SessionOnWorker, &SessionThread, &ObservedSession, &ObservedWorker,
                 &ObservedGeneration](Preview::SharedTransmission &, Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                SessionOnWorker.store(Selected && Selected->IsOnExecutor(), std::memory_order_release);
                SessionThread.store(
                    static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())),
                    std::memory_order_release);
                ObservedSession.store(Context.TaskIdentity.SessionId.Value(), std::memory_order_release);
                ObservedWorker.store(Context.TaskIdentity.WorkerId.Value(), std::memory_order_release);
                ObservedGeneration.store(Context.TaskIdentity.Generation.Value(),
                                         std::memory_order_release);
                co_return Preview::Fault::Code::ProtocolError;
            };
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        };
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        Preview::Fault::Code StartResult = Preview::Fault::Code::GenericError;
        RunCoro(
            ListenerIo,
            [&]() -> Net::awaitable<void>
            {
                StartResult = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
                if (StartResult != Preview::Fault::Code::Success)
                {
                    co_return;
                }

                std::error_code Error;
                Preview::Network::Dialer::Dialer Dialer(ListenerIo.get_executor());
                auto Client = co_await Dialer.Connect(
                    "127.0.0.1", Listener.LocalEndpoint().port(), Error);
                EXPECT_FALSE(Error);
                EXPECT_NE(Client, nullptr);
                if (Error || !Client)
                {
                    co_return;
                }

                const auto Greeting = Socks5Greeting();
                co_await Client->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                               Greeting.size()),
                    Error);
                EXPECT_FALSE(Error);

                for (int Attempt = 0; Attempt < 100 && !SessionOnWorker.load(std::memory_order_acquire);
                     ++Attempt)
                {
                    Net::steady_timer Tick(ListenerIo);
                    Tick.expires_after(std::chrono::milliseconds(1));
                    co_await Tick.async_wait(Net::use_awaitable);
                }
                co_await Listener.Shutdown();
                Client->Close();
            });

        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        EXPECT_TRUE(FactoryOnWorker.load(std::memory_order_acquire));
        EXPECT_TRUE(SessionOnWorker.load(std::memory_order_acquire));
        EXPECT_NE(FactoryThread.load(std::memory_order_acquire), ListenerThread);
        EXPECT_NE(SessionThread.load(std::memory_order_acquire), ListenerThread);
        EXPECT_GT(ObservedSession.load(std::memory_order_acquire), std::uint64_t{0});
        EXPECT_EQ(ObservedWorker.load(std::memory_order_acquire), std::uint64_t{1});
        EXPECT_EQ(ObservedGeneration.load(std::memory_order_acquire), std::uint64_t{47});
    }

    TEST(TcpListener, SessionIdsAreUniqueAcrossListenersInOneProcess)
    {
        Net::io_context ListenerIo;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{41};
        ProcessOptions.Generation = Preview::GenerationId{57};
        ProcessOptions.WorkerCount = 1;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        auto Events = std::make_shared<SessionIdentityEvents>(ListenerIo.get_executor(), 2);
        auto Captured = std::make_shared<SessionIdentityCapture>();
        Preview::Runtime::TcpListener::Options FirstOptions;
        FirstOptions.Executor = ListenerIo.get_executor();
        FirstOptions.Workers = &ProcessValue.Workers();
        FirstOptions.Factory = MakeSessionIdentityFactory(Events, Captured, 0);
        Preview::Runtime::TcpListener::Options SecondOptions;
        SecondOptions.Executor = ListenerIo.get_executor();
        SecondOptions.Workers = &ProcessValue.Workers();
        SecondOptions.Factory = MakeSessionIdentityFactory(Events, Captured, 1);

        auto First = std::make_shared<Preview::Runtime::TcpListener>(std::move(FirstOptions));
        auto Second = std::make_shared<Preview::Runtime::TcpListener>(std::move(SecondOptions));
        auto Result = std::make_shared<SessionIdentityProbeResult>();
        RunCoro(ListenerIo, RunSessionIdentityProbe(SessionIdentityProbeRequest{
                                                         ListenerIo.get_executor(), First, Second,
                                                         Events, Result}));

        EXPECT_EQ(Result->FirstStart, Preview::Fault::Code::Success);
        EXPECT_EQ(Result->SecondStart, Preview::Fault::Code::Success);
        EXPECT_TRUE(Result->FirstConnected);
        EXPECT_TRUE(Result->SecondConnected);
        EXPECT_TRUE(Result->GreetingsWritten);
        EXPECT_EQ(Result->EventsReceived, 2U);
        const auto FirstSession = Captured->Values[0].load(std::memory_order_acquire);
        const auto SecondSession = Captured->Values[1].load(std::memory_order_acquire);
        EXPECT_GT(FirstSession, 0U);
        EXPECT_GT(SecondSession, 0U);
        EXPECT_NE(FirstSession, SecondSession);
    }

    TEST(TcpListener, StopRaceDiscardsQueuedAdmissionAndClosesTransport)
    {
        Net::io_context ListenerIo;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{32};
        ProcessOptions.Generation = Preview::GenerationId{48};
        ProcessOptions.WorkerCount = 1;
        ProcessOptions.MailboxCapacity = 2;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        auto &Workers = ProcessValue.Workers();
        auto *WorkerValue = Workers.Find(Preview::WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        WorkerGroupRunner Runner(Workers);

        std::atomic<bool> BlockerStarted{false};
        std::atomic<bool> ReleaseBlocker{false};
        ASSERT_EQ(Workers.Dispatch(
                      Preview::WorkerId{1}, Preview::GenerationId{48},
                      [&BlockerStarted, &ReleaseBlocker]
                      {
                          BlockerStarted.store(true, std::memory_order_release);
                          BlockerStarted.notify_all();
                          while (!ReleaseBlocker.load(std::memory_order_acquire))
                          {
                              ReleaseBlocker.wait(false, std::memory_order_acquire);
                          }
                      }),
                  Preview::Runtime::Mailbox::Result::Accepted);
        while (!BlockerStarted.load(std::memory_order_acquire))
        {
            BlockerStarted.wait(false, std::memory_order_acquire);
        }

        std::atomic<int> FactoryCalls{0};
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ListenerIo.get_executor();
        ListenerOptions.Workers = &Workers;
        ListenerOptions.Factory =
            [&FactoryCalls](Preview::SharedTransmission, std::size_t)
                -> std::shared_ptr<Preview::Runtime::Session>
        {
            FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            return std::make_shared<Preview::Runtime::Session>(Preview::Runtime::SessionOptions{});
        };
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        Preview::Fault::Code StartResult = Preview::Fault::Code::GenericError;
        RunCoro(
            ListenerIo,
            [&]() -> Net::awaitable<void>
            {
                StartResult = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
                if (StartResult != Preview::Fault::Code::Success)
                {
                    co_return;
                }

                std::error_code Error;
                Preview::Network::Dialer::Dialer Dialer(ListenerIo.get_executor());
                auto Client = co_await Dialer.Connect(
                    "127.0.0.1", Listener.LocalEndpoint().port(), Error);
                EXPECT_FALSE(Error);
                EXPECT_NE(Client, nullptr);
                if (Error || !Client)
                {
                    co_return;
                }

                for (int Attempt = 0; Attempt < 100 && Workers.Snapshot().front().MailboxSize == 0;
                     ++Attempt)
                {
                    Net::steady_timer Tick(ListenerIo);
                    Tick.expires_after(std::chrono::milliseconds(1));
                    co_await Tick.async_wait(Net::use_awaitable);
                }
                EXPECT_EQ(Workers.Snapshot().front().MailboxSize, std::size_t{1});
                if (Workers.Snapshot().front().MailboxSize != std::size_t{1})
                {
                    Client->Close();
                    co_return;
                }

                Listener.Stop();
                Workers.Stop();
                ReleaseBlocker.store(true, std::memory_order_release);
                ReleaseBlocker.notify_all();

                std::array<std::byte, 1> Buffer{};
                std::error_code ReadError;
                (void)co_await Preview::Testing::TailReadGuarded(Client, Buffer, ReadError);
                EXPECT_TRUE(ReadError);
                Client->Close();
            });

        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        EXPECT_EQ(FactoryCalls.load(std::memory_order_acquire), 0);
        ReleaseBlocker.store(true, std::memory_order_release);
        ReleaseBlocker.notify_all();
    }

} // namespace
