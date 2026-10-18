#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file Socks5TcpE2ETest.cpp
 * @brief SOCKS5 TCP CONNECT 真实纵向链路测试（阶段 5 v2 补缺）
 * @details 覆盖：
 *          - 真实 TCP listener → Session → Composition::Adapters::MakeSocks5Accept →
 *            Dial → PostDial(success) → relay → echo 上游
 *          - CONNECT 应答「拨号后发送」：上游拒绝时客户端收到 connection_refused
 *          - runtime 传给 Dial 的目标地址与客户端请求一致
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/SessionAdmissionTestSupport.hpp>
#include <Prism/Runtime/Process.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    namespace Fault = Prism::Fault;
    namespace Network = Prism::Network;
    namespace Runtime = Prism::Runtime;
    using Prism::SharedTransmission;

    // 公共样板（RunCoro/echo 上游见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）
    using Prism::Testing::RunCoro;
    using Prism::Testing::AcceptEchoLoop;
    using Prism::Testing::TcpEchoServer;

    class WorkerGroupRunner final
    {
    public:
        explicit WorkerGroupRunner(Runtime::WorkerGroup &GroupValue)
            : Group_(&GroupValue)
        {
            Threads_.reserve(Group_->Size());
            for (std::size_t Index = 0; Index < Group_->Size(); ++Index)
            {
                auto *WorkerValue = Group_->Find(Prism::WorkerId{
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
        Runtime::WorkerGroup *Group_;
        std::vector<std::thread> Threads_;
    };

    struct Socks5ListenerOptions final
    {
        Net::io_context &IoContext;
        Runtime::WorkerGroup &Workers;
        std::shared_ptr<Runtime::GenerationPublication> Publication;
        std::uint16_t EchoPort;
        bool Refused;
    };

    struct Socks5TcpDial final
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort;
        bool Refused;

        auto operator()(const Prism::Network::Target &Target) const
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            EXPECT_EQ(Target.Host, *Prism::Network::ParseHost("example.com"));
            EXPECT_EQ(Target.Port, 443);
            if (Refused)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ConnectionRefused});
            }
            std::error_code ErrorCode;
            Prism::Network::Dialer::Dialer Dialer(Executor);
            auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), EchoPort});
            Prism::SharedTransmission Connection;
            if (Dialed)
            {
                Connection = std::move(*Dialed);
                ErrorCode.clear();
            }
            else
            {
                ErrorCode = Prism::Fault::ToNative(Dialed.error());
            }
            if (ErrorCode)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Unreachable});
            }
            co_return std::move(Connection);
        }
    };

    struct Socks5TcpSessionFactory final
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort;
        bool Refused;

        auto operator()(Prism::Runtime::SessionAdmission) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            Options.Services->RelayIdleTimeout = std::chrono::milliseconds(500);
            Socks5::ServerConfig Configuration;
            Configuration.EnableTcp = true;
            Options.Services->AcceptProtocol =
                Prism::Testing::MakeSocks5Binding(std::move(Configuration));
            Options.Services->Dial = Socks5TcpDial{Executor, EchoPort, Refused};
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

    /// SOCKS5 无认证 Greeting
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// SOCKS5 CONNECT 请求（domain）
    auto Socks5ConnectRequest(const std::string &Host, std::uint16_t Port) -> std::string
    {
        std::string Request;
        Request.push_back(0x05); // version
        Request.push_back(0x01); // CONNECT
        Request.push_back(0x00); // reserved
        Request.push_back(0x03); // atyp domain
        Request.push_back(static_cast<char>(Host.size()));
        Request += Host;
        Request.push_back(static_cast<char>((Port >> 8) & 0xff));
        Request.push_back(static_cast<char>(Port & 0xff));
        return Request;
    }

    /// 读取 SOCKS5 应答并返回 rep 字段
    /// @note 使用 ReadExact 读满固定长度，避免半包；错误/EOF 时直接返回
    auto ReadSocks5Reply(SharedTransmission Conn, std::uint8_t &Reply) -> Net::awaitable<void>
    {
        std::array<std::byte, 4> head{};
        std::error_code ErrorCode;
        const auto Head = co_await Conn->ReadExact(head);
        ErrorCode = Prism::Fault::ToNative(Head.Failure);
        const auto BytesRead = Head.Bytes;
        if (ErrorCode || BytesRead < 4)
        {
            co_return;
        }
        Reply = static_cast<std::uint8_t>(head[1]);
        // 跳过 BND.ADDR + BND.PORT
        const auto AddressTypeByte = static_cast<std::uint8_t>(head[3]);
        std::size_t SkipBytes = 2;
        if (AddressTypeByte == 0x01)
        {
            SkipBytes += 4;
        }
        else if (AddressTypeByte == 0x04)
        {
            SkipBytes += 16;
        }
        else if (AddressTypeByte == 0x03)
        {
            std::array<std::byte, 1> len{};
            const auto Length = co_await Conn->ReadExact(len);
            ErrorCode = Prism::Fault::ToNative(Length.Failure);
            const auto LengthBytes = Length.Bytes;
            if (ErrorCode || LengthBytes < 1)
            {
                co_return;
            }
            SkipBytes += static_cast<std::size_t>(static_cast<std::uint8_t>(len[0]));
        }
        std::vector<std::byte> Rest(SkipBytes);
        if (!Rest.empty())
        {
            const auto Tail = co_await Conn->ReadExact(Rest);
            ErrorCode = Prism::Fault::ToNative(Tail.Failure);
        }
    }

    /// SOCKS5 TCP 链路用例结果
    struct Socks5ChainResult
    {
        std::string Echo;                 ///< 回显数据
        std::uint8_t ReplyCode{0xff};           ///< CONNECT 应答码
    };

    /// 组装 SOCKS5 TCP 会话 listener（识别 → adapter → Dial）
    auto MakeSocks5Listener(Socks5ListenerOptions Options)
        -> Prism::Runtime::TcpListener
    {
        auto &IoContext = Options.IoContext;
        const auto Executor = IoContext.get_executor();
        auto ListenerOptions = Prism::Runtime::TcpListener::Options{};
        ListenerOptions.Executor = Executor;
        ListenerOptions.Workers = &Options.Workers;
        ListenerOptions.Publication = std::move(Options.Publication);
        ListenerOptions.Factory = Socks5TcpSessionFactory{
            Executor, Options.EchoPort, Options.Refused};
        return Prism::Runtime::TcpListener(std::move(ListenerOptions));
    }

    struct Socks5ConnectFlow final
    {
        Net::io_context &Io;
        Runtime::TcpListener &Listener;
        std::shared_ptr<Net::ip::tcp::acceptor> EchoAcceptor;
        std::shared_ptr<std::exception_ptr> EchoFailure;
        bool Refused;
        Socks5ChainResult &Result;
    };

    /** @brief 驱动 SOCKS5 greeting、CONNECT、dial、relay 与最终 drain。 */
    auto RunSocks5ConnectFlow(Socks5ConnectFlow Flow) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Prism::Fault::Code::Success);
        if (StartResult != Prism::Fault::Code::Success)
        {
            boost::system::error_code CloseError;
            Flow.EchoAcceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        std::error_code ErrorCode;
        Prism::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Prism::SharedTransmission Connection;
        if (Dialed)
        {
            Connection = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Prism::Fault::ToNative(Dialed.error());
        }
        if (ErrorCode || !Connection)
        {
            boost::system::error_code CloseError;
            Flow.EchoAcceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        const auto Greeting = Socks5Greeting();
        const auto GreetingWrite = co_await Connection->WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()));
        ErrorCode = Prism::Fault::ToNative(GreetingWrite.Failure);
        if (ErrorCode)
        {
            (void)Connection->Close();
            boost::system::error_code CloseError;
            Flow.EchoAcceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        std::array<std::byte, 2> MethodReply{};
        const auto MethodReplyRead = co_await Connection->ReadExact(MethodReply);
        ErrorCode = Prism::Fault::ToNative(MethodReplyRead.Failure);
        const auto MethodRead = MethodReplyRead.Bytes;
        if (ErrorCode || MethodRead < MethodReply.size())
        {
            (void)Connection->Close();
            boost::system::error_code CloseError;
            Flow.EchoAcceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        EXPECT_EQ(static_cast<std::uint8_t>(MethodReply[0]), 0x05);
        EXPECT_EQ(static_cast<std::uint8_t>(MethodReply[1]), 0x00);
        const auto Request = Socks5ConnectRequest("example.com", 443);
        const auto RequestWrite = co_await Connection->WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Request.data()), Request.size()));
        ErrorCode = Prism::Fault::ToNative(RequestWrite.Failure);
        if (!ErrorCode)
        {
            co_await ReadSocks5Reply(Connection, Flow.Result.ReplyCode);
        }
        if (!Flow.Refused && !ErrorCode)
        {
            const std::string Payload = "socks5-e2e-payload";
            const auto PayloadWrite = co_await Connection->WriteExact(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
            ErrorCode = Prism::Fault::ToNative(PayloadWrite.Failure);
            std::array<std::byte, 64> Buffer{};
            std::error_code ReadError;
            const auto EchoRead = co_await Connection->ReadExact(
                std::span<std::byte>(Buffer).first(Payload.size()));
            ReadError = Prism::Fault::ToNative(EchoRead.Failure);
            const auto Read = EchoRead.Bytes;
            Flow.Result.Echo.assign(
                reinterpret_cast<const char *>(Buffer.data()), Read);
        }
        (void)Connection->Close();
        Net::steady_timer Drain(Flow.Io.get_executor());
        Drain.expires_after(std::chrono::milliseconds(30));
        co_await Drain.async_wait(Net::use_awaitable);
        boost::system::error_code CloseError;
        Flow.EchoAcceptor->close(CloseError);
        co_await Flow.Listener.Shutdown();
    }

    struct Socks5ReplyFailureDial final
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort;

        auto operator()(const Prism::Network::Target &)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            Net::steady_timer Delay(Executor);
            Delay.expires_after(std::chrono::milliseconds(200));
            boost::system::error_code DelayError;
            co_await Delay.async_wait(
                Net::redirect_error(Net::use_awaitable, DelayError));
            std::error_code ConnectError;
            Prism::Network::Dialer::Dialer Dialer(Executor);
            auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), EchoPort});
            Prism::SharedTransmission Connection;
            if (Dialed)
            {
                Connection = std::move(*Dialed);
                ConnectError.clear();
            }
            else
            {
                ConnectError = Prism::Fault::ToNative(Dialed.error());
            }
            if (ConnectError)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Unreachable});
            }
            co_return std::move(Connection);
        }
    };

    struct Socks5ReplyFailureSessionFactory final
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort;

        auto operator()(Prism::Runtime::SessionAdmission) const
            -> std::shared_ptr<Runtime::Session>
        {
            Runtime::SessionOptions Options;
            Socks5::ServerConfig Configuration;
            Configuration.EnableTcp = true;
            Options.Services->AcceptProtocol =
                Prism::Testing::MakeSocks5Binding(std::move(Configuration));
            Options.Services->Dial = Socks5ReplyFailureDial{Executor, EchoPort};
            return std::make_shared<Runtime::Session>(std::move(Options));
        }
    };

    struct Socks5EchoAcceptLoop final
    {
        Net::io_context &Io;
        boost::asio::ip::tcp::acceptor &Acceptor;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    /** @brief 启动真实 echo accept loop，并通过 completion handler 保留首异常。 */
    auto RunSocks5EchoAcceptLoop(Socks5EchoAcceptLoop Flow)
        -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ErrorCode;
            auto Socket = co_await Flow.Acceptor.async_accept(
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
            auto Failure = Flow.Failure;
            Net::co_spawn(
                Flow.Io.get_executor(), TcpEchoServer(std::move(Socket)),
                [Failure](const std::exception_ptr &Error)
                {
                    if (Error && !*Failure)
                    {
                        *Failure = Error;
                    }
                });
        }
    }

    /// 运行一条 SOCKS5 TCP CONNECT 链路
    /// @param refused 为 true 时 Dial 返回 connection_refused
    auto RunSocks5Connect(bool Refused) -> Socks5ChainResult
    {
        Net::io_context IoContext;
        auto EchoAcceptor = std::make_shared<Net::ip::tcp::acceptor>(
            IoContext, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto EchoPort = EchoAcceptor->local_endpoint().port();
        auto EchoFailure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            IoContext.get_executor(), AcceptEchoLoop(*EchoAcceptor),
            [EchoFailure](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue && !*EchoFailure)
                {
                    *EchoFailure = ErrorValue;
                }
            });
        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{33};
        ProcessOptions.Generation = Prism::GenerationId{49};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());
        auto Listener = MakeSocks5Listener(
            Socks5ListenerOptions{
                IoContext, ProcessValue.Workers(), ProcessOptions.Publication, EchoPort, Refused});

        Socks5ChainResult Output;
        RunCoro(IoContext, RunSocks5ConnectFlow(
            Socks5ConnectFlow{
                IoContext, Listener, EchoAcceptor, EchoFailure, Refused, Output}));
        EXPECT_FALSE(*EchoFailure);
        return Output;
    }

    TEST(Socks5TcpChain, FullConnectEcho)
    {
        const auto Result = RunSocks5Connect(false);
        EXPECT_EQ(Result.ReplyCode, static_cast<std::uint8_t>(Socks5::ReplyCode::Success));
        EXPECT_EQ(Result.Echo, "socks5-e2e-payload");
    }

    TEST(Socks5TcpChain, DialRefusedMapsToConnectionRefused)
    {
        const auto Result = RunSocks5Connect(true);
        EXPECT_EQ(Result.ReplyCode, static_cast<std::uint8_t>(Socks5::ReplyCode::ConnectionRefused));
        EXPECT_TRUE(Result.Echo.empty());
    }



    struct Socks5ReplyFailureScenario final
    {
        Net::io_context &Ioc;
        Prism::Runtime::TcpListener &Listener;
        boost::asio::ip::tcp::acceptor &EchoAcceptor;
        bool &Completed;
    };

    auto RunSocks5ReplyFailureScenario(Socks5ReplyFailureScenario &Scenario)
        -> Net::awaitable<void>
    {
                     const auto StartResultCode = co_await Scenario.Listener.Start(
                         Net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
                     EXPECT_EQ(StartResultCode, Prism::Fault::Code::Success);
                     const auto ListenPort = Scenario.Listener.LocalEndpoint().port();

                     std::error_code ErrorCode;
                     Prism::Network::Dialer::Dialer Dialer(Scenario.Ioc.get_executor());
                     auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), ListenPort});
                     Prism::SharedTransmission Conn;
                     if (Dialed)
                     {
                         Conn = std::move(*Dialed);
                         ErrorCode.clear();
                     }
                     else
                     {
                         ErrorCode = Prism::Fault::ToNative(Dialed.error());
                     }
                     if (ErrorCode || !Conn)
                     {
                         boost::system::error_code CloseError;
                         Scenario.EchoAcceptor.close(CloseError);
                         co_await Scenario.Listener.Shutdown();
                         co_return;
                     }

                     // Greeting → Method Reply
                     const auto Greeting = Socks5Greeting();
                     const auto GreetingWrite = co_await Conn->WriteExact(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(Greeting.data()),
                             Greeting.size()));
                     ErrorCode = Prism::Fault::ToNative(GreetingWrite.Failure);
                     if (ErrorCode)
                     {
                         (void)Conn->Close();
                         boost::system::error_code CloseError;
                         Scenario.EchoAcceptor.close(CloseError);
                         co_await Scenario.Listener.Shutdown();
                         co_return;
                     }
                     std::array<std::byte, 2> mrep{};
                     const auto ReplyRead = co_await Conn->ReadExact(mrep);
                     ErrorCode = Prism::Fault::ToNative(ReplyRead.Failure);
                     const auto MethodBytes = ReplyRead.Bytes;
                     if (ErrorCode || MethodBytes < 2)
                     {
                         (void)Conn->Close();
                         boost::system::error_code CloseError;
                         Scenario.EchoAcceptor.close(CloseError);
                         co_await Scenario.Listener.Shutdown();
                         co_return;
                     }

                     // CONNECT 请求后立即断开
                     const auto RequestBytes = Socks5ConnectRequest("example.com", 443);
                     const auto RequestWrite = co_await Conn->WriteExact(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(RequestBytes.data()),
                             RequestBytes.size()));
                     ErrorCode = Prism::Fault::ToNative(RequestWrite.Failure);
                     (void)Conn->Close();

                     // 等待服务端完成慢拨号 + 应答写失败收口
                     Net::steady_timer Timer(Scenario.Ioc.get_executor(), std::chrono::milliseconds(500));
                     boost::system::error_code TimerErrorCode;
                     co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, TimerErrorCode));
                     Scenario.Completed = true;
                     co_await Scenario.Listener.Shutdown();
                     boost::system::error_code CloseError;
                     Scenario.EchoAcceptor.close(CloseError);

    }
    TEST(Socks5TcpChain, ReplyWriteFailureAfterClientDisconnect)
    {
        // A-2 回归：客户端 CONNECT 后立即断开，服务端慢拨号完成后应答写在已关闭连接上，
        // 必须记录错误并收口，不能静默丢失也不得挂起。
        Net::io_context IoContext;

        boost::asio::ip::tcp::acceptor EchoAcceptor(
            IoContext, Net::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
        const auto EchoPort = EchoAcceptor.local_endpoint().port();
        auto EchoFailure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            IoContext.get_executor(),
            RunSocks5EchoAcceptLoop(
                Socks5EchoAcceptLoop{IoContext, EchoAcceptor, EchoFailure}),
            [EchoFailure](const std::exception_ptr &Error)
            {
                if (Error && !*EchoFailure)
                {
                    *EchoFailure = Error;
                }
            });

        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{34};
        ProcessOptions.Generation = Prism::GenerationId{50};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = IoContext.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory = Socks5ReplyFailureSessionFactory{
            IoContext.get_executor(), EchoPort};
        Prism::Runtime::TcpListener Listener(std::move(ListenerOptions));

        bool Completed = false;
        Socks5ReplyFailureScenario Scenario{IoContext, Listener, EchoAcceptor, Completed};
        RunCoro(IoContext, RunSocks5ReplyFailureScenario(Scenario));
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(*EchoFailure);
    }
} // namespace
