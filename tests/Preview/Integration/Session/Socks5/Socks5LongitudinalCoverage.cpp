#include <TestSupport/Preview/ProviderBindings.hpp>
/**
 * @file Socks5LongitudinalCoverage.cpp
 * @brief SOCKS5 runtime 缺失纵向场景回归
 * @details 覆盖认证、延迟应答后的半关闭、空闲回收、上游中断和流量统计。
 *          测试使用真实 TCP listener 与 loopback upstream，不绕过 runtime。
 */

#include <gtest/gtest.h>
#include <Preview/Runtime/SessionAdmissionTestSupport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Protocols/Vmess/IngressFactory.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;

    struct ListenerFixture
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort{0};
        bool RequireAuth{false};
        std::shared_ptr<Preview::Testing::TrafficRecorder> Recorder{};
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(2)};
    };

    struct Socks5LongitudinalEchoFixture final
    {
        std::shared_ptr<Net::ip::tcp::acceptor> Acceptor;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    auto RunSocks5LongitudinalEchoLoop(
        Socks5LongitudinalEchoFixture Fixture,
        Net::io_context &Io) -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ErrorCode;
            auto Socket = co_await Fixture.Acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
            auto Failure = Fixture.Failure;
            Net::co_spawn(
                Io.get_executor(), Preview::Testing::TcpEchoServer(std::move(Socket)),
                [Failure](const std::exception_ptr &ErrorValue)
                {
                    if (ErrorValue && !*Failure)
                    {
                        *Failure = ErrorValue;
                    }
                });
        }
    }

    auto StartSocks5LongitudinalEcho(Net::io_context &Io)
        -> Socks5LongitudinalEchoFixture
    {
        Socks5LongitudinalEchoFixture Fixture;
        Fixture.Acceptor = std::make_shared<Net::ip::tcp::acceptor>(
            Io, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        Fixture.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), RunSocks5LongitudinalEchoLoop(Fixture, Io),
            [Failure = Fixture.Failure](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue && !*Failure)
                {
                    *Failure = ErrorValue;
                }
            });
        return Fixture;
    }

    struct Socks5LongitudinalDial final
    {
        ListenerFixture Fixture;

        auto operator()(const Preview::Network::Target &)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            std::error_code Error;
            Preview::Network::Dialer::Dialer Dialer(Fixture.Executor);
            auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Fixture.EchoPort});
            Preview::SharedTransmission Upstream;
            if (Dialed)
            {
                Upstream = std::move(*Dialed);
                Error.clear();
            }
            else
            {
                Error = Preview::Fault::ToNative(Dialed.error());
            }
            if (Error || !Upstream)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Unreachable});
            }
            co_return std::move(Upstream);
        }
    };

    auto BuildSession(const ListenerFixture &Fixture, std::string_view SourceIp)
        -> std::shared_ptr<Preview::Runtime::Session>
    {
        Preview::Runtime::SessionOptions Options;
        Options.SourceIp.assign(SourceIp);
        Options.Services->RelayIdleTimeout = Fixture.IdleTimeout;
        Preview::Socks5::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableAuth = Fixture.RequireAuth;
        Config.Authenticator = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Preview::Account::Credential::Password("secret"), "alice", "alice", {}})->Authenticator;
        Options.Services->AcceptProtocol =
            Preview::Testing::MakeSocks5Binding(std::move(Config));
        Options.Services->Dial = Socks5LongitudinalDial{Fixture};
        Options.Services->Traffic = Fixture.Recorder;
        return std::make_shared<Preview::Runtime::Session>(std::move(Options));
    }

    auto MakeListener(Net::io_context &Io, const ListenerFixture &Fixture)
        -> Preview::Runtime::TcpListener
    {
        return Preview::Runtime::TcpListener(Preview::Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
                Preview::GenerationId{1}),
            .Factory = [Fixture](Preview::Runtime::SessionAdmission Admission)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                return BuildSession(Fixture, Admission.SourceIp);
            }});
    }

    auto ReadClose(Preview::SharedTransmission Connection, std::chrono::milliseconds Timeout)
        -> Net::awaitable<bool>
    {
        std::array<std::byte, 1> Buffer{};
        std::error_code Error;
        Net::steady_timer Timer(Connection->Executor());
        Timer.expires_after(Timeout);
        auto Read = Connection->ReadSome(Buffer);
        auto Wait = Timer.async_wait(Net::use_awaitable);
        const auto Race = co_await Net::experimental::awaitable_operators::operator||(
            std::move(Read), std::move(Wait));
        if (Race.index() != 0)
        {
            co_return false;
        }
        const auto Result = std::get<0>(Race);
        Error = Preview::Fault::ToNative(Result.Failure);
        co_return Result.Bytes == 0 || static_cast<bool>(Error);
    }

    struct AuthResult
    {
        Preview::Error Error{Preview::Error::None};
        std::string Echo;
    };

    struct Socks5AuthFlow final
    {
        Net::io_context &Io;
        Preview::Runtime::TcpListener &Listener;
        const Socks5LongitudinalEchoFixture &Echo;
        bool CorrectPassword;
        AuthResult &Result;
    };

    /** @brief 驱动 SOCKS5 UserPass 认证与真实回显。 */
    auto RunSocks5AuthFlow(Socks5AuthFlow Flow) -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Preview::Fault::Code::Success);
        if (StartError != Preview::Fault::Code::Success)
        {
            boost::system::error_code CloseError;
            Flow.Echo.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Preview::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ConnectError;
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Preview::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ConnectError.clear();
        }
        else
        {
            ConnectError = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ConnectError);
        EXPECT_NE(Raw, nullptr);
        if (ConnectError || !Raw)
        {
            boost::system::error_code CloseError;
            Flow.Echo.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Preview::Socks5::ClientConfig Config;
        Config.EnableAuth = true;
        Config.Username = "alice";
        Config.Password = Flow.CorrectPassword ? "secret" : "wrong";
        auto [ErrorValue, Connection] = co_await Preview::Socks5::Connect(
            std::move(Raw), Config,
            Preview::Socks5::Address{Preview::Socks5::AddressType::Domain,
                                     "example.com", 443});
        Flow.Result.Error = ErrorValue;
        if (Connection)
        {
            const std::string Payload = "socks5-auth-runtime";
            std::error_code IoError;
            const auto Write = co_await Connection->WriteExact(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
            IoError = Preview::Fault::ToNative(Write.Failure);
            std::array<std::byte, 64> Buffer{};
            const auto EchoRead = co_await Connection->ReadExact(
                std::span<std::byte>(Buffer).first(Payload.size()));
            IoError = Preview::Fault::ToNative(EchoRead.Failure);
            const auto Read = EchoRead.Bytes;
            Flow.Result.Echo.assign(
                reinterpret_cast<const char *>(Buffer.data()), Read);
            (void)Connection->Close();
        }
        boost::system::error_code CloseError;
        Flow.Echo.Acceptor->close(CloseError);
        co_await Flow.Listener.Shutdown();
    }

    auto RunAuthCase(bool CorrectPassword) -> AuthResult
    {
        Net::io_context Io;
        const auto Echo = StartSocks5LongitudinalEcho(Io);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();
        ListenerFixture Fixture{Io.get_executor(), EchoPort, true, nullptr,
                                std::chrono::seconds(2)};
        auto Listener = MakeListener(Io, Fixture);
        AuthResult Result;
        Preview::Testing::RunCoro(Io, RunSocks5AuthFlow(
            Socks5AuthFlow{Io, Listener, Echo, CorrectPassword, Result}));
        EXPECT_FALSE(*Echo.Failure);
        return Result;
    }

    struct Socks5HalfCloseFlow final
    {
        Net::io_context &Io;
        Preview::Runtime::TcpListener &Listener;
        const Socks5LongitudinalEchoFixture &EchoOwner;
        std::string &Echo;
    };

    /** @brief 驱动 SOCKS5 下游半关闭并等待 relay drain。 */
    auto RunSocks5HalfCloseFlow(Socks5HalfCloseFlow Flow) -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Preview::Fault::Code::Success);
        if (StartError != Preview::Fault::Code::Success)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Preview::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Preview::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ErrorCode);
        EXPECT_NE(Raw, nullptr);
        if (ErrorCode || !Raw)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto [ConnectError, Connection] = co_await Preview::Socks5::Connect(
            std::move(Raw), Preview::Socks5::ClientConfig{},
            Preview::Socks5::Address{Preview::Socks5::AddressType::Domain,
                                     "example.com", 443});
        EXPECT_EQ(ConnectError, Preview::Error::None);
        EXPECT_NE(Connection, nullptr);
        if (ConnectError != Preview::Error::None || !Connection)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        const std::string Payload = "socks5-half-close";
        const auto PayloadWrite = co_await Connection->WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        ErrorCode = Preview::Fault::ToNative(PayloadWrite.Failure);
        (void)co_await Connection->WriteShutdown();
        std::array<std::byte, 64> Buffer{};
        const auto EchoRead = co_await Connection->ReadExact(
            std::span<std::byte>(Buffer).first(Payload.size()));
        ErrorCode = Preview::Fault::ToNative(EchoRead.Failure);
        const auto Read = EchoRead.Bytes;
        Flow.Echo.assign(reinterpret_cast<const char *>(Buffer.data()), Read);
        (void)Connection->Close();
        Net::steady_timer Drain(Flow.Io.get_executor());
        Drain.expires_after(std::chrono::milliseconds(50));
        co_await Drain.async_wait(Net::use_awaitable);
        boost::system::error_code CloseError;
        Flow.EchoOwner.Acceptor->close(CloseError);
        co_await Flow.Listener.Shutdown();
    }

    TEST(Socks5Longitudinal, UserPassAuthenticationSuccess)
    {
        const auto Result = RunAuthCase(true);
        EXPECT_EQ(Result.Error, Preview::Error::None);
        EXPECT_EQ(Result.Echo, "socks5-auth-runtime");
    }

    TEST(Socks5Longitudinal, UserPassAuthenticationFailure)
    {
        const auto Result = RunAuthCase(false);
        EXPECT_EQ(Result.Error, Preview::Error::BadAuth);
        EXPECT_TRUE(Result.Echo.empty());
    }

    TEST(Socks5Longitudinal, HalfCloseKeepsDownstreamAndReportsTraffic)
    {
        Net::io_context Io;
        const auto EchoFixture = StartSocks5LongitudinalEcho(Io);
        const auto EchoPort = EchoFixture.Acceptor->local_endpoint().port();
        auto Recorder = std::make_shared<Preview::Testing::TrafficRecorder>();
        ListenerFixture Fixture{Io.get_executor(), EchoPort, false, Recorder,
                                std::chrono::seconds(2)};
        auto Listener = MakeListener(Io, Fixture);
        std::string Echo;
        Preview::Testing::RunCoro(Io, RunSocks5HalfCloseFlow(
            Socks5HalfCloseFlow{Io, Listener, EchoFixture, Echo}));
        EXPECT_FALSE(*EchoFixture.Failure);
        EXPECT_EQ(Echo, "socks5-half-close");
        EXPECT_GT(Recorder->Calls, 0);
        EXPECT_GE(Recorder->Up, std::string_view{"socks5-half-close"}.size());
        EXPECT_GE(Recorder->Down, std::string_view{"socks5-half-close"}.size());
    }

    struct Socks5IdleFlow final
    {
        Net::io_context &Io;
        Preview::Runtime::TcpListener &Listener;
        const Socks5LongitudinalEchoFixture &EchoOwner;
        bool &Closed;
    };

    /** @brief 驱动 SOCKS5 relay 空闲超时并验证控制连接关闭。 */
    auto RunSocks5IdleFlow(Socks5IdleFlow Flow) -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Preview::Fault::Code::Success);
        if (StartError != Preview::Fault::Code::Success)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Preview::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Preview::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ErrorCode);
        EXPECT_NE(Raw, nullptr);
        if (ErrorCode || !Raw)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto [ConnectError, Connection] = co_await Preview::Socks5::Connect(
            std::move(Raw), Preview::Socks5::ClientConfig{},
            Preview::Socks5::Address{Preview::Socks5::AddressType::Domain,
                                     "example.com", 443});
        EXPECT_EQ(ConnectError, Preview::Error::None);
        EXPECT_NE(Connection, nullptr);
        if (ConnectError != Preview::Error::None || !Connection)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Net::steady_timer Idle(Flow.Io.get_executor());
        Idle.expires_after(std::chrono::milliseconds(350));
        co_await Idle.async_wait(Net::use_awaitable);
        Flow.Closed = co_await ReadClose(
            Connection, std::chrono::milliseconds(300));
        (void)Connection->Close();
        boost::system::error_code CloseError;
        Flow.EchoOwner.Acceptor->close(CloseError);
        co_await Flow.Listener.Shutdown();
    }

    TEST(Socks5Longitudinal, IdleTimeoutClosesRelay)
    {
        Net::io_context Io;
        const auto EchoFixture = StartSocks5LongitudinalEcho(Io);
        const auto EchoPort = EchoFixture.Acceptor->local_endpoint().port();
        ListenerFixture Fixture{Io.get_executor(), EchoPort, false, nullptr,
                                std::chrono::milliseconds(120)};
        auto Listener = MakeListener(Io, Fixture);
        bool Closed = false;
        Preview::Testing::RunCoro(Io, RunSocks5IdleFlow(
            Socks5IdleFlow{Io, Listener, EchoFixture, Closed}));
        EXPECT_FALSE(*EchoFixture.Failure);
        EXPECT_TRUE(Closed);
    }

    struct Socks5UpstreamAbortFlow final
    {
        Net::io_context &Io;
        Preview::Runtime::TcpListener &Listener;
        Net::ip::tcp::acceptor &Upstream;
        bool &Closed;
    };

    /** @brief 驱动 SOCKS5 上游立即 EOF 并观察客户端收口。 */
    auto RunSocks5UpstreamAbortFlow(Socks5UpstreamAbortFlow Flow)
        -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Preview::Fault::Code::Success);
        if (StartError != Preview::Fault::Code::Success)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Preview::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Preview::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ErrorCode);
        EXPECT_NE(Raw, nullptr);
        if (ErrorCode || !Raw)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        auto [ConnectError, Connection] = co_await Preview::Socks5::Connect(
            std::move(Raw), Preview::Socks5::ClientConfig{},
            Preview::Socks5::Address{Preview::Socks5::AddressType::Domain,
                                     "example.com", 443});
        EXPECT_EQ(ConnectError, Preview::Error::None);
        EXPECT_NE(Connection, nullptr);
        if (ConnectError != Preview::Error::None || !Connection)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Flow.Closed = co_await ReadClose(
            Connection, std::chrono::milliseconds(500));
        (void)Connection->Close();
        co_await Flow.Listener.Shutdown();
        boost::system::error_code CloseError;
        Flow.Upstream.close(CloseError);
    }

    TEST(Socks5Longitudinal, UpstreamAbortReachesClient)
    {
        Net::io_context Io;
        Net::ip::tcp::acceptor Upstream(Io, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto UpstreamPort = Upstream.local_endpoint().port();
        std::exception_ptr UpstreamError;
        Net::co_spawn(Io.get_executor(), Preview::Testing::AcceptAndClose(Upstream),
                      [&](std::exception_ptr Error) { UpstreamError = std::move(Error); });
        ListenerFixture Fixture{Io.get_executor(), UpstreamPort, false, nullptr,
                                std::chrono::seconds(2)};
        auto Listener = MakeListener(Io, Fixture);
        bool Closed = false;
        Preview::Testing::RunCoro(Io, RunSocks5UpstreamAbortFlow(
            Socks5UpstreamAbortFlow{Io, Listener, Upstream, Closed}));
        EXPECT_EQ(UpstreamError, nullptr);
        EXPECT_TRUE(Closed);
    }

} // namespace
