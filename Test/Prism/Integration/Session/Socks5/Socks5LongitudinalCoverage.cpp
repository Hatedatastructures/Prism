#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file Socks5LongitudinalCoverage.cpp
 * @brief SOCKS5 runtime 缺失纵向场景回归
 * @details 覆盖认证、延迟应答后的半关闭、空闲回收、上游中断和流量统计。
 *          测试使用真实 TCP listener 与 loopback upstream，不绕过 runtime。
 */

#include <gtest/gtest.h>
#include <Test/Prism/Runtime/Session/SessionAdmissionSupport.hpp>

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

#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;

    struct ListenerFixture
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort{0};
        bool RequireAuth{false};
        std::shared_ptr<Prism::Testing::TrafficRecorder> Recorder{};
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
                Io.get_executor(), Prism::Testing::TcpEchoServer(std::move(Socket)),
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

        auto operator()(const Prism::Network::Target &)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            std::error_code Error;
            Prism::Network::Dialer::Dialer Dialer(Fixture.Executor);
            auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Fixture.EchoPort});
            Prism::SharedTransmission Upstream;
            if (Dialed)
            {
                Upstream = std::move(*Dialed);
                Error.clear();
            }
            else
            {
                Error = Prism::Fault::ToNative(Dialed.error());
            }
            if (Error || !Upstream)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Unreachable});
            }
            co_return std::move(Upstream);
        }
    };

    auto BuildSession(const ListenerFixture &Fixture, std::string_view SourceIp)
        -> std::shared_ptr<Prism::Runtime::Session>
    {
        Prism::Runtime::SessionOptions Options;
        Options.SourceIp.assign(SourceIp);
        Options.Services->RelayIdleTimeout = Fixture.IdleTimeout;
        Prism::Socks5::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableAuth = Fixture.RequireAuth;
        Config.Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("secret"), "alice", "alice", {}})->Authenticator;
        Options.Services->AcceptProtocol =
            Prism::Testing::MakeSocks5Binding(std::move(Config));
        Options.Services->Dial = Socks5LongitudinalDial{Fixture};
        Options.Services->Traffic = Fixture.Recorder;
        return std::make_shared<Prism::Runtime::Session>(std::move(Options));
    }

    auto MakeListener(Net::io_context &Io, const ListenerFixture &Fixture)
        -> Prism::Runtime::TcpListener
    {
        return Prism::Runtime::TcpListener(Prism::Runtime::TcpListener::Options{
            .Executor = Io.get_executor(),
            .Factory = [Fixture](Prism::Runtime::SessionAdmission Admission)
                -> std::shared_ptr<Prism::Runtime::Session>
            {
                return BuildSession(Fixture, Admission.SourceIp);
            },
            .Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
                Prism::GenerationId{1})});
    }

    auto ReadClose(Prism::SharedTransmission Connection, std::chrono::milliseconds Timeout)
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
        Error = Prism::Fault::ToNative(Result.Failure);
        co_return Result.Bytes == 0 || static_cast<bool>(Error);
    }

    struct AuthResult
    {
        Prism::Fault::Code Code{Prism::Fault::Code::Success};
        std::string Echo;
    };

    struct Socks5AuthFlow final
    {
        Net::io_context &Io;
        Prism::Runtime::TcpListener &Listener;
        const Socks5LongitudinalEchoFixture &Echo;
        bool CorrectPassword;
        AuthResult &Result;
    };

    /** @brief 驱动 SOCKS5 UserPass 认证与真实回显。 */
    auto RunSocks5AuthFlow(Socks5AuthFlow Flow) -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Prism::Fault::Code::Success);
        if (StartError != Prism::Fault::Code::Success)
        {
            boost::system::error_code CloseError;
            Flow.Echo.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Prism::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ConnectError;
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Prism::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ConnectError.clear();
        }
        else
        {
            ConnectError = Prism::Fault::ToNative(Dialed.error());
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
        Prism::Socks5::ClientConfig Config;
        Config.EnableAuth = true;
        Config.Username = "alice";
        Config.Password = Flow.CorrectPassword ? "secret" : "wrong";
        const Prism::Socks5::Address Target{
            Prism::Socks5::AddressType::Domain, "example.com", 443};
        auto ConnectResult = co_await Prism::Socks5::Connect(
            Prism::Socks5::ConnectParameters{std::move(Raw), Config, Target});
        Flow.Result.Code = ConnectResult ? Prism::Fault::Code::Success :
            ConnectResult.error().Code;
        if (ConnectResult)
        {
            auto Connection = std::move(*ConnectResult);
            const std::string Payload = "socks5-auth-runtime";
            std::error_code IoError;
            const auto Write = co_await Connection->WriteExact(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
            IoError = Prism::Fault::ToNative(Write.Failure);
            std::array<std::byte, 64> Buffer{};
            const auto EchoRead = co_await Connection->ReadExact(
                std::span<std::byte>(Buffer).first(Payload.size()));
            IoError = Prism::Fault::ToNative(EchoRead.Failure);
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
        Prism::Testing::RunCoro(Io, RunSocks5AuthFlow(
            Socks5AuthFlow{Io, Listener, Echo, CorrectPassword, Result}));
        EXPECT_FALSE(*Echo.Failure);
        return Result;
    }

    struct Socks5HalfCloseFlow final
    {
        Net::io_context &Io;
        Prism::Runtime::TcpListener &Listener;
        const Socks5LongitudinalEchoFixture &EchoOwner;
        std::string &Echo;
    };

    /** @brief 驱动 SOCKS5 下游半关闭并等待 relay drain。 */
    auto RunSocks5HalfCloseFlow(Socks5HalfCloseFlow Flow) -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Prism::Fault::Code::Success);
        if (StartError != Prism::Fault::Code::Success)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Prism::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Prism::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Prism::Fault::ToNative(Dialed.error());
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
        const auto Config = Prism::Socks5::ClientConfig{};
        const Prism::Socks5::Address Target{
            Prism::Socks5::AddressType::Domain, "example.com", 443};
        auto ConnectResult = co_await Prism::Socks5::Connect(
            Prism::Socks5::ConnectParameters{std::move(Raw), Config, Target});
        const auto ConnectError = ConnectResult ? Prism::Fault::Code::Success :
            ConnectResult.error().Code;
        auto Connection = ConnectResult ? std::move(*ConnectResult) :
            Prism::Socks5::SharedConn{};
        EXPECT_EQ(ConnectError, Prism::Fault::Code::Success);
        EXPECT_NE(Connection, nullptr);
        if (ConnectError != Prism::Fault::Code::Success || !Connection)
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
        ErrorCode = Prism::Fault::ToNative(PayloadWrite.Failure);
        (void)co_await Connection->WriteShutdown();
        std::array<std::byte, 64> Buffer{};
        const auto EchoRead = co_await Connection->ReadExact(
            std::span<std::byte>(Buffer).first(Payload.size()));
        ErrorCode = Prism::Fault::ToNative(EchoRead.Failure);
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
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Result.Echo, "socks5-auth-runtime");
    }

    TEST(Socks5Longitudinal, UserPassAuthenticationFailure)
    {
        const auto Result = RunAuthCase(false);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::AuthFailed);
        EXPECT_TRUE(Result.Echo.empty());
    }

    TEST(Socks5Longitudinal, HalfCloseKeepsDownstreamAndReportsTraffic)
    {
        Net::io_context Io;
        const auto EchoFixture = StartSocks5LongitudinalEcho(Io);
        const auto EchoPort = EchoFixture.Acceptor->local_endpoint().port();
        auto Recorder = std::make_shared<Prism::Testing::TrafficRecorder>();
        ListenerFixture Fixture{Io.get_executor(), EchoPort, false, Recorder,
                                std::chrono::seconds(2)};
        auto Listener = MakeListener(Io, Fixture);
        std::string Echo;
        Prism::Testing::RunCoro(Io, RunSocks5HalfCloseFlow(
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
        Prism::Runtime::TcpListener &Listener;
        const Socks5LongitudinalEchoFixture &EchoOwner;
        bool &Closed;
    };

    /** @brief 驱动 SOCKS5 relay 空闲超时并验证控制连接关闭。 */
    auto RunSocks5IdleFlow(Socks5IdleFlow Flow) -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Prism::Fault::Code::Success);
        if (StartError != Prism::Fault::Code::Success)
        {
            boost::system::error_code CloseError;
            Flow.EchoOwner.Acceptor->close(CloseError);
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Prism::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Prism::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Prism::Fault::ToNative(Dialed.error());
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
        const auto Config = Prism::Socks5::ClientConfig{};
        const Prism::Socks5::Address Target{
            Prism::Socks5::AddressType::Domain, "example.com", 443};
        auto ConnectResult = co_await Prism::Socks5::Connect(
            Prism::Socks5::ConnectParameters{std::move(Raw), Config, Target});
        const auto ConnectError = ConnectResult ? Prism::Fault::Code::Success :
            ConnectResult.error().Code;
        auto Connection = ConnectResult ? std::move(*ConnectResult) :
            Prism::Socks5::SharedConn{};
        EXPECT_EQ(ConnectError, Prism::Fault::Code::Success);
        EXPECT_NE(Connection, nullptr);
        if (ConnectError != Prism::Fault::Code::Success || !Connection)
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
        Prism::Testing::RunCoro(Io, RunSocks5IdleFlow(
            Socks5IdleFlow{Io, Listener, EchoFixture, Closed}));
        EXPECT_FALSE(*EchoFixture.Failure);
        EXPECT_TRUE(Closed);
    }

    struct Socks5UpstreamAbortFlow final
    {
        Net::io_context &Io;
        Prism::Runtime::TcpListener &Listener;
        Net::ip::tcp::acceptor &Upstream;
        bool &Closed;
    };

    /** @brief 驱动 SOCKS5 上游立即 EOF 并观察客户端收口。 */
    auto RunSocks5UpstreamAbortFlow(Socks5UpstreamAbortFlow Flow)
        -> Net::awaitable<void>
    {
        const auto StartError = co_await Flow.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartError, Prism::Fault::Code::Success);
        if (StartError != Prism::Fault::Code::Success)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        Prism::Network::Dialer::Dialer Dialer(Flow.Io.get_executor());
        std::error_code ErrorCode;
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Flow.Listener.LocalEndpoint().port()});
        Prism::SharedTransmission Raw;
        if (Dialed)
        {
            Raw = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Prism::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ErrorCode);
        EXPECT_NE(Raw, nullptr);
        if (ErrorCode || !Raw)
        {
            co_await Flow.Listener.Shutdown();
            co_return;
        }
        const auto Config = Prism::Socks5::ClientConfig{};
        const Prism::Socks5::Address Target{
            Prism::Socks5::AddressType::Domain, "example.com", 443};
        auto ConnectResult = co_await Prism::Socks5::Connect(
            Prism::Socks5::ConnectParameters{std::move(Raw), Config, Target});
        const auto ConnectError = ConnectResult ? Prism::Fault::Code::Success :
            ConnectResult.error().Code;
        auto Connection = ConnectResult ? std::move(*ConnectResult) :
            Prism::Socks5::SharedConn{};
        EXPECT_EQ(ConnectError, Prism::Fault::Code::Success);
        EXPECT_NE(Connection, nullptr);
        if (ConnectError != Prism::Fault::Code::Success || !Connection)
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
        Net::co_spawn(Io.get_executor(), Prism::Testing::AcceptAndClose(Upstream),
                      [&](std::exception_ptr Error) { UpstreamError = std::move(Error); });
        ListenerFixture Fixture{Io.get_executor(), UpstreamPort, false, nullptr,
                                std::chrono::seconds(2)};
        auto Listener = MakeListener(Io, Fixture);
        bool Closed = false;
        Prism::Testing::RunCoro(Io, RunSocks5UpstreamAbortFlow(
            Socks5UpstreamAbortFlow{Io, Listener, Upstream, Closed}));
        EXPECT_EQ(UpstreamError, nullptr);
        EXPECT_TRUE(Closed);
    }

} // namespace
