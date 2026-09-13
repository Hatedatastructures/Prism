/**
 * @file Socks5LongitudinalCoverage.cpp
 * @brief SOCKS5 runtime 缺失纵向场景回归
 * @details 覆盖认证、延迟应答后的半关闭、空闲回收、上游中断和流量统计。
 *          测试使用真实 TCP listener 与 loopback upstream，不绕过 runtime。
 */

#include <gtest/gtest.h>

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

#include <preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Runtime/Listener.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;

    struct ListenerFixture
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort{0};
        bool RequireAuth{false};
        Preview::Testing::TrafficRecorder *Recorder{nullptr};
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(2)};
    };

    auto BuildSession(const ListenerFixture &Fixture, Preview::SharedTransmission,
                      std::size_t) -> std::shared_ptr<Preview::Runtime::Session>
    {
        Preview::Runtime::SessionOptions Options;
        Options.RelayIdleTimeout = Fixture.IdleTimeout;
        Preview::Socks5::ServerConfig Config;
        Config.EnableTcp = true;
        Config.EnableUdp = false;
        Config.EnableAuth = Fixture.RequireAuth;
        Config.username = "alice";
        Config.password = "secret";
        Options.AcceptProtocol = Preview::Runtime::MakeAcceptSocks5(std::move(Config));
        Options.Dial = [Fixture](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            std::error_code Error;
            Preview::Network::Dialer::Dialer Dialer(Fixture.Executor);
            auto Upstream = co_await Dialer.Connect("127.0.0.1", Fixture.EchoPort, Error);
            if (Error || !Upstream)
            {
                co_return std::pair{Preview::Fault::Code::Unreachable,
                                    Preview::SharedTransmission{}};
            }
            co_return std::pair{Preview::Fault::Code::Success, std::move(Upstream)};
        };
        Options.traffic = Fixture.Recorder;
        return std::make_shared<Preview::Runtime::Session>(std::move(Options));
    }

    auto MakeListener(Net::io_context &Io, const ListenerFixture &Fixture)
        -> Preview::Runtime::TcpListener
    {
        return Preview::Runtime::TcpListener(
            Io.get_executor(),
            [Fixture](Preview::SharedTransmission Inbound, std::size_t Worker)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                return BuildSession(Fixture, std::move(Inbound), Worker);
            });
    }

    auto ReadClose(Preview::SharedTransmission Connection, std::chrono::milliseconds Timeout)
        -> Net::awaitable<bool>
    {
        std::array<std::byte, 1> Buffer{};
        std::error_code Error;
        Net::steady_timer Timer(Connection->Executor());
        Timer.expires_after(Timeout);
        auto Read = Connection->async_read_some(Buffer, Error);
        auto Wait = Timer.async_wait(Net::use_awaitable);
        const auto Race = co_await Net::experimental::awaitable_operators::operator||(
            std::move(Read), std::move(Wait));
        if (Race.index() != 0)
        {
            co_return false;
        }
        co_return std::get<0>(Race) == 0 || static_cast<bool>(Error);
    }

    struct AuthResult
    {
        Preview::Error Error{Preview::Error::None};
        std::string Echo;
    };

    auto RunAuthCase(bool CorrectPassword) -> AuthResult
    {
        Net::io_context Io;
        const auto EchoPort = Preview::Testing::StartTcpEchoUpstream(Io);
        ListenerFixture Fixture{Io.get_executor(), EchoPort, true, nullptr,
                                std::chrono::seconds(2)};
        auto Listener = MakeListener(Io, Fixture);
        AuthResult Result;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const auto StartError = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                EXPECT_EQ(StartError, Preview::Fault::Code::Success);
                if (StartError != Preview::Fault::Code::Success)
                {
                    Listener.Stop();
                    co_return;
                }
                Preview::Network::Dialer::Dialer Dialer(Io.get_executor());
                std::error_code ConnectError;
                auto Raw = co_await Dialer.Connect("127.0.0.1", Listener.LocalEndpoint().port(),
                                                   ConnectError);
                EXPECT_FALSE(ConnectError);
                EXPECT_NE(Raw, nullptr);
                if (ConnectError || !Raw)
                {
                    Listener.Stop();
                    co_return;
                }
                Preview::Socks5::ClientConfig Config;
                Config.EnableAuth = true;
                Config.username = "alice";
                Config.password = "wrong";
                if (CorrectPassword)
                {
                    Config.password = "secret";
                }
                auto [Error, Connection] = co_await Preview::Socks5::Connect(
                    std::move(Raw), Config,
                    Preview::Socks5::Address{Preview::Socks5::AddressType::Domain,
                                             "example.com", 443});
                Result.Error = Error;
                if (Connection)
                {
                    const std::string Payload = "socks5-auth-runtime";
                    std::error_code IoError;
                    (void)co_await Connection->AsyncWrite(
                        std::span<const std::byte>(
                            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
                        IoError);
                    std::array<std::byte, 64> Buffer{};
                    const auto Read = co_await Connection->AsyncRead(
                        std::span<std::byte>(Buffer).first(Payload.size()), IoError);
                    Result.Echo.assign(reinterpret_cast<const char *>(Buffer.data()), Read);
                    Connection->Close();
                }
                Listener.Stop();
            });
        return Result;
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
        const auto EchoPort = Preview::Testing::StartTcpEchoUpstream(Io);
        Preview::Testing::TrafficRecorder Recorder;
        ListenerFixture Fixture{Io.get_executor(), EchoPort, false, &Recorder,
                                std::chrono::seconds(2)};
        auto Listener = MakeListener(Io, Fixture);
        std::string Echo;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const auto StartError = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                EXPECT_EQ(StartError, Preview::Fault::Code::Success);
                if (StartError != Preview::Fault::Code::Success)
                {
                    Listener.Stop();
                    co_return;
                }
                Preview::Network::Dialer::Dialer Dialer(Io.get_executor());
                std::error_code Error;
                auto Raw = co_await Dialer.Connect("127.0.0.1", Listener.LocalEndpoint().port(), Error);
                EXPECT_FALSE(Error);
                EXPECT_NE(Raw, nullptr);
                if (Error || !Raw)
                {
                    Listener.Stop();
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
                    Listener.Stop();
                    co_return;
                }
                const std::string Payload = "socks5-half-close";
                (void)co_await Connection->AsyncWrite(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
                    Error);
                Connection->Shutdown();
                std::array<std::byte, 64> Buffer{};
                const auto Read = co_await Connection->AsyncRead(
                    std::span<std::byte>(Buffer).first(Payload.size()), Error);
                Echo.assign(reinterpret_cast<const char *>(Buffer.data()), Read);
                Connection->Close();
                Net::steady_timer Drain(Io.get_executor());
                Drain.expires_after(std::chrono::milliseconds(50));
                co_await Drain.async_wait(Net::use_awaitable);
                Listener.Stop();
            });
        EXPECT_EQ(Echo, "socks5-half-close");
        EXPECT_GT(Recorder.Calls, 0);
        EXPECT_GE(Recorder.Up, std::string_view{"socks5-half-close"}.size());
        EXPECT_GE(Recorder.Down, std::string_view{"socks5-half-close"}.size());
    }

    TEST(Socks5Longitudinal, IdleTimeoutClosesRelay)
    {
        Net::io_context Io;
        const auto EchoPort = Preview::Testing::StartTcpEchoUpstream(Io);
        ListenerFixture Fixture{Io.get_executor(), EchoPort, false, nullptr,
                                std::chrono::milliseconds(120)};
        auto Listener = MakeListener(Io, Fixture);
        bool Closed = false;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const auto StartError = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                EXPECT_EQ(StartError, Preview::Fault::Code::Success);
                if (StartError != Preview::Fault::Code::Success)
                {
                    Listener.Stop();
                    co_return;
                }
                Preview::Network::Dialer::Dialer Dialer(Io.get_executor());
                std::error_code Error;
                auto Raw = co_await Dialer.Connect("127.0.0.1", Listener.LocalEndpoint().port(), Error);
                EXPECT_FALSE(Error);
                EXPECT_NE(Raw, nullptr);
                if (Error || !Raw)
                {
                    Listener.Stop();
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
                    Listener.Stop();
                    co_return;
                }
                Net::steady_timer Idle(Io.get_executor());
                Idle.expires_after(std::chrono::milliseconds(350));
                co_await Idle.async_wait(Net::use_awaitable);
                Closed = co_await ReadClose(Connection, std::chrono::milliseconds(300));
                Connection->Close();
                Listener.Stop();
            });
        EXPECT_TRUE(Closed);
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
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const auto StartError = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                EXPECT_EQ(StartError, Preview::Fault::Code::Success);
                if (StartError != Preview::Fault::Code::Success)
                {
                    Listener.Stop();
                    co_return;
                }
                Preview::Network::Dialer::Dialer Dialer(Io.get_executor());
                std::error_code Error;
                auto Raw = co_await Dialer.Connect("127.0.0.1", Listener.LocalEndpoint().port(), Error);
                EXPECT_FALSE(Error);
                EXPECT_NE(Raw, nullptr);
                if (Error || !Raw)
                {
                    Listener.Stop();
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
                    Listener.Stop();
                    co_return;
                }
                Closed = co_await ReadClose(Connection, std::chrono::milliseconds(500));
                Connection->Close();
                Listener.Stop();
                boost::system::error_code CloseError;
                Upstream.close(CloseError);
            });
        EXPECT_EQ(UpstreamError, nullptr);
        EXPECT_TRUE(Closed);
    }

} // namespace
