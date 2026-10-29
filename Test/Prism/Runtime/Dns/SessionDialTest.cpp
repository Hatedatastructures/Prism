/**
 * @file SessionDialTest.cpp
 * @brief Runtime Session 通过 DNS 感知拨号完成真实回声链路。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/HostText.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace Network = Prism::Network;
    using Tcp = Net::ip::tcp;
    using Prism::SharedTransmission;

    using Completion = Net::experimental::channel<void(boost::system::error_code, Fault::Code)>;

    auto DialWithDns(Net::any_io_executor Executor, const Network::Target &Target)
        -> Net::awaitable<std::expected<SharedTransmission, Fault::Failure>>
    {
        Network::Dns::Resolver Resolver(Executor);
        const auto Text = Prism::Network::ToText(Target.Host);
        auto Addresses = co_await Resolver.AsyncResolve(std::string(Text.View()));
        if (!Addresses)
        {
            co_return std::unexpected(Addresses.error());
        }
        if (Addresses->Empty())
        {
            co_return std::unexpected(Fault::Failure{Fault::Code::DnsFailed});
        }
        const auto Port = Target.Port;
        for (const auto &Address : *Addresses)
        {
            std::error_code DialError;
            Network::Dialer::Dialer Dialer(Executor);
            auto Dialed = co_await Dialer.Connect({Prism::Network::FromIpAddress(Address).value_or(Prism::Network::Host{}), Port});
            SharedTransmission Connection;
            if (Dialed)
            {
                Connection = std::move(*Dialed);
                DialError.clear();
            }
            else
            {
                DialError = Fault::ToNative(Dialed.error());
            }
            if (!DialError && Connection)
            {
                co_return std::move(Connection);
            }
        }
        co_return std::unexpected(Fault::Failure{Fault::Code::Unreachable});
    }

    auto AdmitDnsStream(Prism::Contract::StreamAcceptInput Input, std::uint16_t Port)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
        Plane.Target.Route = Prism::Network::RouteKind::Forward;
        Plane.Target.Host = *Prism::Network::ParseHost("localhost");
        Plane.Target.Port = Port;
        co_return Plane;
    }

    auto RunEchoServer(const std::shared_ptr<Tcp::acceptor> &Acceptor)
        -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code Error;
            auto Socket = co_await Acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }
            std::array<std::byte, 4096> Buffer{};
            const auto Bytes = co_await Socket.async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            if (!Error && Bytes != 0U)
            {
                co_await Socket.async_write_some(
                    Net::buffer(Buffer, Bytes), Net::redirect_error(Net::use_awaitable, Error));
            }
        }
    }

    struct DnsSessionScenario final
    {
        Net::io_context &Io;
        std::shared_ptr<Tcp::acceptor> EchoAcceptor;
        std::uint16_t EchoPort{0};
        std::string Payload;
        bool Echoed{false};
    };

    auto RunDnsSessionScenario(DnsSessionScenario &Scenario) -> Net::awaitable<void>
    {
        auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Scenario.Io.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            [Port = Scenario.EchoPort](Prism::Contract::StreamAcceptInput Input)
            {
                return AdmitDnsStream(std::move(Input), Port);
            });
        Options.Services->Dial = [&Scenario](const Network::Target &Target)
        {
            return DialWithDns(Scenario.Io.get_executor(), Target);
        };
        auto Session = std::make_shared<Prism::Runtime::Session>(std::move(Options));
        auto Done = std::make_shared<Completion>(Scenario.Io.get_executor(), 1);
        Net::co_spawn(Scenario.Io, Session->Run(Server),
            [Done](std::exception_ptr Error, Fault::Failure Result)
            {
                if (Error)
                {
                    (void)Done->try_send(boost::system::error_code{}, Fault::Code::IoError);
                    return;
                }
                (void)Done->try_send(boost::system::error_code{}, Result.Code);
            });

        std::error_code Error;
        const auto Write = co_await Client->WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Scenario.Payload.data()), Scenario.Payload.size()));
        Error = Fault::ToNative(Write.Failure);
        EXPECT_FALSE(Error);
        (void)co_await Client->WriteShutdown();
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Client->ReadSome(Buffer);
        Error = Fault::ToNative(Read.Failure);
        const auto Bytes = Read.Bytes;
        EXPECT_FALSE(Error);
        Scenario.Echoed = std::string(reinterpret_cast<const char *>(Buffer.data()), Bytes) == Scenario.Payload;
        Fault::Code SessionCode = Fault::Code::IoError;
        boost::system::error_code CompletionError;
        SessionCode = co_await Done->async_receive(Net::redirect_error(Net::use_awaitable, CompletionError));
        EXPECT_FALSE(CompletionError);
        EXPECT_EQ(SessionCode, Fault::Code::Success);
        (void)Client->Close();
        (void)Server->Close();
    }

    TEST(DnsDialSuite, SessionDialViaDns)
    {
        Net::io_context Io;
        auto EchoAcceptor = std::make_shared<Tcp::acceptor>(
            Io, Tcp::endpoint(Tcp::v4(), 0));
        DnsSessionScenario Scenario{
            Io, EchoAcceptor, EchoAcceptor->local_endpoint().port(), "dns Dial"};
        Net::co_spawn(Io, RunEchoServer(EchoAcceptor), Net::detached);
        Prism::Testing::RunCoro(Io, RunDnsSessionScenario(Scenario));
        boost::system::error_code Error;
        EchoAcceptor->close(Error);
        EXPECT_TRUE(Scenario.Echoed);
    }

} // namespace
