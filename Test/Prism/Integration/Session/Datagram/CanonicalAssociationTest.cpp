/** @file CanonicalAssociationTest.cpp @brief 正式 association 的真实 DNS 期限与取消退栈。 */
#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/HostText.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    using Tcp = Net::ip::tcp;
    using Udp = Net::ip::udp;
    using DatagramRunResult = std::expected<void, Fault::Failure>;
    using DoneChannel = Net::experimental::channel<void(boost::system::error_code, Fault::Failure)>;
    using EchoDoneChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;
    enum class Protocol { Socks5, Vless };
    enum class Completion { Deadline, Cancel, ControlEof };

    struct AssociationState final
    {
        std::shared_ptr<Prism::Contract::DatagramSession> Owner;
        std::shared_ptr<DoneChannel> Done;
    };

    auto MakeReliablePair(Net::io_context& Io)
        -> Net::awaitable<std::pair<Prism::SharedTransmission, Prism::SharedTransmission>>
    {
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Tcp::socket ClientSocket(Io);
        co_await ClientSocket.async_connect(Acceptor.local_endpoint(), Net::use_awaitable);
        auto ServerSocket = co_await Acceptor.async_accept(Net::use_awaitable);
        co_return std::pair{
            Prism::Transport::MakeReliable(std::move(ClientSocket)),
            Prism::Transport::MakeReliable(std::move(ServerSocket))};
    }

    auto ReceiveDoneWithin(
        DoneChannel& Done,
        Net::io_context& Io,
        std::chrono::milliseconds Timeout)
        -> Net::awaitable<std::optional<Fault::Failure>>
    {
        Net::steady_timer Timer(Io);
        Timer.expires_after(Timeout);
        using Net::experimental::awaitable_operators::operator||;
        auto Completed = co_await (Done.async_receive(Net::use_awaitable)
            || Timer.async_wait(Net::use_awaitable));
        if (Completed.index() != 0U)
            co_return std::nullopt;
        co_return std::get<0>(std::move(Completed));
    }

    auto RunAssociation(std::shared_ptr<AssociationState> State,
        std::pair<std::shared_ptr<Prism::Contract::StreamFactory>, Prism::SharedTransmission> Input)
        -> Net::awaitable<DatagramRunResult>
    {
        auto Accepted = co_await Input.first->Accept(Prism::Contract::StreamAcceptInput{
            std::move(Input.second), {}, std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8})});
        if (!Accepted)
            co_return std::unexpected(Accepted.error());
        if (!Accepted->Datagram() || !Accepted->Datagram()->Session)
            co_return std::unexpected(Fault::Failure{Fault::Code::NotSupported});
        State->Owner = Accepted->Datagram()->Session;
        co_return co_await State->Owner->Run();
    }

    auto RunCompletion(std::exception_ptr Error, DatagramRunResult Result) -> Fault::Failure
    {
        if (Error)
        {
            try
            {
                std::rethrow_exception(Error);
            }
            catch (const std::exception& Failure)
            {
                ADD_FAILURE() << "Datagram Run threw: " << Failure.what();
            }
            catch (...)
            {
                ADD_FAILURE() << "Datagram Run threw a non-standard exception";
            }
            return Fault::Failure{Fault::Code::IoError};
        }
        return Result ? Fault::Failure{} : Result.error();
    }

    auto WriteHandshake(Protocol Kind, const Prism::SharedTransmission& Client)
        -> Net::awaitable<Udp::endpoint>
    {
        if (Kind == Protocol::Socks5)
        {
            const std::array<std::uint8_t, 3> Greeting{5, 1, 0};
            const auto GreetingWrite = co_await Client->WriteExact(
                std::as_bytes(std::span(Greeting)));
            EXPECT_EQ(GreetingWrite.Bytes, Greeting.size());
            EXPECT_FALSE(GreetingWrite.Failure.Failed())
                << "code=" << static_cast<std::int32_t>(GreetingWrite.Failure.Code)
                << " native=" << GreetingWrite.Failure.Native.value();
            std::array<std::byte, 2> MethodReply{};
            const auto MethodRead = co_await Client->ReadExact(MethodReply);
            EXPECT_EQ(MethodRead.Bytes, MethodReply.size());
            EXPECT_FALSE(MethodRead.Failure.Failed())
                << "code=" << static_cast<std::int32_t>(MethodRead.Failure.Code)
                << " native=" << MethodRead.Failure.Native.value();
            EXPECT_EQ(MethodReply[0], std::byte{5});
            EXPECT_EQ(MethodReply[1], std::byte{0});

            const std::array<std::uint8_t, 10> Request{
                5, 3, 0, 1, 127, 0, 0, 1, 0, 0};
            const auto RequestWrite = co_await Client->WriteExact(
                std::as_bytes(std::span(Request)));
            EXPECT_EQ(RequestWrite.Bytes, Request.size());
            EXPECT_FALSE(RequestWrite.Failure.Failed())
                << "code=" << static_cast<std::int32_t>(RequestWrite.Failure.Code)
                << " native=" << RequestWrite.Failure.Native.value();
            std::array<std::byte, 10> Response{};
            const auto ReplyRead = co_await Client->ReadExact(Response);
            EXPECT_EQ(ReplyRead.Bytes, Response.size());
            EXPECT_FALSE(ReplyRead.Failure.Failed())
                << "code=" << static_cast<std::int32_t>(ReplyRead.Failure.Code)
                << " native=" << ReplyRead.Failure.Native.value();
            const std::array<std::byte, 8> Prefix{
                std::byte{5}, std::byte{0}, std::byte{0}, std::byte{1},
                std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}};
            EXPECT_TRUE(std::equal(Prefix.begin(), Prefix.end(), Response.begin()));
            const auto Port = (std::to_integer<unsigned>(Response[8]) << 8U)
                | std::to_integer<unsigned>(Response[9]);
            co_return Udp::endpoint(
                Net::ip::address_v4::loopback(), static_cast<std::uint16_t>(Port));
        }

        const std::array<std::uint8_t, 24> Request{
            0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            0, 2, 0, 53, 2, 1, static_cast<std::uint8_t>('x')};
        const auto Written = co_await Client->WriteExact(std::as_bytes(std::span(Request)));
        EXPECT_EQ(Written.Bytes, Request.size());
        EXPECT_FALSE(Written.Failure.Failed())
            << "code=" << static_cast<std::int32_t>(Written.Failure.Code)
            << " native=" << Written.Failure.Native.value();
        std::array<std::byte, 2> Response{};
        const auto Read = co_await Client->ReadExact(Response);
        EXPECT_EQ(Read.Bytes, Response.size());
        EXPECT_FALSE(Read.Failure.Failed())
            << "code=" << static_cast<std::int32_t>(Read.Failure.Code)
            << " native=" << Read.Failure.Native.value();
        EXPECT_EQ(Response[0], std::byte{0});
        EXPECT_EQ(Response[1], std::byte{0});
        co_return Udp::endpoint{};
    }

    struct DnsOutcome final
    {
        Fault::Failure Status{Fault::Code::IoError};
        bool Watchdog{false}, ResolveExited{false}, CarrierClosed{false}, OwnerReleased{false};
        bool FactoryActiveDuringDns{false}, FactoryRetiredAfterDrain{false};
        Fault::Failure ResolveFailure{};
        Fault::Failure FactoryDrainFailure{};
        std::size_t ResolveCalls{0};
        std::size_t GenerationUsesDuringDns{0}, GenerationUsesAfterDrain{0};
        int Reports{0};
        std::chrono::steady_clock::duration Elapsed{};
    };

    class DnsScenario final
    {
    public:
        DnsScenario(Protocol Kind, Completion Finish)
            : DnsSocket(Io, Udp::endpoint(Net::ip::address_v4::loopback(), 0)), Kind_(Kind), Finish_(Finish)
        { Prepare(); }

        auto Run() -> Net::awaitable<void>
        {
            if (Kind_ == Protocol::Socks5)
            {
                auto Pair = co_await MakeReliablePair(Io);
                Client = std::move(Pair.first);
                Server = std::move(Pair.second);
            }
            else
            {
                auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
                Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
                Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
            }
            Client->SetTimeout(std::chrono::seconds(2));
            Net::co_spawn(Io, RunAssociation(State, {Factory, Server}),
                [Value = State](std::exception_ptr Error, DatagramRunResult Result)
                {
                    (void)Value->Done->try_send(boost::system::error_code{},
                        RunCompletion(Error, std::move(Result)));
                });
            const auto Endpoint = co_await WriteHandshake(Kind_, Client);
            co_await SendDatagram(Endpoint);
            const auto Started = std::chrono::steady_clock::now();
            const auto QueryReceived = co_await WaitForDnsQuery();
            co_await Finish(QueryReceived, Started);
        }

        Net::io_context Io;
        DnsOutcome Outcome;

    private:
        auto SendDatagram(Udp::endpoint Endpoint) -> Net::awaitable<void>
        {
            if (Kind_ == Protocol::Socks5)
            {
                Udp::socket Sender(Io, Udp::endpoint(Net::ip::address_v4::loopback(), 0));
                const std::array<std::uint8_t, 9> Packet{0, 0, 0, 3, 1, 'x', 0, 53, 42};
                boost::system::error_code SendError;
                co_await Sender.async_send_to(Net::buffer(Packet), Endpoint,
                    Net::redirect_error(Net::use_awaitable, SendError));
                EXPECT_FALSE(SendError) << SendError.message();
                co_return;
            }
            const std::array<std::uint8_t, 3> Packet{0, 1, 42};
            const auto Written = co_await Client->WriteExact(std::as_bytes(std::span(Packet)));
            EXPECT_EQ(Written.Bytes, Packet.size());
            EXPECT_FALSE(Written.Failure.Failed())
                << "code=" << static_cast<std::int32_t>(Written.Failure.Code)
                << " native=" << Written.Failure.Native.value();
        }

        auto WaitForDnsQuery() -> Net::awaitable<bool>
        {
            std::array<std::byte, 512> Query{};
            Udp::endpoint Peer;
            Net::steady_timer Watchdog(Io);
            Watchdog.expires_after(std::chrono::seconds(2));
            boost::system::error_code QueryError;
            auto QueryRead = DnsSocket.async_receive_from(Net::buffer(Query), Peer,
                Net::redirect_error(Net::use_awaitable, QueryError));
            auto QueryWait = Watchdog.async_wait(Net::use_awaitable);
            using Net::experimental::awaitable_operators::operator||;
            const auto Completed = co_await (std::move(QueryRead) || std::move(QueryWait));
            const bool Received = Completed.index() == 0U && !QueryError;
            Outcome.Watchdog = !Received;
            if (Received)
            {
                EXPECT_GT(std::get<0>(Completed), 12U);
                if (VlessFactory)
                {
                    Outcome.FactoryActiveDuringDns = !VlessFactory->IsRetired();
                    Outcome.GenerationUsesDuringDns = UseState->Outstanding();
                }
            }
            else if (Completed.index() == 0U && QueryError)
            {
                ADD_FAILURE() << "DNS query receive failed: " << QueryError.message();
            }
            co_return Received;
        }

        auto Finish(bool QueryReceived, std::chrono::steady_clock::time_point Started)
            -> Net::awaitable<void>
        {
            if (State->Owner && QueryReceived)
            {
                if (Finish_ == Completion::Cancel) State->Owner->Cancel();
                else if (Finish_ == Completion::ControlEof)
                {
                    const auto Shutdown = co_await Client->WriteShutdown();
                    EXPECT_TRUE(Shutdown.has_value());
                    if (!Shutdown) State->Owner->Cancel();
                }
            }
            else if (State->Owner)
            {
                State->Owner->Cancel();
            }
            auto Status = co_await ReceiveDoneWithin(*State->Done, Io, std::chrono::seconds(2));
            if (!Status)
            {
                Outcome.Watchdog = true;
                if (State->Owner)
                {
                    State->Owner->Cancel();
                    State->Owner->Close();
                }
                (void)Client->Close();
                Status = co_await ReceiveDoneWithin(
                    *State->Done, Io, std::chrono::seconds(2));
                if (!Status)
                {
                    ADD_FAILURE() << "association did not finish after cancel and close";
                    DnsSocket.close();
                    Io.stop();
                    co_return;
                }
            }
            Outcome.Elapsed = std::chrono::steady_clock::now() - Started;
            Outcome.Status = *Status;
            const std::weak_ptr<Prism::Contract::DatagramSession> Weak = State->Owner;
            if (State->Owner)
            {
                State->Owner->Close();
                State->Owner->Close();
                State->Owner.reset();
            }
            if (VlessFactory)
            {
                VlessFactory->Close();
                const auto Retired = co_await VlessFactory->Drain();
                if (!Retired) Outcome.FactoryDrainFailure = Retired.error();
                EXPECT_TRUE(VlessFactory->IsRetired());
                Outcome.FactoryRetiredAfterDrain = VlessFactory->IsRetired();
                Outcome.GenerationUsesAfterDrain = UseState->Outstanding();
            }
            else if (SocksFactory)
            {
                SocksFactory->Close();
                const auto Retired = co_await SocksFactory->Drain();
                if (!Retired) Outcome.FactoryDrainFailure = Retired.error();
                Outcome.FactoryRetiredAfterDrain = static_cast<bool>(Retired);
            }
            Outcome.CarrierClosed = !Server->IsOpen();
            Outcome.Reports = Traffic->Calls;
            Outcome.OwnerReleased = Weak.expired();
            EXPECT_EQ(Traffic->Calls, 1);
            (void)Client->Close();
            DnsSocket.close();
        }

        auto Prepare() -> void
        {
            Prism::Network::Dns::Config Config;
            Config.DisableIpv6 = true;
            Config.TimeoutMs = 30000;
            Config.CacheEnabled = false;
            Prism::Network::Dns::Server Upstream;
            Upstream.Address = "127.0.0.1";
            Upstream.Port = DnsSocket.local_endpoint().port();
            Config.Servers.push_back(Upstream);
            Resolver = std::make_shared<Prism::Network::Dns::Resolver>(Io.get_executor(), Config);
            Traffic = std::make_shared<Prism::Testing::TrafficRecorder>();
            Prism::Contract::DatagramServices Services;
            Services.IdleTimeout = Finish_ == Completion::Deadline ? std::chrono::milliseconds(250)
                : std::chrono::seconds(30);
            Services.Traffic = Traffic;
            Services.Resolve = [this](Prism::Network::Target Target)
                -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
            { return Resolve(std::move(Target)); };
            if (Kind_ == Protocol::Socks5)
            {
                Prism::Socks5::ServerConfig ProtocolConfig;
                ProtocolConfig.EnableUdp = true;
                SocksFactory = Prism::Testing::MakeSocks5Binding(ProtocolConfig, Services);
                Factory = SocksFactory;
            }
            else
            {
                Prism::Vless::ServerConfig ProtocolConfig;
                ProtocolConfig.uuid = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
                ProtocolConfig.EnableUdp = true;
                UseState = Prism::Testing::MakeProtocolIngressUseState();
                VlessFactory = Prism::Testing::MakeVlessIngress(ProtocolConfig,
                    Prism::Testing::ProtocolIngressResources{
                        Services, UseState, Io.get_executor()},
                    Prism::Vless::IngressRoute{});
                Factory = VlessFactory;
            }
            State = std::make_shared<AssociationState>();
            State->Done = std::make_shared<DoneChannel>(Io, 1);
        }

        auto Resolve(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
        {
            ++Outcome.ResolveCalls;
            EXPECT_EQ(Target.Host, *Prism::Network::ParseHost("x"));
            EXPECT_EQ(Target.Port, 53U);
            struct ExitFlag { bool& Value; ~ExitFlag() { Value = true; } } Exit{Outcome.ResolveExited};
            const auto Text = Prism::Network::ToText(Target.Host);
            auto Addresses = co_await Resolver->AsyncResolve(std::string(Text.View()));
            if (!Addresses)
            {
                Outcome.ResolveFailure = Addresses.error();
                co_return std::unexpected(Addresses.error());
            }
            if (Addresses->Empty())
                co_return std::unexpected(Fault::Failure{Fault::Code::DnsFailed});
            co_return Udp::endpoint((*Addresses)[0], Target.Port);
        }

        Udp::socket DnsSocket;
        Protocol Kind_;
        Completion Finish_;
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        Prism::SharedTransmission Client, Server;
        std::shared_ptr<Prism::Testing::TrafficRecorder> Traffic;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::shared_ptr<Prism::Socks5::Binding> SocksFactory;
        std::shared_ptr<Prism::Vless::IngressFactory> VlessFactory;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::shared_ptr<AssociationState> State;
    };

    auto RunDnsScenario(Protocol Kind, Completion Finish) -> DnsOutcome
    {
        DnsScenario Scenario(Kind, Finish);
        Prism::Testing::RunCoro(Scenario.Io, [&Scenario]() -> Net::awaitable<void>
        { co_await Scenario.Run(); });
        return Scenario.Outcome;
    }

    auto CheckDrained(const DnsOutcome& Outcome) -> void
    {
        EXPECT_FALSE(Outcome.Watchdog);
        EXPECT_TRUE(Outcome.ResolveExited);
        EXPECT_TRUE(Outcome.CarrierClosed);
        EXPECT_TRUE(Outcome.OwnerReleased);
        EXPECT_EQ(Outcome.ResolveCalls, 1U);
        EXPECT_EQ(Outcome.Reports, 1);
        EXPECT_LT(Outcome.Elapsed, std::chrono::seconds(1));
    }

    class AcceptedFrameScenario final
    {
    public:
        AcceptedFrameScenario()
        {
            Echo = std::make_shared<Udp::socket>(Io, Udp::endpoint(Net::ip::address_v4::loopback(), 0));
            auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
            Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
            Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
            Traffic = std::make_shared<Prism::Testing::TrafficRecorder>();
            Prism::Contract::DatagramServices Services;
            Services.IdleTimeout = std::chrono::seconds(1);
            Services.Traffic = Traffic;
            Services.Resolve = [Endpoint = Echo->local_endpoint()](Prism::Network::Target Target)
                -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
            {
                EXPECT_EQ(Target.Host, *Prism::Network::ParseHost("x"));
                EXPECT_EQ(Target.Port, 53U);
                co_return Endpoint;
            };
            Prism::Vless::ServerConfig Config;
            Config.uuid = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            Config.EnableUdp = true;
            Factory = Prism::Testing::MakeVlessIngress(Config,
                Prism::Testing::ProtocolIngressResources{
                    Services, Prism::Testing::MakeProtocolIngressUseState(), Io.get_executor()},
                Prism::Vless::IngressRoute{});
            Client->SetTimeout(std::chrono::seconds(2));
            State = std::make_shared<AssociationState>();
            State->Done = std::make_shared<DoneChannel>(Io, 1);
            EchoDone = std::make_shared<EchoDoneChannel>(Io, 1);
        }
        auto Run() -> Net::awaitable<void>
        {
            Net::co_spawn(Io, EchoOnce(), [Done = EchoDone](std::exception_ptr Error)
            {
                (void)Done->try_send(boost::system::error_code{}, static_cast<bool>(Error));
            });
            Net::co_spawn(Io, RunAssociation(State, {Factory, Server}),
                [Value = State](std::exception_ptr Error, DatagramRunResult Result)
                {
                    (void)Value->Done->try_send(boost::system::error_code{},
                        RunCompletion(Error, std::move(Result)));
                });
            (void)co_await WriteHandshake(Protocol::Vless, Client);
            const std::array<std::uint8_t, 3> Packet{0, 1, 42};
            const auto Written = co_await Client->WriteExact(std::as_bytes(std::span(Packet)));
            EXPECT_EQ(Written.Bytes, Packet.size());
            EXPECT_FALSE(Written.Failure.Failed())
                << "code=" << static_cast<std::int32_t>(Written.Failure.Code)
                << " native=" << Written.Failure.Native.value();
            if (Written.Failure.Failed() || Written.Bytes != Packet.size())
            {
                if (State->Owner) State->Owner->Cancel();
                (void)Client->Close();
            }
            else
            {
                const auto Shutdown = co_await Client->WriteShutdown();
                EXPECT_TRUE(Shutdown.has_value());
                if (!Shutdown)
                {
                    if (State->Owner) State->Owner->Cancel();
                    (void)Client->Close();
                }
                else
                {
                    std::array<std::uint8_t, 3> Response{};
                    const auto Read = co_await Client->ReadExact(
                        std::as_writable_bytes(std::span(Response)));
                    EXPECT_EQ(Read.Bytes, Response.size());
                    EXPECT_FALSE(Read.Failure.Failed())
                        << "code=" << static_cast<std::int32_t>(Read.Failure.Code)
                        << " native=" << Read.Failure.Native.value();
                    EXPECT_EQ(Response[0], 0U);
                    EXPECT_EQ(Response[1], 1U);
                    EXPECT_EQ(Response[2], 42U);
                    if (Read.Failure.Failed() || Read.Bytes != Response.size())
                    {
                        if (State->Owner) State->Owner->Cancel();
                        (void)Client->Close();
                    }
                }
            }
            auto Status = co_await ReceiveDoneWithin(
                *State->Done, Io, std::chrono::seconds(2));
            EXPECT_TRUE(Status.has_value());
            if (!Status)
            {
                if (State->Owner)
                {
                    State->Owner->Cancel();
                    State->Owner->Close();
                }
                (void)Client->Close();
                Factory->Close();
                boost::system::error_code EchoError;
                Echo->close(EchoError);
                Status = co_await ReceiveDoneWithin(
                    *State->Done, Io, std::chrono::seconds(2));
                if (!Status)
                {
                    ADD_FAILURE() << "VLESS association did not finish after cancel and close";
                    Io.stop();
                    co_return;
                }
            }
            EXPECT_EQ(Status->Code, Fault::Code::Success);
            const std::weak_ptr<Prism::Contract::DatagramSession> Weak = State->Owner;
            if (State->Owner)
            {
                State->Owner->Close();
                State->Owner.reset();
            }
            Factory->Close();
            const auto Retired = co_await Factory->Drain();
            EXPECT_TRUE(Retired);
            EXPECT_TRUE(Factory->IsRetired());
            EXPECT_TRUE(Weak.expired());
            EXPECT_FALSE(Server->IsOpen());
            EXPECT_EQ(Traffic->Calls, 1);
            EXPECT_EQ(Traffic->Up, 1U);
            EXPECT_EQ(Traffic->Down, 1U);
            boost::system::error_code EchoError;
            Echo->close(EchoError);
            const auto EchoFailed = co_await EchoDone->async_receive(Net::use_awaitable);
            EXPECT_FALSE(EchoFailed);
            (void)Client->Close();
        }
        Net::io_context Io;
    private:
        auto EchoOnce() -> Net::awaitable<void>
        {
            std::array<std::byte, 16> Buffer{};
            Udp::endpoint Peer;
            const auto Size = co_await Echo->async_receive_from(Net::buffer(Buffer), Peer, Net::use_awaitable);
            co_await Echo->async_send_to(Net::buffer(Buffer.data(), Size), Peer, Net::use_awaitable);
        }
        std::shared_ptr<Udp::socket> Echo;
        std::shared_ptr<Prism::MemoryStream> Client, Server;
        std::shared_ptr<Prism::Testing::TrafficRecorder> Traffic;
        std::shared_ptr<Prism::Vless::IngressFactory> Factory;
        std::shared_ptr<AssociationState> State;
        std::shared_ptr<EchoDoneChannel> EchoDone;
    };

    TEST(CanonicalAssociation, VlessAcceptedFrameRepliesAfterPeerHalfClose)
    {
        AcceptedFrameScenario Scenario;
        Prism::Testing::RunCoro(Scenario.Io, [&Scenario]() -> Net::awaitable<void>
        { co_await Scenario.Run(); });
    }

    TEST(CanonicalAssociation, Socks5DnsUsesSessionDeadline)
    { const auto Result = RunDnsScenario(Protocol::Socks5, Completion::Deadline); CheckDrained(Result); EXPECT_EQ(Result.Status.Code, Fault::Code::Timeout); }
    TEST(CanonicalAssociation, VlessDnsUsesSessionDeadline)
    {
        const auto Result = RunDnsScenario(Protocol::Vless, Completion::Deadline);
        CheckDrained(Result);
        EXPECT_EQ(Result.Status.Code, Fault::Code::Timeout);
        EXPECT_TRUE(Result.FactoryActiveDuringDns);
        EXPECT_EQ(Result.GenerationUsesDuringDns, 1U);
        EXPECT_TRUE(Result.FactoryRetiredAfterDrain);
        EXPECT_EQ(Result.GenerationUsesAfterDrain, 0U);
        EXPECT_EQ(Result.FactoryDrainFailure.Code, Result.Status.Code);
        EXPECT_EQ(Result.FactoryDrainFailure.Native, Result.Status.Native);
    }
    TEST(CanonicalAssociation, Socks5CancelDrainsActualDns)
    {
        const auto Result = RunDnsScenario(Protocol::Socks5, Completion::Cancel);
        CheckDrained(Result);
        EXPECT_EQ(Result.Status.Code, Fault::Code::Canceled)
            << "native=" << Result.Status.Native.value()
            << " drain=" << static_cast<std::int32_t>(Result.FactoryDrainFailure.Code)
            << " drain_native=" << Result.FactoryDrainFailure.Native.value()
            << " resolve_calls=" << Result.ResolveCalls
            << " resolve_exited=" << Result.ResolveExited
            << " resolve_failure=" << static_cast<std::int32_t>(Result.ResolveFailure.Code)
            << " resolve_native=" << Result.ResolveFailure.Native.value()
            << " carrier_closed=" << Result.CarrierClosed
            << " reports=" << Result.Reports;
    }
    TEST(CanonicalAssociation, VlessCancelDrainsActualDns)
    {
        const auto Result = RunDnsScenario(Protocol::Vless, Completion::Cancel);
        CheckDrained(Result);
        EXPECT_EQ(Result.Status.Code, Fault::Code::Canceled);
        EXPECT_TRUE(Result.FactoryActiveDuringDns);
        EXPECT_EQ(Result.GenerationUsesDuringDns, 1U);
        EXPECT_TRUE(Result.FactoryRetiredAfterDrain);
        EXPECT_EQ(Result.GenerationUsesAfterDrain, 0U);
        EXPECT_FALSE(Result.FactoryDrainFailure.Failed());
    }
    TEST(CanonicalAssociation, Socks5ControlEofDrainsActualDns)
    {
        const auto Result = RunDnsScenario(Protocol::Socks5, Completion::ControlEof);
        CheckDrained(Result);
        EXPECT_EQ(Result.Status.Code, Fault::Code::Success)
            << "native=" << Result.Status.Native.value()
            << " drain=" << static_cast<std::int32_t>(Result.FactoryDrainFailure.Code)
            << " drain_native=" << Result.FactoryDrainFailure.Native.value()
            << " resolve_calls=" << Result.ResolveCalls
            << " resolve_exited=" << Result.ResolveExited
            << " resolve_failure=" << static_cast<std::int32_t>(Result.ResolveFailure.Code)
            << " resolve_native=" << Result.ResolveFailure.Native.value()
            << " carrier_closed=" << Result.CarrierClosed
            << " reports=" << Result.Reports;
    }
}
