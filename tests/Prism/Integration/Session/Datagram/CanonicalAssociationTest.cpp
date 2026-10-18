/** @file CanonicalAssociationTest.cpp @brief 正式 association 的真实 DNS 期限与取消退栈。 */
#include <gtest/gtest.h>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <array>
#include <expected>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    using Udp = Net::ip::udp;
    using DatagramRunResult = std::expected<void, Fault::Failure>;
    using DoneChannel = Net::experimental::channel<void(boost::system::error_code, Fault::Failure)>;
    enum class Protocol { Socks5, Vless };
    enum class Completion { Deadline, Cancel, ControlEof };

    struct AssociationState final
    {
        std::shared_ptr<Prism::Contract::DatagramSession> Owner;
        std::shared_ptr<DoneChannel> Done;
    };

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

    auto WriteHandshake(Protocol Kind, const std::shared_ptr<Prism::MemoryStream>& Client)
        -> Net::awaitable<Udp::endpoint>
    {
        std::vector<std::uint8_t> Request;
        if (Kind == Protocol::Socks5)
            Request = {5, 1, 0, 5, 3, 0, 1, 127, 0, 0, 1, 0, 0};
        else
            Request = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                       0, 2, 0, 0, 1, 127, 0, 0, 1};
        const auto Written = co_await Client->WriteExact(std::as_bytes(std::span(Request)));
        EXPECT_EQ(Written.Bytes, Request.size());
        EXPECT_FALSE(Written.Failure.Failed());
        std::array<std::byte, 12> Response{};
        const auto Size = Kind == Protocol::Socks5 ? 12U : 2U;
        const auto Read = co_await Client->ReadExact(std::span(Response).first(Size));
        EXPECT_EQ(Read.Bytes, Size);
        EXPECT_FALSE(Read.Failure.Failed());
        if (Kind == Protocol::Vless)
        {
            EXPECT_EQ(Response[0], std::byte{0});
            EXPECT_EQ(Response[1], std::byte{0});
            co_return Udp::endpoint{};
        }
        const std::array<std::byte, 10> Prefix{std::byte{5}, std::byte{0}, std::byte{5}, std::byte{0},
            std::byte{0}, std::byte{1}, std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1}};
        EXPECT_TRUE(std::equal(Prefix.begin(), Prefix.end(), Response.begin()));
        const auto Port = (std::to_integer<unsigned>(Response[10]) << 8U)
            | std::to_integer<unsigned>(Response[11]);
        co_return Udp::endpoint(Net::ip::address_v4::loopback(), static_cast<std::uint16_t>(Port));
    }

    struct DnsOutcome final
    {
        Fault::Failure Status{Fault::Code::IoError};
        bool Watchdog{false}, ResolveExited{false}, CarrierClosed{false}, OwnerReleased{false};
        bool FactoryActiveDuringDns{false}, FactoryRetiredAfterDrain{false};
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
            Net::co_spawn(Io, RunAssociation(State, {Factory, Server}),
                [Value = State](std::exception_ptr Error, DatagramRunResult Result)
                {
                    const auto Status = Error ? Fault::Failure{Fault::Code::IoError}
                        : Result ? Fault::Failure{} : Result.error();
                    (void)Value->Done->try_send(boost::system::error_code{}, Status);
                });
            const auto Endpoint = co_await WriteHandshake(Kind_, Client);
            Udp::socket Sender(Io, Udp::endpoint(Net::ip::address_v4::loopback(), 0));
            if (Kind_ == Protocol::Socks5)
            {
                const std::array<std::uint8_t, 9> Packet{0, 0, 0, 3, 1, 'x', 0, 53, 42};
                co_await Sender.async_send_to(Net::buffer(Packet), Endpoint, Net::use_awaitable);
        }
        else
        {
            const std::array<std::uint8_t, 8> Packet{0, 6, 2, 1, 'x', 0, 53, 42};
            const auto Written = co_await Client->WriteExact(std::as_bytes(std::span(Packet)));
            EXPECT_EQ(Written.Bytes, Packet.size());
            EXPECT_FALSE(Written.Failure.Failed());
        }
        std::array<std::byte, 512> Query{};
        Udp::endpoint Peer;
        EXPECT_GT(co_await DnsSocket.async_receive_from(Net::buffer(Query), Peer, Net::use_awaitable), 12U);
        if (VlessFactory)
        {
            Outcome.FactoryActiveDuringDns = !VlessFactory->IsRetired();
            Outcome.GenerationUsesDuringDns = UseState->Outstanding();
        }
        const auto Start = std::chrono::steady_clock::now();
        if (Finish_ == Completion::Cancel) State->Owner->Cancel();
        else if (Finish_ == Completion::ControlEof) Client->Close();
        Net::steady_timer Watchdog(Io);
        Watchdog.expires_after(std::chrono::milliseconds(200));
        using Net::experimental::awaitable_operators::operator||;
        auto Completed = co_await (State->Done->async_receive(Net::use_awaitable)
            || Watchdog.async_wait(Net::use_awaitable));
        Outcome.Watchdog = Completed.index() != 0;
        if (Outcome.Watchdog)
        {
            State->Owner->Cancel();
            Outcome.Status = co_await State->Done->async_receive(Net::use_awaitable);
        }
        else Outcome.Status = std::get<0>(Completed);
        Outcome.Elapsed = std::chrono::steady_clock::now() - Start;
        Outcome.CarrierClosed = !Server->IsOpen();
        Outcome.Reports = Traffic->Calls;
        const std::weak_ptr<Prism::Contract::DatagramSession> Weak = State->Owner;
        State->Owner->Close();
        State->Owner->Close();
        EXPECT_EQ(Traffic->Calls, Outcome.Reports);
        State->Owner.reset();
        if (VlessFactory)
        {
            VlessFactory->Close();
            const auto Retired = co_await VlessFactory->Drain();
            if (!Retired)
            {
                Outcome.FactoryDrainFailure = Retired.error();
            }
            EXPECT_TRUE(VlessFactory->IsRetired());
            Outcome.FactoryRetiredAfterDrain = VlessFactory->IsRetired();
            Outcome.GenerationUsesAfterDrain = UseState->Outstanding();
        }
        Outcome.OwnerReleased = Weak.expired();
        Client->Close();
        DnsSocket.close();
        }

        Net::io_context Io;
        DnsOutcome Outcome;

    private:
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
            auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
            Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
            Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
            Traffic = std::make_shared<Prism::Testing::TrafficRecorder>();
            Prism::Contract::DatagramServices Services;
            Services.IdleTimeout = Finish_ == Completion::Deadline ? std::chrono::milliseconds(20)
                : std::chrono::seconds(30);
            Services.Traffic = Traffic;
            Services.Resolve = [this](Prism::Network::Target Target)
                -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
            { return Resolve(std::move(Target)); };
            if (Kind_ == Protocol::Socks5)
            {
                Prism::Socks5::ServerConfig ProtocolConfig;
                ProtocolConfig.EnableUdp = true;
                Factory = Prism::Testing::MakeSocks5Binding(ProtocolConfig, Services);
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
            if (!Addresses) co_return std::unexpected(Addresses.error());
            if (Addresses->Empty())
                co_return std::unexpected(Fault::Failure{Fault::Code::DnsFailed});
            co_return Udp::endpoint((*Addresses)[0], Target.Port);
        }

        Udp::socket DnsSocket;
        Protocol Kind_;
        Completion Finish_;
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        std::shared_ptr<Prism::MemoryStream> Client, Server;
        std::shared_ptr<Prism::Testing::TrafficRecorder> Traffic;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
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
            Services.Resolve = [Endpoint = Echo->local_endpoint()](Prism::Network::Target)
                -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
            { co_return Endpoint; };
            Prism::Vless::ServerConfig Config;
            Config.uuid = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            Config.EnableUdp = true;
            Factory = Prism::Testing::MakeVlessIngress(Config,
                Prism::Testing::ProtocolIngressResources{
                    Services, Prism::Testing::MakeProtocolIngressUseState(), Io.get_executor()},
                Prism::Vless::IngressRoute{});
            State = std::make_shared<AssociationState>();
            State->Done = std::make_shared<DoneChannel>(Io, 1);
        }
        auto Run() -> Net::awaitable<void>
        {
            Net::co_spawn(Io, EchoOnce(), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
            Net::co_spawn(Io, RunAssociation(State, {Factory, Server}),
                [Value = State](std::exception_ptr Error, DatagramRunResult Result)
                {
                    const auto Status = Error ? Fault::Failure{Fault::Code::IoError}
                        : Result ? Fault::Failure{} : Result.error();
                    (void)Value->Done->try_send(boost::system::error_code{}, Status);
                });
            (void)co_await WriteHandshake(Protocol::Vless, Client);
            const std::array<std::uint8_t, 8> Packet{0, 6, 2, 1, 'x', 0, 53, 42};
            const auto Written = co_await Client->WriteExact(std::as_bytes(std::span(Packet)));
            EXPECT_EQ(Written.Bytes, Packet.size());
            EXPECT_FALSE(Written.Failure.Failed());
            Client->Shutdown();
            std::array<std::uint8_t, 10> Response{};
            const auto Read = co_await Client->ReadExact(std::as_writable_bytes(std::span(Response)));
            EXPECT_EQ(Read.Bytes, 10U);
            EXPECT_FALSE(Read.Failure.Failed());
            EXPECT_EQ(Response[0], 0U);
            EXPECT_EQ(Response[1], 8U);
            EXPECT_EQ(Response[2], 1U);
            EXPECT_EQ(Response[9], 42U);
            const auto Status = co_await State->Done->async_receive(Net::use_awaitable);
            EXPECT_EQ(Status.Code, Fault::Code::Success);
            EXPECT_FALSE(Server->IsOpen());
            EXPECT_EQ(Traffic->Calls, 1);
            EXPECT_EQ(Traffic->Up, 1U);
            EXPECT_EQ(Traffic->Down, 1U);
            State->Owner.reset();
            Factory->Close();
            const auto Retired = co_await Factory->Drain();
            EXPECT_TRUE(Retired);
            EXPECT_TRUE(Factory->IsRetired());
            Echo->close();
            Client->Close();
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
    { const auto Result = RunDnsScenario(Protocol::Socks5, Completion::Cancel); CheckDrained(Result); EXPECT_EQ(Result.Status.Code, Fault::Code::Canceled); }
    TEST(CanonicalAssociation, VlessCancelDrainsActualDns)
    {
        const auto Result = RunDnsScenario(Protocol::Vless, Completion::Cancel);
        CheckDrained(Result);
        EXPECT_EQ(Result.Status.Code, Fault::Code::Canceled);
        EXPECT_TRUE(Result.FactoryActiveDuringDns);
        EXPECT_EQ(Result.GenerationUsesDuringDns, 1U);
        EXPECT_TRUE(Result.FactoryRetiredAfterDrain);
        EXPECT_EQ(Result.GenerationUsesAfterDrain, 0U);
        EXPECT_EQ(Result.FactoryDrainFailure.Code, Result.Status.Code);
        EXPECT_EQ(Result.FactoryDrainFailure.Native, Result.Status.Native);
    }
    TEST(CanonicalAssociation, Socks5ControlEofDrainsActualDns)
    { const auto Result = RunDnsScenario(Protocol::Socks5, Completion::ControlEof); CheckDrained(Result); EXPECT_EQ(Result.Status.Code, Fault::Code::Success); }
}
