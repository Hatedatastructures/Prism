/** @file MuxRootOwnerTest.cpp @brief 实际 Trojan 认证、sing-mux child 和账户配额闭包。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Protocols/Trojan/Binding.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include "MuxStreamAcceptInputTestSupport.hpp"
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <array>
#include <atomic>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    namespace ParentTask = Prism::Testing::MuxStreamAcceptInputTestSupport;
    using Tcp = Net::ip::tcp;
    constexpr std::string_view Payload{"A4-MUX-CHILD-ECHO"};
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;
    struct Result
    {
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::size_t Dials{0}, FirstStreams{0}, FirstConnections{0}, DialsAfterSecond{0};
        bool FirstEcho{false}, SecondRejected{false}, ReplacementEcho{false};
        bool RootDone{false}, RootRetired{false}, ProtocolRetired{false};
        Prism::Fault::Failure RootRunFailure{}, RootDrainFailure{}, ProtocolDrainFailure{};
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState{
            std::make_shared<Prism::Foundation::GenerationUseState>()};
        std::size_t UsesWithLiveChild{0};
        std::exception_ptr Failure;
        std::vector<Prism::Lifecycle::TaskIdentity> Identities;
    };
    struct Fixture final : Result, std::enable_shared_from_this<Fixture>
    {
        explicit Fixture(Net::any_io_executor Ex) : Acceptor(Ex, Tcp::endpoint(Tcp::v4(), 0)),
            Ready(Ex, 1), Done(Ex, 1), ChildDone(Ex, 8),
            Bytes(std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8}))
        {
            Directory = Prism::Testing::ProviderAccount(
                Prism::Account::Credential::Token(Prism::Trojan::Credential("task4-mux")),
                Prism::AccountId{4001}, {.MaxConnections = 1, .MaxStreams = 1});
            Record = Directory->Store->FindById(Prism::AccountId{4001});
            EXPECT_TRUE(Record);
            auto [ClientRaw, ServerRaw] = Prism::MakeMemoryPair(Ex);
            ClientRawStream = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
            ServerRawStream = std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));

        }
        auto Close() -> void
        {
            boost::system::error_code Ignored;
            Acceptor.close(Ignored);
            if (Owner) { Owner->Cancel(); Owner->Close(); }
            if (Client) Client->Close();
            (void)ClientRawStream->Close();
            if (ServerRawStream) (void)ServerRawStream->Close();
            for (const auto& Socket : Sockets) Socket->close(Ignored);
        }
        Tcp::acceptor Acceptor;
        Signal Ready, Done, ChildDone;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        Prism::SharedTransmission ClientRawStream, ServerRawStream;
        std::shared_ptr<Prism::Contract::MuxSession> Owner;
        std::shared_ptr<Prism::Mux::Smux::Client<>> Client;
        std::vector<std::shared_ptr<Tcp::socket>> Sockets;
    };
    auto Write(Prism::SharedTransmission Stream, std::span<const std::byte> Bytes) -> Net::awaitable<bool>
    {
        std::error_code Error;
        const auto Written = co_await Stream->WriteExact(Bytes);
        Error = Prism::Fault::ToNative(Written.Failure);
        co_return !Error;
    }
    auto EchoSocket(std::shared_ptr<Tcp::socket> Socket) -> Net::awaitable<void>
    {
        std::array<std::byte, 512> Buffer{};
        boost::system::error_code Error;
        while (Socket->is_open())
        {
            const auto Count = co_await Socket->async_read_some(Net::buffer(Buffer),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0) break;
            (void)co_await Net::async_write(*Socket, Net::buffer(Buffer.data(), Count),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
        }
        Socket->close(Error);
    }
    auto AcceptEcho(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        const auto Ex = co_await Net::this_coro::executor;
        while (State->Acceptor.is_open())
        {
            auto Socket = std::make_shared<Tcp::socket>(Ex);
            boost::system::error_code Error;
            co_await State->Acceptor.async_accept(*Socket, Net::redirect_error(Net::use_awaitable, Error));
            if (Error) break;
            State->Sockets.push_back(Socket);
            Net::co_spawn(Ex, EchoSocket(Socket), [](std::exception_ptr Failure) { EXPECT_FALSE(Failure); });
        }
    }
    auto Dial(std::shared_ptr<Fixture> State, const Prism::Network::Target& Target)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        ++State->Dials;
        Tcp::socket Socket(co_await Net::this_coro::executor);
        boost::system::error_code Error;
        co_await Socket.async_connect(Tcp::endpoint(*Prism::Network::IpAddress(Target.Host),
            Target.Port),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::Unreachable, static_cast<std::error_code>(Error)});
        }
        co_return Prism::SharedTransmission{
            std::make_shared<Prism::Transport::Reliable>(std::move(Socket))};
    }
    class Egress final : public Prism::Contract::StreamEgress
    {
    public:
        explicit Egress(std::weak_ptr<Fixture> State) : State_(std::move(State)) {}
        auto Connect(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>> override
        { co_return co_await Dial(State_.lock(), Target); }
    private:
        std::weak_ptr<Fixture> State_;
    };
    class UnusedEgress final : public Prism::Contract::StreamEgress
    {
    public:
        auto Connect(Prism::Network::Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission,
                Prism::Fault::Failure>> override
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
    };
    auto RunRoot(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        const auto Ex = co_await Net::this_coro::executor;
        auto Prepared = Prism::Trojan::PrepareProviderBinding(
            Prism::Trojan::ProviderRequest{
                .Instance = "mux-root-owner",
                .Authentication = {State->Directory->Generation,
                    State->Directory->Credentials, State->Directory->Authenticator},
                .GenerationUseState = State->UseState,
                .Executor = Ex,
                .EnableTcp = true,
                .EnableUdp = true,
                .EnableMux = true});
        EXPECT_TRUE(Prepared);
        if (!Prepared) co_return;
        auto ProtocolBinding = Prism::Trojan::BindProvider(std::move(*Prepared));
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Wire = Prism::Mux::Mode::Smux,
            .Services = {.Egress = std::make_shared<Egress>(State), .IdleTimeout = std::chrono::milliseconds(500),
                .Bytes = State->Bytes},
            .GenerationUseState = State->UseState,
            .Observe = [Weak = std::weak_ptr<Fixture>(State)](Prism::Mux::ChildReport Report)
            {
                if (const auto Value = Weak.lock(); Value && !Report.Target.Host.Empty())
                {
                    Value->Identities.push_back(Report.Identity);
                    (void)Value->ChildDone.try_send(boost::system::error_code{});
                }
            }});
        auto Factory = ProtocolBinding->WithIngress({.Mux = Binding});
        auto Plane = co_await Factory->Accept(
            Prism::Testing::MuxStreamAcceptInputTestSupport::MakeMuxRootAcceptInput(
                std::move(State->ServerRawStream), State->Bytes));
        EXPECT_TRUE(Plane);
        if (!Plane) co_return;
        State->ServerRawStream = Plane->Transport();
        State->Owner = Plane->Mux()->Session;
        Prism::Contract::MuxRootRequest Request;
        Request.Lease = std::move(Plane->AccountLease);
        Request.GenerationUseState = State->UseState;
        Request.Metadata.TaskIdentity.SessionId = Prism::SessionId{941};
        Request.Metadata.TaskIdentity.WorkerId = Prism::WorkerId{23};
        Request.Metadata.TaskIdentity.Generation = Prism::GenerationId{7};
        (void)State->Ready.try_send(boost::system::error_code{});
        const auto RunResult = co_await State->Owner->Run(std::move(Request));
        if (!RunResult) State->RootRunFailure = RunResult.error();
        const auto Activity = State->Owner->Activity();
        if (Activity)
        {
            const auto Drain = co_await Activity->Drain();
            if (!Drain) State->RootDrainFailure = Drain.error();
            State->RootRetired = Activity->IsRetired();
        }
        Factory->Close();
        const auto FactoryDrain = co_await Factory->Drain();
        if (!FactoryDrain) State->ProtocolDrainFailure = FactoryDrain.error();
        State->ProtocolRetired = Factory->IsRetired();
        State->Owner.reset();
        State->RootDone = true;
        (void)State->Done.try_send(boost::system::error_code{});
    }
    auto ReadResponse(Prism::SharedTransmission Stream) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        std::array<std::byte, Payload.size() + 1> Response{};
        std::error_code Error;
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(std::chrono::milliseconds(200));
        const auto Outcome = co_await (Stream->ReadExact(Response) || Timer.async_wait(Net::use_awaitable));
        if (Outcome.index() == 0) Error = Prism::Fault::ToNative(std::get<0>(Outcome).Failure);
        co_return Outcome.index() == 0 && !Error && Response[0] == std::byte{0} &&
            std::equal(Response.begin() + 1, Response.end(), std::as_bytes(std::span(Payload)).begin());
    }
    auto Open(std::shared_ptr<Fixture> State) -> Net::awaitable<Prism::SharedTransmission>
    {
        auto Stream = co_await State->Client->OpenStream();
        if (!Stream) co_return Stream;
        const auto Port = State->Acceptor.local_endpoint().port();
        std::vector<std::byte> Request{std::byte{0}, std::byte{0}, std::byte{1}, std::byte{127},
            std::byte{0}, std::byte{0}, std::byte{1}, std::byte{static_cast<std::uint8_t>(Port >> 8)},
            std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Bytes = std::as_bytes(std::span(Payload));
        Request.insert(Request.end(), Bytes.begin(), Bytes.end());
        EXPECT_TRUE(co_await Write(Stream, Request));
        co_return Stream;
    }
    auto RunClient(std::shared_ptr<Fixture> State) -> Net::awaitable<void>
    {
        const auto Request = Prism::Trojan::BuildRequest(Prism::Trojan::Credential("task4-mux"),
            Prism::Trojan::Command::Mux, {Prism::Trojan::AddressType::Domain, "root.test", 443});
        EXPECT_TRUE(co_await Write(State->ClientRawStream, std::as_bytes(std::span(Request))));
        co_await State->Ready.async_receive(Net::use_awaitable);
        const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{0}};
        EXPECT_TRUE(co_await Write(State->ClientRawStream, Envelope));
        State->Client = std::make_shared<Prism::Mux::Smux::Client<>>();
        EXPECT_TRUE(State->Client->Connect(State->ClientRawStream));
        auto First = co_await Open(State);
        State->FirstEcho = First && co_await ReadResponse(First);
        State->UsesWithLiveChild = State->UseState->Outstanding();
        State->FirstStreams = State->Record->Runtime()->ActiveStreams();
        State->FirstConnections = State->Record->Runtime()->ActiveConnections();
        auto Second = co_await Open(State);
        State->SecondRejected = !Second || !co_await ReadResponse(Second);
        State->DialsAfterSecond = State->Dials;
        if (Second) { (void)Second->Close(); }
        if (First) { (void)First->Close(); }
        co_await State->ChildDone.async_receive(Net::use_awaitable);
        auto Replacement = co_await Open(State);
        State->ReplacementEcho = Replacement && co_await ReadResponse(Replacement);
        if (Replacement) { (void)Replacement->Close(); }
        co_await State->Client->Session()->Close();
        co_await State->Done.async_receive(Net::use_awaitable);
        State->Close();
    }
    auto Scenario() -> Result
    {
        Net::io_context Io;
        auto State = std::make_shared<Fixture>(Io.get_executor());
        const auto Complete = [State](std::exception_ptr Failure)
        { if (Failure) { State->Failure = Failure; State->Close(); } };
        Net::co_spawn(Io, RunRoot(State), Complete);
        Net::co_spawn(Io, AcceptEcho(State), Complete);
        Net::co_spawn(Io, RunClient(State), Complete);
        Io.run();
        State->Close();
        return static_cast<const Result&>(*State);
    }

}
TEST(MuxRootOwner, ActualAuthenticatedChildQuotaRejectsSecondAndReopensAfterDrain)
{
    const auto State = Scenario();
    ASSERT_FALSE(State.Failure);
    EXPECT_TRUE(State.FirstEcho);
    EXPECT_EQ(State.FirstStreams, 1);
    EXPECT_EQ(State.FirstConnections, 1);
    EXPECT_TRUE(State.SecondRejected);
    EXPECT_EQ(State.DialsAfterSecond, 1);
    EXPECT_TRUE(State.ReplacementEcho);
    EXPECT_TRUE(State.RootDone);
    EXPECT_TRUE(State.RootRetired);
    EXPECT_TRUE(State.ProtocolRetired);
    EXPECT_FALSE(State.RootRunFailure.Failed());
    EXPECT_FALSE(State.RootDrainFailure.Failed());
    EXPECT_FALSE(State.ProtocolDrainFailure.Failed());
    EXPECT_EQ(State.UsesWithLiveChild, 2U);
    EXPECT_EQ(State.UseState->Outstanding(), 0U);
    EXPECT_EQ(State.Record->Runtime()->ActiveStreams(), 0);
    EXPECT_EQ(State.Record->Runtime()->ActiveConnections(), 0);
}

TEST(MuxService, ActualChildInheritsParentAndReceivesUniqueTaskIdentity)
{
    const auto Actual = Scenario();
    ASSERT_FALSE(Actual.Failure);
    ASSERT_TRUE(Actual.FirstEcho);
    ASSERT_TRUE(Actual.ReplacementEcho);
    ASSERT_EQ(Actual.Identities.size(), 2);
    for (const auto& Identity : Actual.Identities)
    {
        EXPECT_EQ(Identity.WorkerId, Prism::WorkerId{23});
        EXPECT_EQ(Identity.SessionId, Prism::SessionId{941});
        EXPECT_EQ(Identity.Generation, Prism::GenerationId{7});
        EXPECT_TRUE(Identity.TaskId);
        EXPECT_TRUE(Identity.StreamId);
    }
    EXPECT_NE(Actual.Identities[0].TaskId, Actual.Identities[1].TaskId);
    EXPECT_NE(Actual.Identities[0].StreamId, Actual.Identities[1].StreamId);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveConnections(), 0);
    EXPECT_EQ(Actual.Record->Runtime()->ActiveStreams(), 0);
    EXPECT_EQ(Actual.UseState->Outstanding(), 0U);
}
