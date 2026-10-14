/** @file MuxRoot.hpp @brief 正式 Trojan factory、generic mux 和本地 TCP echo 的行为设施。 */
#pragma once
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Protocols/Trojan/Binding.hpp>
#include <Preview/Protocols/Trojan/IngressFactory.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <barrier>
#include <exception>
#include <expected>
#include <optional>
#include <thread>

namespace Preview::Testing::MuxRoot
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Code = Preview::Fault::Code;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;
    constexpr std::string_view Literal{"A4-FORMAL-ROOT-ECHO"};
    constexpr std::string_view Password{"task4-consumer-password"};
    struct PreparedCreate final
    {
        std::optional<Preview::Contract::InboundAdmission> Admission;
        std::optional<Preview::Contract::MuxRootCreateRequest> Request;
    };

    inline auto PrepareCreate(Preview::SharedTransmission Inbound,
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
        -> Net::awaitable<std::expected<PreparedCreate, Preview::Fault::Failure>>
    {
        auto Reserved = co_await Preview::Contract::InboundAdmission::Prepare(Inbound);
        if (!Reserved) co_return std::unexpected(Reserved.error());
        auto Admission = std::move(*Reserved);
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Preview::Contract::ProtocolType::AnyTls;
        Plane.Root = Preview::Contract::MuxRootDataPlane{std::move(Inbound), {}};
        auto Request = Preview::Contract::MuxRootCreateRequest::Prepare(
            Admission.RootCreateOwner(), std::move(UseState), std::move(Plane));
        if (!Request)
        {
            if (Plane.HasTransport())
                (void)co_await Admission.Reject(std::move(Plane), Request.error());
            co_return std::unexpected(Request.error());
        }
        co_return PreparedCreate{std::move(Admission), std::move(*Request)};
    }

    inline auto CreateRoot(std::shared_ptr<Preview::Mux::RootBinding> Binding,
        Preview::SharedTransmission Inbound)
        -> Net::awaitable<std::expected<Preview::Mux::RootCreateResult,
            Preview::Fault::Failure>>
    {
        auto Prepared = co_await PrepareCreate(std::move(Inbound), Binding->GenerationUseState());
        if (!Prepared) co_return std::unexpected(Prepared.error());
        co_return Binding->Create(std::move(*Prepared->Request));
    }

    struct Peer final
    {
        explicit Peer(Net::any_io_executor Ex) : Ready(Ex, 1), Done(Ex, 1)
        {
            auto [C,S] = Preview::MakeMemoryPair(Ex);
            Client = std::make_shared<Preview::MemoryStream>(std::move(C));
            Server = std::make_shared<Preview::MemoryStream>(std::move(S));
        }
        Preview::SharedTransmission Client, Server;
        std::shared_ptr<Preview::Contract::MuxSession> Root;
        std::weak_ptr<Preview::Contract::MuxSession> WeakRoot;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState{
            std::make_shared<Preview::Foundation::GenerationUseState>()};
        Preview::Contract::RequestMetadata Metadata;
        Signal Ready, Done;
        std::expected<void, Preview::Fault::Failure> Status{std::unexpected(Preview::Fault::Failure{Code::IoError})};
        std::optional<Preview::Fault::Failure> AcceptFailure;
        bool Authenticated{false}, Returned{false};
    };
    struct State final : std::enable_shared_from_this<State>
    {
        explicit State(Net::any_io_executor Ex) : Executor(Ex), Acceptor(Ex, Tcp::endpoint(Tcp::v4(),0)),
            Deadline(Ex), Tasks(std::make_shared<Preview::Lifecycle::TaskRegistry>(Ex)), Reported(Ex,32),
            Bytes(std::make_shared<Preview::Memory::BytePool>(Preview::Memory::BytePoolOptions{.BlockCount=64}))
        {
            Accounts=Preview::Testing::ProviderAccount(
                Preview::Account::Credential::Token(Preview::Trojan::Credential(Password)),
                Preview::AccountId{4700},{.MaxConnections=8,.MaxStreams=8});
            Record=Accounts->Store->FindById(Preview::AccountId{4700});
            EXPECT_TRUE(Record);
        }
        auto Stop() -> void
        {
            if(Binding) Binding->Close();
            for(const auto& P:Peers) { if(P->Root) P->Root->Close(); P->Client->Close(); P->Server->Close(); }
            boost::system::error_code Error; Acceptor.close(Error); Deadline.cancel();
            for(const auto& S:Sockets) S->close(Error);
        }
        Net::any_io_executor Executor;
        Tcp::acceptor Acceptor;
        Net::steady_timer Deadline;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks;
        Signal Reported;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState{
            std::make_shared<Preview::Foundation::GenerationUseState>()};
        std::shared_ptr<Preview::Testing::ProviderAccounts> Accounts;
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
        std::shared_ptr<Preview::Mux::RootBinding> Binding;
        std::vector<std::shared_ptr<Peer>> Peers;
        std::vector<std::shared_ptr<Tcp::socket>> Sockets;
        std::vector<Preview::Mux::ChildReport> Reports;
        std::size_t Dials{0};
        std::exception_ptr Failure;
        bool TimedOut{false};
    };
    class Egress final : public Preview::Contract::StreamEgress
    {
    public:
        explicit Egress(std::weak_ptr<State> Owner) : Owner_(std::move(Owner)) {}
        auto Connect(Preview::Network::Target Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission,Preview::Fault::Failure>> override
        {
            if(const auto S=Owner_.lock()) ++S->Dials;
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(Tcp::endpoint(*Preview::Network::IpAddress(Target.Host),
                Target.Port),Net::redirect_error(Net::use_awaitable,Error));
            if(Error) co_return std::unexpected(Preview::Fault::FromNative(static_cast<std::error_code>(Error)));
            co_return Preview::SharedTransmission{
                std::make_shared<Preview::Transport::Reliable>(std::move(Socket))};
        }
    private: std::weak_ptr<State> Owner_;
    };

    struct ConcurrentRegistryScenario final
    {
        using Prepare = std::expected<PreparedCreate, Preview::Fault::Failure>;
        using Create = std::expected<Preview::Mux::RootCreateResult,
            Preview::Fault::Failure>;
        Net::io_context IoA, IoB, DrainIo;
        Preview::SharedTransmission ClientA, ClientB, AnchorClient;
        std::shared_ptr<Preview::MemoryStream> InboundA, InboundB, AnchorInbound;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState{
            std::make_shared<Preview::Foundation::GenerationUseState>()};
        std::shared_ptr<State> Fixture;
        std::shared_ptr<Preview::Mux::RootBinding> Binding;
        std::optional<Prepare> PreparedA, PreparedB, PreparedAnchor;
        std::exception_ptr PrepareFailureA, PrepareFailureB, PrepareFailureAnchor;
        std::optional<Create> AnchorCreated;
        std::optional<Create> CreatedA, CreatedB;
        std::exception_ptr CreateFailureA, CreateFailureB;
        std::optional<std::expected<void, Preview::Fault::Failure>> Drained;
        std::exception_ptr DrainException;
        std::weak_ptr<Preview::Contract::MuxSession> WeakAnchor, WeakA, WeakB;
        bool NotRetiredAtSeal{false};
        bool RegisteredA{false}, RegisteredB{false};
        bool PreparedReady{false}, RegistrationReady{false};
    };

    inline auto PrepareConcurrentRegistryRoots(ConcurrentRegistryScenario &Scenario) -> void
    {
        auto [ClientA, ServerA] = Preview::MakeMemoryPair(Scenario.IoA.get_executor());
        auto [ClientB, ServerB] = Preview::MakeMemoryPair(Scenario.IoB.get_executor());
        Scenario.ClientA = std::make_shared<Preview::MemoryStream>(std::move(ClientA));
        Scenario.ClientB = std::make_shared<Preview::MemoryStream>(std::move(ClientB));
        Scenario.InboundA = std::make_shared<Preview::MemoryStream>(std::move(ServerA));
        Scenario.InboundB = std::make_shared<Preview::MemoryStream>(std::move(ServerB));
        Scenario.Fixture = std::make_shared<State>(Scenario.IoA.get_executor());
        Scenario.Binding = std::make_shared<Preview::Mux::RootBinding>(Preview::Mux::RootOptions{
            .Services = {.Egress = std::make_shared<Egress>(Scenario.Fixture)},
            .GenerationUseState = Scenario.UseState});
        Net::co_spawn(Scenario.IoA, PrepareCreate(Scenario.InboundA, Scenario.UseState),
            [&Scenario](std::exception_ptr Failure, ConcurrentRegistryScenario::Prepare Value)
            { Scenario.PrepareFailureA = std::move(Failure); Scenario.PreparedA = std::move(Value); });
        Net::co_spawn(Scenario.IoB, PrepareCreate(Scenario.InboundB, Scenario.UseState),
            [&Scenario](std::exception_ptr Failure, ConcurrentRegistryScenario::Prepare Value)
            { Scenario.PrepareFailureB = std::move(Failure); Scenario.PreparedB = std::move(Value); });
        Scenario.IoA.run();
        Scenario.IoB.run();
        Scenario.PreparedReady = !Scenario.PrepareFailureA && !Scenario.PrepareFailureB &&
            Scenario.PreparedA && *Scenario.PreparedA &&
            Scenario.PreparedB && *Scenario.PreparedB;
        if (!Scenario.PreparedReady) return;

        auto [AnchorClient, AnchorServer] = Preview::MakeMemoryPair(
            Scenario.IoA.get_executor());
        Scenario.AnchorClient = std::make_shared<Preview::MemoryStream>(std::move(AnchorClient));
        Scenario.AnchorInbound = std::make_shared<Preview::MemoryStream>(
            std::move(AnchorServer));
        Net::co_spawn(Scenario.IoA,
            PrepareCreate(Scenario.AnchorInbound, Scenario.UseState),
            [&Scenario](std::exception_ptr Failure, ConcurrentRegistryScenario::Prepare Value)
            { Scenario.PrepareFailureAnchor = std::move(Failure); Scenario.PreparedAnchor = std::move(Value); });
        Scenario.IoA.restart();
        Scenario.IoA.run();
        if (Scenario.PrepareFailureAnchor || !Scenario.PreparedAnchor ||
            !*Scenario.PreparedAnchor) return;
        Scenario.AnchorCreated.emplace(Scenario.Binding->Create(
            std::move(*Scenario.PreparedAnchor->value().Request)));
        if (!*Scenario.AnchorCreated) return;
        Scenario.WeakAnchor = Scenario.AnchorCreated->value().Session;
        if (auto *Mux = Scenario.AnchorCreated->value().Plane.Mux()) Mux->Session.reset();
        Scenario.AnchorCreated->value().Session.reset();
    }

    inline auto RegisterConcurrentRootsAndClose(ConcurrentRegistryScenario &Scenario) -> void
    {
        std::barrier Gate(4);
        std::thread RegisterA([&Scenario, &Gate]
        {
            Gate.arrive_and_wait();
            try
            {
                Scenario.CreatedA.emplace(Scenario.Binding->Create(
                    std::move(*Scenario.PreparedA->value().Request)));
            }
            catch (...) { Scenario.CreateFailureA = std::current_exception(); }
        });
        std::thread RegisterB([&Scenario, &Gate]
        {
            Gate.arrive_and_wait();
            try
            {
                Scenario.CreatedB.emplace(Scenario.Binding->Create(
                    std::move(*Scenario.PreparedB->value().Request)));
            }
            catch (...) { Scenario.CreateFailureB = std::current_exception(); }
        });
        std::thread Seal([&Scenario, &Gate]
        {
            Gate.arrive_and_wait();
            Scenario.Binding->Close();
            Scenario.NotRetiredAtSeal = !Scenario.Binding->IsRetired();
        });
        Gate.arrive_and_wait();
        RegisterA.join();
        RegisterB.join();
        Seal.join();
        Scenario.RegistrationReady = !Scenario.CreateFailureA &&
            !Scenario.CreateFailureB && Scenario.CreatedA && Scenario.CreatedB;
        if (!Scenario.RegistrationReady) return;
        Scenario.RegisteredA = static_cast<bool>(*Scenario.CreatedA);
        Scenario.RegisteredB = static_cast<bool>(*Scenario.CreatedB);
        if (*Scenario.CreatedA)
        {
            Scenario.WeakA = (*Scenario.CreatedA)->Session;
            if (auto *Mux = (*Scenario.CreatedA)->Plane.Mux()) Mux->Session.reset();
            (*Scenario.CreatedA)->Session.reset();
        }
        if (*Scenario.CreatedB)
        {
            Scenario.WeakB = (*Scenario.CreatedB)->Session;
            if (auto *Mux = (*Scenario.CreatedB)->Plane.Mux()) Mux->Session.reset();
            (*Scenario.CreatedB)->Session.reset();
        }
    }

    inline auto DrainConcurrentRoots(ConcurrentRegistryScenario &Scenario) -> void
    {
        Net::co_spawn(Scenario.DrainIo, Scenario.Binding->Drain(),
            [&Scenario](std::exception_ptr Failure,
                std::expected<void, Preview::Fault::Failure> Value)
            { Scenario.DrainException = std::move(Failure); Scenario.Drained = std::move(Value); });
        Scenario.IoA.restart();
        Scenario.IoB.restart();
        auto WorkA = Net::make_work_guard(Scenario.IoA);
        auto WorkB = Net::make_work_guard(Scenario.IoB);
        std::thread RunA([&Scenario] { Scenario.IoA.run(); });
        std::thread RunB([&Scenario] { Scenario.IoB.run(); });
        Scenario.DrainIo.run();
        WorkA.reset();
        WorkB.reset();
        RunA.join();
        RunB.join();
    }

    inline auto Echo(std::shared_ptr<Tcp::socket> Socket) -> Net::awaitable<void>
    {
        std::array<std::byte,256> Bytes{}; boost::system::error_code Error;
        for(;;)
        {
            const auto N=co_await Socket->async_read_some(Net::buffer(Bytes),Net::redirect_error(Net::use_awaitable,Error));
            if(Error||N==0) break;
            co_await Net::async_write(*Socket,Net::buffer(Bytes.data(),N),Net::redirect_error(Net::use_awaitable,Error));
            if(Error) break;
        }
        Socket->close(Error);
    }
    inline auto Accept(std::shared_ptr<State> S) -> Net::awaitable<void>
    {
        while(S->Acceptor.is_open())
        {
            auto Socket=std::make_shared<Tcp::socket>(S->Executor); boost::system::error_code Error;
            co_await S->Acceptor.async_accept(*Socket,Net::redirect_error(Net::use_awaitable,Error));
            if(Error) break;
            S->Sockets.push_back(Socket);
            EXPECT_TRUE(S->Tasks->SpawnTracked({.StartOnSubmit=true},Echo(Socket)));
        }
    }
    inline auto Make(Net::any_io_executor Ex, Preview::Mux::Mode Wire) -> std::shared_ptr<State>
    {
        auto S=std::make_shared<State>(Ex); const auto Weak=std::weak_ptr<State>(S);
        Preview::Mux::RootOptions Options{.Wire=Wire,
            .Services={.Egress=std::make_shared<Egress>(S),.Bytes=S->Bytes},
            .GenerationUseState=S->UseState};
        Options.Observe=[Weak](Preview::Mux::ChildReport Report)
        { if(const auto Owner=Weak.lock()){Owner->Reports.push_back(std::move(Report));(void)Owner->Reported.try_send(boost::system::error_code{});} };
        S->Binding=std::make_shared<Preview::Mux::RootBinding>(std::move(Options));
        EXPECT_TRUE(S->Tasks->SpawnTracked({.StartOnSubmit=true},Accept(S)));
        return S;
    }
    inline auto RunPeer(std::shared_ptr<State> S, std::shared_ptr<Peer> P) -> Net::awaitable<void>
    {
        auto Prepared = Preview::Trojan::PrepareProviderBinding(
            Preview::Trojan::ProviderRequest{
                .Instance = "mux-root-fixture",
                .Authentication = {S->Accounts->Generation,
                    S->Accounts->Credentials, S->Accounts->Authenticator},
                .GenerationUseState = S->UseState,
                .Executor = S->Executor,
                .EnableTcp = true,
                .EnableUdp = true,
                .EnableMux = true});
        EXPECT_TRUE(Prepared);
        if (!Prepared)
        {
            P->Returned = true;
            (void)P->Done.try_send(boost::system::error_code{});
            co_return;
        }
        auto ProtocolBinding = Preview::Trojan::BindProvider(std::move(*Prepared));
        auto Factory = ProtocolBinding->WithIngress({.Mux = S->Binding});
        auto Plane=co_await Factory->Accept({P->Server,P->Metadata,S->Bytes});
        if (!Plane)
        {
            P->AcceptFailure = Plane.error();
            P->Authenticated = false;
            (void)P->Ready.try_send(boost::system::error_code{});
            P->Returned = true;
            (void)P->Done.try_send(boost::system::error_code{});
            co_return;
        }
        P->AcceptFailure.reset();
        P->Authenticated = bool(Plane->AccountLease);
        if(Plane)
        {
            P->Root=Plane->Mux()->Session;P->WeakRoot=P->Root;
            (void)P->Ready.try_send(boost::system::error_code{});
            Preview::Contract::MuxRootRequest Request{.Lease=std::move(Plane->AccountLease),
                .Metadata=P->Metadata,.GenerationUseState=S->UseState};
            P->Status=co_await P->Root->Run(std::move(Request));
            P->Root.reset();
        }
        P->Returned=true;(void)P->Done.try_send(boost::system::error_code{});
    }
    inline auto Wait(Signal& Event) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Timer(co_await Net::this_coro::executor);Timer.expires_after(std::chrono::seconds(2));
        const auto Outcome=co_await(Event.async_receive(Net::use_awaitable)||Timer.async_wait(Net::use_awaitable));
        co_return Outcome.index()==0;
    }
    inline auto Start(std::shared_ptr<State> S, Preview::Contract::RequestMetadata Metadata={}) -> Net::awaitable<std::shared_ptr<Peer>>
    {
        auto P=std::make_shared<Peer>(S->Executor);P->Metadata=std::move(Metadata);S->Peers.push_back(P);
        EXPECT_TRUE(S->Tasks->SpawnTracked({.StartOnSubmit=true},RunPeer(S,P)));
        const auto Auth=Preview::Trojan::BuildRequest(Preview::Trojan::Credential(Password),Preview::Trojan::Command::Mux,
            Preview::Trojan::Address{Preview::Trojan::AddressType::Ipv4,"127.0.0.1",80});
        const auto Written=co_await P->Client->WriteExact(std::as_bytes(std::span(Auth)));
        EXPECT_TRUE(Written.Failure.Succeeded());EXPECT_EQ(Written.Bytes,Auth.size());
        EXPECT_TRUE(co_await Wait(P->Ready));
        if (P->AcceptFailure)
        {
            ADD_FAILURE() << "Mux Accept failed Code="
                << static_cast<std::int32_t>(P->AcceptFailure->Code) << " Native="
                << P->AcceptFailure->Native.category().name() << ":"
                << P->AcceptFailure->Native.value();
        }
        EXPECT_TRUE(P->Authenticated);
        co_return P;
    }
    template<class Client>
    auto Connect(std::shared_ptr<Peer> P, Preview::Mux::Mode Wire) -> Net::awaitable<std::shared_ptr<Client>>
    {
        std::uint8_t WireTag = 1;
        if (Wire == Preview::Mux::Mode::Smux) WireTag = 0;
        const std::array<std::byte,2> Envelope{std::byte{0},std::byte{WireTag}};
        const auto Written=co_await P->Client->WriteExact(Envelope);
        EXPECT_TRUE(Written.Failure.Succeeded());EXPECT_EQ(Written.Bytes,Envelope.size());
        auto C=std::make_shared<Client>();EXPECT_TRUE(C->Connect(P->Client));co_return C;
    }
    template<class Client>
    auto RoundTrip(std::shared_ptr<State> S,std::shared_ptr<Client> ClientValue) -> Net::awaitable<Preview::SharedTransmission>
    {
        auto Stream=co_await ClientValue->OpenStream();EXPECT_TRUE(Stream);if(!Stream)co_return nullptr;
        const auto Port=S->Acceptor.local_endpoint().port();
        std::vector<std::byte> Request{std::byte{0},std::byte{0},std::byte{1},std::byte{127},std::byte{0},std::byte{0},std::byte{1},
            std::byte{static_cast<std::uint8_t>(Port>>8)},std::byte{static_cast<std::uint8_t>(Port)}};
        const auto Bytes=std::as_bytes(std::span(Literal));Request.insert(Request.end(),Bytes.begin(),Bytes.end());
        const auto Written=co_await Stream->WriteExact(Request);
        EXPECT_TRUE(Written.Failure.Succeeded());EXPECT_EQ(Written.Bytes,Request.size());
        std::array<std::byte,Literal.size()+1> Reply{};
        const auto Read=co_await Stream->ReadExact(Reply);
        EXPECT_TRUE(Read.Failure.Succeeded());EXPECT_EQ(Read.Bytes,Reply.size());
        EXPECT_EQ(Reply[0],std::byte{0});EXPECT_TRUE(std::equal(Reply.begin()+1,Reply.end(),Bytes.begin()));co_return Stream;
    }
    template<class Client>
    auto Close(std::shared_ptr<Client> ClientValue) -> Net::awaitable<void>
    { co_await ClientValue->Session()->Close(); }
    inline auto Finish(std::shared_ptr<State> S) -> Net::awaitable<void>
    {
        S->Binding->Close();
        const auto Drained = co_await S->Binding->Drain();
        EXPECT_TRUE(Drained || S->Binding->IsRetired());
        S->Stop();co_await S->Tasks->Drain();
        EXPECT_EQ(S->UseState->Outstanding(),0U);
        EXPECT_TRUE(S->UseState->CloseAdmissionIfUnused());
        EXPECT_EQ(S->Tasks->Stats().Active,0U);EXPECT_FALSE(S->Tasks->IsDrainBlocked());
        EXPECT_EQ(S->Record->Runtime()->ActiveConnections(),0U);EXPECT_EQ(S->Record->Runtime()->ActiveStreams(),0U);
        for(const auto& P:S->Peers){EXPECT_TRUE(P->Returned);EXPECT_TRUE(P->WeakRoot.expired());}
    }
    inline auto Watchdog(std::shared_ptr<State> S) -> Net::awaitable<void>
    {
        S->Deadline.expires_after(std::chrono::seconds(4));boost::system::error_code Error;
        co_await S->Deadline.async_wait(Net::redirect_error(Net::use_awaitable,Error));
        if(!Error){S->TimedOut=true;S->Stop();}
    }
    template<class Driver>
    auto Scenario(Preview::Mux::Mode Mode,Driver Operation) -> void
    {
        Net::io_context Io;auto S=Make(Io.get_executor(),Mode);
        const auto Completed=[S](std::exception_ptr Error){if(Error){S->Failure=Error;S->Stop();}};
        Net::co_spawn(Io,Operation(S),Completed);Net::co_spawn(Io,Watchdog(S),Completed);Io.run();
        if(S->Failure) try {std::rethrow_exception(S->Failure);} catch(const std::exception& Error) {ADD_FAILURE()<<Error.what();}
        EXPECT_FALSE(S->Failure);EXPECT_FALSE(S->TimedOut);
    }
}
