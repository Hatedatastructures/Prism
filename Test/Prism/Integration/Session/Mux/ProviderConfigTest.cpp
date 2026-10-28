/** @file ProviderConfigTest.cpp @brief 真实冷配置、认证租约、原始数据与 mux owner 发布/退休。 */
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/GenerationPublication.hpp>
#include <Prism/Application/Startup/Detail/Generation.hpp>
#include <Prism/Application/Startup/Detail/Acceptors.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <expected>
#include <array>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
namespace
{
    namespace Net=boost::asio;
    namespace P=Prism::Composition::Provider;
    namespace A=Prism::Application;
    auto MakeUnavailableMuxServices() -> Prism::Contract::StreamServices
    {
        Prism::Contract::StreamServices Services;
        Services.Egress = Prism::Testing::UnavailableEgress();
        Services.Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        return Services;
    }
    /** @brief 构造携带显式有界字节池的协议接入输入。 */
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound,
        Prism::Contract::RequestMetadata Metadata={}) -> Prism::Contract::StreamAcceptInput
    {
        return {std::move(Inbound),std::move(Metadata),
            std::make_shared<Prism::Memory::BytePool>(Prism::Memory::BytePoolOptions{.BlockCount=8})};
    }
    constexpr std::string_view Payload{"P4-PROVIDER-LITERAL"};
    struct Result
    {
        bool ColdMode{false},Authenticated{false},Lease{false},Mux{false},Literal{false},Complete{false};
        bool MuxOwnerDrained{false};
        std::exception_ptr Failure;
    };
    struct State final : Result
    {
        explicit State(Net::any_io_executor Ex):Deadline(Ex)
        {auto [C,S]=Prism::MakeMemoryPair(Ex);Client=std::make_shared<Prism::MemoryStream>(std::move(C));Server=std::make_shared<Prism::MemoryStream>(std::move(S));}
        Net::steady_timer Deadline;Prism::SharedTransmission Client,Server;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::shared_ptr<Prism::Contract::MuxSession> MuxOwner;
        std::shared_ptr<Prism::Contract::DatagramSession> DatagramOwner;
        bool DatagramOwnerDrained{false};
        std::vector<std::byte> Wire;
        bool Ss{false};
    };
    template<typename TOwner>
    auto CloseAndDrain(std::shared_ptr<TOwner> Owner)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Owner) co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        decltype(Owner->Activity()) Activity;
        bool Failed = false;
        try { Activity = Owner->Activity(); } catch (...) { Failed = true; }
        try { Owner->Close(); } catch (...) { Failed = true; }
        if (!Activity) co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        try
        {
            const auto Drained = co_await Activity->Drain();
            if (!Drained) co_return std::unexpected(Drained.error());
            if (!Activity->IsRetired()) co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            if constexpr (requires { Owner->IsRetired(); })
                if (!Owner->IsRetired()) co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            if (Failed) co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        catch (...) { co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError}); }
    }
    auto LiteralWire()->std::vector<std::byte>
    {
        std::vector<std::byte> Wire{std::byte{0},std::byte{0},std::byte{1},std::byte{0},std::byte{0},std::byte{0},
            std::byte{1},std::byte{0},std::byte{0},std::byte{0}};
        const auto Size=9+Payload.size();
        Wire.insert(Wire.end(),{std::byte{1},std::byte{2},std::byte{static_cast<std::uint8_t>(Size)},std::byte{0},
            std::byte{1},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{1},
            std::byte{127},std::byte{0},std::byte{0},std::byte{1},std::byte{0},std::byte{80}});
        const auto Data=std::as_bytes(std::span(Payload));Wire.insert(Wire.end(),Data.begin(),Data.end());return Wire;
    }
    auto Server(std::shared_ptr<State> S)->Net::awaitable<void>
    {
        auto Plane=co_await S->Factory->Accept(MakeStreamAcceptInput(S->Server));
        if (!Plane)
        {
            const auto Error = Prism::Fault::ToNative(Plane.error());
            ADD_FAILURE() << "category=" << Error.category().name()
                          << " message=" << Error.message()
                          << " code=" << static_cast<int>(Plane.error().Code);
        }
        if(Plane)
        {
            if (const auto* Mux = Plane->Mux(); Mux && Mux->Session) S->MuxOwner = Mux->Session;
            if (const auto* Datagram = Plane->Datagram(); Datagram && Datagram->Session)
                S->DatagramOwner = Datagram->Session;
            S->Authenticated=Plane->ProtocolAuthenticated;S->Lease=bool(Plane->AccountLease);S->Mux=Plane->IsMux();
            EXPECT_TRUE(S->Mux)<<"配置smux的实际provider仍发布普通TCP plane";
            if (Plane->PostDial)
            {
                const auto PostDialFailure =
                    co_await Plane->PostDial(Prism::Fault::Failure{});
                EXPECT_TRUE(PostDialFailure.Succeeded());
            }
            std::vector<std::byte> Incoming(S->Wire.size());std::error_code Error;
            const auto Read=co_await Plane->Transport()->ReadExact(Incoming);Error=Prism::Fault::ToNative(Read.Failure);S->Literal=!Error&&Incoming==S->Wire;
            if (const auto* Mux = Plane->Mux(); Mux && Mux->Session)
            {
                const auto Drained = co_await CloseAndDrain(S->MuxOwner);
                S->MuxOwnerDrained = static_cast<bool>(Drained);
                EXPECT_TRUE(Drained);
                EXPECT_TRUE(S->MuxOwner->IsRetired());
            }
            else if (const auto* Datagram = Plane->Datagram(); Datagram && Datagram->Session)
            {
                const auto Drained = co_await CloseAndDrain(S->DatagramOwner);
                S->DatagramOwnerDrained = static_cast<bool>(Drained);
                EXPECT_TRUE(Drained);
            }
        }
        S->Complete=true;(void)S->Client->Close();
        if (!S->MuxOwner && !S->DatagramOwner)
            (void)S->Server->Close();
        S->Deadline.cancel();
    }
    auto Client(std::shared_ptr<State> S)->Net::awaitable<void>
    {
        Prism::SharedTransmission Connection;
        if(!S->Ss)
        {
            const Prism::Socks5::ClientConfig Configuration{
                true, "configured-account", "task4-provider-password"};
            const Prism::Socks5::Address Target{
                Prism::Socks5::AddressType::Ipv4, "127.0.0.1", 80};
            auto Connected = co_await Prism::Socks5::Connect(
                Prism::Socks5::ConnectParameters{S->Client, Configuration, Target});
            if (!Connected)
            {
                ADD_FAILURE() << "SOCKS5 client connect failed: "
                              << Prism::Fault::ToNative(Connected.error()).message();
                co_return;
            }
            Connection = std::move(*Connected);
        }
        else
        {
            Prism::Shadowsocks2022::ClientConfig Configuration;
            const auto Psk=Prism::Shadowsocks2022::DecodePsk("d3d3d3d3d3d3d3d3d3d3dw==");EXPECT_TRUE(Psk);if(!Psk)co_return;
            Configuration.Psk=*Psk;
            auto Connected = co_await Prism::Shadowsocks2022::Connect(
                S->Client, Configuration,
                {Prism::Shadowsocks2022::AddressType::Ipv4, "127.0.0.1", 80});
            if (!Connected)
            {
                ADD_FAILURE() << "SS2022 client connect failed: "
                              << Prism::Fault::ToNative(Connected.error()).message();
                co_return;
            }
            Connection = std::move(*Connected);
        }
        EXPECT_TRUE(Connection);if(!Connection)co_return;
        std::error_code Error;const auto Write=co_await Connection->WriteExact(S->Wire);Error=Prism::Fault::ToNative(Write.Failure);EXPECT_FALSE(Error);
    }
    auto Watchdog(std::shared_ptr<State> S)->Net::awaitable<void>
    {
        S->Deadline.expires_after(std::chrono::seconds(2));boost::system::error_code Error;
        co_await S->Deadline.async_wait(Net::redirect_error(Net::use_awaitable,Error));
        if (!Error)
        {
            ADD_FAILURE() << "cold provider真实握手未完成";
            if (S->MuxOwner) S->MuxOwner->Close();
            else if (S->DatagramOwner) S->DatagramOwner->Close();
            else (void)S->Server->Close();
            (void)S->Client->Close();
        }
    }
    auto RecordScenarioFailure(const std::shared_ptr<State>& StateValue,
                               std::exception_ptr Error) -> void
    {
        if (!Error) return;
        StateValue->Failure = std::move(Error);
        try
        {
            if (StateValue->MuxOwner) StateValue->MuxOwner->Close();
            else if (StateValue->DatagramOwner) StateValue->DatagramOwner->Close();
            else (void)StateValue->Server->Close();
        }
        catch (...) {}
        try { (void)StateValue->Client->Close(); } catch (...) {}
        try { StateValue->Deadline.cancel(); } catch (...) {}
    }
    auto DrainScenarioOwners(const std::shared_ptr<State>& StateValue,
                             P::BoundCatalog& Bound) -> Net::awaitable<bool>
    {
        if (StateValue->MuxOwner && !StateValue->MuxOwnerDrained)
        {
            try
            {
                const auto OwnerDrain = co_await CloseAndDrain(StateValue->MuxOwner);
                StateValue->MuxOwnerDrained = static_cast<bool>(OwnerDrain);
                EXPECT_TRUE(OwnerDrain);
                EXPECT_TRUE(StateValue->MuxOwner->IsRetired());
            }
            catch (...) { if (!StateValue->Failure) StateValue->Failure = std::current_exception(); }
        }
        if (StateValue->DatagramOwner && !StateValue->DatagramOwnerDrained)
        {
            try
            {
                const auto OwnerDrain = co_await CloseAndDrain(StateValue->DatagramOwner);
                StateValue->DatagramOwnerDrained = static_cast<bool>(OwnerDrain);
                EXPECT_TRUE(OwnerDrain);
            }
            catch (...) { if (!StateValue->Failure) StateValue->Failure = std::current_exception(); }
        }
        try { Bound.Close(); } catch (...) { if (!StateValue->Failure) StateValue->Failure = std::current_exception(); }
        try { co_return static_cast<bool>(co_await Bound.Drain()); }
        catch (...) { if (!StateValue->Failure) StateValue->Failure = std::current_exception(); co_return false; }
    }
    auto Scenario(std::string Family)->Result
    {
        const auto Root=std::filesystem::path{PRISM_TEST_REPO_ROOT};
        auto Phase=A::Startup::GenerationPhase::Build({Root/"Test/TestSupport/Prism/ConfiguredMux"/(Family+".json"),{}});
        if(!Phase){ADD_FAILURE()<<Phase.error().Path<<": "<<Phase.error().Message;return {};}
        auto PublishedAccounts = Prism::Testing::PublishConfiguredAccountCatalog(
            Phase->Accounts, Phase->Generation);
        if (!PublishedAccounts)
        {
            ADD_FAILURE() << "configured account publication failed: "
                          << Prism::Fault::ToNative(PublishedAccounts.error()).message();
            return {};
        }
        auto AccountPublication = std::move(*PublishedAccounts);
        (void)AccountPublication;
        Net::io_context Io;auto S=std::make_shared<State>(Io.get_executor());S->Ss=Family=="ss2022";S->Wire=LiteralWire();
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        P::ConfigurationInput Input{Phase->Generation, UseState,
            Phase->Generation->Configuration().Protocols,
            Phase->Generation->Configuration().ProtocolBindings, {}};
        const auto *Authentication=Phase->Accounts.Find("mux-"+Family);
        if(!Authentication){ADD_FAILURE()<<"configured account services were missing";return {};}
        Input.Authentication.emplace("mux-"+Family,*Authentication);
        P::BindingServices Services{.Executor=Io.get_executor(),
            .Streams=MakeUnavailableMuxServices()};
        auto Prepared=P::Compile(std::move(Input),std::move(Services));EXPECT_TRUE(Prepared);if(!Prepared)return {};
        auto Frozen=Prepared->Freeze();EXPECT_TRUE(Frozen);if(!Frozen)return {};
        auto Bound=Frozen->Bind({});EXPECT_TRUE(Bound);if(!Bound)return {};
        A::ProtocolProfile::ProtocolFactoryContext Context{Phase->Generation->Configuration(),*Phase->Generation,
            Phase->Accounts,{},{},&*Bound,{},
            {.Egress=Prism::Testing::UnavailableEgress()}};
        auto Profile=A::ProtocolProfile::MakeTcpProfile(Context);
        if(!Profile){ADD_FAILURE()<<Profile.error().Path<<": "<<Profile.error().Message;return {};}
        const auto CandidateId=Profile->Profile->CandidateIdAt(0);
        S->ColdMode=Phase->Generation->Configuration().ProtocolBindings.front().MuxModes.front()=="Smux";
        S->Factory=Profile->Resolver(CandidateId);EXPECT_TRUE(S->Factory);
        const auto Done = [S](std::exception_ptr Error)
        { RecordScenarioFailure(S, std::move(Error)); };
        Net::co_spawn(Io,Server(S),Done);Net::co_spawn(Io,Client(S),Done);Net::co_spawn(Io,Watchdog(S),Done);Io.run();
        bool Drained = false;
        const auto Drain = [&]() -> Net::awaitable<void>
        { Drained = co_await DrainScenarioOwners(S, *Bound); };
        Io.restart();Net::co_spawn(Io,Drain(),Done);Io.run();EXPECT_TRUE(Drained);
        return static_cast<const Result&>(*S);
    }
    struct UdpBindingAttempt final
    {
        bool Accepted{false};
        bool Datagram{false};
        bool PeerClosed{false};
        bool ClientCompleted{false};
        bool TimedOut{false};
        bool HasAcceptError{false};
        bool Lease{false};
        bool OwnerDrained{false};
        bool OwnerRetired{false};
        Prism::Fault::Failure AcceptError{};
        Prism::Fault::Failure OwnerDrainFailure{};
        Prism::Socks5::ReplyCode Reply{Prism::Socks5::ReplyCode::GeneralFailure};
        std::exception_ptr Failure;
    };
    struct UdpBindingOrderResult final
    {
        UdpBindingAttempt Disabled;
        UdpBindingAttempt Enabled;
        bool Drained{false};
        bool AccountReleased{false};
        std::exception_ptr Failure;
    };
    struct UdpAttemptState final
    {
        Prism::SharedTransmission Client;
        Prism::SharedTransmission Server;
        std::shared_ptr<Prism::Contract::MuxSession> MuxOwner;
        std::shared_ptr<Prism::Contract::DatagramSession> DatagramOwner;
        UdpBindingAttempt Result;
    };
    enum class WireReadStatus : std::uint8_t
    {
        Complete,
        Closed,
        TimedOut,
    };
    auto WriteWire(const Prism::SharedTransmission& Transport,
                   std::span<const std::uint8_t> Bytes) -> Net::awaitable<bool>
    {
        if (!Transport)
        {
            co_return false;
        }
        std::size_t Offset = 0;
        while (Offset < Bytes.size())
        {
            std::error_code Error;
            const auto Write = co_await Transport->WriteSome(
                std::as_bytes(Bytes.subspan(Offset)));
            Error = Prism::Fault::ToNative(Write.Failure);
            const auto Count = Write.Bytes;
            if (Error || Count == 0U)
            {
                co_return false;
            }
            Offset += Count;
        }
        co_return true;
    }
    auto ReadWire(const Prism::SharedTransmission& Transport,
                  std::span<std::byte> Bytes) -> Net::awaitable<WireReadStatus>
    {
        if (!Transport)
        {
            co_return WireReadStatus::Closed;
        }
        std::size_t Offset = 0;
        while (Offset < Bytes.size())
        {
            std::error_code Error;
            const auto Read = co_await Transport->ReadSome(Bytes.subspan(Offset));
            Error = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (Error == std::make_error_code(std::errc::timed_out))
            {
                co_return WireReadStatus::TimedOut;
            }
            if (Error || Count == 0U)
            {
                co_return WireReadStatus::Closed;
            }
            Offset += Count;
        }
        co_return WireReadStatus::Complete;
    }
    template<typename TOwner>
    auto DrainUdpOwner(const std::shared_ptr<TOwner>& Owner, UdpBindingAttempt& Result)
        -> Net::awaitable<void>
    {
        auto Drained = co_await CloseAndDrain(Owner);
        if (!Drained) Drained = co_await CloseAndDrain(Owner);
        Result.OwnerDrainFailure = {};
        Result.OwnerDrained = Result.OwnerRetired = static_cast<bool>(Drained);
        if (!Drained) Result.OwnerDrainFailure = Drained.error();
        else if (!Result.OwnerRetired) Result.OwnerDrainFailure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
    }
    auto RunUdpBindingServer(const std::shared_ptr<UdpAttemptState>& State,
                             const std::shared_ptr<Prism::Contract::StreamFactory>& Factory)
        -> Net::awaitable<void>
    {
        try
        {
            auto Plane = co_await Factory->Accept(MakeStreamAcceptInput(State->Server));
            if (Plane)
            {
                if (const auto* Mux = Plane->Mux(); Mux && Mux->Session)
                    State->MuxOwner = Mux->Session;
                if (const auto* Datagram = Plane->Datagram(); Datagram && Datagram->Session)
                    State->DatagramOwner = Datagram->Session;
                State->Result.Accepted = true;
                State->Result.Datagram = Plane->IsDatagram();
                State->Result.Lease = static_cast<bool>(Plane->AccountLease);
            }
            else
            {
                State->Result.HasAcceptError = true;
                State->Result.AcceptError = Plane.error();
            }
        }
        catch (...)
        {
            State->Result.Failure = std::current_exception();
        }
    }

    auto RunUdpBindingClient(const std::shared_ptr<UdpAttemptState>& State)
        -> Net::awaitable<void>
    {
        try
        {
            constexpr std::array<std::uint8_t, 3> GreetingWire{0x05, 0x01, 0x02};
            if (!co_await WriteWire(State->Client, GreetingWire))
            {
                co_return;
            }
            std::array<std::byte, 2> MethodReplyWire{};
            const auto MethodStatus = co_await ReadWire(State->Client, MethodReplyWire);
            if (MethodStatus != WireReadStatus::Complete)
            {
                State->Result.TimedOut = MethodStatus == WireReadStatus::TimedOut;
                co_return;
            }
            Prism::Socks5::MethodReply MethodReply;
            if (Prism::Socks5::ParseMethodReply(
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(MethodReplyWire.data()),
                                                   MethodReplyWire.size()),
                    MethodReply) != Prism::Error::None ||
                MethodReply.Method != Prism::Socks5::AuthMethod::UserPass)
            {
                co_return;
            }
            const auto AuthWire = Prism::Socks5::BuildUserpass(
                "configured-account", "task4-provider-password");
            if (!co_await WriteWire(State->Client, AuthWire))
            {
                co_return;
            }
            std::array<std::byte, 2> AuthReplyWire{};
            const auto AuthStatus = co_await ReadWire(State->Client, AuthReplyWire);
            if (AuthStatus != WireReadStatus::Complete)
            {
                State->Result.TimedOut = AuthStatus == WireReadStatus::TimedOut;
                co_return;
            }
            if (Prism::Socks5::ParseUserpassReply(
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(AuthReplyWire.data()),
                                                   AuthReplyWire.size())) != Prism::Error::None)
            {
                co_return;
            }
            constexpr std::array<std::uint8_t, 10> RequestWire{
                0x05, 0x03, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00};
            if (!co_await WriteWire(State->Client, RequestWire))
            {
                co_return;
            }
            std::array<std::byte, 10> ReplyWire{};
            const auto ReplyStatus = co_await ReadWire(State->Client, ReplyWire);
            if (ReplyStatus != WireReadStatus::Complete)
            {
                State->Result.TimedOut = ReplyStatus == WireReadStatus::TimedOut;
                co_return;
            }
            Prism::Socks5::Reply Reply;
            std::size_t Consumed = 0;
            const auto ReplyError = Prism::Socks5::ParseReply(
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(ReplyWire.data()),
                                               ReplyWire.size()),
                Reply, Consumed);
            if (ReplyError != Prism::Error::None || Consumed != ReplyWire.size())
            {
                co_return;
            }
            State->Result.Reply = Reply.Code;
            std::array<std::byte, 1> EofProbe{};
            const auto EofStatus = co_await ReadWire(State->Client, EofProbe);
            State->Result.PeerClosed = EofStatus == WireReadStatus::Closed;
            State->Result.TimedOut = EofStatus == WireReadStatus::TimedOut;
            State->Result.ClientCompleted = true;
        }
        catch (...)
        {
            State->Result.Failure = std::current_exception();
        }
        if (State->Client)
        {
            (void)State->Client->Close();
        }
    }
    /** @brief UDP 关联需要真实 TCP 的本地与对端地址；按值返回双方完整传输 owner。 */
    auto MakeUdpControlPair()
        -> Net::awaitable<std::pair<Prism::SharedTransmission, Prism::SharedTransmission>>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::ip::tcp::acceptor Acceptor(Executor, {Net::ip::address_v4::loopback(), 0});
        Net::ip::tcp::socket Client(Executor);
        co_await Client.async_connect(Acceptor.local_endpoint(), Net::use_awaitable);
        auto Server = co_await Acceptor.async_accept(Net::use_awaitable);
        Acceptor.close();
        co_return std::pair{
            std::make_shared<Prism::Transport::Reliable>(std::move(Client)),
            std::make_shared<Prism::Transport::Reliable>(std::move(Server))};
    }
    auto RunUdpBindingAttempt(const std::shared_ptr<Prism::Contract::StreamFactory>& Factory)
        -> Net::awaitable<UdpBindingAttempt>
    {
        auto [Client, Server] = co_await MakeUdpControlPair();
        auto State = std::make_shared<UdpAttemptState>();
        State->Client = std::move(Client);
        State->Server = std::move(Server);
        State->Client->SetTimeout(std::chrono::milliseconds(1500));
        State->Server->SetTimeout(std::chrono::milliseconds(1500));
        using Net::experimental::awaitable_operators::operator&&;
        try { co_await (RunUdpBindingServer(State, Factory) && RunUdpBindingClient(State)); }
        catch (...) { State->Result.Failure = std::current_exception(); }
        if (State->MuxOwner) co_await DrainUdpOwner(State->MuxOwner, State->Result);
        else if (State->DatagramOwner) co_await DrainUdpOwner(State->DatagramOwner, State->Result);
        else if (State->Server) (void)State->Server->Close();
        if (State->Client) (void)State->Client->Close();
        co_return std::move(State->Result);
    }
    struct UdpBindingDriver final
    {
        std::shared_ptr<P::BoundCatalog> BoundOwner;
        std::shared_ptr<Prism::Contract::StreamFactory> DisabledFactory;
        std::shared_ptr<Prism::Contract::StreamFactory> EnabledFactory;
        std::shared_ptr<UdpBindingOrderResult> Summary;

        auto Run() -> Net::awaitable<void>
        {
            try
            {
                Summary->Disabled = co_await RunUdpBindingAttempt(DisabledFactory);
                Summary->Enabled = co_await RunUdpBindingAttempt(EnabledFactory);
            }
            catch (...)
            {
                Summary->Failure = std::current_exception();
            }
            BoundOwner->Close();
            try
            {
                const auto Drained = co_await BoundOwner->Drain();
                Summary->Drained = static_cast<bool>(Drained);
            }
            catch (...)
            {
                if (!Summary->Failure) Summary->Failure = std::current_exception();
            }
        }
    };
    auto BuildUdpBindingPhase(const bool EnabledFirst)
        -> std::expected<A::Startup::GenerationPhase::Result, std::string>
    {
        const auto Root = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Base = A::Startup::GenerationPhase::Build({
            Root / "Test/TestSupport/Prism/ConfiguredMux/socks5.json", {}});
        if (!Base)
        {
            return std::unexpected(Base.error().Path + ": " + Base.error().Message);
        }
        auto Configuration = Base->Generation->Configuration();
        auto& Protocol = Configuration.Protocols.front();
        Protocol.Id = "provider-socks5";
        Protocol.Name = "socks5";
        Protocol.Builtin = "socks5";
        Protocol.Requires.clear();
        Protocol.Quic.reset();
        Configuration.ProtocolBindings.clear();
        const auto AddBinding = [&Configuration, &Protocol](
            const std::string_view Id, const bool UdpEnabled)
        {
            Prism::Contract::ProtocolBindingConfiguration Binding;
            Binding.Id = std::string(Id);
            Binding.ProtocolId = Protocol.Id;
            Binding.TcpEnabled = true;
            Binding.UdpEnabled = UdpEnabled;
            Configuration.ProtocolBindings.push_back(std::move(Binding));
        };
        if (EnabledFirst)
        {
            AddBinding("binding-enabled", true);
            AddBinding("binding-disabled", false);
        }
        else
        {
            AddBinding("binding-disabled", false);
            AddBinding("binding-enabled", true);
        }
        auto Generation = Prism::Application::Configuration::GenerationBuilder::Build({
            .Configuration = std::move(Configuration),
            .Builtins = Base->Generation->Builtins(),
            .AvailableCapabilities = Base->Generation->Capabilities(),
            .Generation = Prism::GenerationId{Base->Generation->Id().Value() + 1U}});
        if (!Generation)
        {
            return std::unexpected(Generation.error().Path + ": " + Generation.error().Message);
        }
        auto Result = std::move(*Base);
        Result.Generation = std::move(*Generation);
        if (const auto Accounts = A::Startup::GenerationPhase::BuildAccounts(Result); !Accounts)
        {
            return std::unexpected(Accounts.error().Path + ": " + Accounts.error().Message);
        }
        return Result;
    }

    /** @brief 将字面 UDP 目标解析为本用例使用的端点。 */
    auto ResolveUdpBindingTarget(Prism::Network::Target Target)
        -> Net::awaitable<std::expected<Net::ip::udp::endpoint,
            Prism::Fault::Failure>>
    {
        const auto Address = Prism::Network::IpAddress(Target.Host);
        if (!Address || Target.Port == 0)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        co_return Net::ip::udp::endpoint{*Address, Target.Port};
    }

    template<typename TProfile>
    auto FindCandidateIdByName(const TProfile& Profile, const std::string_view CandidateName)
        -> std::optional<decltype(Profile->Profile->CandidateIdAt(0))>
    {
        for (std::size_t Index = 0; Index < Profile->Profile->CandidateCount(); ++Index)
        {
            const auto Id = Profile->Profile->CandidateIdAt(Index);
            if (Profile->Profile->CandidateName(Id) == CandidateName) return Id;
        }
        return std::nullopt;
    }

    auto RunUdpBindingOrder(const bool EnabledFirst) -> UdpBindingOrderResult
    {
        auto Summary = std::make_shared<UdpBindingOrderResult>();
        auto Phase = BuildUdpBindingPhase(EnabledFirst);
        if (!Phase)
        {
            ADD_FAILURE() << Phase.error();
            Summary->Failure = std::make_exception_ptr(std::runtime_error(Phase.error()));
            return *Summary;
        }
        auto PublishedAccounts = Prism::Testing::PublishConfiguredAccountCatalog(
            Phase->Accounts, Phase->Generation);
        if (!PublishedAccounts)
        {
            ADD_FAILURE() << "configured UDP account publication failed: "
                          << Prism::Fault::ToNative(PublishedAccounts.error()).message();
            Summary->Failure = std::make_exception_ptr(std::runtime_error("account publication failed"));
            return *Summary;
        }
        auto AccountPublication = std::move(*PublishedAccounts);
        (void)AccountPublication;
        Net::io_context Io;
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        P::ConfigurationInput Input{
            Phase->Generation, UseState, Phase->Generation->Configuration().Protocols,
            Phase->Generation->Configuration().ProtocolBindings, {}};
        const auto *Authentication = Phase->Accounts.Find("provider-socks5");
        if (!Authentication)
        {
            ADD_FAILURE() << "configured account services were missing";
            Summary->Failure = std::make_exception_ptr(std::runtime_error("account services missing"));
            return *Summary;
        }
        Input.Authentication.emplace("provider-socks5", *Authentication);
        Prism::Contract::DatagramServices Datagram;
        Datagram.Resolve = ResolveUdpBindingTarget;
        P::BindingServices Services{.Executor=Io.get_executor(), .Associations=Datagram,
            .Streams=MakeUnavailableMuxServices()};
        auto Prepared = P::Compile(std::move(Input), std::move(Services));
        if (!Prepared)
        {
            ADD_FAILURE() << Prepared.error().Path;
            return *Summary;
        }
        auto Frozen = Prepared->Freeze();
        EXPECT_TRUE(Frozen);
        if (!Frozen)
        {
            return *Summary;
        }
        auto Bound = Frozen->Bind({});
        EXPECT_TRUE(Bound);
        if (!Bound)
        {
            return *Summary;
        }
        auto BoundOwner = std::make_shared<P::BoundCatalog>(std::move(*Bound));
        A::ProtocolProfile::ProtocolFactoryContext Context{
            Phase->Generation->Configuration(), *Phase->Generation,
            Phase->Accounts,
            {}, {}, BoundOwner.get(), Datagram, {}};
        const auto Profile = A::ProtocolProfile::MakeTcpProfile(Context);
        EXPECT_TRUE(Profile);
        if (!Profile)
        {
            return *Summary;
        }
        EXPECT_EQ(Profile->Profile->CandidateCount(), 2U);
        if (Profile->Profile->CandidateCount() != 2U)
        {
            return *Summary;
        }
        const auto DisabledId = FindCandidateIdByName(
            Profile, "provider-socks5+binding-disabled");
        const auto EnabledId = FindCandidateIdByName(
            Profile, "provider-socks5+binding-enabled");
        EXPECT_TRUE(DisabledId.has_value());
        EXPECT_TRUE(EnabledId.has_value());
        EXPECT_NE(DisabledId, EnabledId);
        if (!DisabledId || !EnabledId)
        {
            return *Summary;
        }
        const auto DisabledFactory = Profile->Resolver(*DisabledId);
        const auto EnabledFactory = Profile->Resolver(*EnabledId);
        EXPECT_TRUE(DisabledFactory);
        EXPECT_TRUE(EnabledFactory);
        if (!DisabledFactory || !EnabledFactory)
        {
            return *Summary;
        }

        auto Driver = std::make_shared<UdpBindingDriver>();
        Driver->BoundOwner = std::move(BoundOwner);
        Driver->DisabledFactory = DisabledFactory;
        Driver->EnabledFactory = EnabledFactory;
        Driver->Summary = Summary;
        Net::co_spawn(Io, Driver->Run(), [Summary](std::exception_ptr Error)
        { if (Error && !Summary->Failure) Summary->Failure = std::move(Error); });
        Io.run();
        if (Summary->Failure)
        {
            return *Summary;
        }
        const auto Record = Phase->Accounts.Store->FindById(Prism::AccountId{1});
        Summary->AccountReleased = Record && Record->Runtime()->ActiveConnections() == 0U &&
            Record->Runtime()->ActiveStreams() == 0U;
        return *Summary;
    }
}
TEST(ConfiguredMuxProvider, Socks5ColdModeAuthLeaseAndLiteralPublishesMuxOwner)
{
    const auto R = Scenario("socks5");
    EXPECT_FALSE(R.Failure);
    EXPECT_TRUE(R.ColdMode);
    EXPECT_TRUE(R.Authenticated);
    EXPECT_TRUE(R.Lease);
    EXPECT_TRUE(R.Literal);
    EXPECT_TRUE(R.Complete);
    EXPECT_TRUE(R.Mux);
    EXPECT_TRUE(R.MuxOwnerDrained);
}
TEST(ConfiguredMuxProvider, Ss2022ColdModeAuthLeaseAndLiteralPublishesMuxOwner)
{
    const auto R = Scenario("ss2022");
    EXPECT_FALSE(R.Failure);
    EXPECT_TRUE(R.ColdMode);
    EXPECT_TRUE(R.Authenticated);
    EXPECT_TRUE(R.Lease);
    EXPECT_TRUE(R.Literal);
    EXPECT_TRUE(R.Complete);
    EXPECT_TRUE(R.Mux);
    EXPECT_TRUE(R.MuxOwnerDrained);
}
TEST(ConfiguredMuxProvider, Socks5UdpAdmissionRemainsBindingSpecificInEitherOrder)
{
    for (const bool EnabledFirst : {false, true})
    {
        const auto Result = RunUdpBindingOrder(EnabledFirst);
        EXPECT_FALSE(Result.Failure);
        EXPECT_TRUE(Result.Drained);
        EXPECT_TRUE(Result.AccountReleased);
        EXPECT_FALSE(Result.Disabled.Failure);
        EXPECT_FALSE(Result.Enabled.Failure);
        EXPECT_TRUE(Result.Disabled.HasAcceptError);
        EXPECT_EQ(Result.Disabled.AcceptError.Code, Prism::Fault::Code::NotSupported);
        EXPECT_FALSE(Result.Disabled.AcceptError.Native);
        EXPECT_EQ(Result.Disabled.Reply, Prism::Socks5::ReplyCode::CommandNotSupported);
        EXPECT_FALSE(Result.Disabled.Accepted);
        EXPECT_TRUE(Result.Disabled.PeerClosed);
        EXPECT_TRUE(Result.Disabled.ClientCompleted);
        EXPECT_FALSE(Result.Disabled.TimedOut);
        EXPECT_TRUE(Result.Enabled.Accepted);
        EXPECT_TRUE(Result.Enabled.Datagram);
        EXPECT_TRUE(Result.Enabled.Lease);
        EXPECT_TRUE(Result.Enabled.OwnerDrained);
        EXPECT_TRUE(Result.Enabled.OwnerRetired);
        EXPECT_FALSE(Result.Enabled.OwnerDrainFailure.Failed());
        EXPECT_EQ(Result.Enabled.Reply, Prism::Socks5::ReplyCode::Success);
        EXPECT_TRUE(Result.Enabled.PeerClosed);
        EXPECT_TRUE(Result.Enabled.ClientCompleted);
        EXPECT_FALSE(Result.Enabled.TimedOut);
    }
}
