/** @file ConfiguredMuxProviderTest.cpp @brief 真实冷配置、原 provider 材料、认证/lease/literal 到正式 mux producer。 */
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Application/ProtocolAcceptors.hpp>
#include <Prism/Composition/Provider/ConfigurationCompiler.hpp>
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
#include <filesystem>
#include <stdexcept>
namespace
{
    namespace Net=boost::asio;
    namespace P=Prism::Composition::Provider;
    namespace A=Prism::Application;
    using Signal=Net::experimental::channel<void(boost::system::error_code)>;
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
        std::exception_ptr Failure;
    };
    struct State final : Result
    {
        explicit State(Net::any_io_executor Ex):Ready(Ex,1),Deadline(Ex)
        {auto [C,S]=Prism::MakeMemoryPair(Ex);Client=std::make_shared<Prism::MemoryStream>(std::move(C));Server=std::make_shared<Prism::MemoryStream>(std::move(S));}
        Signal Ready;Net::steady_timer Deadline;Prism::SharedTransmission Client,Server;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::vector<std::byte> Wire;
        bool Ss{false};
    };
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
            const auto Error = Prism::make_error_code(Plane.error());
            ADD_FAILURE() << "category=" << Error.category().name()
                          << " message=" << Error.message()
                          << " value=" << static_cast<int>(Plane.error());
        }
        if(Plane)
        {
            S->Authenticated=Plane->ProtocolAuthenticated;S->Lease=bool(Plane->AccountLease);S->Mux=Plane->IsMux();
            EXPECT_TRUE(S->Mux)<<"配置smux的实际provider仍发布普通TCP plane";
            if(Plane->PostDial)EXPECT_EQ(co_await Plane->PostDial(Prism::Fault::Code::Success),Prism::Fault::Code::Success);
            (void)S->Ready.try_send(boost::system::error_code{});
            std::vector<std::byte> Incoming(S->Wire.size());std::error_code Error;
            const auto Read=co_await Plane->Transport()->ReadExact(Incoming);Error=Prism::Fault::ToNative(Read.Failure);S->Literal=!Error&&Incoming==S->Wire;
            (void)Plane->Transport()->Close();if(Plane->Mux())Plane->Mux()->Session->Close();
        }
        S->Complete=true;(void)S->Client->Close();(void)S->Server->Close();S->Deadline.cancel();
    }
    auto Client(std::shared_ptr<State> S)->Net::awaitable<void>
    {
        Prism::SharedTransmission Connection;
        if(!S->Ss)
        {
            auto [Error,Value]=co_await Prism::Socks5::Connect(S->Client,{true,"configured-account","task4-provider-password"},
                {Prism::Socks5::AddressType::Ipv4,"127.0.0.1",80});EXPECT_EQ(Error,Prism::Error::None);Connection=std::move(Value);
        }
        else
        {
            Prism::Shadowsocks2022::ClientConfig Configuration;
            const auto Psk=Prism::Shadowsocks2022::DecodePsk("d3d3d3d3d3d3d3d3d3d3dw==");EXPECT_TRUE(Psk);if(!Psk)co_return;
            Configuration.Psk=*Psk;
            auto [Error,Value]=co_await Prism::Shadowsocks2022::Connect(S->Client,Configuration,
                {Prism::Shadowsocks2022::AddressType::Ipv4,"127.0.0.1",80});EXPECT_EQ(Error,Prism::Error::None);Connection=std::move(Value);
        }
        EXPECT_TRUE(Connection);if(!Connection)co_return;
        std::error_code Error;const auto Write=co_await Connection->WriteExact(S->Wire);Error=Prism::Fault::ToNative(Write.Failure);EXPECT_FALSE(Error);
    }
    auto Watchdog(std::shared_ptr<State> S)->Net::awaitable<void>
    {
        S->Deadline.expires_after(std::chrono::seconds(2));boost::system::error_code Error;
        co_await S->Deadline.async_wait(Net::redirect_error(Net::use_awaitable,Error));
        if(!Error){ADD_FAILURE()<<"cold provider真实握手未完成";(void)S->Server->Close();(void)S->Client->Close();}
    }
    auto Scenario(std::string Family)->Result
    {
        const auto Root=std::filesystem::path{PRISM_TEST_REPO_ROOT};
        auto Phase=A::Startup::GenerationPhase::Build({Root/"tests/TestSupport/Prism/ConfiguredMux"/(Family+".json"),{}});
        if(!Phase){ADD_FAILURE()<<Phase.error().Path<<": "<<Phase.error().Message;return {};}
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
        const auto Done=[S](std::exception_ptr Error){if(Error){S->Failure=Error;(void)S->Client->Close();(void)S->Server->Close();S->Deadline.cancel();}};
        Net::co_spawn(Io,Server(S),Done);Net::co_spawn(Io,Client(S),Done);Net::co_spawn(Io,Watchdog(S),Done);Io.run();
        bool Drained=false;const auto Drain=[&]()->Net::awaitable<void>{Bound->Close();Drained=static_cast<bool>(co_await Bound->Drain());};
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
        Prism::Error AcceptError{Prism::Error::None};
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

    auto RunUdpBindingServer(const std::shared_ptr<UdpAttemptState>& State,
                             const std::shared_ptr<Prism::Contract::StreamFactory>& Factory)
        -> Net::awaitable<void>
    {
        try
        {
            auto Plane = co_await Factory->Accept(MakeStreamAcceptInput(State->Server));
            if (Plane)
            {
                State->Result.Accepted = true;
                State->Result.Datagram = Plane->IsDatagram();
                State->Result.Lease = static_cast<bool>(Plane->AccountLease);
                if (const auto* Datagram = Plane->Datagram())
                {
                    Datagram->Session->Close();
                }
                if (const auto Transport = Plane->Transport())
                {
                    (void)Transport->Close();
                }
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
        if (State->Server)
        {
            (void)State->Server->Close();
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
        co_await (RunUdpBindingServer(State, Factory) && RunUdpBindingClient(State));
        co_return std::move(State->Result);
    }

    auto BuildUdpBindingPhase(const bool EnabledFirst)
        -> std::expected<A::Startup::GenerationPhase::Result, std::string>
    {
        const auto Root = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Base = A::Startup::GenerationPhase::Build({
            Root / "tests/TestSupport/Prism/ConfiguredMux/socks5.json", {}});
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
        boost::system::error_code Error;
        const auto Address = Prism::Network::IpAddress(Target.Host);
        if (!Address || Target.Port == 0)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        co_return Net::ip::udp::endpoint{*Address, Target.Port};
    }

    auto RunUdpBindingOrder(const bool EnabledFirst) -> UdpBindingOrderResult
    {
        auto Summary = std::make_shared<UdpBindingOrderResult>();
        const auto Phase = BuildUdpBindingPhase(EnabledFirst);
        if (!Phase)
        {
            ADD_FAILURE() << Phase.error();
            Summary->Failure = std::make_exception_ptr(std::runtime_error(Phase.error()));
            return *Summary;
        }
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
        const auto DisabledIndex = static_cast<std::size_t>(EnabledFirst);
        const auto EnabledIndex = static_cast<std::size_t>(!EnabledFirst);
        const auto DisabledFactory = Profile->Resolver(Profile->Profile->CandidateIdAt(DisabledIndex));
        const auto EnabledFactory = Profile->Resolver(Profile->Profile->CandidateIdAt(EnabledIndex));
        EXPECT_TRUE(DisabledFactory);
        EXPECT_TRUE(EnabledFactory);
        if (!DisabledFactory || !EnabledFactory)
        {
            return *Summary;
        }

        const auto Failure = std::make_shared<std::exception_ptr>();
        auto Driver = [BoundOwner, DisabledFactory, EnabledFactory, Summary]() -> Net::awaitable<void>
        {
            Summary->Disabled = co_await RunUdpBindingAttempt(DisabledFactory);
            Summary->Enabled = co_await RunUdpBindingAttempt(EnabledFactory);
            BoundOwner->Close();
            Summary->Drained = static_cast<bool>(co_await BoundOwner->Drain());
        };
        Net::co_spawn(Io, Driver(), [Failure](std::exception_ptr Error)
        { *Failure = std::move(Error); });
        Io.run();
        if (*Failure)
        {
            Summary->Failure = *Failure;
            return *Summary;
        }
        const auto Record = Phase->Accounts.Store->FindById(Prism::AccountId{1});
        Summary->AccountReleased = Record && Record->Runtime()->ActiveConnections() == 0U &&
            Record->Runtime()->ActiveStreams() == 0U;
        return *Summary;
    }
}
TEST(ConfiguredMuxProvider, Socks5ColdModeAuthLeaseAndLiteralPublishesMuxOwner)
{const auto R=Scenario("socks5");EXPECT_FALSE(R.Failure);EXPECT_TRUE(R.ColdMode);EXPECT_TRUE(R.Authenticated);EXPECT_TRUE(R.Lease);EXPECT_TRUE(R.Literal);EXPECT_TRUE(R.Complete);EXPECT_TRUE(R.Mux);}
TEST(ConfiguredMuxProvider, Ss2022ColdModeAuthLeaseAndLiteralPublishesMuxOwner)
{const auto R=Scenario("ss2022");EXPECT_FALSE(R.Failure);EXPECT_TRUE(R.ColdMode);EXPECT_TRUE(R.Authenticated);EXPECT_TRUE(R.Lease);EXPECT_TRUE(R.Literal);EXPECT_TRUE(R.Complete);EXPECT_TRUE(R.Mux);}

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
        EXPECT_EQ(Result.Disabled.AcceptError, Prism::Error::NotSupported);
        EXPECT_EQ(Result.Disabled.Reply, Prism::Socks5::ReplyCode::CommandNotSupported);
        EXPECT_FALSE(Result.Disabled.Accepted);
        EXPECT_TRUE(Result.Disabled.PeerClosed);
        EXPECT_TRUE(Result.Disabled.ClientCompleted);
        EXPECT_FALSE(Result.Disabled.TimedOut);
        EXPECT_TRUE(Result.Enabled.Accepted);
        EXPECT_TRUE(Result.Enabled.Datagram);
        EXPECT_TRUE(Result.Enabled.Lease);
        EXPECT_EQ(Result.Enabled.Reply, Prism::Socks5::ReplyCode::Success);
        EXPECT_TRUE(Result.Enabled.PeerClosed);
        EXPECT_TRUE(Result.Enabled.ClientCompleted);
        EXPECT_FALSE(Result.Enabled.TimedOut);
    }
}

TEST(ConfiguredMuxProvider, ExplicitWebsocketCarrierFallbackReachesCompiledTlsPolicy)
{
    const auto Root = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Phase = A::Startup::GenerationPhase::Build({
        Root / "tests/TestSupport/Prism/ConfiguredMux/socks5.json", {}});
    if (!Phase)
    {
        ADD_FAILURE() << Phase.error().Message;
        return;
    }

    auto Configuration = Phase->Generation->Configuration();
    Prism::Application::Configuration::CarrierConfiguration Carrier;
    Carrier.Id = "carrier-ws-fallback";
    Carrier.Name = "websocket-fallback";
    Carrier.Builtin = "ws";
    Carrier.Match.ServerNames = {"edge.example.com"};
    Carrier.Match.Fallback = true;
    Carrier.Options = Prism::Application::Configuration::WebSocketOptions{
        "/ws", "edge.example.com"};
    Configuration.Carriers.push_back(Carrier);
    ASSERT_FALSE(Configuration.ProtocolBindings.empty());
    Configuration.ProtocolBindings.front().CarrierId = Carrier.Id;
    Configuration.ProtocolBindings.front().Recognition.Pattern.clear();
    Configuration.ProtocolBindings.front().Recognition.Fallback = false;

    const auto Generation = Prism::Application::Configuration::GenerationBuilder::Build({
        .Configuration = std::move(Configuration),
        .Builtins = Phase->Generation->Builtins(),
        .AvailableCapabilities = Phase->Generation->Capabilities(),
        .Generation = Prism::GenerationId{Phase->Generation->Id().Value() + 1U}});
    if (!Generation)
    {
        ADD_FAILURE() << Generation.error().Message;
        return;
    }

    auto CarrierPhase = *Phase;
    CarrierPhase.Generation = *Generation;
    const auto Accounts = A::Startup::GenerationPhase::BuildAccounts(CarrierPhase);
    if (!Accounts)
    {
        ADD_FAILURE() << Accounts.error().Message;
        return;
    }

    Net::io_context Io;
    auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
    P::ConfigurationInput Input{
        *Generation, UseState, (*Generation)->Configuration().Protocols,
        (*Generation)->Configuration().ProtocolBindings, {}};
    const auto ProtocolId = (*Generation)->Configuration().Protocols.front().Id;
    const auto *CarrierAuthentication = Accounts->Find(ProtocolId);
    ASSERT_TRUE(CarrierAuthentication);
    Input.Authentication.emplace(ProtocolId, *CarrierAuthentication);
    P::BindingServices Services{.Executor=Io.get_executor(),
        .Streams=MakeUnavailableMuxServices()};
    auto Prepared = P::Compile(std::move(Input), std::move(Services));
    if (!Prepared)
    {
        ADD_FAILURE() << Prepared.error().Instance << ": " << Prepared.error().Path;
        return;
    }
    auto Frozen = Prepared->Freeze();
    ASSERT_TRUE(Frozen);
    auto Bound = Frozen->Bind({});
    ASSERT_TRUE(Bound);

    A::ProtocolProfile::ProtocolFactoryContext Context{
        (*Generation)->Configuration(), **Generation,
        *Accounts,
        {}, {}, &*Bound, {}, {.Egress = Prism::Testing::UnavailableEgress()}};
    const auto Profile = A::ProtocolProfile::MakeTcpProfile(Context);
    if (!Profile)
    {
        ADD_FAILURE() << Profile.error().Message;
        return;
    }
    ASSERT_NE(Profile->Profile, nullptr);
    ASSERT_EQ(Profile->Profile->CandidateCount(), 1U);

    const auto CandidateId = Profile->Profile->CandidateIdAt(0);
    EXPECT_TRUE(Profile->Profile->FallbackCandidates().Test(CandidateId));
    const auto Candidate = Profile->Profile->FindCandidate(CandidateId);
    ASSERT_TRUE(Candidate.IsValid());
    EXPECT_TRUE(Candidate.HasCommit());

    auto Bytes = std::make_shared<Prism::Memory::BytePool>(
        Prism::Memory::BytePoolOptions{.BlockCount = 8});
    Prism::Recognition::ProbeBuffer Buffer(4096, std::move(Bytes));
    const auto Hello = Prism::Testing::RecognitionWire::MakeTlsClientHello("wrong.example.com");
    ASSERT_TRUE(Buffer.Seed(Hello));
    EXPECT_EQ(Candidate.Inspect(Buffer.Snapshot()), Prism::Recognition::MatchState::Structural);
}




