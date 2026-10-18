/**
 * @file ConfiguredMuxSessionVlessTest.cpp
 * @brief 配置化 Mux 真实 owner 与 drain 行为契约。
 */

#include "ConfiguredMuxSessionScenarioTypes.hpp"

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Vless/Binding.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>

#include <expected>

namespace
{
    struct VlessBindingOrderResult final
    {
        bool Setup{false};
        bool DisabledRejected{false};
        bool DisabledRejectedEof{false};
        bool DisabledCarrierClosed{false};
        bool EnabledAccepted{false};
        bool EnabledDatagram{false};
        bool EnabledResponseRead{false};
        bool TimedOut{false};
        bool ActiveConnectionsZero{false};
        bool LeaseReleased{false};
        bool GenerationReleased{false};
        bool CatalogDrained{false};
        bool DirectFactoryDrained{false};
        bool DirectFactoryRetired{false};
        std::uint64_t GenerationUsesAfterDrain{0};
        std::string SetupError;
        std::exception_ptr Failure;
    };

    /** @brief 构造指定 UDP 能力及 Mux 模式的 VLESS 绑定。 */
    auto MakeVlessBinding(std::string_view Id, bool Udp, std::string_view Mode)
        -> Prism::Contract::ProtocolBindingConfiguration
    {
        Prism::Contract::ProtocolBindingConfiguration Binding;
        Binding.Id = std::string(Id);
        Binding.ProtocolId = "vless-instance";
        Binding.TcpEnabled = true;
        Binding.UdpEnabled = Udp;
        Binding.MuxModes = {std::string(Mode)};
        return Binding;
    }

    auto BuildVlessPhase(const bool UdpFirst)
        -> std::expected<Application::Startup::GenerationPhase::Result, std::string>
    {
        const auto RootPath = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Base = Application::Startup::GenerationPhase::Build({
            RootPath / "tests/TestSupport/Prism/ConfiguredMux/socks5.json", {}});
        if (!Base)
        {
            return std::unexpected(Base.error().Path + ": " + Base.error().Message);
        }

        constexpr std::string_view UuidText{"123e4567-e89b-12d3-a456-426614174000"};
        auto Configuration = Base->Generation->Configuration();
        if (Configuration.Protocols.empty() || Configuration.Accounts.empty())
        {
            return std::unexpected("base configured generation has no protocol or account");
        }
        auto &Protocol = Configuration.Protocols.front();
        Protocol.Id = "vless-instance";
        Protocol.Name = "vless";
        Protocol.Builtin = "vless";
        Protocol.Requires.clear();
        Protocol.Quic.reset();
        Configuration.Accounts.front().Credentials["Vless"] = std::string(UuidText);
        Configuration.Recognition.Mode = "MixedTrial";
        Configuration.Recognition.ConfiguredCandidate = -1;
        Configuration.ProtocolBindings.clear();

        if (UdpFirst)
        {
            Configuration.ProtocolBindings.push_back(MakeVlessBinding("binding-vless-enabled", true, "Smux"));
            Configuration.ProtocolBindings.push_back(MakeVlessBinding("binding-vless-disabled", false, "Yamux"));
        }
        else
        {
            Configuration.ProtocolBindings.push_back(MakeVlessBinding("binding-vless-disabled", false, "Smux"));
            Configuration.ProtocolBindings.push_back(MakeVlessBinding("binding-vless-enabled", true, "Yamux"));
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
        if (const auto Accounts = Application::Startup::GenerationPhase::BuildAccounts(Result);
            !Accounts)
        {
            return std::unexpected(Accounts.error().Path + ": " + Accounts.error().Message);
        }
        return Result;
    }

    auto MakeVlessUdpWire(const std::array<std::uint8_t, Prism::Vless::UuidLen> &Uuid)
        -> std::vector<std::byte>
    {
        Prism::Vless::RequestHeader Request;
        Request.Uuid = Uuid;
        Request.Cmd = Prism::Vless::Command::Udp;
        Request.Target = Prism::Vless::Address{
            Prism::Vless::AddressType::Domain, "example.com", 443};
        const auto Bytes = Prism::Vless::BuildRequest(Request);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Bytes.size())};
    }

    struct VlessAdmissionResult final
    {
        bool Accepted{false};
        bool Datagram{false};
        bool ResponseRead{false};
        bool RejectedEof{false};
        bool RejectedCarrierClosed{false};
        bool TimedOut{false};
        std::string Error;
        std::exception_ptr Failure;
    };

    using VlessFinishedSignal = Net::experimental::channel<void(boost::system::error_code)>;

    struct VlessAdmissionState final
    {
        std::string Label;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::vector<std::byte> Wire;
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Server;
        std::shared_ptr<std::shared_ptr<Prism::Contract::DatagramSession>> ActiveSession;
        std::shared_ptr<VlessFinishedSignal> Finished;
        std::shared_ptr<Net::steady_timer> Deadline;
        bool ExpectAccept{true};
        VlessAdmissionResult Result;
    };

    /** @brief 同一 worker executor 上一次真实 VLESS admission 场景的借用输入。 */
    struct VlessAdmissionRequest final
    {
        Net::io_context& Io;
        std::string_view Label;
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        const std::vector<std::byte>& Wire;
        bool ExpectAccept{true};
    };

    auto LogVlessAdmission(const VlessAdmissionState &State, const char *Phase) -> void
    {
        std::fprintf(stderr, "[ConfiguredMuxVless:%.*s] %s\n",
                     static_cast<int>(State.Label.size()), State.Label.data(), Phase);
    }

    auto CloseVlessAdmission(const std::shared_ptr<VlessAdmissionState> &State) noexcept -> void
    {
        if (*State->ActiveSession) (*State->ActiveSession)->Close();
        (void)State->Client->Close();
        (void)State->Server->Close();
    }

    auto RunVlessClient(const std::shared_ptr<VlessAdmissionState> &State) -> Net::awaitable<void>
    {
        std::error_code Error;
        const auto Write = co_await State->Client->WriteSome(
            std::span<const std::byte>(State->Wire.data(), State->Wire.size()));
        Error = Prism::Fault::ToNative(Write.Failure);
        const auto Written = Write.Bytes;
        LogVlessAdmission(*State, "client-write-done");
        if (Error || Written != State->Wire.size())
        {
            State->Result.Error = "VLESS wire write failed";
            CloseVlessAdmission(State);
            (void)State->Finished->try_send(boost::system::error_code{});
            co_return;
        }
        std::array<std::byte, 2> Response{};
        const auto ReadResult = co_await State->Client->ReadSome(Response);
        Error = Prism::Fault::ToNative(ReadResult.Failure);
        const auto Read = ReadResult.Bytes;
        State->Result.ResponseRead = !Error && Read == Response.size() &&
            Response[0] == static_cast<std::byte>(Prism::Vless::ProtocolVersion) &&
            Response[1] == static_cast<std::byte>(0);
        State->Result.RejectedEof = ReadResult.Bytes == 0U &&
            ReadResult.Failure.Code == Prism::Fault::Code::Eof;
        if (!State->Result.ResponseRead && !State->Result.RejectedEof)
        {
            State->Result.Error = "VLESS response or rejection EOF read failed";
        }
        auto ReadLabel = "client-read-failed";
        if (State->Result.ResponseRead) ReadLabel = "client-response-read";
        else if (State->Result.RejectedEof) ReadLabel = "client-rejection-eof";
        LogVlessAdmission(*State, ReadLabel);
        (void)State->Finished->try_send(boost::system::error_code{});
    }

    auto RunVlessServer(const std::shared_ptr<VlessAdmissionState> &State) -> Net::awaitable<void>
    {
        LogVlessAdmission(*State, "server-accept-start");
        auto Outcome = co_await State->Factory->Accept({State->Server, {},
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8})});
        State->Result.Accepted = static_cast<bool>(Outcome);
        auto Label = "server-accept-rejected";
        if (State->Result.Accepted)
        {
            Label = "server-accept-success";
        }
        LogVlessAdmission(*State, Label);
        if (Outcome)
        {
            State->Result.Datagram = Outcome->IsDatagram() && Outcome->Datagram()->Session;
            if (const auto *Datagram = Outcome->Datagram(); Datagram && Datagram->Session)
            {
                *State->ActiveSession = Datagram->Session;
            }
        }
        else
        {
            if (State->ExpectAccept)
            {
                const auto Failure = Outcome.error();
                const auto Native = Prism::Fault::ToNative(Failure);
                State->Result.Error = "VLESS Accept failed code=" +
                    std::to_string(static_cast<int>(Failure.Code)) + " native=" + Native.message();
            }
            const auto Closed = State->Server->Close();
            EXPECT_TRUE(Closed);
            const auto Drained = co_await State->Server->Activity()->Drain();
            EXPECT_TRUE(Drained);
            State->Result.RejectedCarrierClosed = Closed && Drained && !State->Server->IsOpen();
            LogVlessAdmission(*State, "server-rejection-closed");
        }
        (void)State->Finished->try_send(boost::system::error_code{});
    }

    auto RunVlessDeadline(const std::shared_ptr<VlessAdmissionState> &State) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await State->Deadline->async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            State->Result.TimedOut = true;
            LogVlessAdmission(*State, "watchdog-timeout");
            CloseVlessAdmission(State);
        }
    }

    auto WaitForVlessCompletions(const std::shared_ptr<VlessAdmissionState> &State)
        -> Net::awaitable<void>
    {
        co_await State->Finished->async_receive(Net::use_awaitable);
        co_await State->Finished->async_receive(Net::use_awaitable);
        LogVlessAdmission(*State, "both-completions");
        State->Deadline->cancel();
        CloseVlessAdmission(State);
    }

    auto RunVlessAdmission(VlessAdmissionRequest Request) -> VlessAdmissionResult
    {
        auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Request.Io.get_executor());
        auto State = std::make_shared<VlessAdmissionState>();
        State->Label = Request.Label;
        State->Factory = std::move(Request.Factory);
        State->Wire = Request.Wire;
        State->ExpectAccept = Request.ExpectAccept;
        State->Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        State->Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        State->ActiveSession = std::make_shared<std::shared_ptr<Prism::Contract::DatagramSession>>();
        State->Finished = std::make_shared<VlessFinishedSignal>(Request.Io.get_executor(), 2);
        State->Deadline = std::make_shared<Net::steady_timer>(Request.Io.get_executor());
        State->Deadline->expires_after(std::chrono::seconds(2));
        LogVlessAdmission(*State, "start");

        Net::co_spawn(Request.Io, RunVlessClient(State), [State](std::exception_ptr Error)
        {
            if (Error)
            {
                State->Result.Failure = std::move(Error);
                CloseVlessAdmission(State);
                (void)State->Finished->try_send(boost::system::error_code{});
            }
        });
        Net::co_spawn(Request.Io, RunVlessServer(State), [State](std::exception_ptr Error)
        {
            if (Error)
            {
                State->Result.Failure = std::move(Error);
                CloseVlessAdmission(State);
                (void)State->Finished->try_send(boost::system::error_code{});
            }
        });
        Net::co_spawn(Request.Io, RunVlessDeadline(State), [State](std::exception_ptr Error)
        {
            if (Error) { State->Result.Failure = std::move(Error); CloseVlessAdmission(State); }
        });
        Net::co_spawn(Request.Io, WaitForVlessCompletions(State), [State](std::exception_ptr Error)
        {
            if (Error) { State->Result.Failure = std::move(Error); CloseVlessAdmission(State); }
        });
        Request.Io.run();
        Request.Io.restart();
        auto Label = "end";
        if (State->Result.TimedOut)
        {
            Label = "end-timeout";
        }
        LogVlessAdmission(*State, Label);
        return State->Result;
    }

    struct VlessBindingOrderSetup final
    {
        std::array<std::uint8_t, Prism::Vless::UuidLen> Uuid{};
        Prism::Contract::AuthenticationServices Authentication;
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::weak_ptr<const Prism::Account::AccountBinding> WeakRecord;
        std::weak_ptr<const Prism::Foundation::GenerationLifetime> WeakGeneration;
        std::shared_ptr<Prism::Contract::StreamFactory> DisabledFactory;
        std::shared_ptr<Prism::Contract::StreamFactory> EnabledFactory;
        std::shared_ptr<Prism::Vless::IngressFactory> DirectFactory;
        std::shared_ptr<Prism::Runtime::GenerationPublication> AdmissionPublication;
        std::shared_ptr<Net::io_context> ProviderIo;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::shared_ptr<Provider::BoundCatalog> Catalog;
        std::vector<std::byte> Wire;
    };

    auto DrainVlessCatalog(Net::io_context &Io,
        const std::shared_ptr<Provider::BoundCatalog> &Catalog) -> bool
    {
        bool Drained = false;
        Net::co_spawn(Io, Catalog->Drain(), [&Drained](std::exception_ptr Failure,
            std::expected<void, Prism::Fault::Failure> Result)
        { Drained = !Failure && static_cast<bool>(Result); });
        Io.run();
        return Drained;
    }

    /** @brief 分开记录协议 factory Drain 返回与独立物理退休回执。 */
    struct VlessFactoryDrainResult final
    {
        bool Drained{false};
        bool Retired{false};
    };

    /** @brief 在 factory 使用的同一 executor 上完整等待 VLESS Binding 退休。 */
    auto DrainVlessFactory(Net::io_context &Io,
        const std::shared_ptr<Prism::Vless::IngressFactory> &Factory)
        -> VlessFactoryDrainResult
    {
        VlessFactoryDrainResult Result;
        Net::co_spawn(Io, Factory->Drain(),
            [&Result, Factory](std::exception_ptr Failure,
                std::expected<void, Prism::Fault::Failure> Drained)
            {
                Result.Drained = !Failure && static_cast<bool>(Drained);
                Result.Retired = Factory->IsRetired();
            });
        Io.run();
        Io.restart();
        return Result;
    }

    auto PrepareVlessAccountOwner(
        Application::Startup::GenerationPhase::Result& Phase,
        VlessBindingOrderSetup& Setup) -> std::expected<void, std::string>
    {
        auto Published = Prism::Testing::PublishConfiguredAccountCatalog(
            Phase.Accounts, Phase.Generation);
        if (!Published)
        {
            return std::unexpected("VLESS account authority publish failed: " +
                Prism::Fault::ToNative(Published.error()).message());
        }
        Setup.AdmissionPublication = std::move(*Published);
        const auto* Authentication = Phase.Accounts.Find("vless-instance");
        if (!Authentication)
        {
            return std::unexpected("VLESS account services were not published");
        }
        Setup.Authentication = *Authentication;
        Prism::Account::UuidBytes CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Setup.Uuid[Index]);
        }
        const auto Credential = Prism::Account::CredentialView::Uuid(CredentialBytes);
        const auto Indexed = Authentication->Credentials.InspectCredential(Credential);
        if (!Indexed || !*Indexed)
        {
            return std::unexpected("VLESS account UUID is absent from its credential scope");
        }
        const auto Probe = Authentication->Authenticator->Authenticate(
            Prism::AuthenticationRequest{.Credential = Credential});
        if (!Probe)
        {
            return std::unexpected("VLESS account UUID preflight failed: " +
                Prism::Fault::ToNative(Probe.error()).message());
        }

        Setup.Record = Phase.Accounts.Store->FindById(Prism::AccountId{1});
        if (!Setup.Record)
        {
            return std::unexpected("VLESS account record was not published");
        }
        const auto PolicyVersion = Setup.Record->Policy()->Version();
        const auto Policy = Setup.Record->Policy()->Rate();
        if (!PolicyVersion || !Policy)
        {
            auto PolicyState = "missing";
            if (Policy) PolicyState = "present";
            return std::unexpected("VLESS account policy mismatch version=" +
                std::to_string(PolicyVersion.Value()) + " policy=" + PolicyState);
        }
        Setup.WeakRecord = Setup.Record;
        Setup.WeakGeneration = Phase.Generation;
        Setup.ProviderIo = std::make_shared<Net::io_context>();
        Setup.UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        return {};
    }

    auto PrepareVlessProviderFactories(
        Application::Startup::GenerationPhase::Result& Phase,
        VlessBindingOrderSetup& Setup) -> std::expected<void, std::string>
    {
        Prism::Contract::DatagramServices Datagrams;
        Datagrams.Resolve = [](Prism::Network::Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Prism::Fault::Failure>>
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        };
        const Prism::Contract::StreamServices Streams{
            Prism::Testing::UnavailableEgress(), {}, std::chrono::milliseconds{30000}};
        auto MuxStreams = Streams;
        MuxStreams.Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Provider::ConfigurationInput Input{
            Phase.Generation, Setup.UseState, Phase.Generation->Configuration().Protocols,
            Phase.Generation->Configuration().ProtocolBindings, {}};
        Input.Authentication.emplace("vless-instance", Setup.Authentication);
        Provider::BindingServices Services{Setup.ProviderIo->get_executor(), Datagrams, {}, {}};
        Services.Streams = std::move(MuxStreams);
        auto Prepared = Provider::Compile(std::move(Input), std::move(Services));
        if (!Prepared)
            return std::unexpected("VLESS provider prepare failed: " + Prepared.error().Path);
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
            return std::unexpected("VLESS provider freeze failed: " + Frozen.error().Path);
        auto Bound = Frozen->Bind({});
        if (!Bound)
            return std::unexpected("VLESS provider bind failed: " + Bound.error().Path);
        Setup.Catalog = std::make_shared<Provider::BoundCatalog>(std::move(*Bound));
        const Application::ProtocolProfile::ProtocolFactoryContext Context{
            Phase.Generation->Configuration(), *Phase.Generation,
            Phase.Accounts, {}, {}, Setup.Catalog.get(), Datagrams, Streams};
        const auto Profile = Application::ProtocolProfile::MakeTcpProfile(Context);
        if (!Profile || Profile->Profile->CandidateCount() != 2U)
        {
            (void)DrainVlessCatalog(*Setup.ProviderIo, Setup.Catalog);
            return std::unexpected("VLESS binding candidates were not published independently");
        }

        Prism::Recognition::CandidateId DisabledId = Prism::Recognition::InvalidCandidate;
        Prism::Recognition::CandidateId EnabledId = Prism::Recognition::InvalidCandidate;
        for (std::size_t Index = 0; Index < Profile->Profile->CandidateCount(); ++Index)
        {
            const auto Id = Profile->Profile->CandidateIdAt(Index);
            const auto Name = Profile->Profile->CandidateName(Id);
            if (Name.ends_with("+binding-vless-disabled")) DisabledId = Id;
            if (Name.ends_with("+binding-vless-enabled")) EnabledId = Id;
        }
        Setup.DisabledFactory = Profile->Resolve(DisabledId);
        Setup.EnabledFactory = Profile->Resolve(EnabledId);
        if (DisabledId == Prism::Recognition::InvalidCandidate ||
            EnabledId == Prism::Recognition::InvalidCandidate ||
            !Setup.DisabledFactory || !Setup.EnabledFactory)
        {
            (void)DrainVlessCatalog(*Setup.ProviderIo, Setup.Catalog);
            return std::unexpected("VLESS binding resolver was not published");
        }
        return {};
    }

    auto PrepareVlessBindingOrder(Application::Startup::GenerationPhase::Result& Phase)
        -> std::expected<VlessBindingOrderSetup, std::string>
    {
        constexpr std::string_view UuidText{"123e4567-e89b-12d3-a456-426614174000"};
        const auto ParsedUuid = Prism::Vless::ParseAccountUuid(UuidText);
        if (!ParsedUuid) return std::unexpected("test UUID did not parse");
        VlessBindingOrderSetup Setup;
        Setup.Uuid = *ParsedUuid;
        if (const auto Accounts = PrepareVlessAccountOwner(Phase, Setup); !Accounts)
            return std::unexpected(Accounts.error());
        if (const auto Factories = PrepareVlessProviderFactories(Phase, Setup); !Factories)
            return std::unexpected(Factories.error());

        Prism::Vless::ServerConfig DirectConfiguration;
        DirectConfiguration.uuid = Setup.Uuid;
        DirectConfiguration.EnableUdp = true;
        DirectConfiguration.AuthenticatorOwner = Setup.Authentication.Authenticator;
        Setup.DirectFactory = Prism::Testing::MakeVlessIngress(
            std::move(DirectConfiguration), Prism::Testing::ProtocolIngressResources{
                {}, Setup.UseState, Setup.ProviderIo->get_executor()}, Prism::Vless::IngressRoute{});
        Setup.Wire = MakeVlessUdpWire(Setup.Uuid);
        return Setup;
    }

    auto RunVlessBindingOrder(const bool UdpFirst) -> VlessBindingOrderResult
    {
        VlessBindingOrderResult Result;
        auto Phase = BuildVlessPhase(UdpFirst);
        if (!Phase)
        {
            Result.SetupError = Phase.error();
            return Result;
        }
        auto Setup = PrepareVlessBindingOrder(*Phase);
        if (!Setup)
        {
            Result.SetupError = Setup.error();
            return Result;
        }
        Result.Setup = true;

        const auto Preflight = RunVlessAdmission(VlessAdmissionRequest{
            *Setup->ProviderIo, "direct-enabled", Setup->DirectFactory, Setup->Wire});
        if (!Preflight.Accepted || !Preflight.Datagram || !Preflight.ResponseRead ||
            Preflight.TimedOut || Preflight.Failure)
        {
            Result.SetupError = "direct EnableUdp=true VLESS admission did not complete";
            if (!Preflight.Error.empty()) Result.SetupError += ": " + Preflight.Error;
            if (Preflight.TimedOut) Result.SetupError += " (timed out)";
        }
        else
        {
            const auto Disabled = RunVlessAdmission(VlessAdmissionRequest{
                *Setup->ProviderIo, "binding-disabled", Setup->DisabledFactory, Setup->Wire, false});
            const auto Enabled = RunVlessAdmission(VlessAdmissionRequest{
                *Setup->ProviderIo, "binding-enabled", Setup->EnabledFactory, Setup->Wire});
            Result.DisabledRejected = !Disabled.Accepted && Disabled.RejectedEof &&
                Disabled.RejectedCarrierClosed;
            Result.DisabledRejectedEof = Disabled.RejectedEof;
            Result.DisabledCarrierClosed = Disabled.RejectedCarrierClosed;
            Result.EnabledAccepted = Enabled.Accepted;
            Result.EnabledDatagram = Enabled.Datagram;
            Result.EnabledResponseRead = Enabled.ResponseRead;
            Result.TimedOut = Disabled.TimedOut || Enabled.TimedOut;
            Result.Failure = Disabled.Failure;
            if (!Result.Failure)
            {
                Result.Failure = Enabled.Failure;
            }
            if (!Disabled.Error.empty()) Result.SetupError = Disabled.Error;
            if (!Enabled.Error.empty()) Result.SetupError = Enabled.Error;
        }

        Result.ActiveConnectionsZero = Setup->Record->Runtime()->ActiveConnections() == 0U;
        Setup->DisabledFactory.reset();
        Setup->EnabledFactory.reset();
        Setup->DirectFactory->Close();
        const auto DirectDrain = DrainVlessFactory(*Setup->ProviderIo, Setup->DirectFactory);
        Result.DirectFactoryDrained = DirectDrain.Drained;
        Result.DirectFactoryRetired = DirectDrain.Retired;
        Setup->DirectFactory.reset();
        Result.CatalogDrained = DrainVlessCatalog(*Setup->ProviderIo, Setup->Catalog);
        Result.GenerationUsesAfterDrain = Setup->UseState->Outstanding();
        Setup->Catalog.reset();
        Setup->UseState.reset();
        Setup->ProviderIo.reset();
        Setup->Record.reset();
        Phase->Accounts.Protocols.clear();
        Phase->Accounts.Store.reset();
        Phase->Accounts.Identities.reset();
        Setup->AdmissionPublication.reset();
        Phase->Generation.reset();
        Result.LeaseReleased = Setup->WeakRecord.expired();
        Result.GenerationReleased = Setup->WeakGeneration.expired();
        return Result;
    }
} // namespace

TEST(ConfiguredMuxSession, VlessUdpBindingCapabilityIsIndependentOfBindingOrder)
{
    for (const auto UdpFirst : {false, true})
    {
        const auto Result = RunVlessBindingOrder(UdpFirst);
        ASSERT_TRUE(Result.Setup) << Result.SetupError;
        EXPECT_TRUE(Result.SetupError.empty()) << Result.SetupError;
        EXPECT_FALSE(Result.Failure);
        EXPECT_TRUE(Result.DisabledRejected);
        EXPECT_TRUE(Result.DisabledRejectedEof);
        EXPECT_TRUE(Result.DisabledCarrierClosed);
        EXPECT_TRUE(Result.EnabledAccepted);
        EXPECT_TRUE(Result.EnabledDatagram);
        EXPECT_TRUE(Result.EnabledResponseRead);
        EXPECT_FALSE(Result.TimedOut);
        EXPECT_TRUE(Result.ActiveConnectionsZero);
        EXPECT_TRUE(Result.DirectFactoryDrained);
        EXPECT_TRUE(Result.DirectFactoryRetired);
        EXPECT_TRUE(Result.CatalogDrained);
        EXPECT_EQ(Result.GenerationUsesAfterDrain, 0U);
        EXPECT_TRUE(Result.LeaseReleased);
        EXPECT_TRUE(Result.GenerationReleased);
    }
}
