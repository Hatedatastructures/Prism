#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
/**
 * @file CandidateRegistryUdpPolicyTest.cpp
 * @brief Configured candidate registry UDP policy tests.
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/CandidateRegistry.hpp>
#include <Prism/Composition/Recognition/TrusttunnelCandidate.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace
{

    namespace Composition = Prism::Composition::Recognition;
    namespace Core = Prism::Recognition;
    namespace Net = boost::asio;
    auto MakeVmessUdpWire(const std::array<std::uint8_t, 16> &Uuid)
        -> std::vector<std::byte>
    {
        Prism::Vmess::Message Message;
        Message.uuid = Uuid;
        Message.Cmd = Prism::Vmess::CmdUdp;
        Message.dst = {Prism::Vmess::AddressType::Domain, "example.com", 443};
        for (std::size_t Index = 0; Index < Message.RequestNonce.size(); ++Index)
        {
            Message.RequestNonce[Index] = static_cast<std::uint8_t>(Index + 1U);
            Message.RequestKey[Index] = static_cast<std::uint8_t>(0xA0U + Index);
        }
        Message.RespHeader = 0x42;
        Prism::Vmess::Serializer Serializer(Uuid);
        Serializer.Reset(Message, static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
        std::array<std::uint8_t, 1024> Bytes{};
        std::error_code Error;
        const auto Size = Serializer.Get(boost::asio::mutable_buffer(Bytes.data(), Bytes.size()), Error);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Size)};
    }

    auto MakeVlessUdpWire(const std::array<std::uint8_t, 16> &Uuid)
        -> std::vector<std::byte>
    {
        Prism::Vless::RequestHeader Request;
        Request.Uuid = Uuid;
        Request.Cmd = Prism::Vless::Command::Udp;
        Request.Target = {Prism::Vless::AddressType::Domain, "example.com", 443};
        const auto Bytes = Prism::Vless::BuildRequest(Request);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Bytes.size())};
    }

    auto MakeTrojanUdpWire(const std::string_view Password) -> std::vector<std::byte>
    {
        const Prism::Trojan::Address Target{
            Prism::Trojan::AddressType::Domain, "example.com", 443};
        const auto Bytes = Prism::Trojan::BuildRequest(
            Prism::Trojan::Credential(Password),
            Prism::Trojan::Command::UdpAssociate, Target);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Bytes.size())};
    }

    auto MakeVmessTcpWire(const std::array<std::uint8_t, 16> &Uuid)
        -> std::vector<std::byte>
    {
        Prism::Vmess::Message Message;
        Message.uuid = Uuid;
        Message.Cmd = Prism::Vmess::CmdTcp;
        Message.dst = {Prism::Vmess::AddressType::Domain, "example.com", 443};
        for (std::size_t Index = 0; Index < Message.RequestNonce.size(); ++Index)
        {
            Message.RequestNonce[Index] = static_cast<std::uint8_t>(Index + 1U);
            Message.RequestKey[Index] = static_cast<std::uint8_t>(0xA0U + Index);
        }
        Message.RespHeader = 0x42;
        Prism::Vmess::Serializer Serializer(Uuid);
        Serializer.Reset(Message, static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
        std::array<std::uint8_t, 1024> Bytes{};
        std::error_code Error;
        const auto Size = Serializer.Get(boost::asio::mutable_buffer(Bytes.data(), Bytes.size()), Error);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Size)};
    }

    auto MakeVlessTcpWire(const std::array<std::uint8_t, 16> &Uuid)
        -> std::vector<std::byte>
    {
        Prism::Vless::RequestHeader Request;
        Request.Uuid = Uuid;
        Request.Cmd = Prism::Vless::Command::Tcp;
        Request.Target = {Prism::Vless::AddressType::Domain, "example.com", 443};
        const auto Bytes = Prism::Vless::BuildRequest(Request);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Bytes.size())};
    }

    auto MakeTrojanTcpWire(const std::string_view Password) -> std::vector<std::byte>
    {
        const Prism::Trojan::Address Target{
            Prism::Trojan::AddressType::Domain, "example.com", 443};
        const auto Bytes = Prism::Trojan::BuildRequest(
            Prism::Trojan::Credential(Password), Prism::Trojan::Command::Connect, Target);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Bytes.size())};
    }

    auto RunCandidatePrepare(
        const Composition::CandidateBinding &Binding,
        std::vector<std::byte> Wire) -> Core::PrepareResult
    {
        auto Storage = std::make_shared<const std::vector<std::byte>>(std::move(Wire));
        Core::PrepareContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Snapshot = Core::ProbeSnapshot{std::move(Storage)};
        Net::io_context Io;
        Core::PrepareResult Result;
        std::exception_ptr Failure;
        Net::co_spawn(Io, Binding.Spec.Prepare(std::move(Context)),
            [&Result, &Failure](std::exception_ptr Error, Core::PrepareResult Value)
            {
                Failure = std::move(Error);
                if (!Failure) Result = std::move(Value);
            });
        Io.run();
        if (Failure) std::rethrow_exception(Failure);
        return Result;
    }

    struct RecognitionBindingDefinitions final
    {
        Composition::CandidateDefinition UdpDisabled;
        Composition::CandidateDefinition UdpEnabled;
    };

    struct RecognitionBindingPair final
    {
        std::optional<Composition::CandidateBinding> UdpDisabled;
        std::optional<Composition::CandidateBinding> UdpEnabled;
    };

    struct RecognitionUdpPolicyMatrix final
    {
        std::string_view Protocol;
        Core::CandidateKind Kind{Core::CandidateKind::Cleartext};
        bool Fallback{false};
        std::size_t MinimumBytes{0};
        std::array<RecognitionBindingPair, 2> ProviderBindings;
        std::vector<std::byte> UdpWire;
        std::vector<std::byte> TcpWire;
    };

    auto BuildRecognitionBindingPair(
        Composition::CandidateRegistry &Registry,
        const RecognitionBindingDefinitions &Definitions) -> RecognitionBindingPair
    {
        return {Registry.Build(Definitions.UdpDisabled), Registry.Build(Definitions.UdpEnabled)};
    }

    auto VerifyRecognitionUdpPolicyMatrix(const RecognitionUdpPolicyMatrix &Matrix) -> void
    {
        constexpr auto Accepted = Core::RecognitionStatus::Accepted;
        constexpr auto NoMatch = Core::RecognitionStatus::NoMatch;
        for (std::size_t ProviderIndex = 0; ProviderIndex < Matrix.ProviderBindings.size(); ++ProviderIndex)
        {
            const auto &Provider = Matrix.ProviderBindings[ProviderIndex];
            for (std::size_t BindingIndex = 0; BindingIndex < 2U; ++BindingIndex)
            {
                const auto &Binding = BindingIndex == 0U ? Provider.UdpDisabled : Provider.UdpEnabled;
                ASSERT_TRUE(Binding) << "protocol=" << Matrix.Protocol
                                     << " provider_udp=" << (ProviderIndex != 0U)
                                     << " binding_udp=" << (BindingIndex != 0U);
                EXPECT_EQ(Binding->Spec.Kind, Matrix.Kind) << Matrix.Protocol;
                EXPECT_TRUE(Binding->Spec.RequiresAuthentication) << Matrix.Protocol;
                EXPECT_EQ(Binding->Spec.Fallback, Matrix.Fallback) << Matrix.Protocol;
                EXPECT_EQ(Binding->Spec.MinimumBytes, Matrix.MinimumBytes) << Matrix.Protocol;
                const auto ExpectedUdp = ProviderIndex == 1U && BindingIndex == 1U
                    ? Accepted : NoMatch;
                EXPECT_EQ(RunCandidatePrepare(*Binding, Matrix.UdpWire).Status, ExpectedUdp)
                    << "protocol=" << Matrix.Protocol
                    << " provider_udp=" << (ProviderIndex != 0U)
                    << " binding_udp=" << (BindingIndex != 0U);
                EXPECT_EQ(RunCandidatePrepare(*Binding, Matrix.TcpWire).Status, Accepted)
                    << "protocol=" << Matrix.Protocol
                    << " provider_udp=" << (ProviderIndex != 0U)
                    << " binding_udp=" << (BindingIndex != 0U);
            }
        }
    }

    struct ConfiguredAdmissionResult final
    {
        bool Accepted{false};
        bool Datagram{false};
        bool DatagramRunCompleted{false};
        Prism::Fault::Failure DatagramRunFailure;
        bool TimedOut{false};
        std::exception_ptr Failure;
    };

    using AdmissionFinishedSignal = Net::experimental::channel<void(boost::system::error_code)>;

    auto ResolveDatagramToLoopback(Prism::Network::Target)
        -> Net::awaitable<std::expected<Net::ip::udp::endpoint, Prism::Fault::Failure>>
    {
        co_return Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 53U);
    }

    /** @brief 关闭并等待协议数据报泵退栈，确保 fixture 不遗留异步 owner。 */
    auto StopAndDrainDatagramSession(
        std::shared_ptr<Prism::Contract::DatagramSession> Session,
        Net::any_io_executor Executor,
        Net::cancellation_slot Cancellation)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Finished = std::make_shared<AdmissionFinishedSignal>(Executor, 1);
        std::exception_ptr Failure;
        std::expected<void, Prism::Fault::Failure> RunResult;
        Net::co_spawn(Executor, Session->Run(),
            Net::bind_cancellation_slot(Cancellation,
            [&Failure, &RunResult, Finished](std::exception_ptr Error,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                Failure = std::move(Error);
                RunResult = std::move(Result);
                (void)Finished->try_send(boost::system::error_code{});
            }));
        co_await Net::post(Executor, Net::use_awaitable);
        Session->Close();
        co_await Finished->async_receive(Net::use_awaitable);
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        co_return RunResult;
    }

    struct ConfiguredAdmissionState final
    {
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::vector<std::byte> Wire;
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Server;
        std::shared_ptr<AdmissionFinishedSignal> Finished;
        std::shared_ptr<Net::steady_timer> Deadline;
        Net::cancellation_signal AdmissionCancellation;
        std::shared_ptr<Prism::Contract::DatagramSession> DatagramSession;
        ConfiguredAdmissionResult Result;
    };

    /** @brief 一个 provider pair 共用 executor；provider 先于其 context 销毁。 */
    struct ConfiguredProviderPair final
    {
        Net::io_context Io;
        Composition::CandidateRegistry DisabledRegistry;
        Composition::CandidateRegistry EnabledRegistry;
    };

    auto RunConfiguredAdmissionOperation(
        const std::shared_ptr<ConfiguredAdmissionState> &State) -> Net::awaitable<void>
    {
        const auto Written = co_await State->Client->WriteExact(
            std::span<const std::byte>(State->Wire.data(), State->Wire.size()));
        if (Written.Failure.Failed() || Written.Bytes != State->Wire.size())
        {
            co_return;
        }
        auto Outcome = co_await Net::co_spawn(
            State->Client->Executor(),
            State->Factory->Accept(Prism::Contract::StreamAcceptInput{
                State->Server, {},
                std::make_shared<Prism::Memory::BytePool>(
                    Prism::Memory::BytePoolOptions{64U * 1024U, 64U}),
                std::make_shared<Prism::Foundation::GenerationUseState>()}),
            Net::bind_cancellation_slot(
                State->AdmissionCancellation.slot(), Net::use_awaitable));
        State->Result.Accepted = static_cast<bool>(Outcome);
        if (Outcome)
        {
            State->Result.Datagram = Outcome->IsDatagram() && Outcome->Datagram()->Session;
            if (const auto *Datagram = Outcome->Datagram(); Datagram && Datagram->Session)
            {
                State->DatagramSession = Datagram->Session;
                if (State->Result.TimedOut)
                {
                    State->DatagramSession->Cancel();
                    State->DatagramSession->Close();
                }
                const auto DatagramResult = co_await StopAndDrainDatagramSession(
                    State->DatagramSession, State->Client->Executor(),
                    State->AdmissionCancellation.slot());
                State->Result.DatagramRunCompleted = true;
                if (!DatagramResult)
                {
                    State->Result.DatagramRunFailure = DatagramResult.error();
                }
            }
            else if (const auto Transport = Outcome->Transport())
            {
                (void)Transport->Close();
            }
        }
        (void)State->Client->Close();
        (void)State->Server->Close();
        (void)State->Finished->try_send(boost::system::error_code{});
    }

    auto RunAdmissionDeadline(
        const std::shared_ptr<ConfiguredAdmissionState> &State) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await State->Deadline->async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            State->Result.TimedOut = true;
            State->AdmissionCancellation.emit(Net::cancellation_type::all);
            if (State->DatagramSession)
            {
                State->DatagramSession->Cancel();
                State->DatagramSession->Close();
            }
            State->Client->Close();
            State->Server->Close();
        }
    }

    auto WaitForAdmissionFinished(
        const std::shared_ptr<ConfiguredAdmissionState> &State) -> Net::awaitable<void>
    {
        co_await State->Finished->async_receive(Net::use_awaitable);
        State->Deadline->cancel();
    }

    auto RunConfiguredAdmission(
        Net::io_context &Io,
        const std::shared_ptr<Prism::Contract::StreamFactory> &Factory,
        const std::vector<std::byte> &Wire) -> ConfiguredAdmissionResult
    {
        Io.restart();
        auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
        auto State = std::make_shared<ConfiguredAdmissionState>();
        State->Factory = Factory;
        State->Wire = Wire;
        State->Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        State->Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        State->Finished = std::make_shared<AdmissionFinishedSignal>(Io.get_executor(), 1);
        State->Deadline = std::make_shared<Net::steady_timer>(Io.get_executor());
        State->Deadline->expires_after(std::chrono::seconds(2));
        Net::co_spawn(Io, RunConfiguredAdmissionOperation(State),
            [State](std::exception_ptr Error)
            {
                if (Error) State->Result.Failure = std::move(Error);
                State->Client->Close();
                State->Server->Close();
                (void)State->Finished->try_send(boost::system::error_code{});
            });
        Net::co_spawn(Io, RunAdmissionDeadline(State),
            [State](std::exception_ptr Error)
            {
                if (Error) State->Result.Failure = std::move(Error);
                State->Client->Close();
                State->Server->Close();
            });
        Net::co_spawn(Io, WaitForAdmissionFinished(State),
            [State](std::exception_ptr Error)
            {
                if (Error) State->Result.Failure = std::move(Error);
            });
        Io.run();
        return State->Result;
    }

    struct BindingDefinitionInput final
    {
        Prism::Recognition::CandidateId Id;
        std::string_view Name;
        std::string_view Protocol;
        std::string_view ProtocolId;
        std::string_view BindingId;
        bool UdpEnabled{false};
    };

    auto MakeBindingDefinition(const BindingDefinitionInput &Input)
        -> Composition::CandidateDefinition
    {
        Composition::CandidateDefinition Candidate{
            Input.Id, std::string(Input.Name), std::string(Input.Protocol), 0, 0, false};
        Candidate.ProtocolId = Input.ProtocolId;
        Candidate.BindingId = Input.BindingId;
        Candidate.UdpEnabled = Input.UdpEnabled;
        return Candidate;
    }

    struct ConfiguredPairInput final
    {
        std::string_view Protocol;
        std::string_view ProtocolId;
        std::vector<std::byte> Wire;
    };

    [[nodiscard]] auto MakeVlessProviderInputs(
        const std::array<std::uint8_t, 16> &Uuid,
        const bool UdpEnabled) -> Composition::ProviderCandidateInputs
    {
        Prism::Vless::ServerConfig Configuration;
        Configuration.uuid = Uuid;
        Configuration.EnableUdp = UdpEnabled;
        Prism::Testing::ProtocolIngressResources Resources;
        Resources.Datagrams.Resolve = ResolveDatagramToLoopback;
        Resources.Executor = boost::asio::system_executor();
        auto Owner = Prism::Testing::MakeVlessProviderBinding(
            std::move(Configuration), std::move(Resources));
        return {Prism::Composition::Provider::BoundInstance{
                    "test-vless", Prism::Contract::ProtocolType::Vless, std::move(Owner)}, {}};
    }

    [[nodiscard]] auto MakeTrojanProviderInputs(
        std::string Password,
        const bool UdpEnabled) -> Composition::ProviderCandidateInputs
    {
        Prism::Trojan::ServerConfig Configuration;
        Configuration.Password = std::move(Password);
        Configuration.EnableTcp = true;
        Configuration.EnableUdp = UdpEnabled;
        Prism::Testing::ProtocolIngressResources Resources;
        Resources.Datagrams.Resolve = ResolveDatagramToLoopback;
        Resources.Executor = boost::asio::system_executor();
        auto Owner = Prism::Testing::MakeTrojanProviderBinding(
            std::move(Configuration), std::move(Resources));
        return {Prism::Composition::Provider::BoundInstance{
                    "test-trojan", Prism::Contract::ProtocolType::Trojan, std::move(Owner)}, {}};
    }

    [[nodiscard]] auto MakeVmessProviderInputs(
        const std::array<std::uint8_t, 16> &Uuid,
        const bool UdpEnabled) -> Composition::ProviderCandidateInputs
    {
        Prism::Vmess::ServerConfig Configuration;
        Configuration.uuid = Uuid;
        Configuration.EnableUdp = UdpEnabled;
        Prism::Testing::VmessIngressResources Resources;
        Resources.Datagrams.Resolve = ResolveDatagramToLoopback;
        Resources.Executor = boost::asio::system_executor();
        auto Owner = Prism::Testing::MakeVmessProviderBinding(
            std::move(Configuration), std::move(Resources));
        return {Prism::Composition::Provider::BoundInstance{
                    "test-vmess", Prism::Contract::ProtocolType::Vmess, std::move(Owner)}, {}};
    }

    auto VerifyConfiguredPair(
        ConfiguredProviderPair &Pair,
        ConfiguredPairInput Input) -> void
    {
        const auto Disabled = MakeBindingDefinition(
            BindingDefinitionInput{80, std::string(Input.Protocol) + "-disabled", Input.Protocol,
                                   Input.ProtocolId, "binding-disabled", false});
        const auto Enabled = MakeBindingDefinition(
            BindingDefinitionInput{81, std::string(Input.Protocol) + "-enabled", Input.Protocol,
                                   Input.ProtocolId, "binding-enabled", true});
        const auto DisabledBinding = Pair.DisabledRegistry.Build(Disabled);
        const auto EnabledBinding = Pair.EnabledRegistry.Build(Enabled);
        EXPECT_TRUE(DisabledBinding.has_value());
        EXPECT_TRUE(EnabledBinding.has_value());
        if (!DisabledBinding || !EnabledBinding)
        {
            return;
        }

        for (const auto UdpFirst : {false, true})
        {
            const auto FirstResult = RunConfiguredAdmission(
                Pair.Io, UdpFirst ? EnabledBinding->Accept : DisabledBinding->Accept, Input.Wire);
            const auto SecondResult = RunConfiguredAdmission(
                Pair.Io, UdpFirst ? DisabledBinding->Accept : EnabledBinding->Accept, Input.Wire);
            EXPECT_FALSE(FirstResult.Failure);
            EXPECT_FALSE(SecondResult.Failure);
            EXPECT_FALSE(FirstResult.TimedOut);
            EXPECT_FALSE(SecondResult.TimedOut);
            if (UdpFirst)
            {
                EXPECT_TRUE(FirstResult.Accepted);
                EXPECT_TRUE(FirstResult.Datagram);
                EXPECT_FALSE(SecondResult.Accepted);
            }
            else
            {
                EXPECT_FALSE(FirstResult.Accepted);
                EXPECT_TRUE(SecondResult.Accepted);
                EXPECT_TRUE(SecondResult.Datagram);
            }
            const auto &DatagramResult = UdpFirst ? FirstResult : SecondResult;
            EXPECT_TRUE(DatagramResult.DatagramRunCompleted);
            EXPECT_FALSE(DatagramResult.DatagramRunFailure.Failed())
                << "protocol=" << Input.Protocol
                << " code=" << static_cast<unsigned>(DatagramResult.DatagramRunFailure.Code)
                << " native=" << DatagramResult.DatagramRunFailure.Native.value();
        }
    }

} // namespace

TEST(CandidateRegistry, ConfiguredVlessTrojanVmessCarryBindingUdpPolicy)
{
    const auto Uuid = std::array<std::uint8_t, 16>{
        0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
        0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    const std::string TrojanPassword{"configured-trojan-password"};
    ConfiguredProviderPair Vless;
    ConfiguredProviderPair Trojan;
    ConfiguredProviderPair Vmess;

    ASSERT_TRUE(Vless.DisabledRegistry.RegisterConfiguredProvider(
        "test-vless", MakeVlessProviderInputs(Uuid, false)));
    ASSERT_TRUE(Vless.EnabledRegistry.RegisterConfiguredProvider(
        "test-vless", MakeVlessProviderInputs(Uuid, true)));
    ASSERT_TRUE(Trojan.DisabledRegistry.RegisterConfiguredProvider(
        "test-trojan", MakeTrojanProviderInputs(TrojanPassword, false)));
    ASSERT_TRUE(Trojan.EnabledRegistry.RegisterConfiguredProvider(
        "test-trojan", MakeTrojanProviderInputs(TrojanPassword, true)));
    ASSERT_TRUE(Vmess.DisabledRegistry.RegisterConfiguredProvider(
        "test-vmess", MakeVmessProviderInputs(Uuid, false)));
    ASSERT_TRUE(Vmess.EnabledRegistry.RegisterConfiguredProvider(
        "test-vmess", MakeVmessProviderInputs(Uuid, true)));

    VerifyConfiguredPair(Vless,
        ConfiguredPairInput{"vless", "test-vless", MakeVlessUdpWire(Uuid)});
    VerifyConfiguredPair(Trojan,
        ConfiguredPairInput{"trojan", "test-trojan", MakeTrojanUdpWire(TrojanPassword)});
    VerifyConfiguredPair(Vmess,
        ConfiguredPairInput{"vmess", "test-vmess", MakeVmessUdpWire(Uuid)});
}

TEST(CandidateRegistry, ConfiguredProvidersApplyPerBindingUdpPolicyAtRecognition)
{
    const auto Uuid = std::array<std::uint8_t, 16>{
        0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
        0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    const std::string TrojanPassword{"binding-policy-trojan-password"};

    ConfiguredProviderPair Vless;
    ASSERT_TRUE(Vless.DisabledRegistry.RegisterConfiguredProvider(
        "test-vless", MakeVlessProviderInputs(Uuid, false)));
    ASSERT_TRUE(Vless.EnabledRegistry.RegisterConfiguredProvider(
        "test-vless", MakeVlessProviderInputs(Uuid, true)));
    RecognitionUdpPolicyMatrix VlessMatrix;
    VlessMatrix.Protocol = "vless";
    VlessMatrix.Kind = Core::CandidateKind::Cleartext;
    VlessMatrix.Fallback = false;
    VlessMatrix.MinimumBytes = 19U;
    VlessMatrix.UdpWire = MakeVlessUdpWire(Uuid);
    VlessMatrix.TcpWire = MakeVlessTcpWire(Uuid);
    VlessMatrix.ProviderBindings[0] = BuildRecognitionBindingPair(Vless.DisabledRegistry,
        RecognitionBindingDefinitions{
            MakeBindingDefinition({91, "vless-provider-off-disabled", "vless", "test-vless",
                                   "vless-off-disabled", false}),
            MakeBindingDefinition({92, "vless-provider-off-enabled", "vless", "test-vless",
                                   "vless-off-enabled", true})});
    VlessMatrix.ProviderBindings[1] = BuildRecognitionBindingPair(Vless.EnabledRegistry,
        RecognitionBindingDefinitions{
            MakeBindingDefinition({93, "vless-provider-on-disabled", "vless", "test-vless",
                                   "vless-on-disabled", false}),
            MakeBindingDefinition({94, "vless-provider-on-enabled", "vless", "test-vless",
                                   "vless-on-enabled", true})});
    VerifyRecognitionUdpPolicyMatrix(VlessMatrix);

    ConfiguredProviderPair Trojan;
    ASSERT_TRUE(Trojan.DisabledRegistry.RegisterConfiguredProvider(
        "test-trojan", MakeTrojanProviderInputs(TrojanPassword, false)));
    ASSERT_TRUE(Trojan.EnabledRegistry.RegisterConfiguredProvider(
        "test-trojan", MakeTrojanProviderInputs(TrojanPassword, true)));
    RecognitionUdpPolicyMatrix TrojanMatrix;
    TrojanMatrix.Protocol = "trojan";
    TrojanMatrix.Kind = Core::CandidateKind::Opaque;
    TrojanMatrix.Fallback = true;
    TrojanMatrix.MinimumBytes = Prism::Trojan::CredentialLen + 2U;
    TrojanMatrix.UdpWire = MakeTrojanUdpWire(TrojanPassword);
    TrojanMatrix.TcpWire = MakeTrojanTcpWire(TrojanPassword);
    TrojanMatrix.ProviderBindings[0] = BuildRecognitionBindingPair(Trojan.DisabledRegistry,
        RecognitionBindingDefinitions{
            MakeBindingDefinition({95, "trojan-provider-off-disabled", "trojan", "test-trojan",
                                   "trojan-off-disabled", false}),
            MakeBindingDefinition({96, "trojan-provider-off-enabled", "trojan", "test-trojan",
                                   "trojan-off-enabled", true})});
    TrojanMatrix.ProviderBindings[1] = BuildRecognitionBindingPair(Trojan.EnabledRegistry,
        RecognitionBindingDefinitions{
            MakeBindingDefinition({97, "trojan-provider-on-disabled", "trojan", "test-trojan",
                                   "trojan-on-disabled", false}),
            MakeBindingDefinition({98, "trojan-provider-on-enabled", "trojan", "test-trojan",
                                   "trojan-on-enabled", true})});
    VerifyRecognitionUdpPolicyMatrix(TrojanMatrix);

    ConfiguredProviderPair Vmess;
    ASSERT_TRUE(Vmess.DisabledRegistry.RegisterConfiguredProvider(
        "test-vmess", MakeVmessProviderInputs(Uuid, false)));
    ASSERT_TRUE(Vmess.EnabledRegistry.RegisterConfiguredProvider(
        "test-vmess", MakeVmessProviderInputs(Uuid, true)));
    RecognitionUdpPolicyMatrix VmessMatrix;
    VmessMatrix.Protocol = "vmess";
    VmessMatrix.Kind = Core::CandidateKind::Opaque;
    VmessMatrix.Fallback = true;
    VmessMatrix.MinimumBytes = 60U;
    VmessMatrix.UdpWire = MakeVmessUdpWire(Uuid);
    VmessMatrix.TcpWire = MakeVmessTcpWire(Uuid);
    VmessMatrix.ProviderBindings[0] = BuildRecognitionBindingPair(Vmess.DisabledRegistry,
        RecognitionBindingDefinitions{
            MakeBindingDefinition({99, "vmess-provider-off-disabled", "vmess", "test-vmess",
                                   "vmess-off-disabled", false}),
            MakeBindingDefinition({100, "vmess-provider-off-enabled", "vmess", "test-vmess",
                                   "vmess-off-enabled", true})});
    VmessMatrix.ProviderBindings[1] = BuildRecognitionBindingPair(Vmess.EnabledRegistry,
        RecognitionBindingDefinitions{
            MakeBindingDefinition({101, "vmess-provider-on-disabled", "vmess", "test-vmess",
                                   "vmess-on-disabled", false}),
            MakeBindingDefinition({102, "vmess-provider-on-enabled", "vmess", "test-vmess",
                                   "vmess-on-enabled", true})});
    VerifyRecognitionUdpPolicyMatrix(VmessMatrix);
}

TEST(CandidateRegistry, VmessAuthenticatedTrialOutranksLaterNeedMore)
{
    auto State = Composition::detail::VmessRequestInspection{
        Core::MatchState::Authenticated, Prism::Vmess::Command::Tcp};
    const Composition::detail::VmessRequestInspection NeedMore{
        Core::MatchState::NeedMore, std::nullopt};

    Composition::detail::UpdateVmessTrial(State, NeedMore);

    EXPECT_EQ(State.State, Core::MatchState::Authenticated);
    ASSERT_TRUE(State.Command);
    EXPECT_EQ(*State.Command, Prism::Vmess::Command::Tcp);

    auto Pending = Composition::detail::VmessRequestInspection{};
    Composition::detail::UpdateVmessTrial(Pending, NeedMore);
    EXPECT_EQ(Pending.State, Core::MatchState::NeedMore);
}
