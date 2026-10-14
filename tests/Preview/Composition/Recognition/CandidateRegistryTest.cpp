#include <TestSupport/Preview/ProviderBindings.hpp>
/**
 * @file CandidateRegistryTest.cpp
 * @brief Settings candidate registry behavior tests.
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
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

#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/CandidateRegistry.hpp>
#include <Preview/Composition/Recognition/TrusttunnelCandidate.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Trojan/RequestCodec.hpp>
#include <Preview/Protocols/Vless/RequestCodec.hpp>
#include <Preview/Protocols/Vmess/RequestCodec.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace
{

    namespace Composition = Preview::Composition::Recognition;
    namespace Core = Preview::Recognition;
    namespace Net = boost::asio;

    auto MakeHttpBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        auto Binding = Composition::CandidateFactory::MakeHttp(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority, Candidate.Tier,
                                          Candidate.Fallback},
            Preview::Testing::MakeHttp1Binding());
        return Binding;
    }

    auto MakeVlessBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        return Composition::CandidateFactory::MakeVless(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority,
                Candidate.Tier, Candidate.Fallback});
    }

    auto MakeTrojanBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        return Composition::CandidateFactory::MakeTrojan(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority,
                Candidate.Tier, Candidate.Fallback});
    }

    auto MakeVmessBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        return Composition::CandidateFactory::MakeVmess(
            Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority,
                Candidate.Tier, Candidate.Fallback});
    }

    auto MakeCarrierRegistration() -> Composition::CandidateRegistry::CarrierRegistration
    {
        return {{}, [](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::Recognition::CarrierAcceptResult>
        {
            Preview::Recognition::CarrierAcceptResult Result;
            Result.Transport = std::move(Inbound);
            co_return Result;
        }, {}};
    }

    auto RegisterDefaultCarrier(Composition::CandidateRegistry &Registry,
        const std::string_view Name) -> bool
    {
        const auto Descriptor = Preview::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor)
        {
            return false;
        }
        return Registry.RegisterTlsCarrier(Descriptor->Slot(), {}, MakeCarrierRegistration());
    }

    auto AppendU16(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    auto AppendU24(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    auto MakeExtension(std::uint16_t Type, const std::vector<std::uint8_t> &Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        AppendU16(Result, Type);
        AppendU16(Result, Payload.size());
        Result.insert(Result.end(), Payload.begin(), Payload.end());
        return Result;
    }

    auto MakeEchClientHello(std::string_view ServerName)
        -> std::vector<std::byte>
    {
        std::vector<std::uint8_t> Names{0};
        AppendU16(Names, ServerName.size());
        Names.insert(Names.end(), ServerName.begin(), ServerName.end());
        std::vector<std::uint8_t> Sni;
        AppendU16(Sni, Names.size());
        Sni.insert(Sni.end(), Names.begin(), Names.end());

        const std::vector<std::uint8_t> AlpnList{2, 'h', '2'};
        std::vector<std::uint8_t> AlpnPayload;
        AppendU16(AlpnPayload, AlpnList.size());
        AlpnPayload.insert(AlpnPayload.end(), AlpnList.begin(), AlpnList.end());
        const auto AlpnExtension = MakeExtension(0x0010, AlpnPayload);

        const auto SniExtension = MakeExtension(0x0000, Sni);
        const auto VersionsExtension = MakeExtension(0x002B, {0x02, 0x03, 0x04});
        const auto EchExtension = MakeExtension(0xFE0D, {0x01});
        std::vector<std::uint8_t> Extensions;
        for (const auto &Extension : {SniExtension, AlpnExtension, VersionsExtension, EchExtension})
        {
            Extensions.insert(Extensions.end(), Extension.begin(), Extension.end());
        }

        std::vector<std::uint8_t> Body{0x03, 0x03};
        Body.insert(Body.end(), 32, 0x42);
        Body.push_back(0);
        AppendU16(Body, 2);
        Body.push_back(0x13);
        Body.push_back(0x01);
        Body.push_back(1);
        Body.push_back(0);
        AppendU16(Body, Extensions.size());
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());

        std::vector<std::uint8_t> Handshake{0x01};
        AppendU24(Handshake, Body.size());
        Handshake.insert(Handshake.end(), Body.begin(), Body.end());
        std::vector<std::byte> Record{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x03},
            static_cast<std::byte>((Handshake.size() >> 8) & 0xFFU),
            static_cast<std::byte>(Handshake.size() & 0xFFU)};
        for (const auto Byte : Handshake)
        {
            Record.push_back(static_cast<std::byte>(Byte));
        }
        return Record;
    }

    auto MakeVmessUdpWire(const std::array<std::uint8_t, 16> &Uuid)
        -> std::vector<std::byte>
    {
        Preview::Vmess::Message Message;
        Message.uuid = Uuid;
        Message.Cmd = Preview::Vmess::CmdUdp;
        Message.dst = {Preview::Vmess::AddressType::Domain, "example.com", 443};
        for (std::size_t Index = 0; Index < Message.RequestNonce.size(); ++Index)
        {
            Message.RequestNonce[Index] = static_cast<std::uint8_t>(Index + 1U);
            Message.RequestKey[Index] = static_cast<std::uint8_t>(0xA0U + Index);
        }
        Message.RespHeader = 0x42;
        Preview::Vmess::Serializer Serializer(Uuid);
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
        Preview::Vless::RequestHeader Request;
        Request.Uuid = Uuid;
        Request.Cmd = Preview::Vless::Command::Udp;
        Request.Target = {Preview::Vless::AddressType::Domain, "example.com", 443};
        const auto Bytes = Preview::Vless::BuildRequest(Request);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Bytes.size())};
    }

    auto MakeTrojanUdpWire(const std::string_view Password) -> std::vector<std::byte>
    {
        const Preview::Trojan::Address Target{
            Preview::Trojan::AddressType::Domain, "example.com", 443};
        const auto Bytes = Preview::Trojan::BuildRequest(
            Preview::Trojan::Credential(Password),
            Preview::Trojan::Command::UdpAssociate, Target);
        return {reinterpret_cast<const std::byte *>(Bytes.data()),
                reinterpret_cast<const std::byte *>(Bytes.data() + Bytes.size())};
    }

    struct ConfiguredAdmissionResult final
    {
        bool Accepted{false};
        bool Datagram{false};
        bool TimedOut{false};
        std::exception_ptr Failure;
    };

    using AdmissionFinishedSignal = Net::experimental::channel<void(boost::system::error_code)>;

    struct ConfiguredAdmissionState final
    {
        std::shared_ptr<Preview::Contract::StreamFactory> Factory;
        std::vector<std::byte> Wire;
        std::shared_ptr<Preview::MemoryStream> Client;
        std::shared_ptr<Preview::MemoryStream> Server;
        std::shared_ptr<AdmissionFinishedSignal> Finished;
        std::shared_ptr<Net::steady_timer> Deadline;
        ConfiguredAdmissionResult Result;
    };

    auto RunConfiguredAdmissionOperation(
        const std::shared_ptr<ConfiguredAdmissionState> &State) -> Net::awaitable<void>
    {
        std::error_code Error;
        const auto Written = co_await State->Client->async_write_some(
            std::span<const std::byte>(State->Wire.data(), State->Wire.size()), Error);
        if (Error || Written != State->Wire.size())
        {
            co_return;
        }
        auto Outcome = co_await State->Factory->Accept(State->Server, {});
        State->Result.Accepted = static_cast<bool>(Outcome);
        if (Outcome)
        {
            State->Result.Datagram = Outcome->IsDatagram() && Outcome->Datagram()->Session;
            if (const auto *Datagram = Outcome->Datagram(); Datagram && Datagram->Session)
            {
                Datagram->Session->Close();
            }
            if (const auto Transport = Outcome->Transport())
            {
                Transport->Close();
            }
            Outcome = std::unexpected(Preview::Error::NotOpen);
        }
        State->Client->Close();
        State->Server->Close();
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
        const std::shared_ptr<Preview::Contract::StreamFactory> &Factory,
        const std::vector<std::byte> &Wire) -> ConfiguredAdmissionResult
    {
        Net::io_context Io;
        auto [ClientValue, ServerValue] = Preview::MakeMemoryPair(Io.get_executor());
        auto State = std::make_shared<ConfiguredAdmissionState>();
        State->Factory = Factory;
        State->Wire = Wire;
        State->Client = std::make_shared<Preview::MemoryStream>(std::move(ClientValue));
        State->Server = std::make_shared<Preview::MemoryStream>(std::move(ServerValue));
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
        Preview::Recognition::CandidateId Id;
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

    auto VerifyConfiguredPair(
        Composition::CandidateRegistry &Registry,
        ConfiguredPairInput Input) -> void
    {
        const auto Disabled = MakeBindingDefinition(
            BindingDefinitionInput{80, std::string(Input.Protocol) + "-disabled", Input.Protocol,
                                   Input.ProtocolId, "binding-disabled", false});
        const auto Enabled = MakeBindingDefinition(
            BindingDefinitionInput{81, std::string(Input.Protocol) + "-enabled", Input.Protocol,
                                   Input.ProtocolId, "binding-enabled", true});
        const auto DisabledBinding = Registry.Build(Disabled);
        const auto EnabledBinding = Registry.Build(Enabled);
        EXPECT_TRUE(DisabledBinding.has_value());
        EXPECT_TRUE(EnabledBinding.has_value());
        if (!DisabledBinding || !EnabledBinding)
        {
            return;
        }

        for (const auto UdpFirst : {false, true})
        {
            const auto *First = &DisabledBinding;
            const auto *Second = &EnabledBinding;
            if (UdpFirst)
            {
                std::swap(First, Second);
            }
            const auto FirstResult = RunConfiguredAdmission((*First)->Accept, Input.Wire);
            const auto SecondResult = RunConfiguredAdmission((*Second)->Accept, Input.Wire);
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
        }
    }

} // namespace

TEST(CandidateRegistry, NormalizesProtocolNamesAndBuildsBinding)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("HTTP", MakeHttpBinding));

    Composition::CandidateDefinition Candidate;
    Candidate.Id = 11;
    Candidate.Name = "http-entry";
    Candidate.Protocol = "http";

    const auto Binding = Registry.Build(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Id, 11);
    EXPECT_EQ(Binding->Spec.Name, "http-entry");
    EXPECT_EQ(Binding->Spec.Protocol, Preview::Contract::ProtocolType::Http);
}

TEST(TrusttunnelCandidate, FailureResultPreservesTypedCodeAndNativeCause)
{
    const auto Native = std::make_error_code(std::errc::timed_out);
    const Preview::Fault::Failure Failure{Preview::Fault::Code::Timeout, Native};

    Preview::Recognition::CarrierAcceptResult Result;
    Result.Metadata.Carrier = "trusttunnel";
    Composition::Detail::SetTrusttunnelFailure(Result, Failure);

    EXPECT_EQ(Result.Code, Preview::Fault::Code::Timeout);
    EXPECT_EQ(Result.NativeError.value(), Native.value());
    EXPECT_STREQ(Result.NativeError.category().name(), Native.category().name());
    EXPECT_FALSE(Result.Transport);
    EXPECT_EQ(Result.Metadata.Carrier, "trusttunnel");
}

TEST(CandidateRegistry, DoesNotResolveRetiredShadowsocksName)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("ss2022", MakeHttpBinding));

    Composition::CandidateDefinition Candidate;
    Candidate.Id = 12;
    Candidate.Protocol = "shadowsocks";

    EXPECT_TRUE(Registry.Has("SS2022"));
    EXPECT_FALSE(Registry.Build(Candidate).has_value());
    Candidate.Protocol = "ss2022";
    EXPECT_TRUE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, RejectsDuplicateNormalizedProtocol)
{
    Composition::CandidateRegistry Registry;

    EXPECT_TRUE(Registry.Register("http", MakeHttpBinding));
    EXPECT_FALSE(Registry.Register("HTTP", MakeHttpBinding));
}

TEST(CandidateRegistry, DoesNotMergeDistinctRegisteredNames)
{
    Composition::CandidateRegistry Registry;

    EXPECT_TRUE(Registry.Register("shadowsocks", MakeHttpBinding));
    EXPECT_TRUE(Registry.Register("SS2022", MakeHttpBinding));
    EXPECT_FALSE(Registry.Register("ss2022", MakeHttpBinding));
}

TEST(CandidateRegistry, FactoryOwnsRegisteredBuilders)
{
    Composition::CandidateBuilder Factory;
    {
        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.Register("http", MakeHttpBinding));
        Factory = Registry.MakeFactory();
    }

    Composition::CandidateDefinition Candidate;
    Candidate.Id = 13;
    Candidate.Protocol = "http";

    EXPECT_TRUE(Factory);
    EXPECT_TRUE(Factory(Candidate).has_value());
}

TEST(CandidateRegistry, MissingProtocolReturnsNoBinding)
{
    Composition::CandidateRegistry Registry;
    Composition::CandidateDefinition Candidate;
    Candidate.Protocol = "vless";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
    EXPECT_FALSE(Registry.Has("vless"));
}

TEST(CandidateRegistry, RegistersCoreProtocolFactories)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(Registry.RegisterConfiguredProvider(
        "socks5",
        Composition::ProviderCandidateInputs{
            Preview::Composition::Provider::BoundInstance{
                "socks5", Preview::Contract::ProtocolType::Socks5,
                Preview::Testing::MakeSocks5Binding({})},
            {}}));
    ASSERT_TRUE(Registry.RegisterConfigured("vless", MakeVlessBinding));
    ASSERT_TRUE(Registry.RegisterConfigured("trojan", MakeTrojanBinding));
    ASSERT_TRUE(Registry.RegisterConfigured("vmess", MakeVmessBinding));
    ASSERT_TRUE(Registry.RegisterConfiguredProvider(
        "ss2022",
        Composition::ProviderCandidateInputs{
            Preview::Composition::Provider::BoundInstance{
                "ss2022", Preview::Contract::ProtocolType::Shadowsocks,
                Preview::Testing::MakeSs2022Binding(
                    Preview::Shadowsocks2022::ServerConfig{Preview::Testing::Ss2022FixturePsk})},
            {}}));

    std::array<Composition::CandidateDefinition, 6> Candidates{
        Composition::CandidateDefinition{1, "http", "http", 0, 0, false},
        Composition::CandidateDefinition{2, "socks5", "socks5", 0, 0, false},
        Composition::CandidateDefinition{3, "vless", "vless", 0, 0, false},
        Composition::CandidateDefinition{4, "trojan", "trojan", 0, 0, false},
        Composition::CandidateDefinition{5, "vmess", "vmess", 0, 0, false},
        Composition::CandidateDefinition{6, "ss2022", "ss2022", 0, 0, false},
    };
    Candidates[0].ProtocolId = "http";
    Candidates[1].ProtocolId = "socks5";
    Candidates[2].ProtocolId = "vless";
    Candidates[3].ProtocolId = "trojan";
    Candidates[4].ProtocolId = "vmess";
    Candidates[5].ProtocolId = "ss2022";

    for (const auto &Candidate : Candidates)
    {
        const auto Binding = Registry.Build(Candidate);
        ASSERT_TRUE(Binding.has_value()) << Candidate.Protocol;
        EXPECT_EQ(Binding->Spec.Id, Candidate.Id);
        EXPECT_TRUE(Binding->Accept);
        EXPECT_TRUE(Binding->Spec.Inspect);
        EXPECT_TRUE(Binding->Spec.Commit);
    }
}

TEST(CandidateRegistry, ComposesRegisteredCarrierWithCoreCandidate)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(RegisterDefaultCarrier(Registry, "native"));

    Composition::CandidateDefinition Candidate{17, "native-http", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "native";
    Candidate.ServerNames = {"example.com"};
    Candidate.Alpn = {"h2"};

    const auto Binding = Registry.Build(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Kind, Core::CandidateKind::TlsCarrier);
    EXPECT_EQ(Binding->Spec.Protocol, Preview::Contract::ProtocolType::Http);
    EXPECT_EQ(Binding->Spec.Scheme, "native");
    EXPECT_TRUE(Binding->Accept);
}

TEST(CandidateRegistry, RejectsUnregisteredCarrierInsteadOfPassthrough)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));

    Composition::CandidateDefinition Candidate{18, "missing-carrier", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "reality";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
    EXPECT_FALSE(Registry.RegisterTlsCarrier(
        {Preview::Composition::Protocol::ProviderCategory::TlsCarrier,
            Preview::Composition::Protocol::CarrierKind::TrustTunnel},
        "trusttunnel", MakeCarrierRegistration()));
}

TEST(CandidateRegistry, RejectsUnknownConfiguredCarrierId)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(RegisterDefaultCarrier(Registry, "native"));

    Composition::CandidateDefinition Candidate{21, "unknown-id", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "native";
    Candidate.CarrierId = "carrier-missing";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, RejectsSchemeMismatchFromPrebuiltTlsBinding)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register(
        "http",
        [](const auto &Candidate) -> std::optional<Composition::CandidateBinding>
        {
            auto Binding = Composition::CandidateFactory::MakeHttp(
                Composition::CandidateOptions{Candidate.Id, Candidate.Name, Candidate.Priority, Candidate.Tier,
                                              Candidate.Fallback},
                Preview::Testing::MakeHttp1Binding());
            Binding.Spec.Kind = Core::CandidateKind::TlsCarrier;
            Binding.Spec.Scheme = "reality";
            return Binding;
        }));

    Composition::CandidateDefinition Candidate{19, "mismatch", "http", 0, 0, false};
    Candidate.Scheme = "native";

    EXPECT_FALSE(Registry.Build(Candidate).has_value());
}

TEST(CandidateRegistry, FactoryOwnsCarrierBuilders)
{
    Composition::CandidateBuilder Factory;
    {
        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
        ASSERT_TRUE(RegisterDefaultCarrier(Registry, "native"));
        Factory = Registry.MakeFactory();
    }

    Composition::CandidateDefinition Candidate{20, "owned", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "native";
    const auto Binding = Factory(Candidate);

    ASSERT_TRUE(Binding.has_value());
    EXPECT_EQ(Binding->Spec.Kind, Core::CandidateKind::TlsCarrier);
    EXPECT_EQ(Binding->Spec.Scheme, "native");
}

TEST(CandidateRegistry, RejectsEchForRegisteredNonNativeCarrier)
{
    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.RegisterConfigured("http", MakeHttpBinding));
    ASSERT_TRUE(RegisterDefaultCarrier(Registry, "ws"));

    Composition::CandidateDefinition Candidate{23, "ws-ech", "http", 0, 0, false};
    Candidate.ProtocolId = "http";
    Candidate.Scheme = "ws";
    Candidate.ServerNames = {"edge.example"};
    Candidate.Alpn = {"h2"};
    const auto Binding = Registry.Build(Candidate);
    ASSERT_TRUE(Binding.has_value());

    const auto Record = MakeEchClientHello("edge.example");
    const auto Bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(Record.data()), Record.size());
    const auto [ParseError, Features] = Core::ParseClientHelloProgress(Bytes);
    ASSERT_EQ(ParseError, Preview::Error::None);
    ASSERT_TRUE(Features.HasEch);
    Preview::Recognition::ProbeBuffer Buffer(64 * 1024);
    ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Record.data(), Record.size())));

    EXPECT_EQ(Binding->Spec.Inspect(Buffer.Snapshot()), Core::MatchState::Rejected);
}

TEST(CandidateRegistry, ConfiguredVlessTrojanVmessCarryBindingUdpPolicy)
{
    const auto Uuid = std::array<std::uint8_t, 16>{
        0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
        0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    Preview::Account::UuidBytes UuidCredential{};
    for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
    {
        UuidCredential[Index] = static_cast<std::byte>(Uuid[Index]);
    }

    auto VlessAuthenticator = Preview::Testing::ProviderAccount(Preview::Account::Credential::Uuid(UuidCredential), Preview::AccountId{1U}, {})->Authenticator;
    Composition::CandidateRegistry Registry;
    auto VlessOwner = std::make_shared<const Preview::Vless::Binding>(Preview::Vless::Binding{
        Preview::Vless::PreparedBinding{"vless-instance", Uuid, VlessAuthenticator, {}, true}});
    Composition::Provider::ProviderCandidateInputs VlessInputs{
        Composition::Provider::BoundInstance{"vless-instance", Preview::Contract::ProtocolType::Vless,
            std::move(VlessOwner)}, {}};
    ASSERT_TRUE(Registry.RegisterConfiguredProvider("vless-instance", std::move(VlessInputs)));

    const std::string TrojanPassword{"configured-trojan-password"};
    Preview::Trojan::ServerConfig TrojanConfiguration;
    TrojanConfiguration.Password = TrojanPassword;
    auto TrojanAuthenticator = Preview::Testing::ProviderAccount(Preview::Account::Credential::Token(Preview::Trojan::Credential(TrojanPassword)), Preview::AccountId{1U}, {})->Authenticator;
    auto TrojanOwner = std::make_shared<const Preview::Trojan::Binding>(Preview::Trojan::Binding{
        Preview::Trojan::PreparedBinding{"trojan-instance", std::move(TrojanConfiguration),
            TrojanAuthenticator, {}}});
    Composition::Provider::ProviderCandidateInputs TrojanInputs{
        Composition::Provider::BoundInstance{"trojan-instance", Preview::Contract::ProtocolType::Trojan,
            std::move(TrojanOwner)}, {}};
    ASSERT_TRUE(Registry.RegisterConfiguredProvider("trojan-instance", std::move(TrojanInputs)));

    auto VmessAccounts = Preview::Testing::ProviderAccount(
        Preview::Account::Credential::Uuid(UuidCredential));
    ASSERT_TRUE(VmessAccounts->Store->FindById(Preview::AccountId{1}));
    auto VmessOwner = std::make_shared<const Preview::Vmess::Binding>(Preview::Vmess::Binding{
        Preview::Vmess::PreparedBinding{"vmess-instance", Uuid, VmessAccounts->Authenticator,
            VmessAccounts->Credentials, {}, true}});
    Composition::Provider::ProviderCandidateInputs VmessInputs{
        Composition::Provider::BoundInstance{"vmess-instance", Preview::Contract::ProtocolType::Vmess,
            std::move(VmessOwner)}, {}};
    ASSERT_TRUE(Registry.RegisterConfiguredProvider("vmess-instance", std::move(VmessInputs)));

    VerifyConfiguredPair(
        Registry, ConfiguredPairInput{"vless", "vless-instance", MakeVlessUdpWire(Uuid)});
    VerifyConfiguredPair(
        Registry, ConfiguredPairInput{"trojan", "trojan-instance", MakeTrojanUdpWire(TrojanPassword)});
    VerifyConfiguredPair(
        Registry, ConfiguredPairInput{"vmess", "vmess-instance", MakeVmessUdpWire(Uuid)});
}
