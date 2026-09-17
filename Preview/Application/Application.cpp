/**
 * @file Application.cpp
 * @brief PrismPreview 应用启动与生命周期实现。
 */

#include "Application.hpp"

#include <Preview/Account/Account.hpp>
#include <Preview/Application/Configuration/Configuration.hpp>
#include <Preview/Composition/Adapters/Anytls.hpp>
#include <Preview/Composition/AnytlsService.hpp>
#include <Preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <Preview/Composition/Quic/Hysteria2Factory.hpp>
#include <Preview/Composition/Quic/TuicFactory.hpp>
#include <Preview/Composition/UdpService.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Preview/Composition/Protocol/ProtocolCatalog.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/SettingsBuilder.hpp>
#include <Preview/Composition/Recognition/ShadowtlsCarrier.hpp>
#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Operations/HttpServer.hpp>
#include <Preview/Operations/Models.hpp>
#include <Preview/Statistics/EventRing.hpp>
#include <Preview/Foundation/Utility/Diagnose/Context.hpp>
#include <Preview/Foundation/Utility/Diagnose/Logger.hpp>
#include <Preview/Ingress/IngressDispatcher.hpp>
#include <Preview/Ingress/QuicAdmissionContext.hpp>
#include <Preview/Ingress/QuicCidRegistry.hpp>
#include <Preview/Ingress/QuicGateway.hpp>
#include <Preview/Ingress/Ss2022Gateway.hpp>
#include <Preview/Ingress/UdpListener.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>
#include <Preview/Protocols/Socks5/Conn.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>
#include <Preview/Transport/Encrypted.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Process.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Composition/MuxService.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <csignal>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <span>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Application
{

    namespace Net = boost::asio;
    namespace Configuration = Preview::Application::Configuration;
    namespace Builtin = Preview::Composition::Builtin;
    namespace Recognition = Preview::Composition::Recognition;
    namespace Core = Preview::Recognition;
    namespace Settings = Preview::Settings;

    namespace
    {

        using ProtocolAcceptFn = Preview::Runtime::SessionServices::ProtocolAcceptFn;

        enum class RuntimePhase : std::uint8_t
        {
            Created,
            Ready,
            Stopping,
            Stopped,
            Failed,
        };

        [[nodiscard]] auto MakeStartupError(const StartupErrorCode Code,
                                            std::string Path,
                                            std::string Message) -> StartupError
        {
            return StartupError{Code, std::move(Path), std::move(Message)};
        }

        [[nodiscard]] auto DescribeException(const std::exception_ptr &Failure) -> std::string
        {
            if (!Failure)
            {
                return {};
            }
            try
            {
                std::rethrow_exception(Failure);
            }
            catch (const std::exception &Error)
            {
                return Error.what();
            }
            catch (...)
            {
                return "unknown exception";
            }
        }

        [[nodiscard]] auto ApplicationCapabilities() -> Builtin::CapabilitySet
        {
            auto Result = Builtin::ProtocolBuiltinCapabilities();
            Result.Add(Builtin::Capability::Observability);
            return Result;
        }

        [[nodiscard]] auto RequiredCapabilities(
            const Configuration::PreviewConfiguration &ConfigurationValue)
            -> std::expected<Builtin::CapabilitySet, StartupError>
        {
            Builtin::CapabilitySet Result;
            for (const auto &Name : ConfigurationValue.Runtime.RequiredCapabilities)
            {
                const auto CapabilityValue =
                    Configuration::ConfigurationValidator::CapabilityFromName(Name);
                if (!CapabilityValue)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Runtime.RequiredCapabilities",
                        "unknown Preview capability: " + Name));
                }
                Result.Add(*CapabilityValue);
            }
            return Result;
        }

        [[nodiscard]] auto MapDialFailure(const std::error_code &Error)
            -> Preview::Fault::Code
        {
            if (!Error)
            {
                return Preview::Fault::Code::BadGateway;
            }
            if (Error == std::make_error_code(std::errc::timed_out))
            {
                return Preview::Fault::Code::Timeout;
            }
            if (Error == std::make_error_code(std::errc::connection_refused))
            {
                return Preview::Fault::Code::ConnectionRefused;
            }
            if (Error == std::make_error_code(std::errc::no_such_file_or_directory))
            {
                return Preview::Fault::Code::DnsFailed;
            }
            if (Error == std::make_error_code(std::errc::network_unreachable))
            {
                return Preview::Fault::Code::NetNoreply;
            }
            if (Error == std::make_error_code(std::errc::host_unreachable))
            {
                return Preview::Fault::Code::HostNoreply;
            }
            if (Error == std::make_error_code(std::errc::operation_canceled))
            {
                return Preview::Fault::Code::Canceled;
            }
            return Preview::Fault::Code::Unreachable;
        }

        [[nodiscard]] auto ParseTargetPort(const std::string &PortText)
            -> std::optional<std::uint16_t>
        {
            std::uint32_t Port = 0;
            const auto [End, Error] = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port);
            if (Error != std::errc{} || End != PortText.data() + PortText.size() ||
                Port == 0U || Port > 65535U)
            {
                return std::nullopt;
            }
            return static_cast<std::uint16_t>(Port);
        }

        enum class StaticProtocol : std::uint8_t
        {
            Http,
            Socks5,
            Vless,
            Trojan,
            Vmess,
            Shadowsocks2022,
            AnyTls,
        };

        [[nodiscard]] auto ParseStaticProtocol(const std::string_view Name)
            -> std::optional<StaticProtocol>
        {
            const auto Descriptor = Preview::Composition::Protocol::ProtocolCatalog::Find(Name);
            if (!Descriptor || Descriptor->Kind !=
                                  Preview::Composition::Protocol::DescriptorKind::Protocol ||
                !Descriptor->SupportsTcp)
            {
                return std::nullopt;
            }
            switch (Descriptor->Id)
            {
            case Preview::Recognition::ProtocolType::Http: return StaticProtocol::Http;
            case Preview::Recognition::ProtocolType::Socks5: return StaticProtocol::Socks5;
            case Preview::Recognition::ProtocolType::Vless: return StaticProtocol::Vless;
            case Preview::Recognition::ProtocolType::Trojan: return StaticProtocol::Trojan;
            case Preview::Recognition::ProtocolType::Vmess: return StaticProtocol::Vmess;
            case Preview::Recognition::ProtocolType::Shadowsocks:
                return StaticProtocol::Shadowsocks2022;
            case Preview::Recognition::ProtocolType::AnyTls: return StaticProtocol::AnyTls;
            default: return std::nullopt;
            }
        }

        [[nodiscard]] auto IsQuicProtocolName(const std::string_view Name) noexcept -> bool
        {
            return Name == "hysteria2" || Name == "tuic";
        }

        [[nodiscard]] auto ConfiguredMuxMode(
            const Configuration::PreviewConfiguration &ConfigurationValue)
            -> Preview::Composition::MuxMode
        {
            for (const auto &Binding : ConfigurationValue.ProtocolBindings)
            {
                for (const auto &Mode : Binding.MuxModes)
                {
                    if (Mode == "H2Mux")
                    {
                        return Preview::Composition::MuxMode::H2Mux;
                    }
                    if (Mode == "Yamux")
                    {
                        return Preview::Composition::MuxMode::Yamux;
                    }
                    if (Mode == "Smux")
                    {
                        return Preview::Composition::MuxMode::Smux;
                    }
                }
            }
            return Preview::Composition::MuxMode::Auto;
        }

        [[nodiscard]] auto ParseHexDigit(const char Character) noexcept -> int
        {
            if (Character >= '0' && Character <= '9')
            {
                return Character - '0';
            }
            if (Character >= 'a' && Character <= 'f')
            {
                return Character - 'a' + 10;
            }
            if (Character >= 'A' && Character <= 'F')
            {
                return Character - 'A' + 10;
            }
            return -1;
        }

        [[nodiscard]] auto ParseUuid(const std::string_view Text)
            -> std::optional<std::array<std::uint8_t, 16>>
        {
            std::array<std::uint8_t, 16> Result{};
            std::size_t Output = 0;
            int High = -1;
            for (const char Character : Text)
            {
                if (Character == '-')
                {
                    continue;
                }
                const auto Digit = ParseHexDigit(Character);
                if (Digit < 0 || Output >= Result.size())
                {
                    return std::nullopt;
                }
                if (High < 0)
                {
                    High = Digit;
                }
                else
                {
                    Result[Output++] = static_cast<std::uint8_t>((High << 4) | Digit);
                    High = -1;
                }
            }
            if (Output != Result.size() || High >= 0)
            {
                return std::nullopt;
            }
            return Result;
        }

        [[nodiscard]] auto ProtocolCredentialKey(const StaticProtocol Protocol) noexcept
            -> std::string_view
        {
            switch (Protocol)
            {
            case StaticProtocol::Http: return "Http";
            case StaticProtocol::Socks5: return "Socks5";
            case StaticProtocol::Vless: return "Vless";
            case StaticProtocol::Trojan: return "Trojan";
            case StaticProtocol::Vmess: return "Vmess";
            case StaticProtocol::Shadowsocks2022: return "Shadowsocks2022";
            case StaticProtocol::AnyTls: return "AnyTls";
            }
            return {};
        }

        [[nodiscard]] auto CredentialForProtocol(
            const Configuration::AccountConfiguration &Configured,
            const StaticProtocol Protocol) -> std::string_view
        {
            const auto Key = ProtocolCredentialKey(Protocol);
            if (const auto It = Configured.Credentials.find(std::string(Key));
                It != Configured.Credentials.end())
            {
                return It->second;
            }
            return Configured.Credential;
        }

        [[nodiscard]] auto ResolvedCredentialForProtocol(
            const Configuration::ConfigurationGeneration &Generation,
            const Configuration::AccountConfiguration &Configured,
            const StaticProtocol Protocol) -> std::expected<std::string_view, StartupError>
        {
            const auto Key = ProtocolCredentialKey(Protocol);
            if (const auto It = Configured.Credentials.find(std::string(Key));
                It != Configured.Credentials.end())
            {
                return It->second;
            }
            if (Configured.SecretRef.empty())
            {
                return Configured.Credential;
            }
            const auto Secret = Generation.LookupSecret(Configured.SecretRef);
            if (Secret.empty())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::Generation,
                    "Accounts." + Configured.Id + ".SecretRef",
                    "configuration generation does not contain the resolved secret"));
            }
            return std::string_view(reinterpret_cast<const char *>(Secret.data()), Secret.size());
        }

        [[nodiscard]] auto MakeAccountCredential(
            const Configuration::AccountConfiguration &Configured,
            const StaticProtocol Protocol) -> std::expected<Preview::Account::Credential, StartupError>
        {
            const auto Credential = CredentialForProtocol(Configured, Protocol);
            switch (Protocol)
            {
            case StaticProtocol::Http:
            case StaticProtocol::Socks5:
            case StaticProtocol::AnyTls:
                return Preview::Account::Credential::Password(Credential);
            case StaticProtocol::Trojan:
                return Preview::Account::Credential::Token(
                    Preview::Trojan::Credential(Credential));
            case StaticProtocol::Vless:
            case StaticProtocol::Vmess:
            {
                const auto Uuid = ParseUuid(Credential);
                if (!Uuid)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Accounts." + Configured.Id + ".Credential",
                        "VLESS and VMess credentials must be 16-byte UUID text"));
                }
                Preview::Account::UuidBytes Bytes{};
                for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
                {
                    Bytes[Index] = static_cast<std::byte>((*Uuid)[Index]);
                }
                return Preview::Account::Credential::Uuid(Bytes);
            }
            case StaticProtocol::Shadowsocks2022:
            {
                const auto Psk = Preview::Shadowsocks2022::DecodePsk(Credential);
                if (!Psk)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Accounts." + Configured.Id + ".Credential",
                        "Shadowsocks2022 credentials must be Base64-encoded 16-byte PSKs"));
                }
                const std::string PskBytes(
                    reinterpret_cast<const char *>(Psk->data()), Psk->size());
                return Preview::Account::Credential::Psk(PskBytes);
            }
            }
            return std::unexpected(MakeStartupError(
                StartupErrorCode::UnsupportedService,
                "Protocols[0]",
                "configured TCP protocol has no Preview factory"));
        }

        [[nodiscard]] auto DialTarget(
            Net::any_io_executor Executor,
            const std::chrono::milliseconds Timeout,
            Preview::Network::Target Target)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            const std::string Host(Target.Host.data(), Target.Host.size());
            const std::string PortText(Target.Port.data(), Target.Port.size());
            const auto Port = ParseTargetPort(PortText);
            if (Host.empty() || !Port)
            {
                co_return std::pair{Preview::Fault::Code::InvalidArgument,
                                    Preview::SharedTransmission{}};
            }

            Preview::Network::Dialer::Dialer Dialer(
                std::move(Executor),
                Preview::Network::Dialer::DialOptions{Timeout, true});
            std::error_code Error;
            auto Outbound = co_await Dialer.Connect(Host, *Port, Error);
            if (!Outbound)
            {
                co_return std::pair{MapDialFailure(Error), Preview::SharedTransmission{}};
            }
            co_return std::pair{Preview::Fault::Code::Success, std::move(Outbound)};
        }

        struct ResolverDialRequest final
        {
            Net::any_io_executor Executor;
            std::chrono::milliseconds Timeout;
            std::shared_ptr<Preview::Network::Dns::Resolver> Resolver;
            Preview::Network::Target Target;
        };

        [[nodiscard]] auto DialTargetWithResolver(ResolverDialRequest Request)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            const std::string Host(Request.Target.Host.data(), Request.Target.Host.size());
            const std::string PortText(Request.Target.Port.data(), Request.Target.Port.size());
            const auto Port = ParseTargetPort(PortText);
            if (Host.empty() || !Port)
            {
                co_return std::pair{Preview::Fault::Code::InvalidArgument,
                                    Preview::SharedTransmission{}};
            }

            std::error_code ResolveError;
            std::vector<Net::ip::address> Addresses;
            if (Request.Resolver)
            {
                Addresses = co_await Request.Resolver->AsyncResolve(Host, ResolveError);
                if (Addresses.empty())
                {
                    co_return std::pair{MapDialFailure(ResolveError),
                                        Preview::SharedTransmission{}};
                }
            }
            else
            {
                boost::system::error_code LiteralError;
                const auto Literal = Net::ip::make_address(Host, LiteralError);
                if (!LiteralError)
                {
                    Addresses.push_back(Literal);
                }
            }

            std::error_code LastError = ResolveError;
            for (const auto &Address : Addresses)
            {
                if (Address.is_v6())
                {
                    continue;
                }
                Preview::Network::Dialer::Dialer Dialer(
                    Request.Executor,
                    Preview::Network::Dialer::DialOptions{Request.Timeout, false});
                std::error_code Error;
                auto Outbound = co_await Dialer.Connect(Address.to_string(), *Port, Error);
                if (Outbound)
                {
                    co_return std::pair{Preview::Fault::Code::Success, std::move(Outbound)};
                }
                LastError = Error;
            }
            co_return std::pair{MapDialFailure(LastError), Preview::SharedTransmission{}};
        }

        [[nodiscard]] auto ResolveUdpTarget(
            std::shared_ptr<Preview::Network::Dns::Resolver> DnsResolver,
            Preview::Composition::UdpResolveRequest Request)
            -> Net::awaitable<std::pair<Preview::Error, Net::ip::udp::endpoint>>
        {
            if (Request.Host.empty() || Request.Port == 0U)
            {
                co_return std::pair{Preview::Error::BadAddress, Net::ip::udp::endpoint{}};
            }
            if (DnsResolver)
            {
                std::error_code ResolveError;
                auto Addresses = co_await DnsResolver->AsyncResolve(Request.Host, ResolveError);
                if (ResolveError || Addresses.empty())
                {
                    co_return std::pair{Preview::Error::BadAddress, Net::ip::udp::endpoint{}};
                }
                co_return std::pair{
                    Preview::Error::None, Net::ip::udp::endpoint(Addresses.front(), Request.Port)};
            }

            boost::system::error_code AddressError;
            const auto Address = Net::ip::make_address(Request.Host, AddressError);
            if (AddressError)
            {
                co_return std::pair{Preview::Error::BadAddress, Net::ip::udp::endpoint{}};
            }
            co_return std::pair{Preview::Error::None,
                                Net::ip::udp::endpoint(Address, Request.Port)};
        }

        [[nodiscard]] auto MakeDnsConfig(
            const Configuration::DnsConfiguration &Configured) -> Preview::Network::Dns::Config
        {
            Preview::Network::Dns::Config Result;
            Result.TimeoutMs = Configured.Timeout;
            Result.DisableIpv6 = true;
            for (const auto &Server : Configured.Servers)
            {
                Result.Servers.push_back(Preview::Network::Dns::ParseServer(Server));
            }
            return Result;
        }

        [[nodiscard]] auto AccountCredentialKindName(
            const Preview::Account::CredentialKind Kind) noexcept -> std::string_view
        {
            switch (Kind)
            {
            case Preview::Account::CredentialKind::Password: return "password";
            case Preview::Account::CredentialKind::Uuid: return "uuid";
            case Preview::Account::CredentialKind::Psk: return "psk";
            case Preview::Account::CredentialKind::Token: return "token";
            case Preview::Account::CredentialKind::Extension: return "extension";
            case Preview::Account::CredentialKind::Unknown: return "unknown";
            }
            return "unknown";
        }

        [[nodiscard]] auto DescribeAccountDirectory(
            const std::shared_ptr<const Preview::Account::AccountDirectory> &Directory) -> std::string
        {
            std::size_t Count = 0;
            std::string Kinds;
            if (Directory)
            {
                Directory->ForEach([&](const auto &Record)
                {
                    if (!Record)
                    {
                        return;
                    }
                    ++Count;
                    if (!Kinds.empty())
                    {
                        Kinds.push_back(',');
                    }
                    Kinds.append(AccountCredentialKindName(Record->Credential().Kind()));
                });
            }
            return "records=" + std::to_string(Count) + " kinds=" +
                   (Kinds.empty() ? std::string("none") : Kinds);
        }

        [[nodiscard]] auto FindStaticBuiltin(
            const std::shared_ptr<const Builtin::BuiltinSnapshot> &Snapshot,
            const Configuration::BuiltinConfiguration &Configured)
            -> const Builtin::RegisteredBuiltin *
        {
            if (!Snapshot)
            {
                return nullptr;
            }
            for (const auto &Entry : Snapshot->Entries())
            {
                if (Entry.Descriptor.Kind.Value() == Configured.Kind &&
                    Entry.Descriptor.Name.Value() == Configured.Name)
                {
                    return &Entry;
                }
            }
            return nullptr;
        }

        [[nodiscard]] auto ValidateSupportedServices(
            const Configuration::PreviewConfiguration &ConfigurationValue,
            const std::shared_ptr<const Builtin::BuiltinSnapshot> &Snapshot)
            -> std::expected<void, StartupError>
        {
            if (ConfigurationValue.Listeners.Tcp.size() != 1U)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Listeners.Tcp",
                    "PrismPreview requires exactly one configured TCP listener"));
            }
            if (ConfigurationValue.Listeners.Udp.size() > 1U ||
                ConfigurationValue.Listeners.Quic.size() > 1U)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Listeners",
                    "Preview uses one shared UDP socket; configure at most one Udp and one Quic endpoint"));
            }
            if (!ConfigurationValue.Listeners.Udp.empty() &&
                !ConfigurationValue.Listeners.Quic.empty())
            {
                const auto &Udp = ConfigurationValue.Listeners.Udp.front();
                const auto &Quic = ConfigurationValue.Listeners.Quic.front();
                if (Udp.Address != Quic.Address || Udp.Port != Quic.Port)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Listeners.Quic[0]",
                        "Udp and Quic must share the same address and numeric port"));
                }
            }
            if (ConfigurationValue.Protocols.empty())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Protocols",
                    "PrismPreview requires at least one configured TCP protocol"));
            }
            if (ConfigurationValue.Protocols.size() >= Core::CandidateBitmap::Capacity)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Protocols",
                    "PrismPreview supports at most 127 TCP protocol candidates"));
            }
            std::array<bool, 7> SeenProtocols{};
            std::array<bool, 2> SeenQuicProtocols{};
            std::optional<std::size_t> AnyTlsIndex;
            bool HasTcpProtocol = false;
            bool HasQuicProtocol = false;
            for (std::size_t Index = 0; Index < ConfigurationValue.Protocols.size(); ++Index)
            {
                const auto &Protocol = ConfigurationValue.Protocols[Index];
                const auto ProtocolValue = ParseStaticProtocol(Protocol.Name);
                const auto Path = "Protocols[" + std::to_string(Index) + "]";
                if (IsQuicProtocolName(Protocol.Builtin))
                {
                    if (Protocol.Name != Protocol.Builtin || !Protocol.Quic)
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::UnsupportedService,
                            Path,
                            "Hysteria2 and TUIC require a QUIC protocol configuration"));
                    }
                    const auto QuicIndex = Protocol.Builtin == "hysteria2" ? 0U : 1U;
                    if (SeenQuicProtocols[QuicIndex])
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::InvalidConfiguration,
                            Path + ".Builtin",
                            "duplicate QUIC protocol candidate"));
                    }
                    SeenQuicProtocols[QuicIndex] = true;
                    HasQuicProtocol = true;
                    continue;
                }
                if (Protocol.Name != Protocol.Builtin || !ProtocolValue)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        Path,
                        "PrismPreview only provides static TCP factories for http, socks5, vless, "
                        "trojan, vmess, shadowsocks2022 and anytls; Hysteria2 and TUIC require QUIC fronts"));
                }
                const auto ProtocolIndex = static_cast<std::size_t>(*ProtocolValue);
                if (SeenProtocols[ProtocolIndex])
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        Path,
                        "duplicate TCP protocol candidate"));
                }
                SeenProtocols[ProtocolIndex] = true;
                HasTcpProtocol = true;
                if (*ProtocolValue == StaticProtocol::AnyTls)
                {
                    AnyTlsIndex = Index;
                }
            }
            if (!HasTcpProtocol)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Protocols",
                    "PrismPreview requires at least one TCP protocol alongside QUIC protocols"));
            }
            if (HasQuicProtocol && ConfigurationValue.Listeners.Quic.empty())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Listeners.Quic",
                    "a configured Hysteria2 or TUIC protocol requires a QUIC listener"));
            }
            bool HasNativeCarrier = false;
            for (std::size_t Index = 0; Index < ConfigurationValue.Carriers.size(); ++Index)
            {
                const auto &Carrier = ConfigurationValue.Carriers[Index];
                if (Carrier.Builtin == "reality" || Carrier.Builtin == "restls")
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        "Carriers[" + std::to_string(Index) + "]",
                        Carrier.Builtin == "reality"
                            ? "Reality requires a complete TLS 1.3 wire engine and ClientHello mutation"
                            : "Restls requires a completed TLS handover before carrier commit"));
                }
                if (Carrier.Builtin != "native" && Carrier.Builtin != "ws" &&
                    Carrier.Builtin != "websocket" && Carrier.Builtin != "shadowtls" &&
                    Carrier.Builtin != "xhttp" && Carrier.Builtin != "gun")
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        "Carriers[" + std::to_string(Index) + "]",
                        "configured carrier has no Preview admission callback: " +
                            Carrier.Builtin));
                }
                if (const auto *Options =
                        std::get_if<Configuration::NativeTlsOptions>(&Carrier.Options);
                    Options != nullptr && !Options->CertificateFile.empty() &&
                    !Options->PrivateKeyFile.empty())
                {
                    HasNativeCarrier = true;
                }
            }
            if (AnyTlsIndex.has_value() &&
                !(ConfigurationValue.NativeTls.Enabled &&
                  !ConfigurationValue.NativeTls.CertificateFile.empty() &&
                  !ConfigurationValue.NativeTls.PrivateKeyFile.empty()) &&
                !HasNativeCarrier)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Protocols[" + std::to_string(*AnyTlsIndex) + "]",
                    "AnyTls requires an enabled NativeTls outer layer with certificate and key "
                    "or a native carrier with NativeTlsOptions certificate and key"));
            }
            if (HasQuicProtocol &&
                !(ConfigurationValue.NativeTls.Enabled &&
                  !ConfigurationValue.NativeTls.CertificateFile.empty() &&
                  !ConfigurationValue.NativeTls.PrivateKeyFile.empty()) &&
                !HasNativeCarrier)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Listeners.Quic",
                    "QUIC protocols require an enabled NativeTls certificate and private key"));
            }
            if (!ConfigurationValue.Routes.empty())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Routes",
                    "configured routes are not wired into PrismPreview startup"));
            }
            for (const auto &Configured : ConfigurationValue.Builtins)
            {
                const auto *Entry = FindStaticBuiltin(Snapshot, Configured);
                if (Entry == nullptr)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        "Builtins." + Configured.Id,
                        "configured builtin has no registered Preview implementation"));
                }
                if (!Snapshot->Invoke(Builtin::InvocationRequest{Entry->Id}))
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        "Builtins." + Configured.Id,
                        "configured builtin descriptor has no callable Preview callback"));
                }
            }
            return {};
        }

        [[nodiscard]] auto IsSampleCredential(const std::string_view Credential) noexcept -> bool
        {
            return Credential == "local-token" || Credential == "password" ||
                   Credential == "change-me" || Credential == "changeme";
        }

        [[nodiscard]] auto ValidateSampleCredentials(
            const Configuration::PreviewConfiguration &ConfigurationValue,
            const Net::ip::tcp::endpoint &Endpoint) -> std::expected<void, StartupError>
        {
            if (Endpoint.address().is_loopback())
            {
                return {};
            }
            for (const auto &Account : ConfigurationValue.Accounts)
            {
                if (Account.SecretRef.empty() && IsSampleCredential(Account.Credential))
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Accounts." + Account.Id + ".Credential",
                        "sample credentials are only allowed on a loopback TCP listener"));
                }
            }
            return {};
        }

        [[nodiscard]] auto MakeAccountDirectoryForProtocol(
            const Configuration::ConfigurationGeneration &Generation,
            const StaticProtocol Protocol)
            -> std::expected<std::shared_ptr<Preview::Account::AccountDirectory>, StartupError>
        {
            const auto &ConfigurationValue = Generation.Configuration();
            if (ConfigurationValue.Accounts.empty())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Accounts",
                    "at least one Preview account is required for an authenticated protocol"));
            }
            auto Directory = std::make_shared<Preview::Account::AccountDirectory>();
            std::uint64_t NextId = 1;
            for (const auto &Configured : ConfigurationValue.Accounts)
            {
                try
                {
                    auto Effective = Configured;
                    if (!Configured.SecretRef.empty())
                    {
                        const auto Secret = Generation.LookupSecret(Configured.SecretRef);
                        if (Secret.empty())
                        {
                            return std::unexpected(MakeStartupError(
                                StartupErrorCode::Generation,
                                "Accounts." + Configured.Id + ".SecretRef",
                                "configuration generation does not contain the resolved secret"));
                        }
                        Effective.SecretRef.clear();
                        Effective.Credential.assign(
                            reinterpret_cast<const char *>(Secret.data()), Secret.size());
                    }
                    auto Credential = MakeAccountCredential(Effective, Protocol);
                    if (!Credential)
                    {
                        return std::unexpected(Credential.error());
                    }
                    auto Record = std::make_shared<Preview::Account::AccountRecord>(
                            Preview::Account::AccountRecord::CreateRequest{
                                Preview::AccountId{NextId++},
                                std::move(*Credential),
                                Preview::Account::QuotaPolicy{},
                                Preview::Account::UnlimitedRatePolicy{},
                                Generation.Id()});
                    if (!Directory->Upsert(std::move(Record)))
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::Runtime,
                            "Accounts." + Configured.Id,
                            "typed Preview account directory rejected the account record"));
                    }
                }
                catch (const std::exception &Error)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::Runtime,
                        "Accounts." + Configured.Id,
                        "typed Preview account construction failed: " + std::string(Error.what())));
                }
            }
            return Directory;
        }

        [[nodiscard]] auto MakeAccountDirectory(
            const Configuration::ConfigurationGeneration &Generation)
            -> std::expected<std::shared_ptr<Preview::Account::AccountDirectory>, StartupError>
        {
            const auto &ConfigurationValue = Generation.Configuration();
            for (const auto &Configured : ConfigurationValue.Protocols)
            {
                if (const auto Protocol = ParseStaticProtocol(Configured.Name))
                {
                    return MakeAccountDirectoryForProtocol(Generation, *Protocol);
                }
            }
            return std::unexpected(MakeStartupError(
                StartupErrorCode::UnsupportedService,
                "Protocols",
                "configured protocols contain no Preview TCP account factory"));
        }

        [[nodiscard]] auto AccountMatchesQuicCredential(
            const Configuration::ConfigurationGeneration &Generation,
            const Configuration::AccountConfiguration &Account,
            const Configuration::ProtocolConfiguration &Protocol,
            const std::string_view Credential) -> bool
        {
            if (Protocol.Quic && Account.SecretRef == Protocol.Quic->CredentialSecretRef)
            {
                return true;
            }
            if (!Account.SecretRef.empty())
            {
                const auto Secret = Generation.LookupSecret(Account.SecretRef);
                if (!Secret.empty() && Preview::ConstantTimeEqual(
                                           std::string_view(
                                               reinterpret_cast<const char *>(Secret.data()),
                                               Secret.size()),
                                           Credential))
                {
                    return true;
                }
            }
            if (Preview::ConstantTimeEqual(Account.Credential, Credential))
            {
                return true;
            }
            if (Protocol.Quic)
            {
                if (const auto It = Account.Credentials.find(Protocol.Builtin);
                    It != Account.Credentials.end() &&
                    Preview::ConstantTimeEqual(It->second, Credential))
                {
                    return true;
                }
            }
            return false;
        }

        struct QuicCredentialContext final
        {
            std::shared_ptr<const Preview::Account::AccountDirectory> Directory;
            Preview::SharedAuthenticator Authenticator;
            std::shared_ptr<const Preview::Account::Credential> Credential;
            Preview::AccountId AccountId{};
        };

        [[nodiscard]] auto MakeQuicCredentialContext(
            const Configuration::ConfigurationGeneration &Generation,
            const Configuration::ProtocolConfiguration &Protocol)
            -> std::expected<QuicCredentialContext, StartupError>
        {
            if (!Protocol.Quic)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Protocols." + Protocol.Id + ".Quic",
                    "QUIC protocol options are required"));
            }
            const auto Secret = Generation.LookupSecret(Protocol.Quic->CredentialSecretRef);
            if (Secret.empty())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::Generation,
                    "Protocols." + Protocol.Id + ".Quic.CredentialSecretRef",
                    "configuration generation does not contain the resolved QUIC credential"));
            }
            const std::string CredentialText(
                reinterpret_cast<const char *>(Secret.data()), Secret.size());
            const auto &Accounts = Generation.Configuration().Accounts;
            std::optional<std::size_t> AccountIndex;
            for (std::size_t Index = 0; Index < Accounts.size(); ++Index)
            {
                if (AccountMatchesQuicCredential(Generation, Accounts[Index], Protocol,
                                                 CredentialText))
                {
                    AccountIndex = Index;
                    break;
                }
            }
            if (!AccountIndex)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Protocols." + Protocol.Id + ".Quic.CredentialSecretRef",
                    "QUIC credential must resolve to one configured account"));
            }

            auto Directory = std::make_shared<Preview::Account::AccountDirectory>();
            try
            {
                auto Record = std::make_shared<Preview::Account::AccountRecord>(
                    Preview::Account::AccountRecord::CreateRequest{
                        Preview::AccountId{static_cast<std::uint64_t>(*AccountIndex + 1U)},
                        Preview::Account::Credential::Token(CredentialText),
                        Preview::Account::QuotaPolicy{},
                        Preview::Account::UnlimitedRatePolicy{},
                        Generation.Id()});
                if (!Directory->Upsert(std::move(Record)))
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::Runtime,
                        "Protocols." + Protocol.Id + ".Quic.CredentialSecretRef",
                        "QUIC account directory rejected the credential record"));
                }
            }
            catch (const std::exception &Error)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::Runtime,
                    "Protocols." + Protocol.Id + ".Quic.CredentialSecretRef",
                    "QUIC account construction failed: " + std::string(Error.what())));
            }
            std::shared_ptr<const Preview::Account::AccountDirectory> PublishedDirectory = Directory;
            return QuicCredentialContext{
                std::move(PublishedDirectory),
                std::make_shared<Preview::Account::ProtocolAuthenticator>(Directory),
                std::make_shared<const Preview::Account::Credential>(
                    Preview::Account::Credential::Token(CredentialText)),
                Preview::AccountId{static_cast<std::uint64_t>(*AccountIndex + 1U)}};
        }

        [[nodiscard]] auto MakeQuicAdmissionContext(
            const Configuration::ConfigurationGeneration &Generation,
            const Configuration::ProtocolConfiguration &Protocol,
            const Net::any_io_executor &Executor,
            const std::shared_ptr<Preview::Network::Dns::Resolver> &Resolver,
            Preview::Middleware::Builtin::DialMiddleware::DialFn Dial,
            const std::shared_ptr<Preview::Foundation::TrafficSink> &Metrics)
            -> std::expected<Preview::Ingress::SharedQuicAdmissionContext, StartupError>
        {
            if (!Protocol.Quic || Protocol.Builtin != "hysteria2")
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Protocols." + Protocol.Id,
                    "only Hysteria2 is currently wired to the Native QUIC factory"));
            }
            const auto Credential = MakeQuicCredentialContext(Generation, Protocol);
            if (!Credential)
            {
                return std::unexpected(Credential.error());
            }

            auto Mutable = std::make_shared<Preview::Ingress::QuicAdmissionContext>();
            Mutable->AccountId = Credential->AccountId;
            Mutable->Credential = Credential->Credential;
            Mutable->Authenticator = Credential->Authenticator;
            Mutable->ExpectedAlpn = Protocol.Quic->Alpn;
            Mutable->ServerName = Protocol.Quic->ServerName;
            Mutable->MaxStreams = Protocol.Quic->MaxStreams;
            Mutable->MaxDatagrams = Protocol.Quic->MaxDatagrams;
            Mutable->Executor = Executor;
            Mutable->Resolver = Resolver;
            Mutable->Dial = std::move(Dial);
            Mutable->Metrics = Metrics;
            const Preview::Ingress::SharedQuicAdmissionContext Shared = Mutable;
            const std::weak_ptr<const Preview::Ingress::QuicAdmissionContext> Weak = Shared;

            Mutable->Hysteria2Stream = [Weak](Preview::Hysteria2::Message Message,
                                               Preview::Hysteria2::SharedConn Connection)
                -> Net::awaitable<void>
            {
                const auto Context = Weak.lock();
                if (!Context || !Connection || !Context->Dial || Message.dst.Host.empty() ||
                    Message.dst.Port == 0U)
                {
                    if (Connection)
                    {
                        Connection->Close();
                    }
                    co_return;
                }
                Preview::Network::Target Target;
                Target.Host.assign(Message.dst.Host.data(), Message.dst.Host.size());
                Target.Port.assign(std::to_string(Message.dst.Port));
                const auto AccountId = Connection->AccountId();
                auto Lease = Connection->TakeAuthLease();
                const auto Identity = std::string(Connection->Identity());
                auto [DialError, Outbound] = co_await Context->Dial(Target);
                if (Preview::Fault::Failed(DialError) || !Outbound)
                {
                    Connection->Close();
                    co_return;
                }

                Preview::Middleware::Context SessionContext;
                SessionContext.Inbound = std::move(Connection);
                SessionContext.Outbound = std::move(Outbound);
                SessionContext.Target = std::move(Target);
                SessionContext.AccountId = AccountId ? AccountId : Context->AccountId;
                SessionContext.AccountLease = std::move(Lease);
                SessionContext.Credential = Context->Credential;
                SessionContext.ProtocolAuthenticated = true;
                SessionContext.identity = Identity.empty()
                                               ? std::to_string(SessionContext.AccountId.Value())
                                               : Identity;
                SessionContext.traffic = Context->Metrics.get();
                Preview::Middleware::Builtin::RelayMiddleware Relay(
                    nullptr, std::chrono::milliseconds(0));
                (void)co_await Relay.Handle(SessionContext.Inbound, SessionContext);
            };

            Mutable->Hysteria2Datagram = [Weak](Preview::Hysteria2::SharedDgram Datagram)
                -> Net::awaitable<void>
            {
                const auto Context = Weak.lock();
                if (!Context || !Datagram)
                {
                    co_return;
                }
                using Udp = Net::ip::udp;
                Udp::socket Egress(Context->Executor);
                std::vector<std::byte> ReceiveBuffer(65535);
                std::size_t Uploaded = 0;
                std::size_t Downloaded = 0;
                while (true)
                {
                    Preview::Hysteria2::Address Target;
                    std::vector<std::uint8_t> Payload;
                    const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Target, Payload);
                    if (ReceiveError != Preview::Error::None)
                    {
                        break;
                    }
                    const auto Resolved = co_await ResolveUdpTarget(
                        Context->Resolver,
                        Preview::Composition::UdpResolveRequest{Target.Host, Target.Port});
                    if (Resolved.first != Preview::Error::None)
                    {
                        continue;
                    }
                    boost::system::error_code Error;
                    Egress.close(Error);
                    Egress.open(Resolved.second.protocol(), Error);
                    if (Error)
                    {
                        break;
                    }
                    co_await Egress.async_send_to(
                        Net::buffer(Payload), Resolved.second,
                        Net::redirect_error(Net::use_awaitable, Error));
                    if (Error)
                    {
                        break;
                    }
                    Uploaded += Payload.size();
                    Udp::endpoint Source;
                    const auto Size = co_await Egress.async_receive_from(
                        Net::buffer(ReceiveBuffer), Source,
                        Net::redirect_error(Net::use_awaitable, Error));
                    if (Error || Size == 0U)
                    {
                        break;
                    }
                    const auto SourceType = Source.address().is_v4()
                                                ? Preview::Hysteria2::AddressType::Ipv4
                                                : Preview::Hysteria2::AddressType::Ipv6;
                    const Preview::Hysteria2::Address ResponseTarget{
                        SourceType, Source.address().to_string(), Source.port()};
                    const auto SendError = co_await Datagram->AsyncSendTo(
                        ResponseTarget,
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t *>(ReceiveBuffer.data()), Size));
                    if (SendError != Preview::Error::None)
                    {
                        break;
                    }
                    Downloaded += Size;
                }
                boost::system::error_code Error;
                Egress.cancel(Error);
                Egress.close(Error);
                if (Context->Metrics)
                {
                    Context->Metrics->Report(
                        std::to_string(Context->AccountId.Value()), Uploaded, Downloaded);
                }
            };
            return Shared;
        }

        struct ProtocolFactoryContext final
        {
            const Configuration::PreviewConfiguration &ConfigurationValue;
            const Configuration::ConfigurationGeneration &Generation;
            std::array<Preview::SharedAuthenticator, 7> Authenticators;
            std::array<std::shared_ptr<const Preview::Account::AccountDirectory>, 7> Accounts;
            std::shared_ptr<Net::ssl::context> NativeTls;
            Preview::Middleware::Builtin::DialMiddleware::DialFn Dial;
        };

        [[nodiscard]] auto FirstAccount(
            const Configuration::PreviewConfiguration &ConfigurationValue)
            -> const Configuration::AccountConfiguration *
        {
            if (ConfigurationValue.Accounts.empty())
            {
                return nullptr;
            }
            return &ConfigurationValue.Accounts.front();
        }

        [[nodiscard]] auto FirstAccountPath(
            const Configuration::PreviewConfiguration &ConfigurationValue) -> std::string
        {
            const auto *Account = FirstAccount(ConfigurationValue);
            if (Account == nullptr)
            {
                return "Accounts";
            }
            return "Accounts." + Account->Id + ".Credential";
        }

        [[nodiscard]] auto MakeFirstUuid(
            const Configuration::ConfigurationGeneration &Generation,
            const StaticProtocol Protocol)
            -> std::expected<std::array<std::uint8_t, 16>, StartupError>
        {
            const auto &ConfigurationValue = Generation.Configuration();
            const auto *Account = FirstAccount(ConfigurationValue);
            if (Account == nullptr)
            {
                return std::array<std::uint8_t, 16>{};
            }
            const auto Credential = ResolvedCredentialForProtocol(Generation, *Account, Protocol);
            if (!Credential)
            {
                return std::unexpected(Credential.error());
            }
            const auto Uuid = ParseUuid(*Credential);
            if (!Uuid)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    FirstAccountPath(ConfigurationValue),
                    std::string(ProtocolCredentialKey(Protocol)) +
                    " credentials must be 16-byte UUID text"));
            }
            return *Uuid;
        }

        [[nodiscard]] auto MakeFirstPsk(
            const Configuration::ConfigurationGeneration &Generation)
            -> std::expected<std::array<std::uint8_t, 16>, StartupError>
        {
            const auto &ConfigurationValue = Generation.Configuration();
            const auto *Account = FirstAccount(ConfigurationValue);
            if (Account == nullptr)
            {
                return std::array<std::uint8_t, 16>{};
            }
            const auto Credential = ResolvedCredentialForProtocol(
                Generation, *Account, StaticProtocol::Shadowsocks2022);
            if (!Credential)
            {
                return std::unexpected(Credential.error());
            }
            const auto Psk = Preview::Shadowsocks2022::DecodePsk(*Credential);
            if (!Psk)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    FirstAccountPath(ConfigurationValue),
                    "Shadowsocks2022 credentials must be Base64-encoded 16-byte PSKs"));
            }
            return *Psk;
        }

        [[nodiscard]] auto CanonicalProtocolName(const StaticProtocol Protocol) noexcept
            -> std::string_view
        {
            switch (Protocol)
            {
            case StaticProtocol::Http: return "http";
            case StaticProtocol::Socks5: return "socks5";
            case StaticProtocol::Vless: return "vless";
            case StaticProtocol::Trojan: return "trojan";
            case StaticProtocol::Vmess: return "vmess";
            case StaticProtocol::Shadowsocks2022: return "ss2022";
            case StaticProtocol::AnyTls: return "anytls";
            }
            return {};
        }

        [[nodiscard]] auto ProtocolUdpEnabled(
            const Configuration::PreviewConfiguration &ConfigurationValue,
            const std::string_view ProtocolId) noexcept -> bool
        {
            for (const auto &Binding : ConfigurationValue.ProtocolBindings)
            {
                if (Binding.ProtocolId == ProtocolId)
                {
                    return Binding.UdpEnabled;
                }
            }
            return false;
        }

        [[nodiscard]] auto FindCarrier(
            const Configuration::PreviewConfiguration &ConfigurationValue,
            const std::string_view CarrierId) noexcept
            -> const Configuration::CarrierConfiguration *
        {
            const auto It = std::find_if(
                ConfigurationValue.Carriers.begin(), ConfigurationValue.Carriers.end(),
                [CarrierId](const auto &Carrier) { return Carrier.Id == CarrierId; });
            return It == ConfigurationValue.Carriers.end() ? nullptr : &*It;
        }

        [[nodiscard]] auto ClampCandidatePriority(const std::int32_t Priority) noexcept
            -> std::uint16_t
        {
            if (Priority <= 0)
            {
                return 0;
            }
            return static_cast<std::uint16_t>((std::min)(Priority, 65535));
        }

        auto AppendRecognitionCandidate(
            Settings::RecognitionConfig &Result,
            Core::CandidateId &CandidateId,
            const Configuration::ProtocolConfiguration &Configured,
            const std::string_view Scheme,
            const std::vector<std::string> &ServerNames,
            const std::vector<std::string> &Alpn,
            const std::uint16_t Priority,
            const bool Fallback,
            const std::string_view CarrierId = {}) -> void
        {
            if (CandidateId == Core::InvalidCandidate)
            {
                return;
            }
            const auto Protocol = ParseStaticProtocol(Configured.Name);
            if (!Protocol)
            {
                return;
            }
            Settings::RecognitionCandidate Candidate;
            Candidate.Id = CandidateId++;
            Candidate.Name = Configured.Id;
            Candidate.Protocol = std::string(CanonicalProtocolName(*Protocol));
            Candidate.Priority = Priority;
            Candidate.Fallback = Fallback;
            Candidate.Scheme = std::string(Scheme);
            Candidate.ServerNames = ServerNames;
            Candidate.Alpn = Alpn;
            Candidate.CarrierId = std::string(CarrierId);
            if (!Scheme.empty())
            {
                Candidate.Name += "+";
                Candidate.Name += Scheme;
            }
            Result.Candidates.push_back(std::move(Candidate));
        }

        [[nodiscard]] auto BindingRecognitionName(
            const Configuration::RecognitionRouteConfiguration &Recognition) noexcept
            -> std::string_view
        {
            return Recognition.Pattern.empty() ? std::string_view(Recognition.Domain)
                                               : std::string_view(Recognition.Pattern);
        }

        auto AppendBindingRecognitionRoute(
            Settings::RecognitionConfig &Result,
            const Configuration::RecognitionRouteConfiguration &Recognition,
            const Core::CandidateId Candidate) -> void
        {
            const auto Name = BindingRecognitionName(Recognition);
            if (!Name.empty())
            {
                Result.Routes.emplace_back(std::string(Name), Candidate);
            }
        }

        [[nodiscard]] auto MakeTcpRecognitionConfig(
            const Configuration::PreviewConfiguration &ConfigurationValue)
            -> Settings::RecognitionConfig
        {
            Settings::RecognitionConfig Result;
            Result.Explicit = true;
            if (ConfigurationValue.Recognition.Mode == "Configured")
            {
                Result.Mode = Core::RecognitionMode::Configured;
            }
            else if (ConfigurationValue.Recognition.Mode == "Deterministic" ||
                     ConfigurationValue.Recognition.Mode == "DeterministicRoute")
            {
                Result.Mode = Core::RecognitionMode::DeterministicRoute;
            }
            else
            {
                Result.Mode = Core::RecognitionMode::MixedTrial;
            }
            if (ConfigurationValue.Recognition.ConfiguredCandidate >= 0)
            {
                Result.ConfiguredCandidate = static_cast<Core::CandidateId>(
                    ConfigurationValue.Recognition.ConfiguredCandidate);
            }
            Result.Budget.MaxCandidates = static_cast<std::uint16_t>(Core::CandidateBitmap::Capacity);
            Result.Candidates.reserve(ConfigurationValue.ProtocolBindings.empty()
                                          ? ConfigurationValue.Protocols.size()
                                          : ConfigurationValue.ProtocolBindings.size());
            Core::CandidateId CandidateId = 1;
            bool HasDefaultCandidate = false;
            std::uint16_t DefaultPriority = 0;
            const auto SelectDefault = [&](const Core::CandidateId Candidate,
                                           const std::uint16_t Priority,
                                           const bool IsDefault)
            {
                if (IsDefault && (!HasDefaultCandidate || Priority > DefaultPriority))
                {
                    Result.DefaultCandidate = Candidate;
                    DefaultPriority = Priority;
                    HasDefaultCandidate = true;
                }
            };

            for (const auto &Configured : ConfigurationValue.Protocols)
            {
                if (ConfigurationValue.ProtocolBindings.empty())
                {
                    AppendRecognitionCandidate(Result, CandidateId, Configured, {}, {}, {}, 0, false);
                    continue;
                }

                bool HasTcpBinding = false;
                for (const auto &Binding : ConfigurationValue.ProtocolBindings)
                {
                    if (Binding.ProtocolId != Configured.Id || !Binding.TcpEnabled)
                    {
                        continue;
                    }
                    HasTcpBinding = true;
                    if (!Binding.CarrierId)
                    {
                        const auto BindingCandidate = CandidateId;
                        const auto Priority = ClampCandidatePriority(Binding.Priority);
                        AppendRecognitionCandidate(
                            Result, CandidateId, Configured, {}, {}, {},
                            Priority, Binding.Recognition.Fallback);
                        if (CandidateId != BindingCandidate)
                        {
                            AppendBindingRecognitionRoute(
                                Result, Binding.Recognition, BindingCandidate);
                            SelectDefault(
                                BindingCandidate, Priority, Binding.Recognition.Fallback);
                        }
                        continue;
                    }
                    const auto *Carrier = FindCarrier(ConfigurationValue, *Binding.CarrierId);
                    if (Carrier == nullptr)
                    {
                        continue;
                    }
                    const auto BindingCandidate = CandidateId;
                    const auto BindingRoute = BindingRecognitionName(Binding.Recognition);
                    const auto BindingPriority = ClampCandidatePriority(Binding.Priority);
                    const auto CarrierPriority = ClampCandidatePriority(Carrier->Match.Priority);
                    const auto Priority = (std::max)(BindingPriority, CarrierPriority);
                    const bool NativeFallback = Carrier->Builtin == "native" &&
                                                Carrier->Match.ServerNames.empty() &&
                                                Carrier->Match.Alpn.empty() &&
                                                BindingRoute.empty() &&
                                                !Binding.Recognition.Fallback;
                    AppendRecognitionCandidate(
                        Result, CandidateId, Configured, Carrier->Builtin,
                        Carrier->Match.ServerNames, Carrier->Match.Alpn,
                        Priority,
                        Binding.Recognition.Fallback || Carrier->Match.Fallback || NativeFallback,
                        Carrier->Id);
                    if (CandidateId != BindingCandidate)
                    {
                        AppendBindingRecognitionRoute(
                            Result, Binding.Recognition, BindingCandidate);
                        SelectDefault(
                            BindingCandidate, Priority, Binding.Recognition.Fallback);
                    }
                }
                if (!HasTcpBinding)
                {
                    continue;
                }
            }
            return Result;
        }

        [[nodiscard]] auto BuildProfileWithStaticProtocolMap(
            const Settings::RecognitionConfig &Config,
            Recognition::SettingsCandidateFactory Factory)
            -> std::expected<Recognition::ProfileBuildResult, Core::ProfileError>
        {
            if (!Factory)
            {
                return std::unexpected(Core::ProfileError::MissingResolver);
            }
            std::vector<Recognition::CandidateBinding> Bindings;
            Bindings.reserve(Config.Candidates.size());
            for (const auto &Source : Config.Candidates)
            {
                auto Candidate = Recognition::detail::WithRouteServerNames(Config, Source);
                const auto Protocol = ParseStaticProtocol(Candidate.Protocol);
                if (!Protocol)
                {
                    return std::unexpected(Core::ProfileError::MissingResolver);
                }
                auto Binding = Factory(Candidate);
                if (!Binding)
                {
                    return std::unexpected(Core::ProfileError::MissingResolver);
                }
                const auto Scheme = Preview::Settings::detail::NormalizeScheme(Candidate.Scheme);
                if (!Candidate.Scheme.empty() &&
                    (Scheme.empty() || Binding->Spec.Kind != Core::CandidateKind::TlsCarrier ||
                     Preview::Settings::detail::NormalizeScheme(Binding->Spec.Scheme) != Scheme))
                {
                    return std::unexpected(Core::ProfileError::MissingResolver);
                }
                Recognition::detail::ApplySettingsMetadata(Candidate, *Binding);
                Bindings.push_back(std::move(*Binding));
            }

            Recognition::ProfileBuilderOptions Options;
            Options.Mode = Config.Mode;
            Options.ConfiguredCandidate = Config.ConfiguredCandidate;
            Options.DefaultCandidate = Config.DefaultCandidate;
            Options.Budget = Config.Budget;
            Options.Routes = Config.Routes;
            return Recognition::ProfileBuilder::Build(std::move(Bindings), std::move(Options));
        }

        [[nodiscard]] auto RegisterTcpCandidate(
            Recognition::CandidateRegistry &Registry,
            const Configuration::ProtocolConfiguration &Configured,
            const ProtocolFactoryContext &Context) -> std::expected<void, StartupError>
        {
            const auto Protocol = ParseStaticProtocol(Configured.Name);
            if (!Protocol)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Protocols." + Configured.Id,
                    "configured TCP protocol has no Preview candidate factory"));
            }
            bool Registered = false;
            switch (*Protocol)
            {
            case StaticProtocol::Http: {
                Recognition::HttpConfig Config;
                Config.RequireAuth = false;
                Registered = Registry.RegisterHttp(std::move(Config));
                break;
            }
            case StaticProtocol::Socks5: {
                Preview::Socks5::ServerConfig Config;
                Config.EnableTcp = true;
                Config.EnableUdp = ProtocolUdpEnabled(
                    Context.ConfigurationValue, Configured.Id);
                Config.EnableAuth = true;
                Config.DeferConnectReply = true;
                Registered = Registry.RegisterSocks5(std::move(Config));
                break;
            }
            case StaticProtocol::Vless: {
                const auto Uuid = MakeFirstUuid(Context.Generation, StaticProtocol::Vless);
                if (!Uuid)
                {
                    return std::unexpected(Uuid.error());
                }
                Preview::Vless::ServerConfig Config;
                Config.uuid = *Uuid;
                Config.EnableUdp = ProtocolUdpEnabled(
                    Context.ConfigurationValue, Configured.Id);
                Registered = Registry.RegisterVless(std::move(Config));
                break;
            }
            case StaticProtocol::Trojan: {
                Preview::Trojan::ServerConfig Config;
                Config.EnableTcp = true;
                Config.EnableUdp = ProtocolUdpEnabled(
                    Context.ConfigurationValue, Configured.Id);
                if (const auto *Account = FirstAccount(Context.ConfigurationValue); Account != nullptr)
                {
                    const auto Credential = ResolvedCredentialForProtocol(
                        Context.Generation, *Account, StaticProtocol::Trojan);
                    if (!Credential)
                    {
                        return std::unexpected(Credential.error());
                    }
                    Config.password = std::string(*Credential);
                }
                Registered = Registry.RegisterTrojan(std::move(Config));
                break;
            }
            case StaticProtocol::Vmess: {
                const auto Uuid = MakeFirstUuid(Context.Generation, StaticProtocol::Vmess);
                if (!Uuid)
                {
                    return std::unexpected(Uuid.error());
                }
                Preview::Vmess::ServerConfig Config;
                Config.uuid = *Uuid;
                Config.EnableUdp = ProtocolUdpEnabled(
                    Context.ConfigurationValue, Configured.Id);
                Registered = Registry.RegisterVmess(std::move(Config));
                break;
            }
            case StaticProtocol::Shadowsocks2022: {
                const auto Psk = MakeFirstPsk(Context.Generation);
                if (!Psk)
                {
                    return std::unexpected(Psk.error());
                }
                Preview::Shadowsocks2022::ServerConfig Config;
                Config.UsePsk = true;
                Config.Psk = *Psk;
                Registered = Registry.RegisterSs2022(std::move(Config));
                break;
            }
            case StaticProtocol::AnyTls: {
                Preview::Anytls::ServerConfig Config;
                if (const auto *Account = FirstAccount(Context.ConfigurationValue);
                    Account != nullptr)
                {
                    const auto Credential = ResolvedCredentialForProtocol(
                        Context.Generation, *Account, StaticProtocol::AnyTls);
                    if (!Credential)
                    {
                        return std::unexpected(Credential.error());
                    }
                    Config.Password = std::string(*Credential);
                }
                Registered = Registry.RegisterAnytls(std::move(Config));
                break;
            }
            }
            if (!Registered)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::Runtime,
                    "Protocols." + Configured.Id,
                    "Preview candidate factory registration failed"));
            }
            return {};
        }

        [[nodiscard]] auto MakeRuntimeAcceptors(const ProtocolFactoryContext &Context)
            -> std::expected<std::array<ProtocolAcceptFn, 7>, StartupError>
        {
            std::array<ProtocolAcceptFn, 7> Result;
            for (const auto &Configured : Context.ConfigurationValue.Protocols)
            {
                if (IsQuicProtocolName(Configured.Builtin))
                {
                    continue;
                }
                const auto Protocol = ParseStaticProtocol(Configured.Name);
                if (!Protocol)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::UnsupportedService,
                        "Protocols." + Configured.Id,
                        "configured TCP protocol has no Preview handler factory"));
                }
                const auto ProtocolIndex = static_cast<std::size_t>(*Protocol);
                const auto &Authenticator = Context.Authenticators[ProtocolIndex];
                const auto &Accounts = Context.Accounts[ProtocolIndex];
                if (!Authenticator || !Accounts)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::Runtime,
                        "Protocols." + Configured.Id,
                        "typed Preview account services are not available"));
                }
                switch (*Protocol)
                {
                case StaticProtocol::Http: {
                    Recognition::HttpConfig Config;
                    Config.RequireAuth = true;
                    Config.Authenticator = Authenticator;
                    auto Handler = std::make_shared<Recognition::HttpHandler>(std::move(Config));
                    Result[ProtocolIndex] =
                        Preview::Runtime::MakeProtocolAccept(std::move(Handler));
                    break;
                }
                case StaticProtocol::Socks5: {
                    Preview::Socks5::ServerConfig Config;
                    Config.EnableTcp = true;
                    Config.EnableUdp = ProtocolUdpEnabled(
                        Context.ConfigurationValue, Configured.Id);
                    Config.EnableAuth = true;
                    Config.DeferConnectReply = true;
                    Config.AuthenticatorOwner = Authenticator;
                    Result[ProtocolIndex] =
                        Preview::Runtime::MakeAcceptSocks5(std::move(Config));
                    break;
                }
                case StaticProtocol::Vless: {
                    const auto Uuid = MakeFirstUuid(Context.Generation, StaticProtocol::Vless);
                    if (!Uuid)
                    {
                        return std::unexpected(Uuid.error());
                    }
                    Preview::Vless::ServerConfig Config;
                    Config.uuid = *Uuid;
                    Config.EnableUdp = ProtocolUdpEnabled(
                        Context.ConfigurationValue, Configured.Id);
                    Config.AuthenticatorOwner = Authenticator;
                    Result[ProtocolIndex] =
                        Preview::Runtime::MakeAcceptVless(std::move(Config));
                    break;
                }
                case StaticProtocol::Trojan: {
                    Preview::Trojan::ServerConfig Config;
                    Config.EnableTcp = true;
                    Config.EnableUdp = ProtocolUdpEnabled(
                        Context.ConfigurationValue, Configured.Id);
                    Config.AuthenticatorOwner = Authenticator;
                    if (const auto *Account = FirstAccount(Context.ConfigurationValue);
                        Account != nullptr)
                    {
                        const auto Credential = ResolvedCredentialForProtocol(
                            Context.Generation, *Account, StaticProtocol::Trojan);
                        if (!Credential)
                        {
                            return std::unexpected(Credential.error());
                        }
                        Config.password = std::string(*Credential);
                    }
                    Result[ProtocolIndex] =
                        Preview::Runtime::MakeAcceptTrojan(std::move(Config));
                    break;
                }
                case StaticProtocol::Vmess: {
                    const auto Uuid = MakeFirstUuid(Context.Generation, StaticProtocol::Vmess);
                    if (!Uuid)
                    {
                        return std::unexpected(Uuid.error());
                    }
                    Preview::Vmess::ServerConfig Config;
                    Config.uuid = *Uuid;
                    Config.EnableUdp = ProtocolUdpEnabled(
                        Context.ConfigurationValue, Configured.Id);
                    Result[ProtocolIndex] =
                        Preview::Runtime::MakeAcceptVmess(std::move(Config), Accounts);
                    break;
                }
                case StaticProtocol::Shadowsocks2022: {
                    const auto Psk = MakeFirstPsk(Context.Generation);
                    if (!Psk)
                    {
                        return std::unexpected(Psk.error());
                    }
                    Preview::Shadowsocks2022::ServerConfig Config;
                    Config.UsePsk = true;
                    Config.Psk = *Psk;
                    Result[ProtocolIndex] =
                        Preview::Runtime::MakeAcceptSs2022(std::move(Config), Accounts);
                    break;
                }
                case StaticProtocol::AnyTls: {
                    Preview::Anytls::ServerConfig Config;
                    if (const auto *Account = FirstAccount(Context.ConfigurationValue);
                        Account != nullptr)
                    {
                        const auto Credential = ResolvedCredentialForProtocol(
                            Context.Generation, *Account, StaticProtocol::AnyTls);
                        if (!Credential)
                        {
                            return std::unexpected(Credential.error());
                        }
                        Config.Password = std::string(*Credential);
                    }
                    Result[ProtocolIndex] = Preview::Runtime::MakeProtocolAccept(
                        std::make_shared<Preview::Runtime::Handler::Anytls>(std::move(Config)));
                    break;
                }
                }
            }
            return Result;
        }

        [[nodiscard]] auto MakeTcpCandidateRegistry(const ProtocolFactoryContext &Context)
            -> std::expected<Recognition::CandidateRegistry, StartupError>
        {
            Recognition::CandidateRegistry Registry;
            Recognition::CarrierAcceptFn NativeAccept;
            if (Context.NativeTls)
            {
                const auto NativeTls = Context.NativeTls;
                NativeAccept = [NativeTls](Preview::SharedTransmission Inbound)
                    -> Net::awaitable<Preview::Recognition::CarrierAcceptResult>
                {
                    auto TlsResult = co_await Preview::Transport::UpgradeNativeTls(
                        std::move(Inbound), NativeTls);
                    Preview::Recognition::CarrierAcceptResult Result;
                    Result.Code = TlsResult.Code;
                    Result.Transport = std::move(TlsResult.Transport);
                    Result.NativeError = TlsResult.NativeError;
                    Result.Metadata.Carrier = "native";
                    co_return Result;
                };
                if (!Registry.RegisterCarrier("native", NativeAccept))
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::Runtime,
                        "NativeTls",
                        "native TLS carrier registration failed"));
                }
            }
            for (const auto &Carrier : Context.ConfigurationValue.Carriers)
            {
                if (Carrier.Builtin == "native")
                {
                    if (!NativeAccept || !Registry.RegisterCarrier(Carrier.Id, "native", NativeAccept))
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::Runtime,
                            "Carriers." + Carrier.Id,
                            "native TLS carrier instance registration failed"));
                    }
                    continue;
                }
                if (Carrier.Builtin == "ws" || Carrier.Builtin == "websocket")
                {
                    Preview::Ws::ServerConfig Config;
                    if (const auto *Options =
                            std::get_if<Configuration::WebSocketOptions>(&Carrier.Options);
                        Options != nullptr)
                    {
                        Config.Path = Options->Path;
                        Config.Host = Options->Host;
                    }
                    const auto Accept = Recognition::MakeWebsocketServerAccept(std::move(Config));
                    if (!Registry.RegisterCarrier(Carrier.Id, Carrier.Builtin, Accept))
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::Runtime,
                            "Carriers." + Carrier.Id,
                            "WebSocket carrier instance registration failed"));
                    }
                    continue;
                }
                if (Carrier.Builtin == "shadowtls")
                {
                    const auto *Options =
                        std::get_if<Configuration::ShadowTlsOptions>(&Carrier.Options);
                    if (Options == nullptr || !Context.Dial)
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::UnsupportedService,
                            "Carriers." + Carrier.Id,
                            "ShadowTLS carrier requires a runtime dial context"));
                    }
                    const auto Secret = Context.Generation.LookupSecret(Options->PasswordSecretRef);
                    if (Secret.empty())
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::Generation,
                            "Carriers." + Carrier.Id + ".Options.PasswordSecretRef",
                            "ShadowTLS password secret is not available in the configuration generation"));
                    }
                    Recognition::ShadowtlsCarrierOptions CarrierOptions;
                    CarrierOptions.HandshakeDest = Options->HandshakeDest;
                    CarrierOptions.Password.assign(
                        reinterpret_cast<const char *>(Secret.data()), Secret.size());
                    CarrierOptions.Dial = Context.Dial;
                    const auto Accept = Recognition::MakeConfiguredShadowtlsServerAccept(
                        std::move(CarrierOptions));
                    if (!Accept)
                    {
                        return std::unexpected(MakeStartupError(
                            Accept.error() == Recognition::ShadowtlsCarrierBuildError::InvalidDestination
                                ? StartupErrorCode::InvalidConfiguration
                                : StartupErrorCode::UnsupportedService,
                            "Carriers." + Carrier.Id,
                            "ShadowTLS carrier configuration cannot build a real relay acceptor"));
                    }
                    if (!Registry.RegisterCarrier(Carrier.Id, "shadowtls", std::move(*Accept)))
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::Runtime,
                            "Carriers." + Carrier.Id,
                            "ShadowTLS carrier instance registration failed"));
                    }
                    continue;
                }
                if (Carrier.Builtin == "xhttp")
                {
                    if (!Context.NativeTls)
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::UnsupportedService,
                            "Carriers." + Carrier.Id,
                            "XHTTP carrier requires a configured NativeTls context"));
                    }
                    Preview::Xhttp::Config Config;
                    if (const auto *Options =
                            std::get_if<Configuration::XhttpOptions>(&Carrier.Options);
                        Options != nullptr)
                    {
                        Config.Path = Options->Path;
                        Config.Host = Options->Host;
                        Config.Mode = Options->Mode;
                    }
                    const auto Accept = Recognition::MakeXhttpServerAccept(
                        Context.NativeTls, std::move(Config));
                    if (!Registry.RegisterCarrier(Carrier.Id, "xhttp", Accept))
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::Runtime,
                            "Carriers." + Carrier.Id,
                            "XHTTP carrier instance registration failed"));
                    }
                    continue;
                }
                if (Carrier.Builtin == "gun")
                {
                    if (!Context.NativeTls)
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::UnsupportedService,
                            "Carriers." + Carrier.Id,
                            "Gun carrier requires a configured NativeTls context"));
                    }
                    std::string Path;
                    std::string ServiceName;
                    std::string Mode{"GunLite"};
                    if (const auto *Options =
                            std::get_if<Configuration::GunOptions>(&Carrier.Options);
                        Options != nullptr)
                    {
                        Mode = Options->Mode;
                        Path = Options->Path;
                        ServiceName = Options->ServiceName;
                    }
                    const auto Accept = Recognition::MakeGunServerAccept(
                        Context.NativeTls, std::move(Path), std::move(ServiceName), std::move(Mode));
                    if (!Registry.RegisterCarrier(Carrier.Id, "gun", Accept))
                    {
                        return std::unexpected(MakeStartupError(
                            StartupErrorCode::Runtime,
                            "Carriers." + Carrier.Id,
                            "Gun carrier instance registration failed"));
                    }
                    continue;
                }
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Carriers." + Carrier.Id,
                    "configured carrier has no Preview admission callback: " + Carrier.Builtin));
            }
            for (const auto &Configured : Context.ConfigurationValue.Protocols)
            {
                if (IsQuicProtocolName(Configured.Builtin))
                {
                    continue;
                }
                const auto Registered = RegisterTcpCandidate(Registry, Configured, Context);
                if (!Registered)
                {
                    return std::unexpected(Registered.error());
                }
            }
            return Registry;
        }

        [[nodiscard]] auto MakeProfileBuildError(const Core::ProfileError Error) -> StartupError
        {
            const auto Code = Error == Core::ProfileError::QuicCandidateRequiresGateway
                                  ? StartupErrorCode::UnsupportedService
                                  : StartupErrorCode::Generation;
            return MakeStartupError(
                Code, "Protocols", "Preview TCP recognition profile build failed: " +
                                         std::string(Core::ToStringView(Error)));
        }

        [[nodiscard]] auto MakeTcpProfile(const ProtocolFactoryContext &Context)
            -> std::expected<Recognition::ProfileBuildResult, StartupError>
        {
            const auto Registry = MakeTcpCandidateRegistry(Context);
            if (!Registry)
            {
                return std::unexpected(Registry.error());
            }
            const auto Acceptors = MakeRuntimeAcceptors(Context);
            if (!Acceptors)
            {
                return std::unexpected(Acceptors.error());
            }
            auto SettingsConfig = MakeTcpRecognitionConfig(Context.ConfigurationValue);
            auto Factory = Registry->MakeFactory();
            auto MixedFactory = [Factory = std::move(Factory),
                                 Acceptors = std::move(*Acceptors)](
                                    const Settings::RecognitionCandidate &Candidate)
                -> std::optional<Recognition::CandidateBinding>
            {
                auto Binding = Factory(Candidate);
                const auto Protocol = ParseStaticProtocol(Candidate.Protocol);
                if (!Binding || !Protocol)
                {
                    return std::nullopt;
                }
                const auto ProtocolIndex = static_cast<std::size_t>(*Protocol);
                if (!Acceptors[ProtocolIndex])
                {
                    return std::nullopt;
                }
                Binding->Accept = Acceptors[ProtocolIndex];
                if (Binding->Spec.Kind == Core::CandidateKind::EarlyResponse)
                {
                    // Application 只在识别提交后调用 handler；识别阶段的 Inspect、Prepare 和
                    // Commit 均不向入站写响应，因此这里可以安全地参与 opaque MixedTrial。
                    Binding->Spec.Kind = Core::CandidateKind::Cleartext;
                }
                return Binding;
            };
            bool HasAnyTls = false;
            for (const auto &Candidate : SettingsConfig.Candidates)
            {
                const auto Protocol = ParseStaticProtocol(Candidate.Protocol);
                if (Protocol && *Protocol == StaticProtocol::AnyTls)
                {
                    HasAnyTls = true;
                    break;
                }
            }
            auto Built = HasAnyTls
                             ? BuildProfileWithStaticProtocolMap(
                                   SettingsConfig, std::move(MixedFactory))
                             : Recognition::BuildProfileFromSettings(
                                   SettingsConfig, std::move(MixedFactory));
            if (!Built)
            {
                return std::unexpected(MakeProfileBuildError(Built.error()));
            }
            return std::move(*Built);
        }

        [[nodiscard]] auto MakeAddress(const std::string &Text)
            -> std::expected<Net::ip::address, StartupError>
        {
            if (Text == "localhost")
            {
                return Net::ip::address_v4::loopback();
            }
            boost::system::error_code Error;
            const auto Address = Net::ip::make_address(Text, Error);
            if (Error)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::Bind,
                    "Listeners.Tcp[0].Address",
                    "invalid TCP listen address: " + Text));
            }
            return Address;
        }

        [[nodiscard]] auto MakeEndpoint(const Configuration::ListenerEndpoint &Configured)
            -> std::expected<Net::ip::tcp::endpoint, StartupError>
        {
            const auto Address = MakeAddress(Configured.Address);
            if (!Address)
            {
                return std::unexpected(Address.error());
            }
            return Net::ip::tcp::endpoint(*Address, Configured.Port);
        }

        [[nodiscard]] auto MakeUdpEndpoint(const Configuration::ListenerEndpoint &Configured)
            -> std::expected<Net::ip::udp::endpoint, StartupError>
        {
            const auto Address = MakeAddress(Configured.Address);
            if (!Address)
            {
                auto Error = Address.error();
                Error.Path = "Listeners.Udp[0].Address";
                Error.Message = "invalid UDP listen address: " + Configured.Address;
                return std::unexpected(std::move(Error));
            }
            return Net::ip::udp::endpoint(*Address, Configured.Port);
        }

        [[nodiscard]] auto ResolveConfigurationPath(
            const std::filesystem::path &ConfigurationPath,
            const std::string &ConfiguredPath) -> std::filesystem::path
        {
            const std::filesystem::path Path(ConfiguredPath);
            if (Path.is_absolute() || ConfigurationPath.parent_path().empty())
            {
                return Path;
            }
            return ConfigurationPath.parent_path() / Path;
        }

        [[nodiscard]] auto MakeNativeTlsContext(
            const Configuration::PreviewConfiguration &ConfigurationValue,
            const std::filesystem::path &ConfigurationPath)
            -> std::expected<std::shared_ptr<Net::ssl::context>, StartupError>
        {
            std::string CertificateFile = ConfigurationValue.NativeTls.CertificateFile;
            std::string PrivateKeyFile = ConfigurationValue.NativeTls.PrivateKeyFile;
            bool Enabled = ConfigurationValue.NativeTls.Enabled;
            if (!Enabled)
            {
                for (const auto &Carrier : ConfigurationValue.Carriers)
                {
                    if (Carrier.Builtin != "native" ||
                        !std::holds_alternative<Configuration::NativeTlsOptions>(Carrier.Options))
                    {
                        continue;
                    }
                    const auto &Options = std::get<Configuration::NativeTlsOptions>(Carrier.Options);
                    CertificateFile = Options.CertificateFile;
                    PrivateKeyFile = Options.PrivateKeyFile;
                    Enabled = true;
                    break;
                }
            }
            if (!Enabled)
            {
                return std::shared_ptr<Net::ssl::context>{};
            }
            const auto Certificate = ResolveConfigurationPath(
                ConfigurationPath, CertificateFile);
            const auto PrivateKey = ResolveConfigurationPath(
                ConfigurationPath, PrivateKeyFile);
            try
            {
                auto Context = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
                Context->set_options(Net::ssl::context::default_workarounds |
                                     Net::ssl::context::no_sslv2 |
                                     Net::ssl::context::no_sslv3 |
                                     Net::ssl::context::single_dh_use);
                Context->use_certificate_chain_file(Certificate.string());
                Context->use_private_key_file(PrivateKey.string(), Net::ssl::context::pem);
                if (!SSL_CTX_check_private_key(Context->native_handle()))
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "NativeTls.PrivateKeyFile",
                        "NativeTls certificate and private key do not match"));
                }
                // QUIC requires a server-side ALPN selection callback; keep the same
                // context usable by native TCP carriers by selecting only protocols
                // actually offered by the client.
                SSL_CTX_set_alpn_select_cb(
                    Context->native_handle(),
                    [](SSL *, const unsigned char **Out, unsigned char *OutLength,
                       const unsigned char *In, const unsigned int InLength, void *) -> int
                    {
                        static constexpr unsigned char H3[] = {0x02, 'h', '3'};
                        static constexpr unsigned char H2[] = {0x02, 'h', '2'};
                        static constexpr unsigned char Http11[] =
                            {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
                        for (const auto *Protocol : {H3, H2, Http11})
                        {
                            const auto Length = Protocol == H3 ? sizeof(H3) :
                                                Protocol == H2 ? sizeof(H2) : sizeof(Http11);
                            if (SSL_select_next_proto(
                                    const_cast<unsigned char **>(Out), OutLength,
                                    Protocol, Length, In, InLength) == OPENSSL_NPN_NEGOTIATED)
                            {
                                return SSL_TLSEXT_ERR_OK;
                            }
                        }
                        return SSL_TLSEXT_ERR_NOACK;
                    },
                    nullptr);
                return Context;
            }
            catch (const std::exception &Error)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "NativeTls",
                    "NativeTls context failed: " + std::string(Error.what())));
            }
        }

        [[nodiscard]] auto MakeOperationsEndpoint(const std::string_view Configured)
            -> std::expected<Net::ip::tcp::endpoint, StartupError>
        {
            if (Configured.empty())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Operations.Endpoint",
                    "operations Endpoint is required"));
            }

            std::string_view AddressText;
            std::string_view PortText;
            if (Configured.front() == '[')
            {
                const auto Close = Configured.find(']');
                if (Close == std::string_view::npos || Close + 2U > Configured.size() ||
                    Configured[Close + 1U] != ':')
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Operations.Endpoint",
                        "operations Endpoint must be address:port"));
                }
                AddressText = Configured.substr(1U, Close - 1U);
                PortText = Configured.substr(Close + 2U);
            }
            else
            {
                const auto Separator = Configured.rfind(':');
                if (Separator == std::string_view::npos ||
                    Configured.find(':') != Separator)
                {
                    return std::unexpected(MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "Operations.Endpoint",
                        "operations IPv6 endpoints must use brackets"));
                }
                AddressText = Configured.substr(0, Separator);
                PortText = Configured.substr(Separator + 1U);
            }

            const auto Address = MakeAddress(std::string(AddressText));
            if (!Address)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Operations.Endpoint",
                    Address.error().Message));
            }
            if (!Address->is_loopback())
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Operations.Endpoint",
                    "operations listener must use a loopback address"));
            }

            std::uint32_t Port{};
            const auto [End, Error] = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port, 10);
            if (Error != std::errc{} || End != PortText.data() + PortText.size() || Port > 65535U)
            {
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "Operations.Endpoint",
                    "operations port must be between 0 and 65535"));
            }
            return Net::ip::tcp::endpoint(*Address, static_cast<std::uint16_t>(Port));
        }

        [[nodiscard]] auto CheckBindAvailable(const Net::ip::tcp::endpoint &Endpoint)
            -> std::expected<void, StartupError>
        {
            Net::io_context ProbeIo;
            Net::ip::tcp::acceptor Probe(ProbeIo);
            boost::system::error_code Error;
            Probe.open(Endpoint.protocol(), Error);
            if (!Error)
            {
                Probe.bind(Endpoint, Error);
            }
            if (!Error)
            {
                Probe.listen(Net::socket_base::max_listen_connections, Error);
            }
            if (Error)
            {
                boost::system::error_code CloseError;
                Probe.close(CloseError);
                return std::unexpected(MakeStartupError(
                    StartupErrorCode::Bind,
                    "Listeners.Tcp[0]",
                    "TCP listen endpoint is unavailable: " + Error.message()));
            }
            return {};
        }

        struct SessionFactoryOptions final
        {
            Preview::Runtime::SharedSessionServices Services;
            Preview::Runtime::WorkerGroup *Workers{nullptr};
        };

        [[nodiscard]] auto MakeSessionFactory(SessionFactoryOptions FactoryOptions)
            -> Preview::Runtime::TcpListener::SessionFactory
        {
            return [Services = std::move(FactoryOptions.Services),
                    Workers = FactoryOptions.Workers](Preview::SharedTransmission, std::size_t WorkerIndex)
                -> std::shared_ptr<Preview::Runtime::Session>
            {
                Preview::Runtime::SessionOptions Options;
                auto SessionServices = std::make_shared<Preview::Runtime::SessionServices>(*Services);
                if (Workers)
                {
                    const auto WorkerId = Preview::WorkerId{
                        static_cast<std::uint64_t>(WorkerIndex + 1U)};
                    if (auto *Worker = Workers->Find(WorkerId); Worker &&
                        Worker->Resources().DialService)
                    {
                        const auto DialService = Worker->Resources().DialService;
                        SessionServices->Dial = [DialService](
                                                    const Preview::Network::Target &Target)
                            -> Net::awaitable<std::pair<Preview::Fault::Code,
                                                         Preview::SharedTransmission>>
                        {
                            co_return co_await DialService->Connect(Target);
                        };
                    }
                }
                Options.Services = std::move(SessionServices);
                return std::make_shared<Preview::Runtime::Session>(std::move(Options));
            };
        }

        struct ListenerStartResult final
        {
            bool Completed{false};
            std::exception_ptr Failure;
            Preview::Fault::Code Code{Preview::Fault::Code::IoError};
        };

    } // namespace

    struct Application::RuntimeState final
    {
        explicit RuntimeState(const std::size_t WorkerCount,
                              const Preview::GenerationId GenerationValue,
                              Preview::Network::Dns::Config DnsConfig)
            : Signals(Io),
              Tasks(std::make_shared<Preview::Lifecycle::TaskRegistry>(Io.get_executor()))
        {
            Process = std::make_unique<Preview::Runtime::Process>(
                Preview::Runtime::Process::Options{
                    Preview::ProcessId{1}, GenerationValue, WorkerCount, 64,
                    std::move(DnsConfig)});
            Events = std::make_shared<Preview::Statistics::EventRing>();
        }

        ~RuntimeState() noexcept
        {
            StopWorkers();
        }

        auto StartWorkers(const std::size_t WorkerCount) -> void
        {
            WorkerThreads.reserve(WorkerCount);
            for (std::size_t Index = 0; Index < WorkerCount; ++Index)
            {
                auto *WorkerValue = Process->Workers().Find(
                    Preview::WorkerId{static_cast<std::uint64_t>(Index + 1)});
                if (!WorkerValue)
                {
                    throw std::runtime_error("Preview worker is missing");
                }
                WorkerThreads.emplace_back([WorkerValue]
                                           { WorkerValue->Run(); });
            }
        }

        auto StopWorkers() noexcept -> void
        {
            if (Process)
            {
                Process->Stop();
            }
            for (auto &WorkerThread : WorkerThreads)
            {
                if (WorkerThread.joinable())
                {
                    WorkerThread.join();
                }
            }
        }

        Net::io_context Io;
        Net::signal_set Signals;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks;
        std::shared_ptr<Preview::Account::AccountDirectory> Accounts;
        Configuration::SharedConfigurationGeneration Generation;
        std::shared_ptr<Preview::Statistics::EventRing> Events;
        std::shared_ptr<Preview::Network::Dns::Resolver> DnsResolver;
        std::shared_ptr<Preview::Ingress::UdpDemux> UdpDemux;
        std::shared_ptr<Preview::Ingress::QuicGateway> QuicGateway;
        std::shared_ptr<Preview::Ingress::QuicCidRegistry> QuicCidRegistry;
        std::shared_ptr<Preview::Ingress::Ss2022Gateway> Ss2022Gateway;
        std::shared_ptr<Preview::Ingress::IngressDispatcher> IngressDispatcher;
        Preview::Diagnose::Logger::Owner Logger;
        std::shared_ptr<Preview::Diagnose::TraceContext> Trace;
        Preview::Runtime::SharedSessionServices Services;
        std::unique_ptr<Preview::Runtime::Process> Process;
        std::unique_ptr<Preview::Runtime::TcpListener> Listener;
            std::unique_ptr<Preview::Ingress::UdpListener> UdpListener;
            std::shared_ptr<Preview::Composition::MuxService> MuxService;
            bool QuicConfigured{false};
        std::unique_ptr<Preview::Operations::HttpServer> OperationsServer;
        std::vector<std::thread> WorkerThreads;
        std::atomic<RuntimePhase> Phase{RuntimePhase::Created};
        std::atomic<bool> StopRequested{false};
        std::atomic<bool> StopCompleted{false};
        std::atomic<bool> ShutdownScheduled{false};
        std::atomic<bool> Running{false};
        std::atomic<bool> SignalsArmed{false};
        std::chrono::milliseconds ShutdownTimeout{5000};
        int ExitCode{0};
        Readiness Ready{};
    };

    struct ShutdownWaitResult final
    {
        bool Completed{false};
        bool Succeeded{false};
    };

    struct ShutdownOperationState final
    {
        using Signal = Net::experimental::channel<void(boost::system::error_code)>;

        explicit ShutdownOperationState(Net::any_io_executor ExecutorValue)
            : Timer(ExecutorValue), Completion(ExecutorValue, 1)
        {
        }

        Net::steady_timer Timer;
        Signal Completion;
        Net::cancellation_signal Cancellation;
        std::atomic<bool> TimedOut{false};
        std::atomic<bool> Succeeded{false};
    };

    [[nodiscard]] static auto AwaitShutdownOperation(
        Net::awaitable<void> Operation,
        const std::chrono::steady_clock::time_point Deadline) -> Net::awaitable<ShutdownWaitResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto State = std::make_shared<ShutdownOperationState>(Executor);
        State->Timer.expires_at(Deadline);
        State->Timer.async_wait(
            [State](const boost::system::error_code &Error)
            {
                if (!Error)
                {
                    State->TimedOut.store(true, std::memory_order_release);
                    (void)State->Completion.try_send(boost::system::error_code{});
                }
            });
        try
        {
            Net::co_spawn(
                Executor, std::move(Operation),
                Net::bind_cancellation_slot(
                    State->Cancellation.slot(),
                    [State](std::exception_ptr Failure) noexcept
                    {
                        State->Succeeded.store(!Failure, std::memory_order_release);
                        State->Timer.cancel();
                        (void)State->Completion.try_send(boost::system::error_code{});
                    }));
        }
        catch (...)
        {
            State->Timer.cancel();
            co_return ShutdownWaitResult{true, false};
        }

        boost::system::error_code Error;
        co_await State->Completion.async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        if (State->TimedOut.load(std::memory_order_acquire))
        {
            State->Cancellation.emit(Net::cancellation_type::all);
            co_return ShutdownWaitResult{};
        }
        co_return ShutdownWaitResult{true, State->Succeeded.load(std::memory_order_acquire)};
    }

    static auto MarkShutdownFailed(const std::shared_ptr<Application::RuntimeState> &State) noexcept
        -> void
    {
        State->ExitCode = 1;
        State->Phase.store(RuntimePhase::Failed, std::memory_order_release);
        if (State->Events)
        {
            Preview::Statistics::DetailedEvent Event;
            Event.Timestamp = static_cast<std::uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count());
            Event.Generation = State->Generation ? State->Generation->Id() : Preview::GenerationId{};
            Event.Process = State->Process ? State->Process->Id() : Preview::ProcessId{};
            Event.Kind = Preview::Statistics::EventKind::Failed;
            Event.Severity = Preview::Statistics::EventSeverity::Error;
            Event.Terminal = true;
            Event.Detail = "application shutdown failed";
            (void)State->Events->Append(std::move(Event));
        }
    }

    static auto ReleaseRuntimeResources(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
    {
        State->OperationsServer.reset();
        State->Ss2022Gateway.reset();
        State->QuicCidRegistry.reset();
        State->UdpListener.reset();
        State->IngressDispatcher.reset();
        State->QuicGateway.reset();
        State->UdpDemux.reset();
        State->Listener.reset();
        State->Tasks.reset();
        if (State->Process)
        {
            State->Process->Stop();
            State->StopWorkers();
        }
        State->Services.reset();
        State->DnsResolver.reset();
        State->Generation.reset();
        State->Accounts.reset();
        if (State->Logger)
        {
            State->Logger->Stop();
        }
        State->Logger.reset();
        State->Trace.reset();
        State->Process.reset();
    }

    [[nodiscard]] static auto ShutdownRuntime(
        std::shared_ptr<Application::RuntimeState> State) -> Net::awaitable<void>
    {
        const auto WasFailed =
            State->Phase.load(std::memory_order_acquire) == RuntimePhase::Failed;
        if (!WasFailed)
        {
            State->Phase.store(RuntimePhase::Stopping, std::memory_order_release);
        }
        const auto Deadline = std::chrono::steady_clock::now() + State->ShutdownTimeout;

        if (State->OperationsServer)
        {
            State->OperationsServer->Close();
            auto Operation = State->OperationsServer->Drain();
            const auto Result = co_await AwaitShutdownOperation(
                std::move(Operation), Deadline);
            if (!Result.Completed || !Result.Succeeded)
            {
                MarkShutdownFailed(State);
            }
        }

        if (State->Listener)
        {
            State->Listener->Stop();
            State->Listener->Registry().BeginShutdown();
            const auto Result = co_await AwaitShutdownOperation(
                State->Listener->Shutdown(), Deadline);
            if (!Result.Completed || !Result.Succeeded)
            {
                MarkShutdownFailed(State);
            }
        }

        if (State->UdpListener)
        {
            if (State->Ss2022Gateway)
            {
                State->Ss2022Gateway->Close();
            }
            if (State->QuicCidRegistry)
            {
                State->QuicCidRegistry->Close();
            }
            State->UdpListener->Stop(Preview::Ingress::UdpListener::StopRequest{});
            if (State->QuicGateway)
            {
                State->QuicGateway->Drain();
            }
            const auto DrainOperation = [State]() -> Net::awaitable<void>
            {
                (void)co_await State->UdpListener->Drain();
                co_return;
            };
            const auto Result = co_await AwaitShutdownOperation(
                DrainOperation(), Deadline);
            if (!Result.Completed || !Result.Succeeded)
            {
                MarkShutdownFailed(State);
            }
            if (State->QuicGateway)
            {
                State->QuicGateway->Close();
            }
        }

        if (State->Tasks)
        {
            (void)State->Tasks->Cancel();
            const auto Result = co_await AwaitShutdownOperation(State->Tasks->Drain(), Deadline);
            if (!Result.Completed || !Result.Succeeded)
            {
                MarkShutdownFailed(State);
            }
        }

        ReleaseRuntimeResources(State);
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Failed)
        {
            State->Phase.store(RuntimePhase::Stopped, std::memory_order_release);
        }
    }

    static auto RunStartupRollback(const std::shared_ptr<Application::RuntimeState> &State) noexcept
        -> void
    {
        State->StopRequested.store(true, std::memory_order_release);
        bool Completed = false;
        try
        {
            Net::co_spawn(
                State->Io.get_executor(), ShutdownRuntime(State),
                [&Completed](std::exception_ptr) noexcept { Completed = true; });
            while (!Completed)
            {
                if (State->Io.run_one() == 0U)
                {
                    State->Io.restart();
                }
            }
            State->StopCompleted.store(true, std::memory_order_release);
            State->Io.stop();
        }
        catch (...)
        {
            MarkShutdownFailed(State);
            ReleaseRuntimeResources(State);
            State->StopCompleted.store(true, std::memory_order_release);
            State->Io.stop();
        }
    }

    [[nodiscard]] static auto StartListener(const std::shared_ptr<Application::RuntimeState> &State,
                                            const Net::ip::tcp::endpoint &Endpoint)
        -> std::expected<void, StartupError>
    {
        ListenerStartResult Result;
        Net::co_spawn(
            State->Io.get_executor(), State->Listener->Start(Endpoint),
            [&Result](std::exception_ptr Failure, const Preview::Fault::Code Code)
            {
                Result.Failure = std::move(Failure);
                Result.Code = Code;
                Result.Completed = true;
            });

        while (!Result.Completed)
        {
            if (State->Io.run_one() == 0U)
            {
                State->Io.restart();
            }
        }
        if (Result.Failure)
        {
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Bind,
                "Listeners.Tcp[0]",
                "TCP listener startup threw: " + DescribeException(Result.Failure)));
        }
        if (Preview::Fault::Failed(Result.Code))
        {
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Bind,
                "Listeners.Tcp[0]",
                "TCP listener bind/listen failed"));
        }
        return {};
    }

    struct UdpListenerStartResult final
    {
        bool Completed{false};
        std::exception_ptr Failure;
        Preview::Ingress::UdpStartResult Result;
    };

    [[nodiscard]] static auto StartUdpListener(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Net::ip::udp::endpoint &Endpoint) -> std::expected<void, StartupError>
    {
        if (!State->UdpListener || !State->UdpDemux || !State->IngressDispatcher)
        {
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Runtime,
                "Listeners.Udp",
                "UDP listener composition is incomplete"));
        }

        UdpListenerStartResult Result;
        const auto WeakState = std::weak_ptr<Application::RuntimeState>(State);
        const auto Handler = [Dispatcher = State->IngressDispatcher](Preview::Ingress::UdpPacket Packet)
        {
            Dispatcher->Dispatch(std::move(Packet));
        };
        const auto OnError = [WeakState](const boost::system::error_code Error) noexcept
        {
            if (const auto StateValue = WeakState.lock(); StateValue && StateValue->Logger)
            {
                (void)StateValue->Logger->TryWrite(
                    Preview::Diagnose::LogLevel::Error,
                    "event=udp_receive_failed code=" + std::to_string(Error.value()) +
                        " message=" + Error.message(),
                    StateValue->Trace ? StateValue->Trace->Snapshot()
                                      : Preview::Statistics::TraceSnapshot{});
            }
        };
        Net::co_spawn(
            State->Io.get_executor(),
            State->UdpListener->Start(Preview::Ingress::UdpListener::StartRequest{
                Endpoint, State->UdpDemux, Handler, OnError}),
            [&Result](std::exception_ptr Failure, Preview::Ingress::UdpStartResult Started)
            {
                Result.Failure = std::move(Failure);
                Result.Result = std::move(Started);
                Result.Completed = true;
            });

        while (!Result.Completed)
        {
            if (State->Io.run_one() == 0U)
            {
                State->Io.restart();
            }
        }
        if (Result.Failure)
        {
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Bind,
                "Listeners.Udp[0]",
                "UDP listener startup threw: " + DescribeException(Result.Failure)));
        }
        if (!Result.Result.Succeeded())
        {
            const auto Message = Result.Result.Error
                                      ? Result.Result.Error.message()
                                      : std::string("UDP listener bind/listen failed");
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Bind,
                "Listeners.Udp[0]",
                Message));
        }
        return {};
    }

    struct OperationsStartResult final
    {
        bool Completed{false};
        std::exception_ptr Failure;
        std::optional<Preview::Operations::HttpServer::StartResult> Result;
    };

    [[nodiscard]] static auto StartOperations(
        const std::shared_ptr<Application::RuntimeState> &State)
        -> std::expected<void, StartupError>
    {
        OperationsStartResult Result;
        Net::co_spawn(
            State->Io.get_executor(), State->OperationsServer->Start(),
            [&Result](std::exception_ptr Failure,
                      Preview::Operations::HttpServer::StartResult Started)
            {
                Result.Failure = std::move(Failure);
                Result.Result = std::move(Started);
                Result.Completed = true;
            });

        while (!Result.Completed)
        {
            if (State->Io.run_one() == 0U)
            {
                State->Io.restart();
            }
        }
        if (Result.Failure)
        {
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Bind,
                "Operations.Endpoint",
                "operations listener startup threw: " + DescribeException(Result.Failure)));
        }
        if (!Result.Result || !*Result.Result)
        {
            const auto Message = Result.Result ? Result.Result->error().message()
                                               : std::string("operations listener did not return a result");
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Bind,
                "Operations.Endpoint",
                "operations listener bind/listen failed: " + Message));
        }
        return {};
    }

    static auto ScheduleShutdown(
        const std::shared_ptr<Application::RuntimeState> &State) noexcept -> void
    {
        if (State->ShutdownScheduled.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        try
        {
            Net::co_spawn(
                State->Io.get_executor(),
                ShutdownRuntime(State),
                [State](std::exception_ptr Failure) noexcept
                {
                    if (Failure)
                    {
                        MarkShutdownFailed(State);
                    }
                    State->StopCompleted.store(true, std::memory_order_release);
                    State->Io.stop();
                });
        }
        catch (...)
        {
            MarkShutdownFailed(State);
            ReleaseRuntimeResources(State);
            State->StopCompleted.store(true, std::memory_order_release);
            State->Io.stop();
        }
    }

    [[nodiscard]] static auto InvalidOperationsQuery(const Preview::RequestId Correlation)
        -> Preview::Operations::QueryResult
    {
        return Preview::Operations::QueryResult{
            Correlation,
            Preview::Operations::QueryStatus::Invalid,
            std::monostate{},
            "query_invalid"};
    }

    [[nodiscard]] static auto MakeOperationsHealth(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Operations::HealthQuery &QueryValue) -> Preview::Operations::QueryResult
    {
        Preview::Operations::HealthSnapshot Health;
        const auto Phase = State->Phase.load(std::memory_order_acquire);
        switch (Phase)
        {
        case RuntimePhase::Ready:
            Health.Status = Preview::Operations::HealthStatus::Healthy;
            Health.Ready = true;
            break;
        case RuntimePhase::Stopping:
            Health.Status = Preview::Operations::HealthStatus::Draining;
            break;
        case RuntimePhase::Failed:
            Health.Status = Preview::Operations::HealthStatus::Unhealthy;
            Health.Errors = 1;
            break;
        case RuntimePhase::Created:
        case RuntimePhase::Stopped:
            Health.Status = Preview::Operations::HealthStatus::Unknown;
            break;
        }
        Health.CheckedAt = static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        Health.Active = State->Listener ? State->Listener->Registry().Size() : 0U;
        Health.TcpReady = State->Ready.Port != 0U;
        Health.UdpReady = State->Ready.UdpReady;
        Health.UdpSocketReady = State->Ready.UdpSocketReady;
        Health.QuicReady = State->Ready.QuicReady;
        Health.QuicSocketReady = State->Ready.QuicSocketReady;
        Health.QuicHandshakeReady = State->Ready.QuicHandshakeReady;
        Health.QuicProtocolReady = State->Ready.QuicProtocolReady;
        Health.Ready = false;
        if (Phase == RuntimePhase::Ready && Health.TcpReady &&
            (!State->UdpListener || Health.UdpReady) &&
            (!State->QuicConfigured || Health.QuicReady))
        {
            Health.Ready = true;
        }
        return Preview::Operations::QueryResult::Health(QueryValue.Correlation, std::move(Health));
    }

    [[nodiscard]] static auto MakeOperationsWorkers(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Operations::WorkerQuery &QueryValue) -> Preview::Operations::QueryResult
    {
        Preview::Operations::Page<Preview::Operations::WorkerSnapshot> Page;
        if (State->Process)
        {
            for (const auto &Source : State->Process->Snapshot())
            {
                if (QueryValue.Id && QueryValue.Id != Source.Id)
                {
                    continue;
                }
                Preview::Operations::WorkerSnapshot Item;
                Item.Process = Source.Process;
                Item.Id = Source.Id;
                Item.Generation = Source.Generation;
                Item.Health.Status = Source.Running
                                         ? Preview::Operations::HealthStatus::Healthy
                                         : Preview::Operations::HealthStatus::Draining;
                Item.Health.Ready = Source.Running;
                Item.Health.Active = Source.ActiveTasks;
                Item.Running = Source.Running;
                Item.Accepting = Source.Accepting;
                Item.ActiveTasks = Source.ActiveTasks;
                Page.Items.push_back(std::move(Item));
            }
        }
        if (!Page.Items.empty())
        {
            Page.NextCursor = Page.Items.back().Id.Value();
        }
        return Preview::Operations::QueryResult::Workers(QueryValue.Correlation, std::move(Page));
    }

    [[nodiscard]] static auto MakeOperationsAccounts(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Operations::AccountQuery &QueryValue) -> Preview::Operations::QueryResult
    {
        Preview::Operations::Page<Preview::Operations::AccountSnapshot> Page;
        if (!State->Generation || !State->Accounts)
        {
            return Preview::Operations::QueryResult::Accounts(QueryValue.Correlation,
                                                               std::move(Page));
        }
        std::uint64_t NextId = 1;
        for (const auto &Configured : State->Generation->Configuration().Accounts)
        {
            const Preview::AccountId Id{NextId++};
            if (QueryValue.Id && QueryValue.Id != Id)
            {
                continue;
            }
            const auto Record = State->Accounts->FindById(Id);
            if (!Record)
            {
                continue;
            }
            const auto Runtime = Record->Runtime();
            Preview::Operations::AccountSnapshot Item;
            Item.Id = Id;
            Item.Generation = State->Generation->Id();
            Item.ActiveSessions = Runtime->ActiveConnections();
            Item.Label = Configured.Id;
            Item.Enabled = !Runtime->IsRevoked();
            Page.Items.push_back(std::move(Item));
        }
        if (!Page.Items.empty())
        {
            Page.NextCursor = Page.Items.back().Id.Value();
        }
        return Preview::Operations::QueryResult::Accounts(QueryValue.Correlation, std::move(Page));
    }

    [[nodiscard]] static auto MakeOperationsSessions(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Operations::SessionQuery &QueryValue) -> Preview::Operations::QueryResult
    {
        Preview::Operations::Page<Preview::Operations::SessionSnapshot> Page;
        if (!State->Listener || !State->Process)
        {
            return Preview::Operations::QueryResult::Sessions(QueryValue.Correlation,
                                                               std::move(Page));
        }
        const auto Snapshot = State->Listener->Registry().Snapshot();
        for (const auto &[RawId, Source] : *Snapshot)
        {
            const Preview::SessionId Id{RawId};
            if (QueryValue.Id && QueryValue.Id != Id)
            {
                continue;
            }
            Preview::Operations::SessionSnapshot Item;
            Item.Id = Id;
            Item.Process = State->Process->Id();
            Item.Account = Source.AccountId;
            Item.Generation = State->Process->Generation();
            Item.StartedAt = Source.StartedAt;
            Item.Protocol = std::to_string(Source.Protocol);
            Item.Target = Source.Target;
            Item.Active = true;
            Item.Draining = State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready;
            Page.Items.push_back(std::move(Item));
        }
        if (!Page.Items.empty())
        {
            Page.NextCursor = Page.Items.back().Id.Value();
        }
        return Preview::Operations::QueryResult::Sessions(QueryValue.Correlation, std::move(Page));
    }

    [[nodiscard]] static auto MakeOperationsEvents(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Preview::Operations::EventQuery &QueryValue) -> Preview::Operations::QueryResult
    {
        Preview::Operations::Page<Preview::Operations::EventSnapshot> Page;
        if (!State->Events)
        {
            return Preview::Operations::QueryResult::Events(QueryValue.Correlation,
                                                             std::move(Page));
        }

        const auto Events = State->Events->Page(QueryValue.Page.Cursor,
                                                QueryValue.Page.BoundedLimit());
        Page.NextCursor = Events.NextCursor;
        Page.HasMore = Events.HasMore;
        Page.Items.reserve(Events.Items.size());
        for (auto Event : Events.Items)
        {
            if (!QueryValue.IncludeDetails)
            {
                Event.Detail.clear();
            }
            Page.Items.push_back(std::move(Event));
        }
        return Preview::Operations::QueryResult::Events(QueryValue.Correlation,
                                                         std::move(Page));
    }

    [[nodiscard]] static auto MakeOperationsQuery(
        const std::weak_ptr<Application::RuntimeState> &WeakState,
        const Preview::Operations::Query &QueryValue) -> Preview::Operations::QueryResult
    {
        const auto Correlation = Preview::Operations::CorrelationOf(QueryValue);
        const auto State = WeakState.lock();
        if (!State)
        {
            return Preview::Operations::QueryResult::Unavailable(Correlation);
        }
        return std::visit(
            [&State](const auto &Value) -> Preview::Operations::QueryResult
            {
                using ValueType = std::remove_cvref_t<decltype(Value)>;
                if constexpr (std::is_same_v<ValueType, Preview::Operations::HealthQuery>)
                {
                    return MakeOperationsHealth(State, Value);
                }
                else if constexpr (std::is_same_v<ValueType, Preview::Operations::WorkerQuery>)
                {
                    return MakeOperationsWorkers(State, Value);
                }
                else if constexpr (std::is_same_v<ValueType, Preview::Operations::AccountQuery>)
                {
                    return MakeOperationsAccounts(State, Value);
                }
                else if constexpr (std::is_same_v<ValueType, Preview::Operations::SessionQuery>)
                {
                    return MakeOperationsSessions(State, Value);
                }
                else if constexpr (std::is_same_v<ValueType, Preview::Operations::EventQuery>)
                {
                    return MakeOperationsEvents(State, Value);
                }
                else
                {
                    return InvalidOperationsQuery(Value.Correlation);
                }
            },
            QueryValue.Value);
    }

    [[nodiscard]] static auto MakeOperationsCommand(
        const std::weak_ptr<Application::RuntimeState> &WeakState,
        const Preview::Operations::Command &CommandValue) -> Preview::Operations::CommandResult
    {
        const auto Correlation = Preview::Operations::CorrelationOf(CommandValue);
        const auto State = WeakState.lock();
        if (!State)
        {
            return Preview::Operations::CommandResult::Unavailable(Correlation);
        }
        return std::visit(
            [&State](const auto &Value) -> Preview::Operations::CommandResult
            {
                using ValueType = std::remove_cvref_t<decltype(Value)>;
                auto Result = Preview::Operations::CommandResult::Completed(Value.Correlation);
                if constexpr (std::is_same_v<ValueType, Preview::Operations::RevokeCommand>)
                {
                    Result.Account = Value.Account;
                    if (!State->Accounts || !State->Accounts->Revoke(Value.Account))
                    {
                        Result.Status = Preview::Operations::CommandStatus::Rejected;
                        Result.Message = "account_unavailable";
                    }
                }
                else if constexpr (std::is_same_v<ValueType, Preview::Operations::CancelCommand>)
                {
                    Result.Session = Value.Session;
                    Result.Stream = Value.Stream;
                    Result.Task = Value.Task;
                    if (!State->Listener || !Value.Session ||
                        !State->Listener->Registry().Cancel(Value.Session.Value()))
                    {
                        Result.Status = Preview::Operations::CommandStatus::Rejected;
                        Result.Message = Value.Stream ? "stream_unavailable" : "session_unavailable";
                    }
                }
                else if constexpr (std::is_same_v<ValueType, Preview::Operations::DrainCommand>)
                {
                    Result.Worker = Value.Worker;
                    if (!State->StopRequested.exchange(true, std::memory_order_acq_rel))
                    {
                        ScheduleShutdown(State);
                    }
                }
                else
                {
                    Result.Status = Preview::Operations::CommandStatus::Rejected;
                    Result.Message = "reload_unavailable";
                }
                return Result;
            },
            CommandValue.Value);
    }

    [[nodiscard]] static auto MakeOperationsRouter(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Net::ip::tcp::endpoint &Endpoint) -> Preview::Operations::Router
    {
        Preview::Operations::RouterOptions Options;
        Options.Endpoint.Address = Endpoint.address().to_string();
        Options.Endpoint.Port = Endpoint.port();
        const std::weak_ptr<Application::RuntimeState> WeakState = State;
        return Preview::Operations::Router(
            State->Io.get_executor(),
            [WeakState](const Preview::Operations::Query &QueryValue)
            { return MakeOperationsQuery(WeakState, QueryValue); },
            [WeakState](const Preview::Operations::Command &CommandValue)
            { return MakeOperationsCommand(WeakState, CommandValue); },
            std::move(Options));
    }

    [[nodiscard]] static auto ArmSignals(const std::shared_ptr<Application::RuntimeState> &State)
        -> std::expected<void, StartupError>
    {
        if (State->SignalsArmed.exchange(true, std::memory_order_acq_rel))
        {
            return {};
        }

        boost::system::error_code Error;
        State->Signals.add(SIGINT, Error);
        if (Error)
        {
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Signal, {}, "cannot register SIGINT: " + Error.message()));
        }
        State->Signals.add(SIGTERM, Error);
        if (Error)
        {
            return std::unexpected(MakeStartupError(
                StartupErrorCode::Signal, {}, "cannot register SIGTERM: " + Error.message()));
        }

        const std::weak_ptr<Application::RuntimeState> WeakState = State;
        State->Signals.async_wait(
            [WeakState](const boost::system::error_code &SignalError, const int)
            {
                if (!SignalError)
                {
                    if (const auto StateValue = WeakState.lock())
                    {
                        StateValue->Io.stop();
                    }
                }
            });
        return {};
    }

    Application::Application(Options OptionsValue) : Options_(std::move(OptionsValue))
    {
    }

    Application::Application(std::filesystem::path ConfigurationPath)
        : Application(Options{std::move(ConfigurationPath), nullptr})
    {
    }

    Application::~Application() noexcept
    {
        Stop();
        if (State_ && !State_->Running.load(std::memory_order_acquire) &&
            !State_->StopCompleted.load(std::memory_order_acquire))
        {
            State_->Io.restart();
            while (!State_->StopCompleted.load(std::memory_order_acquire))
            {
                if (State_->Io.run_one() == 0U)
                {
                    State_->Io.restart();
                }
            }
        }
        if (State_)
        {
            State_->StopWorkers();
        }
    }

    auto Application::Start() -> std::expected<Readiness, StartupError>
    {
        if (State_ && State_->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            if (!LastError_)
            {
                LastError_ = MakeStartupError(
                    StartupErrorCode::Runtime, {}, "Preview application cannot restart after stop");
            }
            return std::unexpected(*LastError_);
        }
        if (Readiness_)
        {
            return *Readiness_;
        }
        if (LastError_)
        {
            return std::unexpected(*LastError_);
        }

        const auto Capabilities = ApplicationCapabilities();
        Configuration::ValidationOptions Validation;
        Validation.Secrets = Configuration::SecretRefResolver(Options_.SecretResolver);
        Validation.AvailableCapabilities = Capabilities;
        const auto Parsed = Configuration::ConfigurationParser::LoadFile(
            Configuration::LoadRequest{Options_.ConfigurationPath, std::move(Validation)});
        if (!Parsed)
        {
            const auto ErrorCode =
                Parsed.error().Code == Configuration::ConfigurationErrorCode::FileOpen
                    ? StartupErrorCode::MissingConfiguration
                    : StartupErrorCode::InvalidConfiguration;
            LastError_ = MakeStartupError(ErrorCode, Parsed.error().Path, Parsed.error().Message);
            return std::unexpected(*LastError_);
        }

        auto ConfigurationValue = *Parsed;
        const auto Required = RequiredCapabilities(ConfigurationValue);
        if (!Required)
        {
            LastError_ = Required.error();
            return std::unexpected(*LastError_);
        }

        auto Registry = Builtin::MakeStaticBuiltinRegistry();
        const auto Registered = Builtin::RegisterAllBuiltins(Registry);
        if (!Registered)
        {
            LastError_ = MakeStartupError(
                StartupErrorCode::Builtin, {}, "Preview builtin registration failed");
            return std::unexpected(*LastError_);
        }
        const auto Snapshot = Registry.Freeze(Builtin::FreezeRequest{
            *Required, "PrismPreview", Preview::GenerationId{1}});
        if (!Snapshot)
        {
            LastError_ = MakeStartupError(
                StartupErrorCode::Builtin, {}, "Preview builtin snapshot freeze failed");
            return std::unexpected(*LastError_);
        }

        if (const auto Supported = ValidateSupportedServices(ConfigurationValue, *Snapshot);
            !Supported)
        {
            LastError_ = Supported.error();
            return std::unexpected(*LastError_);
        }

        const auto Generation = Configuration::GenerationBuilder::Build(
            Configuration::GenerationBuildOptions{
                std::move(ConfigurationValue),
                *Snapshot,
                Options_.SecretResolver,
                Capabilities,
                Preview::GenerationId{1}});
        if (!Generation)
        {
            LastError_ = MakeStartupError(
                StartupErrorCode::Generation, Generation.error().Path, Generation.error().Message);
            return std::unexpected(*LastError_);
        }

        const auto Accounts = MakeAccountDirectory(**Generation);
        if (!Accounts)
        {
            LastError_ = Accounts.error();
            return std::unexpected(*LastError_);
        }
        std::optional<StaticProtocol> PrimaryProtocol;
        for (const auto &Configured : (*Generation)->Configuration().Protocols)
        {
            if (const auto Protocol = ParseStaticProtocol(Configured.Name))
            {
                PrimaryProtocol = Protocol;
                break;
            }
        }
        if (!PrimaryProtocol)
        {
            LastError_ = MakeStartupError(
                StartupErrorCode::UnsupportedService,
                "Protocols",
                "configured TCP protocol has no Preview account factory");
            return std::unexpected(*LastError_);
        }
            std::array<std::shared_ptr<const Preview::Account::AccountDirectory>, 7> ProtocolAccounts;
            std::array<Preview::SharedAuthenticator, 7> ProtocolAuthenticators;
        const auto PrimaryIndex = static_cast<std::size_t>(*PrimaryProtocol);
        ProtocolAccounts[PrimaryIndex] = *Accounts;
        ProtocolAuthenticators[PrimaryIndex] =
            std::make_shared<Preview::Account::ProtocolAuthenticator>(ProtocolAccounts[PrimaryIndex]);
        for (const auto &Configured : (*Generation)->Configuration().Protocols)
        {
            if (IsQuicProtocolName(Configured.Builtin))
            {
                continue;
            }
            const auto Protocol = ParseStaticProtocol(Configured.Name);
            if (!Protocol)
            {
                LastError_ = MakeStartupError(
                    StartupErrorCode::UnsupportedService,
                    "Protocols." + Configured.Id,
                    "configured TCP protocol has no Preview account factory");
                return std::unexpected(*LastError_);
            }
            const auto Index = static_cast<std::size_t>(*Protocol);
            if (ProtocolAccounts[Index])
            {
                continue;
            }
            const auto Directory = MakeAccountDirectoryForProtocol(
                **Generation, *Protocol);
            if (!Directory)
            {
                LastError_ = Directory.error();
                return std::unexpected(*LastError_);
            }
            ProtocolAccounts[Index] = *Directory;
            ProtocolAuthenticators[Index] =
                std::make_shared<Preview::Account::ProtocolAuthenticator>(ProtocolAccounts[Index]);
        }
        const auto Endpoint = MakeEndpoint((*Generation)->Configuration().Listeners.Tcp.front());
        if (!Endpoint)
        {
            LastError_ = Endpoint.error();
            return std::unexpected(*LastError_);
        }
        if (const auto Credentials =
                ValidateSampleCredentials((*Generation)->Configuration(), *Endpoint);
            !Credentials)
        {
            LastError_ = Credentials.error();
            return std::unexpected(*LastError_);
        }
        if (const auto Available = CheckBindAvailable(*Endpoint); !Available)
        {
            LastError_ = Available.error();
            return std::unexpected(*LastError_);
        }

        std::optional<Net::ip::udp::endpoint> UdpEndpoint;
        if (!(*Generation)->Configuration().Listeners.Udp.empty())
        {
            const auto ParsedUdp = MakeUdpEndpoint(
                (*Generation)->Configuration().Listeners.Udp.front());
            if (!ParsedUdp)
            {
                LastError_ = ParsedUdp.error();
                return std::unexpected(*LastError_);
            }
            UdpEndpoint = *ParsedUdp;
        }
        else if (!(*Generation)->Configuration().Listeners.Quic.empty())
        {
            const auto ParsedQuic = MakeUdpEndpoint(
                (*Generation)->Configuration().Listeners.Quic.front());
            if (!ParsedQuic)
            {
                LastError_ = ParsedQuic.error();
                return std::unexpected(*LastError_);
            }
            UdpEndpoint = *ParsedQuic;
        }

        std::optional<Net::ip::tcp::endpoint> OperationsEndpoint;
        if ((*Generation)->Configuration().Operations.Enabled)
        {
            const auto ParsedOperations = MakeOperationsEndpoint(
                (*Generation)->Configuration().Operations.Endpoint);
            if (!ParsedOperations)
            {
                LastError_ = ParsedOperations.error();
                return std::unexpected(*LastError_);
            }
            OperationsEndpoint = *ParsedOperations;
        }

        const auto LogLevel = Preview::Diagnose::ParseLogLevel(
            (*Generation)->Configuration().Logging.Level);
        if (!LogLevel)
        {
            LastError_ = MakeStartupError(
                StartupErrorCode::InvalidConfiguration,
                "Logging.Level",
                "unsupported Preview logging level");
            return std::unexpected(*LastError_);
        }
        Preview::Diagnose::LoggerOptions LoggerOptions;
        LoggerOptions.Level = *LogLevel;
        LoggerOptions.Directory = (*Generation)->Configuration().Logging.Directory;
        LoggerOptions.FileName = (*Generation)->Configuration().Logging.FileName;
        LoggerOptions.Console = (*Generation)->Configuration().Logging.Console;
        LoggerOptions.RotateBytes = (*Generation)->Configuration().Logging.RotateBytes;
        LoggerOptions.RotateFiles = (*Generation)->Configuration().Logging.RotateFiles;
        LoggerOptions.FlushIntervalMs =
            (*Generation)->Configuration().Logging.FlushIntervalMs;
        const auto LoggerOwner = Preview::Diagnose::Logger::Create(std::move(LoggerOptions));
        if (!LoggerOwner)
        {
            LastError_ = MakeStartupError(
                StartupErrorCode::Runtime,
                "Logging",
                LoggerOwner.error().Message);
            return std::unexpected(*LastError_);
        }
        const auto TraceOwner = std::make_shared<Preview::Diagnose::TraceContext>(
            Preview::Statistics::TraceSelection{
                (*Generation)->Configuration().Trace.IncludeCorrelation,
                (*Generation)->Configuration().Trace.IncludeWorker,
                (*Generation)->Configuration().Trace.IncludeSession,
                (*Generation)->Configuration().Trace.IncludeStream});

        try
        {
            auto Runtime = std::make_shared<RuntimeState>(
                (*Generation)->Configuration().Runtime.WorkerCount,
                (*Generation)->Id(),
                MakeDnsConfig((*Generation)->Configuration().Dns));
            State_ = Runtime;
            Runtime->Accounts = *Accounts;
            Runtime->Generation = *Generation;
            Runtime->QuicConfigured = !(*Generation)->Configuration().Listeners.Quic.empty();
            Runtime->Logger = *LoggerOwner;
            Runtime->Trace = TraceOwner;
            Runtime->Services = std::make_shared<Preview::Runtime::SessionServices>();
            Runtime->Services->Logger = Runtime->Logger;
            Runtime->Services->TraceSelection = Preview::Statistics::TraceSelection{
                (*Generation)->Configuration().Trace.IncludeCorrelation,
                (*Generation)->Configuration().Trace.IncludeWorker,
                (*Generation)->Configuration().Trace.IncludeSession,
                (*Generation)->Configuration().Trace.IncludeStream};
            Runtime->DnsResolver = std::make_shared<Preview::Network::Dns::Resolver>(
                Runtime->Io.get_executor(),
                MakeDnsConfig((*Generation)->Configuration().Dns));
            if (UdpEndpoint)
            {
                const auto Logger = Runtime->Logger;
                const auto Trace = Runtime->Trace;
                const auto WeakRuntime = std::weak_ptr<RuntimeState>(Runtime);
                Runtime->UdpDemux = std::make_shared<Preview::Ingress::UdpDemux>();
                Runtime->QuicGateway = std::make_shared<Preview::Ingress::QuicGateway>(
                    Preview::Ingress::QuicGatewayOptions{
                        4096,
                        65536,
                        [WeakRuntime, Logger, Trace](const Preview::Ingress::UdpPacket &Packet)
                        {
                            const auto StateValue = WeakRuntime.lock();
                            if (!StateValue || !StateValue->Process)
                            {
                                return;
                            }
                            const auto WorkerCount = StateValue->Process->Workers().Size();
                            const auto WorkerIndex = Preview::Runtime::AffinityBalancer(WorkerCount)
                                                         .Select(Packet.Peer.address().to_string());
                            const auto WorkerId = Preview::WorkerId{
                                static_cast<std::uint64_t>(WorkerIndex + 1U)};
                            const auto Generation = StateValue->Process->Workers().Generation();
                            const auto Bytes = Packet.Payload.size();
                            const auto ConnectionId = Packet.Classification.ConnectionId;
                            const auto Peer = Packet.Peer.address().to_string() + ":" +
                                              std::to_string(Packet.Peer.port());
                            const auto Result = StateValue->Process->Workers().Dispatch(
                                WorkerId, Generation,
                                [Logger, Trace, WorkerId, Bytes, ConnectionId, Peer]
                                {
                                    auto Snapshot = Trace ? Trace->Snapshot()
                                                          : Preview::Statistics::TraceSnapshot{};
                                    Snapshot.Worker = WorkerId;
                                    if (Logger)
                                    {
                                        (void)Logger->TryWrite(
                                            Preview::Diagnose::LogLevel::Debug,
                                            "event=quic_packet_received cid=" +
                                                std::to_string(ConnectionId) + " bytes=" +
                                                std::to_string(Bytes) + " peer=" + Peer,
                                            Snapshot);
                                    }
                                });
                            if (Result != Preview::Runtime::Mailbox::Result::Accepted && Logger)
                            {
                                (void)Logger->TryWrite(
                                    Preview::Diagnose::LogLevel::Warn,
                                    "event=quic_packet_dispatch_rejected worker=" +
                                        std::to_string(WorkerId.Value()) + " result=" +
                                        std::to_string(static_cast<unsigned int>(Result)),
                                    Trace ? Trace->Snapshot()
                                          : Preview::Statistics::TraceSnapshot{});
                            }
                        }});
                Runtime->IngressDispatcher =
                    std::make_shared<Preview::Ingress::IngressDispatcher>(
                        Preview::Ingress::IngressDispatcher::Options{
                            Runtime->QuicGateway,
                            [WeakRuntime, Logger, Trace](Preview::Ingress::UdpPacket Packet)
                            {
                                const auto StateValue = WeakRuntime.lock();
                                if (!StateValue || !StateValue->Process)
                                {
                                    return;
                                }
                                if (StateValue->Ss2022Gateway &&
                                    StateValue->Ss2022Gateway->Handle(Packet))
                                {
                                    return;
                                }
                                const auto WorkerCount = StateValue->Process->Workers().Size();
                                const auto WorkerIndex = Preview::Runtime::AffinityBalancer(WorkerCount)
                                                             .Select(Packet.Peer.address().to_string());
                                const auto WorkerId = Preview::WorkerId{
                                    static_cast<std::uint64_t>(WorkerIndex + 1U)};
                                const auto Generation = StateValue->Process->Workers().Generation();
                                const auto Bytes = Packet.Payload.size();
                                const auto Peer = Packet.Peer.address().to_string() + ":" +
                                                  std::to_string(Packet.Peer.port());
                                const auto Result = StateValue->Process->Workers().Dispatch(
                                    WorkerId, Generation,
                                    [Logger, Trace, WorkerId, Bytes, Peer]
                                    {
                                        auto Snapshot = Trace ? Trace->Snapshot()
                                                              : Preview::Statistics::TraceSnapshot{};
                                        Snapshot.Worker = WorkerId;
                                        if (Logger)
                                        {
                                            (void)Logger->TryWrite(
                                                Preview::Diagnose::LogLevel::Debug,
                                                "event=udp_datagram_received status=unclaimed bytes=" +
                                                    std::to_string(Bytes) + " peer=" + Peer,
                                                Snapshot);
                                        }
                                    });
                                if (Result != Preview::Runtime::Mailbox::Result::Accepted && Logger)
                                {
                                    (void)Logger->TryWrite(
                                        Preview::Diagnose::LogLevel::Warn,
                                        "event=udp_datagram_dispatch_rejected worker=" +
                                            std::to_string(WorkerId.Value()) + " result=" +
                                            std::to_string(static_cast<unsigned int>(Result)),
                                        Trace ? Trace->Snapshot()
                                              : Preview::Statistics::TraceSnapshot{});
                                }
                            },
                            [WeakRuntime](Preview::Ingress::UdpPacket Packet) -> bool
                            {
                                const auto StateValue = WeakRuntime.lock();
                                return StateValue && StateValue->QuicCidRegistry &&
                                       StateValue->QuicCidRegistry->Handle(std::move(Packet));
                            }});
                Runtime->UdpListener =
                    std::make_unique<Preview::Ingress::UdpListener>(Runtime->Io.get_executor());
                const auto SsIndex = static_cast<std::size_t>(StaticProtocol::Shadowsocks2022);
                if (ProtocolAccounts[SsIndex])
                {
                    std::vector<std::array<std::uint8_t, 16>> Keys;
                    ProtocolAccounts[SsIndex]->ForEach(
                        [&Keys](const auto &Record)
                        {
                            const auto Credential = Record->Credential();
                            if (Credential.Kind() != Preview::Account::CredentialKind::Psk ||
                                Credential.Size() != 16U)
                            {
                                return;
                            }
                            std::array<std::uint8_t, 16> Key{};
                            const auto Bytes = Credential.Bytes();
                            for (std::size_t Index = 0; Index < Key.size(); ++Index)
                            {
                                Key[Index] = std::to_integer<std::uint8_t>(Bytes[Index]);
                            }
                            Keys.push_back(Key);
                        });
                    if (!Keys.empty())
                    {
                        const auto WeakRuntime = std::weak_ptr<RuntimeState>(Runtime);
                        Preview::Ingress::Ss2022Gateway::Options GatewayOptions;
                        GatewayOptions.Executor = Runtime->Io.get_executor();
                        GatewayOptions.Keys = std::move(Keys);
                        GatewayOptions.Resolver = Runtime->DnsResolver;
                        GatewayOptions.Send = [WeakRuntime](
                                                   std::span<const std::byte> Payload,
                                                   const Net::ip::udp::endpoint &Peer)
                            -> Net::awaitable<boost::system::error_code>
                        {
                            const auto StateValue = WeakRuntime.lock();
                            if (!StateValue || !StateValue->UdpListener)
                            {
                                co_return boost::system::errc::make_error_code(
                                    boost::system::errc::operation_canceled);
                            }
                            co_return co_await StateValue->UdpListener->SendTo(Payload, Peer);
                        };
                        Runtime->Ss2022Gateway = std::make_shared<Preview::Ingress::Ss2022Gateway>(
                            std::move(GatewayOptions));
                    }
                }
            }
            const auto NativeTls = MakeNativeTlsContext(
                (*Generation)->Configuration(), Options_.ConfigurationPath);
            if (!NativeTls)
            {
                LastError_ = NativeTls.error();
                RunStartupRollback(Runtime);
                State_.reset();
                return std::unexpected(*LastError_);
            }
            Runtime->Services->NativeTls = *NativeTls;
            for (const auto &Configured : (*Generation)->Configuration().Protocols)
            {
                if (const auto Protocol = ParseStaticProtocol(Configured.Name))
                {
                    const auto Index = static_cast<std::size_t>(*Protocol);
                    (void)Runtime->Logger->TryWrite(
                        Preview::Diagnose::LogLevel::Info,
                        "event=account_directory protocol=" + Configured.Name + " " +
                            DescribeAccountDirectory(ProtocolAccounts[Index]));
                }
            }
            (void)Runtime->Logger->TryWrite(
                Preview::Diagnose::LogLevel::Info,
                "event=runtime_start",
                Runtime->Trace->Snapshot());
            Runtime->ShutdownTimeout = std::chrono::milliseconds(
                (*Generation)->Configuration().Shutdown.Timeout);
            Runtime->Services->HandshakeTimeout = std::chrono::milliseconds(
                (*Generation)->Configuration().Listeners.Tcp.front().Timeout);
            Runtime->Services->RelayIdleTimeout = std::chrono::milliseconds(
                (*Generation)->Configuration().Runtime.SessionTimeout);
            const auto DialTimeout = std::chrono::milliseconds(
                (*Generation)->Configuration().Listeners.Tcp.front().Timeout);
            const auto Executor = Runtime->Io.get_executor();
            Runtime->Services->Dial = [Executor, DialTimeout, Resolver = Runtime->DnsResolver](
                                           const Preview::Network::Target &Target)
                -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
            {
                return DialTargetWithResolver(
                    ResolverDialRequest{Executor, DialTimeout, Resolver, Target});
            };
            if (Runtime->UdpListener && Runtime->Services->NativeTls)
            {
                const auto Socket = Runtime->UdpListener->SharedSocket();
                const auto TlsContext = Runtime->Services->NativeTls;
                Preview::Ingress::SharedQuicAdmissionContext QuicContext;
                if (!(*Generation)->Configuration().Listeners.Quic.empty())
                {
                    for (const auto &Configured : (*Generation)->Configuration().Protocols)
                    {
                        if (!Configured.Quic)
                        {
                            continue;
                        }
                        const auto Built = MakeQuicAdmissionContext(
                            **Generation, Configured, Executor, Runtime->DnsResolver,
                            Runtime->Services->Dial, Runtime->Services->Traffic);
                        if (!Built)
                        {
                            LastError_ = Built.error();
                            RunStartupRollback(Runtime);
                            State_.reset();
                            return std::unexpected(*LastError_);
                        }
                        QuicContext = *Built;
                        break;
                    }
                }
                Runtime->QuicCidRegistry = std::make_shared<Preview::Ingress::QuicCidRegistry>(
                    Preview::Ingress::QuicCidRegistry::Options{
                        [Executor, Socket, TlsContext](
                            std::span<const std::byte>,
                            const Net::ip::udp::endpoint &,
                            Preview::Ingress::SharedQuicAdmissionContext Context)
                            -> std::shared_ptr<Preview::Quic::Server>
                        {
                            if (!Socket || !TlsContext || !Context ||
                                !Context->Ready())
                            {
                                return nullptr;
                            }
                            Preview::Quic::ServerOptions Options;
                            Options.Executor = Executor;
                            Options.Socket = Socket;
                            Options.TlsContext = TlsContext->native_handle();
                            Options.ExternalReceive = true;
                            if (Context->Protocol == "tuic")
                            {
                                Options = Preview::Composition::Quic::ConfigureTuicServer(
                                    std::move(Options), Context);
                            }
                            else
                            {
                                Options = Preview::Composition::Quic::ConfigureHysteria2Server(
                                    std::move(Options), Context);
                            }
                            return std::make_shared<Preview::Quic::Server>(std::move(Options));
                        },
                        QuicContext});
            }
            Preview::Composition::UdpServiceOptions UdpOptions;
            UdpOptions.Resolver = [Resolver = Runtime->DnsResolver](
                                      Preview::Composition::UdpResolveRequest Request)
                -> Net::awaitable<std::pair<Preview::Error, Net::ip::udp::endpoint>>
            {
                return ResolveUdpTarget(Resolver, std::move(Request));
            };
            const auto Socks5UdpService = Preview::Composition::UdpServiceFactory::MakeSocks5(UdpOptions);
            const auto VlessUdpService = Preview::Composition::UdpServiceFactory::MakeVless(UdpOptions);
            const auto TrojanUdpService = Preview::Composition::UdpServiceFactory::MakeTrojan(UdpOptions);
            const auto VmessUdpService = Preview::Composition::UdpServiceFactory::MakeVmess(UdpOptions);
            Runtime->Services->UdpService = [Socks5UdpService, VlessUdpService,
                                             TrojanUdpService, VmessUdpService](
                                                  Preview::Middleware::Context &Context)
                -> Net::awaitable<Preview::Fault::Code>
            {
                switch (static_cast<Preview::Recognition::ProtocolType>(Context.detected))
                {
                case Preview::Recognition::ProtocolType::Socks5:
                    co_return co_await Socks5UdpService(Context);
                case Preview::Recognition::ProtocolType::Vless:
                    co_return co_await VlessUdpService(Context);
                case Preview::Recognition::ProtocolType::Trojan:
                    co_return co_await TrojanUdpService(Context);
                case Preview::Recognition::ProtocolType::Vmess:
                    co_return co_await VmessUdpService(Context);
                default:
                    co_return Preview::Fault::Code::NotSupported;
                }
            };
            Runtime->Services->Auth = std::make_shared<Preview::Account::ProtocolAuthenticator>(
                Runtime->Accounts);
            Runtime->MuxService = std::make_shared<Preview::Composition::MuxService>(
                Preview::Composition::MuxServiceOptions{
                    .Mode = ConfiguredMuxMode((*Generation)->Configuration()),
                    .Control = {},
                    .Identity = {},
                    .MaxStreams = 256,
                    .Timeout = std::chrono::milliseconds(0),
                    .StreamHandlerFn = [Services = Runtime->Services](
                                           Preview::SharedTransmission Stream,
                                           const Preview::Lifecycle::TaskIdentity &Identity)
                        -> Net::awaitable<Preview::Fault::Code>
                    {
                        auto ChildControl = std::make_shared<Preview::Runtime::SessionControl>(
                            Stream ? Stream->Executor() : Net::any_io_executor{});
                        ChildControl->SetIdentity(Preview::Lifecycle::TaskIdentity{
                            Preview::TaskId{}, Identity.SessionId, Identity.StreamId,
                            Identity.WorkerId, Identity.Generation});
                        Preview::Runtime::SessionOptions ChildOptions;
                        ChildOptions.Services = Services;
                        ChildOptions.Control = std::move(ChildControl);
                        Preview::Runtime::Session Child(std::move(ChildOptions));
                        co_return co_await Child.Run(std::move(Stream));
                    }});
            Runtime->Services->Mux = [Service = Runtime->MuxService,
                                      Services = Runtime->Services](
                                          Preview::SharedTransmission &Inbound,
                                          Preview::Middleware::Context &Context)
                -> Net::awaitable<bool>
            {
                if (!Context.DataPlane.IsMux())
                {
                    co_return true;
                }
                if (static_cast<Preview::Recognition::ProtocolType>(Context.detected) ==
                    Preview::Recognition::ProtocolType::AnyTls)
                {
                    const auto Code = co_await Preview::Composition::AnytlsService::Run(
                        Inbound, Context, Services->Dial);
                    co_return Code == Preview::Fault::Code::Success;
                }
                const auto Code = co_await Service->Run(Inbound, Context);
                co_return Code == Preview::Fault::Code::Success;
            };
            const ProtocolFactoryContext ProtocolContext{
                (*Generation)->Configuration(), **Generation, std::move(ProtocolAuthenticators),
                std::move(ProtocolAccounts), Runtime->Services->NativeTls,
                Runtime->Services->Dial};
            const auto Profile = MakeTcpProfile(ProtocolContext);
            if (!Profile)
            {
                LastError_ = Profile.error();
                return std::unexpected(*LastError_);
            }
            Runtime->Services->Profile = Profile->Profile;
            Runtime->Services->ResolveCandidate = std::move(Profile->Resolver);
            Runtime->Services->Resolver = Runtime->Services->ResolveCandidate;
            const auto WeakState = std::weak_ptr<RuntimeState>(Runtime);
            Preview::Runtime::TcpListener::Options ListenerOptions;
            ListenerOptions.Executor = Runtime->Io.get_executor();
            ListenerOptions.Factory = MakeSessionFactory(
                SessionFactoryOptions{Runtime->Services, &Runtime->Process->Workers()});
            ListenerOptions.WorkerCount = (*Generation)->Configuration().Runtime.WorkerCount;
            ListenerOptions.Workers = &Runtime->Process->Workers();
            ListenerOptions.OnFailure = [WeakState](const Preview::Fault::Code) noexcept
            {
                if (const auto State = WeakState.lock())
                {
                    MarkShutdownFailed(State);
                    if (!State->StopRequested.exchange(true, std::memory_order_acq_rel))
                    {
                        ScheduleShutdown(State);
                    }
                }
            };
            Runtime->Listener = std::make_unique<Preview::Runtime::TcpListener>(
                std::move(ListenerOptions));
            Runtime->StartWorkers((*Generation)->Configuration().Runtime.WorkerCount);

            if (const auto Started = StartListener(State_, *Endpoint); !Started)
            {
                LastError_ = Started.error();
                RunStartupRollback(State_);
                State_.reset();
                return std::unexpected(*LastError_);
            }
            if (UdpEndpoint)
            {
                if (const auto Started = StartUdpListener(State_, *UdpEndpoint); !Started)
                {
                    LastError_ = Started.error();
                    RunStartupRollback(State_);
                    State_.reset();
                    return std::unexpected(*LastError_);
                }
                Runtime->QuicGateway->MarkSocketReady();
                Runtime->QuicGateway->MarkReceiveLoopReady();
            }
            if (OperationsEndpoint)
            {
                const auto OperationsRouter = MakeOperationsRouter(State_, *OperationsEndpoint);
                State_->OperationsServer = std::make_unique<Preview::Operations::HttpServer>(
                    State_->Io.get_executor(), *OperationsEndpoint, OperationsRouter);
                if (const auto Started = StartOperations(State_); !Started)
                {
                    LastError_ = Started.error();
                    RunStartupRollback(State_);
                    State_.reset();
                    return std::unexpected(*LastError_);
                }
            }
            const auto UdpHealth = Runtime->UdpListener
                                       ? Runtime->UdpListener->Health()
                                       : Preview::Ingress::UdpListenerHealth{};
            const auto QuicHealth = Runtime->QuicGateway
                                        ? Runtime->QuicGateway->Health()
                                        : Preview::Ingress::QuicGatewayHealth{};
            State_->Ready = Readiness{
                State_->Listener->LocalEndpoint().port(),
                State_->OperationsServer
                    ? static_cast<std::uint16_t>(State_->OperationsServer->LocalEndpoint().port())
                    : static_cast<std::uint16_t>(0),
                (*Generation)->Id(),
                static_cast<std::uint16_t>(UdpHealth.Bound
                                               ? Runtime->UdpListener->LocalEndpoint().port()
                                               : 0),
                UdpHealth.Healthy(),
                !(*Generation)->Configuration().Listeners.Quic.empty() && QuicHealth.Healthy(),
                UdpHealth.Bound,
                QuicHealth.SocketReady,
                QuicHealth.HandshakeReady,
                QuicHealth.ProtocolReady};
            if (const auto Signals = ArmSignals(State_); !Signals)
                {
                    LastError_ = Signals.error();
                    RunStartupRollback(State_);
                    State_.reset();
                    return std::unexpected(*LastError_);
            }
            State_->Phase.store(RuntimePhase::Ready, std::memory_order_release);
            if (State_->Events)
            {
                Preview::Statistics::DetailedEvent Event;
                Event.Timestamp = static_cast<std::uint64_t>(
                    std::chrono::steady_clock::now().time_since_epoch().count());
                Event.Generation = State_->Generation->Id();
                Event.Process = State_->Process->Id();
                Event.Kind = Preview::Statistics::EventKind::GenerationReloaded;
                Event.Severity = Preview::Statistics::EventSeverity::Info;
                Event.Detail = "application ready";
                (void)State_->Events->Append(std::move(Event));
            }
            if (State_->Logger)
            {
                (void)State_->Logger->TryWrite(
                    Preview::Diagnose::LogLevel::Info,
                    "event=runtime_ready",
                    State_->Trace ? State_->Trace->Snapshot()
                                  : Preview::Statistics::TraceSnapshot{});
            }
            auto *Output = Options_.Output != nullptr ? Options_.Output : &std::cout;
            *Output << "PrismPreview READY tcp_port=" << State_->Ready.Port
                    << " udp_port=" << State_->Ready.UdpPort
                    << " udp_ready=" << (State_->Ready.UdpReady ? "true" : "false")
                    << " quic_ready=" << (State_->Ready.QuicReady ? "true" : "false")
                    << " generation=" << State_->Ready.Generation.Value()
                    << " quic_socket_ready="
                    << (State_->Ready.QuicSocketReady ? "true" : "false")
                    << " quic_handshake_ready="
                    << (State_->Ready.QuicHandshakeReady ? "true" : "false")
                    << " quic_protocol_ready="
                    << (State_->Ready.QuicProtocolReady ? "true" : "false")
                    << '\n'
                    << std::flush;
            Readiness_ = State_->Ready;
            return *Readiness_;
        }
        catch (const std::exception &Error)
        {
            LastError_ = MakeStartupError(
                StartupErrorCode::Runtime, {}, "Preview runtime construction failed: " +
                                                   std::string(Error.what()));
            if (State_)
            {
                RunStartupRollback(State_);
                State_.reset();
            }
            return std::unexpected(*LastError_);
        }
    }

    auto Application::Run() -> int
    {
        if (!State_ || State_->Phase.load(std::memory_order_acquire) == RuntimePhase::Ready)
        {
            const auto Started = Start();
            if (!Started)
            {
                std::cerr << "PrismPreview startup failed code="
                          << static_cast<unsigned int>(Started.error().Code);
                if (!Started.error().Path.empty())
                {
                    std::cerr << " path=" << Started.error().Path;
                }
                std::cerr << " message=" << Started.error().Message << '\n';
                return 1;
            }
        }
        if (!State_ || IsStopped())
        {
            return State_ ? State_->ExitCode : 0;
        }

        State_->Running.store(true, std::memory_order_release);
        State_->Io.run();
        State_->Running.store(false, std::memory_order_release);
        if (!State_->StopCompleted.load(std::memory_order_acquire))
        {
            Stop();
            State_->Io.restart();
            State_->Io.run();
        }
        State_->StopWorkers();
        return State_->ExitCode;
    }

    auto Application::Stop() noexcept -> void
    {
        if (!State_ || State_->StopRequested.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        if (State_->Phase.load(std::memory_order_acquire) != RuntimePhase::Failed)
        {
            State_->Phase.store(RuntimePhase::Stopping, std::memory_order_release);
        }
        ScheduleShutdown(State_);
    }

    auto Application::IsReady() const noexcept -> bool
    {
        return State_ && State_->Phase.load(std::memory_order_acquire) == RuntimePhase::Ready;
    }

    auto Application::IsStopping() const noexcept -> bool
    {
        if (!State_)
        {
            return false;
        }
        return State_->Phase.load(std::memory_order_acquire) == RuntimePhase::Stopping;
    }

    auto Application::IsStopped() const noexcept -> bool
    {
        return State_ && State_->StopCompleted.load(std::memory_order_acquire);
    }

    auto Application::LastError() const noexcept -> const std::optional<StartupError> &
    {
        return LastError_;
    }

} // namespace Preview::Application
