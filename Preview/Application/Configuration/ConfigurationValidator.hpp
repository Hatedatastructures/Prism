/**
 * @file ConfigurationValidator.hpp
 * @brief Preview 配置语义校验和 SecretRef 解析。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationError.hpp>
#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Application/Configuration/SecretRefResolver.hpp>
#include <Preview/Composition/Builtin/Snapshot.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <charconv>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Preview::Application::Configuration
{

    struct ValidationOptions final
    {
        SecretRefResolver Secrets{};
        Preview::Composition::Builtin::CapabilitySet AvailableCapabilities{};
        std::shared_ptr<const Preview::Composition::Builtin::BuiltinSnapshot> Builtins{};
        bool CheckSecrets{true};
        bool CheckCapabilities{true};
        bool RequireBuiltinSnapshot{false};
    };

    struct ValidationRequest final
    {
        const PreviewConfiguration &Configuration;
        ValidationOptions Options{};
    };

    class ConfigurationValidator final
    {
    public:
        using Result = std::expected<void, ConfigurationError>;

        [[nodiscard]] static auto Validate(const PreviewConfiguration &Configuration) -> Result
        {
            return Validate(ValidationRequest{
                Configuration,
                ValidationOptions{.CheckSecrets = true, .CheckCapabilities = true}});
        }

        [[nodiscard]] static auto Validate(ValidationRequest Request) -> Result
        {
            const auto &Configuration = Request.Configuration;
            if (Configuration.SchemaVersion != 1U)
            {
                return Failure(ConfigurationErrorCode::UnsupportedSchemaVersion, "SchemaVersion",
                               "only schema version 1 is supported");
            }
            if (Configuration.Runtime.WorkerCount == 0U ||
                Configuration.Runtime.WorkerCount > MaxWorkerCount)
            {
                return Failure(ConfigurationErrorCode::InvalidValue, "Runtime.WorkerCount",
                               "WorkerCount must be between 1 and 4096");
            }
            if (const auto Result = ValidateTimeout(Configuration.Runtime.SessionTimeout,
                                                    "Runtime.SessionTimeout");
                !Result)
            {
                return Result;
            }

            const auto &Recognition = Configuration.Recognition;
            const bool ConfiguredMode = Recognition.Mode == "Configured";
            const bool MixedTrialMode = Recognition.Mode == "MixedTrial";
            const bool DeterministicMode = Recognition.Mode == "Deterministic" ||
                                           Recognition.Mode == "DeterministicRoute";
            if (!ConfiguredMode && !MixedTrialMode && !DeterministicMode)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Recognition.Mode",
                               "mode must be Configured, MixedTrial, or Deterministic");
            }
            if (Recognition.ConfiguredCandidate < -1 ||
                Recognition.ConfiguredCandidate > 127)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Recognition.ConfiguredCandidate",
                               "ConfiguredCandidate must be between -1 and 127");
            }
            if (!ConfiguredMode && Recognition.ConfiguredCandidate != -1)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Recognition.ConfiguredCandidate",
                               "ConfiguredCandidate is only valid in Configured mode");
            }

            if (Configuration.Listeners.Tcp.size() != 1U)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Listeners.Tcp",
                               "PrismPreview requires exactly one configured TCP listener");
            }
            if (Configuration.Listeners.Udp.size() > 1U ||
                Configuration.Listeners.Quic.size() > 1U)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Listeners",
                               "configure at most one Udp and one Quic listener");
            }

            std::unordered_set<std::string> Ids;
            std::unordered_set<std::string> ProtocolIds;
            std::unordered_set<std::string> QuicProtocolNames;
            std::unordered_set<std::string> CarrierIds;
            std::vector<const Preview::Composition::Builtin::BuiltinSnapshot::Entry *>
                ProtocolDescriptors(Configuration.Protocols.size(), nullptr);
            if (const auto Result = ValidateEndpoints(Configuration.Listeners.Tcp, "Listeners.Tcp", Ids);
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateEndpoints(Configuration.Listeners.Udp, "Listeners.Udp", Ids);
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateEndpoints(Configuration.Listeners.Quic, "Listeners.Quic", Ids);
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateTimeout(Configuration.Listeners.Timeout, "Listeners.Timeout");
                !Result)
            {
                return Result;
            }
            if (!Configuration.Listeners.Udp.empty() && !Configuration.Listeners.Quic.empty())
            {
                const auto &Udp = Configuration.Listeners.Udp.front();
                const auto &Quic = Configuration.Listeners.Quic.front();
                if (Udp.Address != Quic.Address || Udp.Port != Quic.Port)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   "Listeners.Quic[0]",
                                   "Udp and Quic must share the same address and numeric port");
                }
            }
            if (Configuration.NativeTls.Enabled &&
                (Configuration.NativeTls.CertificateFile.empty() ||
                 Configuration.NativeTls.PrivateKeyFile.empty()))
            {
                return Failure(ConfigurationErrorCode::MissingField, "NativeTls",
                               "Enabled NativeTls requires CertificateFile and PrivateKeyFile");
            }

            for (std::size_t Index = 0; Index < Configuration.Builtins.size(); ++Index)
            {
                const auto &Builtin = Configuration.Builtins[Index];
                const auto Path = "Builtins[" + std::to_string(Index) + "]";
                if (const auto Result = AddId(Ids, Builtin.Id, Path + ".Id"); !Result)
                {
                    return Result;
                }
                if (Builtin.Kind.empty() || Builtin.Name.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue, Path,
                                   "builtin Kind and Name are required");
                }

                Preview::Composition::Builtin::CapabilitySet ClaimedCapabilities;
                if (const auto Result = AddCapabilities(
                        Builtin.Provides, ClaimedCapabilities, Path + ".Provides");
                    !Result)
                {
                    return Result;
                }
                if (!Request.Options.Builtins)
                {
                    if (Request.Options.RequireBuiltinSnapshot)
                    {
                        return Failure(ConfigurationErrorCode::MissingReference, Path,
                                       "configured builtin requires a frozen snapshot");
                    }
                    continue;
                }

                const auto Entries = Request.Options.Builtins->Entries();
                const auto Entry = std::find_if(
                    Entries.begin(), Entries.end(), [&Builtin](const auto &Value)
                    {
                        return Value.Descriptor.Kind.Value() == Builtin.Kind &&
                               Value.Descriptor.Name.Value() == Builtin.Name;
                    });
                if (Entry == Entries.end())
                {
                    return Failure(ConfigurationErrorCode::MissingReference, Path,
                                   "builtin Kind and Name do not resolve in the frozen snapshot");
                }
                if (!Entry->Descriptor.Provides.Includes(ClaimedCapabilities))
                {
                    return Failure(ConfigurationErrorCode::MissingCapability,
                                   Path + ".Provides",
                                   "configured capability is not provided by the registered builtin");
                }
            }
            for (std::size_t Index = 0; Index < Configuration.Protocols.size(); ++Index)
            {
                const auto &Protocol = Configuration.Protocols[Index];
                const auto Path = "Protocols[" + std::to_string(Index) + "]";
                if (const auto Result = AddId(Ids, Protocol.Id, Path + ".Id"); !Result)
                {
                    return Result;
                }
                if (Protocol.Name.empty() || Protocol.Builtin.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue, Path,
                                   "protocol Name and Builtin are required");
                }
                if (IsCarrierBuiltin(Protocol.Builtin))
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".Builtin",
                                   "carrier builtin cannot be configured as a protocol");
                }
                if (Request.Options.Builtins)
                {
                    const auto *Entry = FindBuiltinDescriptor(
                        *Request.Options.Builtins, "protocol", Protocol.Builtin);
                    if (!Entry)
                    {
                        return Failure(ConfigurationErrorCode::MissingReference,
                                       Path + ".Builtin",
                                       "protocol builtin is unavailable in the frozen snapshot");
                    }
                    ProtocolDescriptors[Index] = Entry;
                }
                else if (Request.Options.RequireBuiltinSnapshot)
                {
                    return Failure(ConfigurationErrorCode::MissingReference,
                                   Path + ".Builtin",
                                   "configured protocol requires a frozen builtin snapshot");
                }
                ProtocolIds.insert(Protocol.Id);
                const bool IsQuic = Protocol.Builtin == "hysteria2" || Protocol.Builtin == "tuic";
                if (IsQuic && !QuicProtocolNames.insert(Protocol.Builtin).second)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".Builtin",
                                   "duplicate QUIC protocol builtin");
                }
                if (IsQuic && !Protocol.Quic)
                {
                    return Failure(ConfigurationErrorCode::MissingField,
                                   Path + ".Quic",
                                   "QUIC protocol configuration is required");
                }
                if (!IsQuic && Protocol.Quic)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".Quic",
                                   "Quic options are only valid for hysteria2 or tuic");
                }
                if (Protocol.Quic)
                {
                    if (Protocol.Builtin == "tuic" &&
                        !IsValidUuidText(Protocol.Quic->Uuid))
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".Quic.Uuid",
                                       "TUIC requires a 16-byte UUID text");
                    }
                    if (Protocol.Quic->Alpn != "h3")
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".Quic.Alpn",
                                       "Hysteria2 and TUIC require ALPN h3");
                    }
                    if (Protocol.Quic->ServerName.empty())
                    {
                        return Failure(ConfigurationErrorCode::MissingField,
                                       Path + ".Quic.ServerName",
                                       "QUIC ServerName is required");
                    }
                    if (Protocol.Quic->MaxStreams == 0U || Protocol.Quic->MaxDatagrams == 0U)
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".Quic",
                                       "QUIC stream and datagram limits must be positive");
                    }
                    if (const auto Result = ValidateSecretReference(
                            Protocol.Quic->CredentialSecretRef,
                            Path + ".Quic.CredentialSecretRef",
                            Request.Options);
                        !Result)
                    {
                        return Result;
                    }
                }
            }
            for (std::size_t Index = 0; Index < Configuration.Carriers.size(); ++Index)
            {
                const auto &Carrier = Configuration.Carriers[Index];
                const auto Path = "Carriers[" + std::to_string(Index) + "]";
                if (const auto Result = AddId(Ids, Carrier.Id, Path + ".Id"); !Result)
                {
                    return Result;
                }
                if (Carrier.Name.empty() || Carrier.Builtin.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue, Path,
                                   "carrier Name and Builtin are required");
                }
                if (Request.Options.Builtins)
                {
                    if (!FindBuiltinDescriptor(
                            *Request.Options.Builtins, "carrier", Carrier.Builtin))
                    {
                        return Failure(ConfigurationErrorCode::MissingReference,
                                       Path + ".Builtin",
                                       "carrier builtin is unavailable in the frozen snapshot");
                    }
                }
                else if (Request.Options.RequireBuiltinSnapshot)
                {
                    return Failure(ConfigurationErrorCode::MissingReference,
                                   Path + ".Builtin",
                                   "configured carrier requires a frozen builtin snapshot");
                }
                CarrierIds.insert(Carrier.Id);
                if (const auto Result = ValidateCarrierMatch(Carrier.Match, Path + ".Match");
                    !Result)
                {
                    return Result;
                }
                if (const auto Result = ValidateCarrier(Carrier, Path, Request.Options); !Result)
                {
                    return Result;
                }
            }
            for (std::size_t Index = 0; Index < Configuration.ProtocolBindings.size(); ++Index)
            {
                const auto &Binding = Configuration.ProtocolBindings[Index];
                const auto Path = "ProtocolBindings[" + std::to_string(Index) + "]";
                if (const auto Result = AddId(Ids, Binding.Id, Path + ".Id"); !Result)
                {
                    return Result;
                }
                if (Binding.ProtocolId.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".ProtocolId",
                                   "ProtocolId is required");
                }
                if (!ProtocolIds.contains(Binding.ProtocolId))
                {
                    return Failure(ConfigurationErrorCode::MissingReference,
                                   Path + ".ProtocolId",
                                   "ProtocolId does not reference a configured protocol");
                }
                if (Binding.CarrierId)
                {
                    if (Binding.CarrierId->empty())
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".CarrierId",
                                       "CarrierId must not be empty when present");
                    }
                    if (!CarrierIds.contains(*Binding.CarrierId))
                    {
                        return Failure(ConfigurationErrorCode::MissingReference,
                                       Path + ".CarrierId",
                                       "CarrierId does not reference a configured carrier");
                    }
                    const auto Protocol = std::find_if(
                        Configuration.Protocols.begin(), Configuration.Protocols.end(),
                        [&Binding](const ProtocolConfiguration &Value)
                        { return Value.Id == Binding.ProtocolId; });
                    const auto Carrier = std::find_if(
                        Configuration.Carriers.begin(), Configuration.Carriers.end(),
                        [&Binding](const CarrierConfiguration &Value)
                        { return Value.Id == *Binding.CarrierId; });
                    if (Protocol != Configuration.Protocols.end() &&
                        IsStackProtocolBuiltin(Protocol->Builtin) &&
                        !(Protocol->Builtin == "anytls" &&
                          Carrier != Configuration.Carriers.end() &&
                          Carrier->Builtin == "native"))
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".CarrierId",
                                       "stack protocol can only use the native TLS outer carrier");
                    }
                }
                if (const auto Result = ValidateRecognitionRoute(
                        Binding.Recognition, Path + ".Recognition");
                    !Result)
                {
                    return Result;
                }
                if (!Binding.TcpEnabled && !Binding.UdpEnabled)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path,
                                   "at least one of TcpEnabled and UdpEnabled is required");
                }
                for (std::size_t MuxIndex = 0; MuxIndex < Binding.MuxModes.size(); ++MuxIndex)
                {
                    if (Binding.MuxModes[MuxIndex] == "4C64S" ||
                        Binding.MuxModes[MuxIndex] == "1C256S")
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".MuxModes[" + std::to_string(MuxIndex) + "]",
                                       "mux connection profiles require a physical connection pool");
                    }
                    if (!IsMuxMode(Binding.MuxModes[MuxIndex]))
                    {
                        return Failure(ConfigurationErrorCode::UnknownMuxMode,
                                       Path + ".MuxModes[" + std::to_string(MuxIndex) + "]",
                                       "unknown mux mode");
                    }
                }
                const auto Protocol = std::find_if(
                    Configuration.Protocols.begin(), Configuration.Protocols.end(),
                    [&Binding](const ProtocolConfiguration &Value)
                    { return Value.Id == Binding.ProtocolId; });
                if (Protocol != Configuration.Protocols.end())
                {
                    const auto ProtocolIndex = static_cast<std::size_t>(
                        Protocol - Configuration.Protocols.begin());
                    const auto *Entry = ProtocolDescriptors[ProtocolIndex];
                    if (Entry)
                    {
                        const auto &Provides = Entry->Descriptor.Provides;
                        if (Binding.TcpEnabled &&
                            !Provides.Declares(Preview::Composition::Builtin::Capability::Stream))
                        {
                            return Failure(ConfigurationErrorCode::MissingCapability,
                                           Path + ".TcpEnabled",
                                           "protocol builtin does not provide Stream");
                        }
                        if (Binding.UdpEnabled &&
                            !Provides.Declares(Preview::Composition::Builtin::Capability::Datagram) &&
                            !Provides.Declares(Preview::Composition::Builtin::Capability::Quic))
                        {
                            return Failure(ConfigurationErrorCode::MissingCapability,
                                           Path + ".UdpEnabled",
                                           "protocol builtin does not provide Datagram or Quic");
                        }
                        if (!Binding.MuxModes.empty() &&
                            !Provides.Declares(Preview::Composition::Builtin::Capability::Multiplex))
                        {
                            return Failure(ConfigurationErrorCode::MissingCapability,
                                           Path + ".MuxModes",
                                           "protocol builtin does not provide Multiplex");
                        }
                    }
                }
            }
            if (const auto Result = ValidateProtocolBindingRouteAmbiguity(
                    Configuration.ProtocolBindings);
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateCarrierRouteAmbiguity(Configuration); !Result)
            {
                return Result;
            }
            for (std::size_t Index = 0; Index < Configuration.Accounts.size(); ++Index)
            {
                const auto &Account = Configuration.Accounts[Index];
                const auto Path = "Accounts[" + std::to_string(Index) + "]";
                if (const auto Result = AddId(Ids, Account.Id, Path + ".Id"); !Result)
                {
                    return Result;
                }
                if (Account.SecretRef.empty() && Account.Credential.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue, Path,
                                   "Credential or SecretRef is required");
                }
                if (Request.Options.CheckSecrets && !Account.SecretRef.empty())
                {
                    std::optional<std::string> Secret;
                    try
                    {
                        Secret = Request.Options.Secrets.Resolve(Account.SecretRef);
                    }
                    catch (...)
                    {
                        Secret.reset();
                    }
                    if (!Secret || Secret->empty())
                    {
                        return Failure(ConfigurationErrorCode::UnresolvedSecret,
                                       Path + ".SecretRef", "SecretRef cannot be resolved");
                    }
                }
            }
            for (std::size_t Index = 0; Index < Configuration.Routes.size(); ++Index)
            {
                const auto &Route = Configuration.Routes[Index];
                const auto Path = "Routes[" + std::to_string(Index) + "]";
                if (const auto Result = AddId(Ids, Route.Id, Path + ".Id"); !Result)
                {
                    return Result;
                }
                if (Route.Match.empty() || Route.Target.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue, Path,
                                   "route Match and Target are required");
                }
            }
            for (std::size_t Index = 0; Index < Configuration.Dns.Servers.size(); ++Index)
            {
                if (Configuration.Dns.Servers[Index].empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   "Dns.Servers[" + std::to_string(Index) + "]",
                                   "DNS server must not be empty");
                }
            }
            if (const auto Result = ValidateTimeout(Configuration.Dns.Timeout, "Dns.Timeout"); !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateLogging(Configuration.Logging); !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateOperationsEndpoint(Configuration.Operations.Endpoint);
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateTimeout(Configuration.Statistics.Interval,
                                                    "Statistics.Interval");
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateTimeout(Configuration.Operations.Timeout,
                                                    "Operations.Timeout");
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateTimeout(Configuration.HotReload.AckTimeout,
                                                    "HotReload.AckTimeout");
                !Result)
            {
                return Result;
            }
            if (const auto Result = ValidateTimeout(Configuration.Shutdown.Timeout,
                                                    "Shutdown.Timeout");
                !Result)
            {
                return Result;
            }

            Preview::Composition::Builtin::CapabilitySet Available =
                Request.Options.AvailableCapabilities;
            if (Request.Options.Builtins)
            {
                Available |= Request.Options.Builtins->Capabilities();
            }
            Preview::Composition::Builtin::CapabilitySet Declared;
            if (const auto Result = AddCapabilities(Configuration.Runtime.RequiredCapabilities,
                                                    Declared, "Runtime.RequiredCapabilities");
                !Result)
            {
                return Result;
            }
            for (std::size_t Index = 0; Index < Configuration.Builtins.size(); ++Index)
            {
                if (const auto Result = AddCapabilities(
                        Configuration.Builtins[Index].Requires,
                        Declared,
                        "Builtins[" + std::to_string(Index) + "].Requires");
                    !Result)
                {
                    return Result;
                }
            }
            for (std::size_t Index = 0; Index < Configuration.Protocols.size(); ++Index)
            {
                if (const auto Result = AddCapabilities(
                        Configuration.Protocols[Index].Requires,
                        Declared,
                        "Protocols[" + std::to_string(Index) + "].Requires");
                    !Result)
                {
                    return Result;
                }
            }
            for (std::size_t Index = 0; Index < Configuration.Carriers.size(); ++Index)
            {
                if (const auto Result = AddCapabilities(
                        Configuration.Carriers[Index].Requires,
                        Declared,
                        "Carriers[" + std::to_string(Index) + "].Requires");
                    !Result)
                {
                    return Result;
                }
            }
            for (std::size_t Index = 0; Index < Configuration.Routes.size(); ++Index)
            {
                if (const auto Result = AddCapabilities(
                        Configuration.Routes[Index].Requires,
                        Declared,
                        "Routes[" + std::to_string(Index) + "].Requires");
                    !Result)
                {
                    return Result;
                }
            }
            if (Request.Options.CheckCapabilities &&
                !Available.Includes(Declared))
            {
                return Failure(ConfigurationErrorCode::MissingCapability,
                               "Runtime.RequiredCapabilities",
                               "required capability is not available");
            }
            return {};
        }

        [[nodiscard]] static auto CapabilityFromName(const std::string_view Name)
            -> std::optional<Preview::Composition::Builtin::Capability>
        {
            using Preview::Composition::Builtin::Capability;
            if (Name == "Core") return Capability::Core;
            if (Name == "Request") return Capability::Request;
            if (Name == "Memory") return Capability::Memory;
            if (Name == "Executor") return Capability::Executor;
            if (Name == "Cancellation") return Capability::Cancellation;
            if (Name == "Transport" || Name == "Network") return Capability::Transport;
            if (Name == "Stream") return Capability::Stream;
            if (Name == "Datagram") return Capability::Datagram;
            if (Name == "Tls") return Capability::Tls;
            if (Name == "Multiplex" || Name == "Mux") return Capability::Multiplex;
            if (Name == "Inbound") return Capability::Inbound;
            if (Name == "Outbound") return Capability::Outbound;
            if (Name == "Observability" || Name == "Metrics") return Capability::Observability;
            if (Name == "Session") return Capability::Session;
            return std::nullopt;
        }

    private:
        static constexpr std::uint32_t MaxWorkerCount = 4096U;
        static constexpr std::uint32_t MaxTimeoutMs = 600000U;
        static constexpr std::uint64_t MinRotateBytes = 4096ULL;
        static constexpr std::uint64_t MaxRotateBytes = 1024ULL * 1024ULL * 1024ULL;
        static constexpr std::uint32_t MaxRotateFiles = 64U;

        [[nodiscard]] static auto IsMuxMode(const std::string_view Mode) noexcept -> bool
        {
            return Mode == "Smux" || Mode == "Yamux" || Mode == "H2Mux";
        }

        [[nodiscard]] static auto IsTrustTunnelNetwork(const std::string_view Network) noexcept -> bool
        {
            return Network == "Tcp" || Network == "Udp" || Network == "Both";
        }

        [[nodiscard]] static auto IsXhttpMode(const std::string_view Mode) noexcept -> bool
        {
            return Mode == "StreamOne" || Mode == "StreamUp" || Mode == "PacketUp";
        }

        [[nodiscard]] static auto IsValidUuidText(const std::string_view Value) noexcept -> bool
        {
            std::size_t Bytes = 0;
            int High = -1;
            for (const char Character : Value)
            {
                if (Character == '-')
                {
                    continue;
                }
                const auto Digit = [](const char Value) noexcept -> int
                {
                    if (Value >= '0' && Value <= '9') return Value - '0';
                    if (Value >= 'a' && Value <= 'f') return Value - 'a' + 10;
                    if (Value >= 'A' && Value <= 'F') return Value - 'A' + 10;
                    return -1;
                }(Character);
                if (Digit < 0)
                {
                    return false;
                }
                if (High < 0)
                {
                    High = Digit;
                }
                else
                {
                    ++Bytes;
                    High = -1;
                }
            }
            return Bytes == 16U && High < 0;
        }

        [[nodiscard]] static auto IsAsciiAlphaNumeric(const char Character) noexcept -> bool
        {
            return (Character >= 'a' && Character <= 'z') ||
                   (Character >= 'A' && Character <= 'Z') ||
                   (Character >= '0' && Character <= '9');
        }

        [[nodiscard]] static auto IsAsciiHex(const char Character) noexcept -> bool
        {
            return (Character >= '0' && Character <= '9') ||
                   (Character >= 'a' && Character <= 'f') ||
                   (Character >= 'A' && Character <= 'F');
        }

        [[nodiscard]] static auto ToAsciiLower(const char Character) noexcept -> char
        {
            if (Character >= 'A' && Character <= 'Z')
            {
                return static_cast<char>(Character + ('a' - 'A'));
            }
            return Character;
        }

        [[nodiscard]] static auto EqualAsciiInsensitive(const std::string_view Left,
                                                        const std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                if (ToAsciiLower(Left[Index]) != ToAsciiLower(Right[Index]))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] static auto IsValidServerNamePattern(std::string_view Name,
                                                            const bool AllowWildcard) noexcept -> bool
        {
            if (Name.size() > 253U)
            {
                return false;
            }
            if (Name.starts_with("*."))
            {
                if (!AllowWildcard)
                {
                    return false;
                }
                Name.remove_prefix(2U);
            }
            else if (Name.find('*') != std::string_view::npos)
            {
                return false;
            }
            if (Name.empty())
            {
                return false;
            }

            std::size_t LabelStart = 0;
            while (LabelStart < Name.size())
            {
                const auto Dot = Name.find('.', LabelStart);
                const auto LabelEnd = Dot == std::string_view::npos ? Name.size() : Dot;
                const auto Label = Name.substr(LabelStart, LabelEnd - LabelStart);
                if (Label.empty() || Label.size() > 63U || Label.front() == '-' || Label.back() == '-')
                {
                    return false;
                }
                for (const auto Character : Label)
                {
                    if (!IsAsciiAlphaNumeric(Character) && Character != '-')
                    {
                        return false;
                    }
                }
                if (Dot == std::string_view::npos)
                {
                    return true;
                }
                LabelStart = Dot + 1U;
            }
            return false;
        }

        [[nodiscard]] static auto ValidateServerNameList(
            const std::vector<std::string> &Names,
            const std::string &Path,
            const bool Required,
            const bool AllowWildcard,
            const bool AllowNoSni = false) -> Result
        {
            if (Names.empty())
            {
                if (Required)
                {
                    return Failure(ConfigurationErrorCode::MissingField,
                                   Path,
                                   "at least one ServerName is required");
                }
                return {};
            }
            for (std::size_t Index = 0; Index < Names.size(); ++Index)
            {
                if (AllowNoSni && Names[Index].empty())
                {
                    continue;
                }
                if (!IsValidServerNamePattern(Names[Index], AllowWildcard))
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + "[" + std::to_string(Index) + "]",
                                   "ServerName must be a valid DNS name or supported wildcard");
                }
            }
            return {};
        }

        [[nodiscard]] static auto ValidateAlpnList(const std::vector<std::string> &Alpn,
                                                   const std::string &Path) -> Result
        {
            for (std::size_t Index = 0; Index < Alpn.size(); ++Index)
            {
                const auto &Protocol = Alpn[Index];
                if (Protocol.empty() || Protocol.size() > 255U)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + "[" + std::to_string(Index) + "]",
                                   "ALPN identifiers must contain between 1 and 255 bytes");
                }
                for (const auto Byte : Protocol)
                {
                    const auto Value = static_cast<unsigned char>(Byte);
                    if (Value < 0x21U || Value > 0x7eU)
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + "[" + std::to_string(Index) + "]",
                                       "ALPN identifiers must use visible ASCII characters");
                    }
                }
            }
            return {};
        }

        [[nodiscard]] static auto IsValidPort(const std::string_view Port) noexcept -> bool
        {
            if (Port.empty())
            {
                return false;
            }
            std::uint32_t Value = 0;
            const auto [End, Error] = std::from_chars(Port.data(), Port.data() + Port.size(), Value, 10);
            return Error == std::errc{} && End == Port.data() + Port.size() &&
                   Value > 0U && Value <= std::numeric_limits<std::uint16_t>::max();
        }

        [[nodiscard]] static auto IsValidHost(const std::string_view Host) -> bool
        {
            if (Host.empty())
            {
                return false;
            }
            boost::system::error_code Error;
            (void)boost::asio::ip::make_address(std::string(Host), Error);
            return !Error || IsValidServerNamePattern(Host, false);
        }

        [[nodiscard]] static auto IsValidHostPort(const std::string_view Value,
                                                  const bool RequirePort) -> bool
        {
            if (Value.empty())
            {
                return false;
            }
            if (Value.front() == '[')
            {
                const auto Close = Value.find(']');
                if (Close == std::string_view::npos)
                {
                    return false;
                }
                boost::system::error_code Error;
                const auto Address = boost::asio::ip::make_address(
                    std::string(Value.substr(1U, Close - 1U)), Error);
                if (Error || !Address.is_v6())
                {
                    return false;
                }
                const auto Suffix = Value.substr(Close + 1U);
                if (Suffix.empty())
                {
                    return !RequirePort;
                }
                return Suffix.front() == ':' && IsValidPort(Suffix.substr(1U));
            }

            const auto Separator = Value.find(':');
            if (Separator == std::string_view::npos)
            {
                return !RequirePort && IsValidHost(Value);
            }
            if (Value.find(':', Separator + 1U) != std::string_view::npos ||
                !IsValidHost(Value.substr(0, Separator)))
            {
                return false;
            }
            return IsValidPort(Value.substr(Separator + 1U));
        }

        [[nodiscard]] static auto ValidateHostPort(const std::string &Value,
                                                   const std::string &Path,
                                                   const std::string_view Field) -> Result
        {
            if (!IsValidHostPort(Value, true))
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               std::string(Field) + " must be a valid host:port target");
            }
            return {};
        }

        [[nodiscard]] static auto ValidateOptionalHost(const std::string &Value,
                                                       const std::string &Path) -> Result
        {
            if (!Value.empty() && !IsValidHostPort(Value, false))
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "Host must be a valid host name with an optional port");
            }
            return {};
        }

        [[nodiscard]] static auto ValidateHttpPath(const std::string &Value,
                                                   const std::string &Path) -> Result
        {
            if (Value.empty() || Value.front() != '/')
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "Path must be an absolute HTTP path beginning with /");
            }
            for (std::size_t Index = 0; Index < Value.size(); ++Index)
            {
                const auto Byte = static_cast<unsigned char>(Value[Index]);
                if (Byte <= 0x20U || Byte == 0x7fU || Value[Index] == '\\' || Value[Index] == '#')
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path,
                                   "Path contains an invalid HTTP path character");
                }
                if (Value[Index] == '%')
                {
                    if (Index + 2U >= Value.size() || !IsAsciiHex(Value[Index + 1U]) ||
                        !IsAsciiHex(Value[Index + 2U]))
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path,
                                       "Path contains an invalid percent escape");
                    }
                    Index += 2U;
                }
            }
            return {};
        }

        [[nodiscard]] static auto IsValidToken(const std::string_view Value,
                                               const std::size_t MaxLength) noexcept -> bool
        {
            if (Value.empty() || Value.size() > MaxLength)
            {
                return false;
            }
            for (const auto Character : Value)
            {
                if (!IsAsciiAlphaNumeric(Character) && Character != '.' && Character != '_' &&
                    Character != '-')
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] static auto ValidateShortIds(const std::vector<std::string> &ShortIds,
                                                   const std::string &Path) -> Result
        {
            if (ShortIds.empty())
            {
                return Failure(ConfigurationErrorCode::MissingField,
                               Path,
                               "at least one ShortId is required");
            }
            for (std::size_t Index = 0; Index < ShortIds.size(); ++Index)
            {
                const auto &ShortId = ShortIds[Index];
                if (ShortId.size() > 16U || ShortId.size() % 2U != 0U ||
                    !std::all_of(ShortId.begin(), ShortId.end(), IsAsciiHex))
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + "[" + std::to_string(Index) + "]",
                                   "ShortId must be an even-length hex string of at most 16 characters");
                }
            }
            return {};
        }

        [[nodiscard]] static auto ReadScriptNumber(const std::string_view Value,
                                                   std::size_t &Position,
                                                   const std::uint32_t Maximum,
                                                   std::uint32_t &Number) noexcept -> bool
        {
            const auto Start = Position;
            while (Position < Value.size() && Value[Position] >= '0' && Value[Position] <= '9')
            {
                ++Position;
            }
            if (Start == Position)
            {
                return false;
            }
            const auto [End, Error] = std::from_chars(
                Value.data() + Start, Value.data() + Position, Number, 10);
            return Error == std::errc{} && End == Value.data() + Position && Number <= Maximum;
        }

        [[nodiscard]] static auto IsValidRestlsScript(const std::string_view Script) noexcept -> bool
        {
            constexpr auto MaxTarget = static_cast<std::uint32_t>(
                std::numeric_limits<std::int16_t>::max());
            std::size_t RuleStart = 0;
            for (;;)
            {
                const auto Comma = Script.find(',', RuleStart);
                const auto Rule = Script.substr(
                    RuleStart, Comma == std::string_view::npos ? Script.size() - RuleStart
                                                              : Comma - RuleStart);
                std::size_t Position = 0;
                std::uint32_t Base = 0;
                if (Rule.empty() || !ReadScriptNumber(Rule, Position, MaxTarget, Base))
                {
                    return false;
                }
                if (Position < Rule.size() && (Rule[Position] == '?' || Rule[Position] == '~'))
                {
                    ++Position;
                    std::uint32_t Range = 0;
                    if (!ReadScriptNumber(Rule, Position, MaxTarget, Range) || Base + Range > MaxTarget)
                    {
                        return false;
                    }
                }
                if (Position < Rule.size() && Rule[Position] == '<')
                {
                    ++Position;
                    std::uint32_t Responses = 0;
                    if (!ReadScriptNumber(
                            Rule, Position, std::numeric_limits<std::uint8_t>::max(), Responses))
                    {
                        return false;
                    }
                }
                if (Position != Rule.size())
                {
                    return false;
                }
                if (Comma == std::string_view::npos)
                {
                    return true;
                }
                RuleStart = Comma + 1U;
                if (RuleStart == Script.size())
                {
                    return false;
                }
            }
        }

        [[nodiscard]] static auto ValidateCarrierMatch(const CarrierMatchOptions &Match,
                                                       const std::string &Path) -> Result
        {
            if (const auto Result = ValidateServerNameList(
                    Match.ServerNames, Path + ".ServerNames", false, true, true);
                !Result)
            {
                return Result;
            }
            return ValidateAlpnList(Match.Alpn, Path + ".Alpn");
        }

        [[nodiscard]] static auto ServerNamePatternMatches(
            const std::string_view Pattern,
            const std::string_view Name) noexcept -> bool
        {
            if (!Pattern.starts_with("*."))
            {
                return EqualAsciiInsensitive(Pattern, Name);
            }
            const auto Suffix = Pattern.substr(2U);
            if (Name.size() <= Suffix.size() + 1U)
            {
                return false;
            }
            const auto PrefixSize = Name.size() - Suffix.size() - 1U;
            return Name[PrefixSize] == '.' &&
                   Name.substr(0, PrefixSize).find('.') == std::string_view::npos &&
                   EqualAsciiInsensitive(Name.substr(PrefixSize + 1U), Suffix);
        }

        [[nodiscard]] static auto ServerNamePatternsOverlap(
            const std::string_view Left,
            const std::string_view Right) noexcept -> bool
        {
            if (Left.empty() || Right.empty())
            {
                return Left.empty() && Right.empty();
            }
            const bool LeftWildcard = Left.starts_with("*.");
            const bool RightWildcard = Right.starts_with("*.");
            if (LeftWildcard && RightWildcard)
            {
                return EqualAsciiInsensitive(Left.substr(2U), Right.substr(2U));
            }
            if (LeftWildcard)
            {
                return ServerNamePatternMatches(Left, Right);
            }
            if (RightWildcard)
            {
                return ServerNamePatternMatches(Right, Left);
            }
            return EqualAsciiInsensitive(Left, Right);
        }

        [[nodiscard]] static auto ServerNameListsOverlap(
            const std::vector<std::string> &Left,
            const std::vector<std::string> &Right) noexcept -> bool
        {
            if (Left.empty() || Right.empty())
            {
                return true;
            }
            for (const auto &LeftName : Left)
            {
                for (const auto &RightName : Right)
                {
                    if (ServerNamePatternsOverlap(LeftName, RightName))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        [[nodiscard]] static auto AlpnListsOverlap(const std::vector<std::string> &Left,
                                                   const std::vector<std::string> &Right) noexcept -> bool
        {
            if (Left.empty() || Right.empty())
            {
                return true;
            }
            for (const auto &Protocol : Left)
            {
                if (std::find(Right.begin(), Right.end(), Protocol) != Right.end())
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] static auto ClampCandidatePriority(const std::int32_t Priority) noexcept
            -> std::uint16_t
        {
            if (Priority <= 0)
            {
                return 0;
            }
            return static_cast<std::uint16_t>((std::min)(Priority, 65535));
        }

        [[nodiscard]] static auto EffectiveCandidatePriority(
            const ProtocolBindingConfiguration &Binding,
            const CarrierConfiguration &Carrier) noexcept -> std::uint16_t
        {
            return (std::max)(ClampCandidatePriority(Binding.Priority),
                              ClampCandidatePriority(Carrier.Match.Priority));
        }

        [[nodiscard]] static auto EffectiveCarrierFallback(
            const CarrierConfiguration &Carrier) noexcept -> bool
        {
            return Carrier.Match.Fallback ||
                   (Carrier.Builtin == "native" && Carrier.Match.ServerNames.empty() &&
                    Carrier.Match.Alpn.empty());
        }

        [[nodiscard]] static auto ValidateCarrierRouteAmbiguity(
            const PreviewConfiguration &Configuration) -> Result
        {
            struct CandidatePriorities final
            {
                const CarrierConfiguration *Carrier{nullptr};
                std::vector<std::uint16_t> Values;
            };

            std::vector<CandidatePriorities> Candidates;
            Candidates.reserve(Configuration.Carriers.size());
            for (const auto &Carrier : Configuration.Carriers)
            {
                Candidates.push_back(CandidatePriorities{&Carrier, {}});
            }

            for (const auto &Binding : Configuration.ProtocolBindings)
            {
                if (!Binding.TcpEnabled || !Binding.CarrierId)
                {
                    continue;
                }
                const auto Candidate = std::find_if(
                    Candidates.begin(), Candidates.end(),
                    [&Binding](const CandidatePriorities &Value)
                    { return Value.Carrier->Id == *Binding.CarrierId; });
                if (Candidate != Candidates.end())
                {
                    Candidate->Values.push_back(
                        EffectiveCandidatePriority(Binding, *Candidate->Carrier));
                }
            }

            for (auto &Candidate : Candidates)
            {
                auto &Values = Candidate.Values;
                std::sort(Values.begin(), Values.end());
                Values.erase(std::unique(Values.begin(), Values.end()), Values.end());
            }

            for (std::size_t LeftIndex = 0; LeftIndex < Candidates.size(); ++LeftIndex)
            {
                const auto &Left = Candidates[LeftIndex];
                if (Left.Values.empty())
                {
                    continue;
                }
                for (std::size_t RightIndex = LeftIndex + 1U;
                     RightIndex < Candidates.size(); ++RightIndex)
                {
                    const auto &Right = Candidates[RightIndex];
                    if (Right.Values.empty() ||
                        EffectiveCarrierFallback(*Left.Carrier) !=
                            EffectiveCarrierFallback(*Right.Carrier))
                    {
                        continue;
                    }
                    if (!ServerNameListsOverlap(Left.Carrier->Match.ServerNames,
                                                Right.Carrier->Match.ServerNames) ||
                        !AlpnListsOverlap(Left.Carrier->Match.Alpn,
                                          Right.Carrier->Match.Alpn))
                    {
                        continue;
                    }
                    for (const auto Priority : Left.Values)
                    {
                        if (std::binary_search(Right.Values.begin(), Right.Values.end(), Priority))
                        {
                            return Failure(
                                ConfigurationErrorCode::InvalidValue,
                                "Carriers[" + std::to_string(RightIndex) + "].Match",
                                "carrier SNI/ALPN route is ambiguous at effective TCP priority");
                        }
                    }
                }
            }
            return {};
        }

        [[nodiscard]] static auto EffectiveRecognitionName(
            const RecognitionRouteConfiguration &Recognition) noexcept -> std::string_view
        {
            return Recognition.Pattern.empty() ? std::string_view(Recognition.Domain)
                                               : std::string_view(Recognition.Pattern);
        }

        [[nodiscard]] static auto ValidateRecognitionRoute(
            const RecognitionRouteConfiguration &Recognition,
            const std::string &Path) -> Result
        {
            if (!Recognition.Pattern.empty() &&
                !IsValidServerNamePattern(Recognition.Pattern, true))
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + ".Pattern",
                               "Pattern must be a valid DNS name or supported wildcard");
            }
            if (!Recognition.Domain.empty() &&
                !IsValidServerNamePattern(Recognition.Domain, true))
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + ".Domain",
                               "Domain must be a valid DNS name or supported wildcard");
            }
            return {};
        }

        [[nodiscard]] static auto IsCarrierBuiltin(const std::string_view Builtin) noexcept -> bool
        {
            return Builtin == "native" || Builtin == "reality" || Builtin == "shadowtls" ||
                   Builtin == "restls" || Builtin == "ws" || Builtin == "websocket" ||
                   Builtin == "xhttp" || Builtin == "gun";
        }

        [[nodiscard]] static auto CanonicalBuiltinName(const std::string_view Kind,
                                                       const std::string_view Name) noexcept
            -> std::string_view
        {
            if (Kind == "protocol" && Name == "shadowsocks2022")
            {
                return "ss2022";
            }
            if (Kind == "carrier" && Name == "websocket")
            {
                return "ws";
            }
            return Name;
        }

        [[nodiscard]] static auto FindBuiltinDescriptor(
            const Preview::Composition::Builtin::BuiltinSnapshot &Snapshot,
            const std::string_view Kind,
            const std::string_view Name)
            -> const Preview::Composition::Builtin::BuiltinSnapshot::Entry *
        {
            const auto EffectiveName = CanonicalBuiltinName(Kind, Name);
            const auto Entries = Snapshot.Entries();
            const auto Entry = std::find_if(
                Entries.begin(), Entries.end(), [Kind, EffectiveName](const auto &Value)
                {
                    return Value.Descriptor.Kind.Value() == Kind &&
                           Value.Descriptor.Name.Value() == EffectiveName;
                });
            return Entry == Entries.end() ? nullptr : &*Entry;
        }

        [[nodiscard]] static auto IsStackProtocolBuiltin(const std::string_view Builtin) noexcept -> bool
        {
            return Builtin == "anytls" || Builtin == "trusttunnel";
        }

        [[nodiscard]] static auto ValidateProtocolBindingRouteAmbiguity(
            const std::vector<ProtocolBindingConfiguration> &Bindings) -> Result
        {
            for (std::size_t LeftIndex = 0; LeftIndex < Bindings.size(); ++LeftIndex)
            {
                const auto &Left = Bindings[LeftIndex];
                const auto LeftName = EffectiveRecognitionName(Left.Recognition);
                if (LeftName.empty() && !Left.Recognition.Fallback)
                {
                    continue;
                }
                for (std::size_t RightIndex = LeftIndex + 1U; RightIndex < Bindings.size(); ++RightIndex)
                {
                    const auto &Right = Bindings[RightIndex];
                    if (Left.Priority != Right.Priority ||
                        Left.Recognition.Fallback != Right.Recognition.Fallback)
                    {
                        continue;
                    }
                    const auto RightName = EffectiveRecognitionName(Right.Recognition);
                    if (RightName.empty() && !Right.Recognition.Fallback)
                    {
                        continue;
                    }
                    if (LeftName.empty() || RightName.empty() ||
                        ServerNamePatternsOverlap(LeftName, RightName))
                    {
                        return Failure(
                            ConfigurationErrorCode::InvalidValue,
                            "ProtocolBindings[" + std::to_string(RightIndex) + "].Recognition",
                            "protocol recognition route is ambiguous at equal priority");
                    }
                }
            }
            return {};
        }

        [[nodiscard]] static auto RequireText(const std::string &Value,
                                              const std::string &Path,
                                              const std::string_view Message) -> Result
        {
            if (Value.empty())
            {
                return Failure(ConfigurationErrorCode::MissingField, Path, std::string(Message));
            }
            return {};
        }

        [[nodiscard]] static auto RequireTextList(const std::vector<std::string> &Values,
                                                  const std::string &Path,
                                                  const std::string_view Message) -> Result
        {
            if (Values.empty())
            {
                return Failure(ConfigurationErrorCode::MissingField, Path, std::string(Message));
            }
            for (std::size_t Index = 0; Index < Values.size(); ++Index)
            {
                if (Values[Index].empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + "[" + std::to_string(Index) + "]",
                                   "value must not be empty");
                }
            }
            return {};
        }

        [[nodiscard]] static auto ValidateSecretReference(const std::string &Reference,
                                                          const std::string &Path,
                                                          const ValidationOptions &Options) -> Result
        {
            if (const auto Result = RequireText(Reference, Path, "SecretRef is required"); !Result)
            {
                return Result;
            }
            if (!Options.CheckSecrets)
            {
                return {};
            }

            std::optional<std::string> Secret;
            try
            {
                Secret = Options.Secrets.Resolve(Reference);
            }
            catch (...)
            {
                Secret.reset();
            }
            if (!Secret || Secret->empty())
            {
                return Failure(ConfigurationErrorCode::UnresolvedSecret,
                               Path,
                               "SecretRef cannot be resolved");
            }
            return {};
        }

        [[nodiscard]] static auto ValidateCarrier(const CarrierConfiguration &Carrier,
                                                  const std::string &Path,
                                                  const ValidationOptions &Options) -> Result
        {
            if (IsStackProtocolBuiltin(Carrier.Builtin))
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + ".Builtin",
                               "AnyTLS and TrustTunnel are stack protocols and cannot be carriers");
            }

            return std::visit(
                [&Carrier, &Path, &Options](const auto &TypedOptions) -> Result
                {
                    using Option = std::decay_t<decltype(TypedOptions)>;
                    const auto OptionsPath = Path + ".Options";
                    const auto RequireBuiltin = [&Carrier, &Path](const std::string_view Expected) -> Result
                    {
                        if (CanonicalBuiltinName("carrier", Carrier.Builtin) != Expected)
                        {
                            return Failure(ConfigurationErrorCode::InvalidCarrierOptions,
                                           Path + ".Options.Type",
                                           "carrier Builtin does not match typed Options");
                        }
                        return {};
                    };

                    if constexpr (std::is_same_v<Option, NativeTlsOptions>)
                    {
                        if (const auto Result = RequireBuiltin("native"); !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.CertificateFile,
                                OptionsPath + ".CertificateFile",
                                "CertificateFile is required");
                            !Result)
                        {
                            return Result;
                        }
                        return RequireText(TypedOptions.PrivateKeyFile,
                                           OptionsPath + ".PrivateKeyFile",
                                           "PrivateKeyFile is required");
                    }
                    else if constexpr (std::is_same_v<Option, RealityOptions>)
                    {
                        if (const auto Result = RequireBuiltin("reality"); !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.HandshakeTarget,
                                OptionsPath + ".HandshakeTarget",
                                "HandshakeTarget is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateHostPort(
                                TypedOptions.HandshakeTarget,
                                OptionsPath + ".HandshakeTarget",
                                "HandshakeTarget");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateServerNameList(
                                TypedOptions.ServerNames,
                                OptionsPath + ".ServerNames",
                                true,
                                false,
                                true);
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateSecretReference(
                                TypedOptions.PrivateKeyRef,
                                OptionsPath + ".PrivateKeyRef",
                                Options);
                            !Result)
                        {
                            return Result;
                        }
                        return ValidateShortIds(TypedOptions.ShortIds,
                                                OptionsPath + ".ShortIds");
                    }
                    else if constexpr (std::is_same_v<Option, ShadowTlsOptions>)
                    {
                        if (const auto Result = RequireBuiltin("shadowtls"); !Result)
                        {
                            return Result;
                        }
                        if (TypedOptions.Version != 3U)
                        {
                            return Failure(ConfigurationErrorCode::InvalidValue,
                                           OptionsPath + ".Version",
                                           "ShadowTls Version must be 3");
                        }
                        if (const auto Result = ValidateSecretReference(
                                TypedOptions.PasswordSecretRef,
                                OptionsPath + ".PasswordSecretRef",
                                Options);
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.HandshakeDest,
                                OptionsPath + ".HandshakeDest",
                                "HandshakeDest is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateHostPort(
                                TypedOptions.HandshakeDest,
                                OptionsPath + ".HandshakeDest",
                                "HandshakeDest");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateServerNameList(
                                TypedOptions.ServerNames,
                                OptionsPath + ".ServerNames",
                                true,
                                false);
                            !Result)
                        {
                            return Result;
                        }
                        return ValidateTimeout(TypedOptions.HandshakeTimeoutMs,
                                              OptionsPath + ".HandshakeTimeoutMs");
                    }
                    else if constexpr (std::is_same_v<Option, RestlsOptions>)
                    {
                        if (const auto Result = RequireBuiltin("restls"); !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateServerNameList(
                                TypedOptions.ServerNames,
                                OptionsPath + ".ServerNames",
                                true,
                                false);
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.Host, OptionsPath + ".Host", "Host is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateHostPort(
                                TypedOptions.Host, OptionsPath + ".Host", "Host");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateSecretReference(
                                TypedOptions.PasswordSecretRef,
                                OptionsPath + ".PasswordSecretRef",
                                Options);
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.VersionHint,
                                OptionsPath + ".VersionHint",
                                "VersionHint is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (!IsValidToken(TypedOptions.VersionHint, 32U))
                        {
                            return Failure(ConfigurationErrorCode::InvalidValue,
                                           OptionsPath + ".VersionHint",
                                           "VersionHint must be a non-empty ASCII token");
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.RestlsScript,
                                OptionsPath + ".RestlsScript",
                                "RestlsScript is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (!IsValidRestlsScript(TypedOptions.RestlsScript))
                        {
                            return Failure(ConfigurationErrorCode::InvalidValue,
                                           OptionsPath + ".RestlsScript",
                                           "RestlsScript does not match the supported rule syntax");
                        }
                        return ValidateTimeout(TypedOptions.HandshakeTimeoutMs,
                                              OptionsPath + ".HandshakeTimeoutMs");
                    }
                    else if constexpr (std::is_same_v<Option, WebSocketOptions>)
                    {
                        if (Carrier.Builtin != "ws" && Carrier.Builtin != "websocket")
                        {
                            return Failure(ConfigurationErrorCode::InvalidCarrierOptions,
                                           Path + ".Options.Type",
                                           "carrier Builtin does not match typed Options");
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.Path, OptionsPath + ".Path", "Path is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateHttpPath(
                                TypedOptions.Path, OptionsPath + ".Path");
                            !Result)
                        {
                            return Result;
                        }
                        return ValidateOptionalHost(TypedOptions.Host, OptionsPath + ".Host");
                    }
                    else if constexpr (std::is_same_v<Option, XhttpOptions>)
                    {
                        if (const auto Result = RequireBuiltin("xhttp"); !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.Path,
                                OptionsPath + ".Path",
                                "Path is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateHttpPath(
                                TypedOptions.Path, OptionsPath + ".Path");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateOptionalHost(
                                TypedOptions.Host, OptionsPath + ".Host");
                            !Result)
                        {
                            return Result;
                        }
                        if (!IsXhttpMode(TypedOptions.Mode))
                        {
                            return Failure(ConfigurationErrorCode::InvalidValue,
                                           OptionsPath + ".Mode",
                                           "unknown Xhttp mode");
                        }
                        return {};
                    }
                    else if constexpr (std::is_same_v<Option, GunOptions>)
                    {
                        if (const auto Result = RequireBuiltin("gun"); !Result)
                        {
                            return Result;
                        }
                        if (TypedOptions.Mode != "GunLite" && TypedOptions.Mode != "Grpc")
                        {
                            return Failure(ConfigurationErrorCode::InvalidValue,
                                           OptionsPath + ".Mode",
                                           "Gun mode must be GunLite or Grpc");
                        }
                        if (const auto Result = ValidateServerNameList(
                                TypedOptions.ServerNames,
                                OptionsPath + ".ServerNames",
                                true,
                                false);
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.Path,
                                OptionsPath + ".Path",
                                "Path is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateHttpPath(
                                TypedOptions.Path, OptionsPath + ".Path");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.ServiceName,
                                OptionsPath + ".ServiceName",
                                "ServiceName is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (!IsValidToken(TypedOptions.ServiceName, 255U))
                        {
                            return Failure(ConfigurationErrorCode::InvalidValue,
                                           OptionsPath + ".ServiceName",
                                           "ServiceName must be an ASCII token");
                        }
                        return {};
                    }
                    else if constexpr (std::is_same_v<Option, TrustTunnelOptions>)
                    {
                        if (const auto Result = RequireBuiltin("trusttunnel"); !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateServerNameList(
                                TypedOptions.ServerNames,
                                OptionsPath + ".ServerNames",
                                true,
                                false);
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.CertificateFile,
                                OptionsPath + ".CertificateFile",
                                "CertificateFile is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateSecretReference(
                                TypedOptions.PrivateKeySecretRef,
                                OptionsPath + ".PrivateKeySecretRef",
                                Options);
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateSecretReference(
                                TypedOptions.PasswordSecretRef,
                                OptionsPath + ".PasswordSecretRef",
                                Options);
                            !Result)
                        {
                            return Result;
                        }
                        if (!IsTrustTunnelNetwork(TypedOptions.Network))
                        {
                            return Failure(ConfigurationErrorCode::InvalidValue,
                                           OptionsPath + ".Network",
                                           "unknown TrustTunnel network");
                        }
                        if (const auto Result = RequireText(
                                TypedOptions.Congestion,
                                OptionsPath + ".Congestion",
                                "Congestion is required");
                            !Result)
                        {
                            return Result;
                        }
                        if (const auto Result = ValidateTimeout(
                                TypedOptions.HandshakeTimeoutMs,
                                OptionsPath + ".HandshakeTimeoutMs");
                            !Result)
                        {
                            return Result;
                        }
                        return ValidateTimeout(TypedOptions.IdleTimeoutMs,
                                              OptionsPath + ".IdleTimeoutMs");
                    }
                },
                Carrier.Options);
        }

        [[nodiscard]] static auto IsLoggingLevel(const std::string_view Level) noexcept -> bool
        {
            return Level == "Trace" || Level == "Debug" || Level == "Info" ||
                   Level == "Access" || Level == "Warn" || Level == "Error" ||
                   Level == "Critical" || Level == "Off";
        }

        [[nodiscard]] static auto ValidateLogging(const LoggingConfiguration &Configuration)
            -> Result
        {
            if (!IsLoggingLevel(Configuration.Level))
            {
                return Failure(ConfigurationErrorCode::InvalidValue, "Logging.Level",
                               "Level must be Trace, Debug, Info, Access, Warn, Error, Critical, or Off");
            }
            if (Configuration.Directory.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue, "Logging.Directory",
                               "Directory must not be empty");
            }
            if (Configuration.FileName.empty() || Configuration.FileName == "." ||
                Configuration.FileName == ".." ||
                Configuration.FileName.find_first_of("/\\:") != std::string::npos)
            {
                return Failure(ConfigurationErrorCode::InvalidValue, "Logging.FileName",
                               "FileName must be a single file name");
            }
            if (Configuration.RotateBytes < MinRotateBytes ||
                Configuration.RotateBytes > MaxRotateBytes)
            {
                return Failure(ConfigurationErrorCode::InvalidValue, "Logging.RotateBytes",
                               "RotateBytes must be between 4096 and 1073741824");
            }
            if (Configuration.RotateFiles == 0U ||
                Configuration.RotateFiles > MaxRotateFiles)
            {
                return Failure(ConfigurationErrorCode::InvalidValue, "Logging.RotateFiles",
                               "RotateFiles must be between 1 and 64");
            }
            if (Configuration.FlushIntervalMs == 0U ||
                Configuration.FlushIntervalMs > MaxTimeoutMs)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Logging.FlushIntervalMs",
                               "FlushIntervalMs must be between 1 and 600000 milliseconds");
            }
            return {};
        }

        [[nodiscard]] static auto Failure(const ConfigurationErrorCode Code,
                                          std::string Path,
                                          std::string Message) -> Result
        {
            return std::unexpected(MakeConfigurationError(Code, std::move(Path), std::move(Message)));
        }

        [[nodiscard]] static auto AddId(std::unordered_set<std::string> &Ids,
                                        const std::string &Id,
                                        const std::string &Path) -> Result
        {
            if (Id.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue, Path, "Id is required");
            }
            if (!Ids.insert(Id).second)
            {
                return Failure(ConfigurationErrorCode::DuplicateId, Path, "duplicate configuration Id");
            }
            return {};
        }

        [[nodiscard]] static auto ValidateTimeout(const std::uint32_t Timeout,
                                                  const std::string &Path) -> Result
        {
            if (Timeout == 0U || Timeout > MaxTimeoutMs)
            {
                return Failure(ConfigurationErrorCode::InvalidValue, Path,
                               "timeout must be between 1 and 600000 milliseconds");
            }
            return {};
        }

        [[nodiscard]] static auto ValidateOperationsEndpoint(const std::string &Endpoint) -> Result
        {
            if (Endpoint.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Operations.Endpoint",
                               "operations Endpoint is required");
            }

            std::string_view Address;
            std::string_view PortText;
            if (Endpoint.front() == '[')
            {
                const auto Close = Endpoint.find(']');
                if (Close == std::string::npos || Close + 2U > Endpoint.size() ||
                    Endpoint[Close + 1U] != ':')
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   "Operations.Endpoint",
                                   "operations Endpoint must be address:port");
                }
                Address = std::string_view(Endpoint).substr(1U, Close - 1U);
                PortText = std::string_view(Endpoint).substr(Close + 2U);
            }
            else
            {
                const auto Separator = Endpoint.rfind(':');
                if (Separator == std::string::npos || Endpoint.find(':') != Separator)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   "Operations.Endpoint",
                                   "operations IPv6 endpoints must use brackets");
                }
                Address = std::string_view(Endpoint).substr(0, Separator);
                PortText = std::string_view(Endpoint).substr(Separator + 1U);
            }

            if (Address != "127.0.0.1" && Address != "localhost" && Address != "::1")
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Operations.Endpoint",
                               "operations listener must use a loopback address");
            }
            if (PortText.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Operations.Endpoint",
                               "operations port must be between 0 and 65535");
            }

            std::uint32_t Port = 0;
            const auto [End, Error] = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port, 10);
            if (Error != std::errc{} || End != PortText.data() + PortText.size() || Port > 65535U)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               "Operations.Endpoint",
                               "operations port must be between 0 and 65535");
            }
            return {};
        }

        [[nodiscard]] static auto ValidateEndpoints(const std::vector<ListenerEndpoint> &Endpoints,
                                                    const std::string &Path,
                                                    std::unordered_set<std::string> &Ids) -> Result
        {
            for (std::size_t Index = 0; Index < Endpoints.size(); ++Index)
            {
                const auto &Endpoint = Endpoints[Index];
                const auto ItemPath = Path + "[" + std::to_string(Index) + "]";
                if (const auto Result = AddId(Ids, Endpoint.Id, ItemPath + ".Id"); !Result)
                {
                    return Result;
                }
                if (Endpoint.Address.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue, ItemPath + ".Address",
                                   "listener Address is required");
                }
                if (Endpoint.Port == 0U)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue, ItemPath + ".Port",
                                   "port must be between 1 and 65535");
                }
                if (const auto Result = ValidateTimeout(Endpoint.Timeout, ItemPath + ".Timeout"); !Result)
                {
                    return Result;
                }
            }
            return {};
        }

        [[nodiscard]] static auto AddCapabilities(
            const std::vector<std::string> &Names,
            Preview::Composition::Builtin::CapabilitySet &Available,
            const std::string &Path) -> Result
        {
            for (std::size_t Index = 0; Index < Names.size(); ++Index)
            {
                const auto CapabilityValue = CapabilityFromName(Names[Index]);
                if (!CapabilityValue)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + "[" + std::to_string(Index) + "]", "unknown capability");
                }
                Available.Add(*CapabilityValue);
            }
            return {};
        }
    };

} // namespace Preview::Application::Configuration
