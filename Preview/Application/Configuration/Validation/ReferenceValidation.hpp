/**
 * @file ReferenceValidation.hpp
 * @brief builtin、协议、绑定引用和识别路由的校验。
 */
#pragma once

#include <Preview/Application/Configuration/ReferenceGraph.hpp>
#include <Preview/Application/Configuration/Validation/CapabilityValidation.hpp>
#include <Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp>
#include <Preview/Application/Configuration/Validation/SecretValidation.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace Preview::Application::Configuration::Validation
{

    using BuiltinEntry = Preview::Composition::Builtin::BuiltinSnapshot::Entry;
    using BuiltinEntryPointer = const BuiltinEntry *;

    [[nodiscard]] inline auto ServerNamePatternMatches(
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

    [[nodiscard]] inline auto ServerNamePatternsOverlap(
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

    [[nodiscard]] inline auto ServerNameListsOverlap(
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

    [[nodiscard]] inline auto AlpnListsOverlap(
        const std::vector<std::string> &Left,
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

    [[nodiscard]] inline auto ClampCandidatePriority(const std::int32_t Priority) noexcept
        -> std::uint16_t
    {
        if (Priority <= 0)
        {
            return 0;
        }
        return static_cast<std::uint16_t>((std::min)(Priority, 65535));
    }

    [[nodiscard]] inline auto EffectiveCandidatePriority(
        const Preview::Contract::ProtocolBindingConfiguration &Binding,
        const Preview::Contract::CarrierConfiguration &Carrier) noexcept -> std::uint16_t
    {
        return (std::max)(ClampCandidatePriority(Binding.Priority),
                          ClampCandidatePriority(Carrier.Match.Priority));
    }

    [[nodiscard]] inline auto EffectiveCarrierFallback(
        const Preview::Contract::CarrierConfiguration &Carrier) noexcept -> bool
    {
        return Carrier.Match.Fallback ||
               (Carrier.Builtin == "native" && Carrier.Match.ServerNames.empty() &&
                Carrier.Match.Alpn.empty());
    }

    [[nodiscard]] inline auto IsCarrierBuiltin(const std::string_view Builtin) noexcept -> bool
    {
        return Builtin == "native" || Builtin == "reality" || Builtin == "shadowtls" ||
               Builtin == "restls" || Builtin == "ws" || Builtin == "websocket" ||
               Builtin == "xhttp" || Builtin == "gun";
    }

    [[nodiscard]] inline auto CanonicalBuiltinName(const std::string_view Kind,
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

    [[nodiscard]] inline auto FindBuiltinDescriptor(
        const Preview::Composition::Builtin::BuiltinSnapshot &Snapshot,
        const std::string_view Kind,
        const std::string_view Name) -> BuiltinEntryPointer
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

    [[nodiscard]] inline auto IsStackProtocolBuiltin(
        const std::string_view Builtin) noexcept -> bool
    {
        return Builtin == "anytls" || Builtin == "trusttunnel";
    }

    [[nodiscard]] inline auto ValidateBuiltins(
        const std::vector<BuiltinConfiguration> &Builtins,
        const ValidationOptions &Options,
        std::unordered_set<std::string> &Ids) -> Result
    {
        for (std::size_t Index = 0; Index < Builtins.size(); ++Index)
        {
            const auto &Builtin = Builtins[Index];
            const auto Path = "Builtins[" + std::to_string(Index) + "]";
            if (const auto ResultValue = AddId(Ids, Builtin.Id, Path + ".Id"); !ResultValue)
            {
                return ResultValue;
            }
            if (Builtin.Kind.empty() || Builtin.Name.empty())
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path,
                               "builtin Kind and Name are required");
            }

            Preview::Composition::Builtin::CapabilitySet ClaimedCapabilities;
            if (const auto ResultValue = AddCapabilities(
                    Builtin.Provides, ClaimedCapabilities, Path + ".Provides");
                !ResultValue)
            {
                return ResultValue;
            }
            if (!Options.Builtins)
            {
                if (Options.RequireBuiltinSnapshot)
                {
                    return Failure(ConfigurationErrorCode::MissingReference,
                                   Path,
                                   "configured builtin requires a frozen snapshot");
                }
                continue;
            }

            const auto Entries = Options.Builtins->Entries();
            const auto Entry = std::find_if(
                Entries.begin(), Entries.end(), [&Builtin](const auto &Value)
                {
                    return Value.Descriptor.Kind.Value() == Builtin.Kind &&
                           Value.Descriptor.Name.Value() == Builtin.Name;
                });
            if (Entry == Entries.end())
            {
                return Failure(ConfigurationErrorCode::MissingReference,
                               Path,
                               "builtin Kind and Name do not resolve in the frozen snapshot");
            }
            if (!Entry->Descriptor.Provides.Includes(ClaimedCapabilities))
            {
                return Failure(ConfigurationErrorCode::MissingCapability,
                               Path + ".Provides",
                               "configured capability is not provided by the registered builtin");
            }
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateCarrierRouteAmbiguity(
        const PreviewConfiguration &Configuration,
        const ReferenceGraph &References) -> Result
    {
        struct CandidatePriorities final
        {
            const Preview::Contract::CarrierConfiguration *Carrier{nullptr};
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
            const auto CarrierIndex = References.FindCarrierIndex(*Binding.CarrierId);
            if (CarrierIndex)
            {
                Candidates[*CarrierIndex].Values.push_back(
                    EffectiveCandidatePriority(Binding, *Candidates[*CarrierIndex].Carrier));
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
                 RightIndex < Candidates.size();
                 ++RightIndex)
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
                    !AlpnListsOverlap(Left.Carrier->Match.Alpn, Right.Carrier->Match.Alpn))
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

} // namespace Preview::Application::Configuration::Validation
