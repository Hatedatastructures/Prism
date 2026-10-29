/**
 * @file Capability.hpp
 * @brief 配置声明能力与 frozen builtin 能力的校验。
 */
#pragma once

#include <Prism/Application/Configuration/Validation/Detail/Common.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Application::Configuration::Validation
{

    [[nodiscard]] inline auto CapabilityFromName(const std::string_view Name)
        -> std::optional<Prism::Composition::Builtin::Capability>
    {
        using Prism::Composition::Builtin::Capability;
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

    [[nodiscard]] inline auto AddCapabilities(
        const std::vector<std::string> &Names,
        Prism::Composition::Builtin::CapabilitySet &Available,
        const std::string &Path) -> Result
    {
        for (std::size_t Index = 0; Index < Names.size(); ++Index)
        {
            const auto CapabilityValue = CapabilityFromName(Names[Index]);
            if (!CapabilityValue)
            {
                return Failure(ConfigurationErrorCode::InvalidValue,
                               Path + "[" + std::to_string(Index) + "]",
                               "unknown capability");
            }
            Available.Add(*CapabilityValue);
        }
        return {};
    }

    [[nodiscard]] inline auto ValidateRequiredCapabilities(
        const PrismConfiguration &Configuration,
        const ValidationOptions &Options) -> Result
    {
        auto Available = Options.AvailableCapabilities;
        if (Options.Builtins)
        {
            Available |= Options.Builtins->Capabilities();
        }
        Prism::Composition::Builtin::CapabilitySet Declared;
        if (const auto ResultValue = AddCapabilities(Configuration.Runtime.RequiredCapabilities,
                                                     Declared,
                                                     "Runtime.RequiredCapabilities");
            !ResultValue)
        {
            return ResultValue;
        }
        for (std::size_t Index = 0; Index < Configuration.Builtins.size(); ++Index)
        {
            if (const auto ResultValue = AddCapabilities(
                    Configuration.Builtins[Index].Requires,
                    Declared,
                    "Builtins[" + std::to_string(Index) + "].Requires");
                !ResultValue)
            {
                return ResultValue;
            }
        }
        for (std::size_t Index = 0; Index < Configuration.Protocols.size(); ++Index)
        {
            if (const auto ResultValue = AddCapabilities(
                    Configuration.Protocols[Index].Requires,
                    Declared,
                    "Protocols[" + std::to_string(Index) + "].Requires");
                !ResultValue)
            {
                return ResultValue;
            }
        }
        for (std::size_t Index = 0; Index < Configuration.Carriers.size(); ++Index)
        {
            if (const auto ResultValue = AddCapabilities(
                    Configuration.Carriers[Index].Requires,
                    Declared,
                    "Carriers[" + std::to_string(Index) + "].Requires");
                !ResultValue)
            {
                return ResultValue;
            }
        }
        for (std::size_t Index = 0; Index < Configuration.Routes.size(); ++Index)
        {
            if (const auto ResultValue = AddCapabilities(
                    Configuration.Routes[Index].Requires,
                    Declared,
                    "Routes[" + std::to_string(Index) + "].Requires");
                !ResultValue)
            {
                return ResultValue;
            }
        }
        if (Options.CheckCapabilities && !Available.Includes(Declared))
        {
            return Failure(ConfigurationErrorCode::MissingCapability,
                           "Runtime.RequiredCapabilities",
                           "required capability is not available");
        }
        return {};
    }

} // namespace Prism::Application::Configuration::Validation
