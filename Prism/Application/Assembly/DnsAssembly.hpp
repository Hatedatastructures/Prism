/**
 * @file DnsAssembly.hpp
 * @brief Prism 应用 DNS 配置装配。
 */

#pragma once

#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Net/Dns/Config.hpp>

namespace Prism::Application::Assembly
{

    [[nodiscard]] inline auto MakeDnsConfig(
        const Prism::Application::Configuration::DnsConfiguration &Configured)
        -> Prism::Network::Dns::Config
    {
        Prism::Network::Dns::Config Result;
        Result.TimeoutMs = Configured.Timeout;
        Result.DisableIpv6 = true;
        for (const auto &Server : Configured.Servers)
        {
            Result.Servers.push_back(Prism::Network::Dns::ParseServer(Server));
        }
        return Result;
    }

} // namespace Prism::Application::Assembly
