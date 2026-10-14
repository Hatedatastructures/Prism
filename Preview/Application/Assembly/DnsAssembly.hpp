/**
 * @file DnsAssembly.hpp
 * @brief Preview 应用 DNS 配置装配。
 */

#pragma once

#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Net/Dns/Config.hpp>

namespace Preview::Application::Assembly
{

    [[nodiscard]] inline auto MakeDnsConfig(
        const Preview::Application::Configuration::DnsConfiguration &Configured)
        -> Preview::Network::Dns::Config
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

} // namespace Preview::Application::Assembly
