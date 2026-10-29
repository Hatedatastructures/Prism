/**
 * @file Dns.hpp
 * @brief Prism 应用 DNS 配置装配。
 */

#pragma once

#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Net/Dns/Config.hpp>

namespace Prism::Application::Assembly
{

    [[nodiscard]] auto MakeDnsConfig(
        const Prism::Application::Configuration::DnsConfiguration &Configured)
        -> Prism::Network::Dns::Config;

} // namespace Prism::Application::Assembly
