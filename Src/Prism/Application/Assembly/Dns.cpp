/** @file Dns.cpp @brief Prism 应用 DNS 配置装配实现。 */
#include <Prism/Application/Assembly/Dns.hpp>

namespace Prism::Application::Assembly
{

    auto MakeDnsConfig(
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
