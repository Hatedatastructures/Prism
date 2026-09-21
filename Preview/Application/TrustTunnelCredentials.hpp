/**
 * @file TrustTunnelCredentials.hpp
 * @brief TrustTunnel 账户凭据解析。
 */

#pragma once

#include <Preview/Application/Application.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>

#include <expected>
#include <string>
#include <string_view>

namespace Preview::Application::TrustTunnelCredentials
{

    [[nodiscard]] inline auto Parse(
        const std::string_view Credential,
        const std::string_view Path)
        -> std::expected<Preview::Trusttunnel::ServerConfig, StartupError>
    {
        const auto Separator = Credential.find(':');
        if (Separator == std::string_view::npos || Separator == 0U ||
            Separator + 1U >= Credential.size())
        {
            return std::unexpected(StartupError{
                StartupErrorCode::InvalidConfiguration,
                std::string(Path),
                "TrustTunnel credentials must be username:password"});
        }
        return Preview::Trusttunnel::ServerConfig{
            std::string(Credential.substr(0, Separator)),
            std::string(Credential.substr(Separator + 1U))};
    }

} // namespace Preview::Application::TrustTunnelCredentials
