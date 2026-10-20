/**
 * @file WireAuthBinding.hpp
 * @brief TrustTunnel wire 与账户认证凭据的私有 generation binding。
 */
#pragma once

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>

#include <memory>
#include <string>

namespace Prism::Trusttunnel
{
    class IngressFactory;

    namespace Detail
    {
        class Http2Accept;
    }

    struct WireAuthBinding final
    {
    private:
        friend class IngressFactory;
        friend class Detail::Http2Accept;
        friend auto MakeWireAuthBinding(
            ServerConfig Configuration,
            Prism::SharedAuthenticator Authenticator)
            -> std::shared_ptr<const WireAuthBinding>;

        WireAuthBinding(
            ServerConfig ConfigurationValue,
            Prism::SharedAuthenticator AuthenticatorValue);

        const ServerConfig Configuration;
        const std::string Credential;
        const Prism::SharedAuthenticator Authenticator;
    };
}
