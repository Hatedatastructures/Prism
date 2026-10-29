/** @file Preparation.cpp @brief 冷路径协议凭据分派实现。 */

#include <Prism/Composition/Provider/Credential/Preparation.hpp>

#include <Prism/Protocols/Anytls/Binding.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Binding.hpp>
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Protocols/Trojan/Binding.hpp>
#include <Prism/Protocols/Trusttunnel/Binding.hpp>
#include <Prism/Protocols/Vless/Binding.hpp>
#include <Prism/Protocols/Vmess/Binding.hpp>

#include <expected>
#include <string_view>

namespace Prism::Composition::Provider::ProtocolCredentialPreparation
{

    auto Prepare(const Prism::Contract::ProtocolType Protocol,
        const std::string_view Credential)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>
    {
        switch (Protocol)
        {
        case Prism::Contract::ProtocolType::Http:
            return Prism::Http11::PrepareAccountCredential(Credential);
        case Prism::Contract::ProtocolType::Socks5:
            return Prism::Socks5::PrepareAccountCredential(Credential);
        case Prism::Contract::ProtocolType::Vless:
            return Prism::Vless::PrepareAccountCredential(Credential);
        case Prism::Contract::ProtocolType::Trojan:
            return Prism::Trojan::PrepareAccountCredential(Credential);
        case Prism::Contract::ProtocolType::Vmess:
            return Prism::Vmess::PrepareAccountCredential(Credential);
        case Prism::Contract::ProtocolType::Shadowsocks:
            return Prism::Shadowsocks2022::PrepareAccountCredential(Credential);
        case Prism::Contract::ProtocolType::AnyTls:
            return Prism::Anytls::PrepareAccountCredential(Credential);
        case Prism::Contract::ProtocolType::TrustTunnel:
            return Prism::Trusttunnel::PrepareAccountCredential(Credential);
        default:
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::UnsupportedInstance, {}, "Credential.Protocol"});
        }
    }

} // namespace Prism::Composition::Provider::ProtocolCredentialPreparation
