/** @file ProtocolCredentialPreparation.hpp @brief 协议凭据材料的唯一冷分派入口。 */
#pragma once

#include <Prism/Protocols/Anytls/Binding.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Binding.hpp>
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Protocols/Trojan/Binding.hpp>
#include <Prism/Protocols/Trusttunnel/Binding.hpp>
#include <Prism/Protocols/Vless/Binding.hpp>
#include <Prism/Protocols/Vmess/Binding.hpp>
#include <Prism/Account/Credential.hpp>
#include <Prism/Contract/Ingress/Protocol.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>

#include <expected>
#include <string>
#include <string_view>

namespace Prism::Composition::Provider::ProtocolCredentialPreparation
{
    /** @brief 将配置凭据交给其协议 owner 解释；返回值只含该协议的 typed material。 */
    [[nodiscard]] inline auto Prepare(
        const Prism::Contract::ProtocolType Protocol,
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
}
