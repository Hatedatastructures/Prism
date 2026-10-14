/** @file ProtocolCredentialPreparation.hpp @brief 协议凭据材料的唯一冷分派入口。 */
#pragma once

#include <Preview/Protocols/Anytls/Binding.hpp>
#include <Preview/Protocols/Http1/Binding.hpp>
#include <Preview/Protocols/Shadowsocks2022/Binding.hpp>
#include <Preview/Protocols/Socks5/Binding.hpp>
#include <Preview/Protocols/Trojan/Binding.hpp>
#include <Preview/Protocols/Trusttunnel/Binding.hpp>
#include <Preview/Protocols/Vless/Binding.hpp>
#include <Preview/Protocols/Vmess/Binding.hpp>
#include <Preview/Account/Credential.hpp>
#include <Preview/Contract/Ingress/Protocol.hpp>
#include <Preview/Contract/Ingress/ProviderFailure.hpp>

#include <expected>
#include <string>
#include <string_view>

namespace Preview::Composition::Provider::ProtocolCredentialPreparation
{
    /** @brief 将配置凭据交给其协议 owner 解释；返回值只含该协议的 typed material。 */
    [[nodiscard]] inline auto Prepare(
        const Preview::Contract::ProtocolType Protocol,
        const std::string_view Credential)
        -> std::expected<Preview::Account::Credential, Preview::Contract::ProviderFailure>
    {
        switch (Protocol)
        {
        case Preview::Contract::ProtocolType::Http:
            return Preview::Http11::PrepareAccountCredential(Credential);
        case Preview::Contract::ProtocolType::Socks5:
            return Preview::Socks5::PrepareAccountCredential(Credential);
        case Preview::Contract::ProtocolType::Vless:
            return Preview::Vless::PrepareAccountCredential(Credential);
        case Preview::Contract::ProtocolType::Trojan:
            return Preview::Trojan::PrepareAccountCredential(Credential);
        case Preview::Contract::ProtocolType::Vmess:
            return Preview::Vmess::PrepareAccountCredential(Credential);
        case Preview::Contract::ProtocolType::Shadowsocks:
            return Preview::Shadowsocks2022::PrepareAccountCredential(Credential);
        case Preview::Contract::ProtocolType::AnyTls:
            return Preview::Anytls::PrepareAccountCredential(Credential);
        case Preview::Contract::ProtocolType::TrustTunnel:
            return Preview::Trusttunnel::PrepareAccountCredential(Credential);
        default:
            return std::unexpected(Preview::Contract::ProviderFailure{
                Preview::Contract::ProviderError::UnsupportedInstance, {}, "Credential.Protocol"});
        }
    }
}
