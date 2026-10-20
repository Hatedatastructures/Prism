/** @file ProtocolCredentialPreparation.hpp @brief 协议凭据材料的唯一冷分派入口。 */
#pragma once

#include <Prism/Account/Credential.hpp>
#include <Prism/Contract/Ingress/Protocol.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>

#include <expected>
#include <string_view>

namespace Prism::Composition::Provider::ProtocolCredentialPreparation
{

    /** @brief 将借用凭据文本交给协议 owner 解析为 typed credential。 */
    [[nodiscard]] auto Prepare(
        Prism::Contract::ProtocolType Protocol,
        std::string_view Credential)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>;

} // namespace Prism::Composition::Provider::ProtocolCredentialPreparation
