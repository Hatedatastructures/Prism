/** @file QuicPreparation.hpp @brief 共享的实际 QUIC listener 与 owning token 材料校验。 */
#pragma once
#include <Prism/Protocols/Common/Authentication/ScopedMaterial.hpp>
#include <Prism/Contract/Services/Quic.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Ingress/ProtocolConfiguration.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <expected>
#include <string>
namespace Prism::Protocols
{
    struct QuicPreparation final
    {
        std::string Instance;
        Prism::Foundation::GenerationPin Generation;
        Prism::Contract::ProtocolConfiguration::QuicOptions Config;
    };
    /** @brief 校验真实服务与原 generation 控制块，零 lease；非敏感错误路径可直接定位配置。 */
    [[nodiscard]] auto ValidateQuic(const QuicPreparation& Input,
        const Prism::Contract::QuicBindingServices& Services)
        -> std::expected<void,Prism::Contract::ProviderFailure>;
    [[nodiscard]] auto ValidateQuicAuthentication(const QuicPreparation& Input,
        const Prism::Contract::AuthenticationServices& Authentication)
        -> std::expected<ScopedMaterial, Prism::Contract::ProviderFailure>;
}
