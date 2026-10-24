/** @file ProviderInstancePreparation.hpp @brief 每个正式 proxy provider 的唯一冷 credential/Prepare 分派。 */
#pragma once

#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Provider/ProviderCatalogInputs.hpp>
#include <Prism/Composition/Provider/ProviderBindingVariants.hpp>

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>

namespace Prism::Composition::Provider::ProtocolProviderPreparation
{
    /** @brief 一次 catalog Prepare 的重复项与 listener 唯一性状态。 */
    struct State final
    {
        std::unordered_set<std::string> Seen;
        bool QuicListenerUsed{false};
    };

    /** @brief 一个协议实例的 cold owner 输入；Prepare 同步消费配置和 service handles。 */
    struct Input final
    {
        ConfiguredInstance Instance;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        BindingServices Services;
    };

    /** @brief 只接受 ProtocolCatalog 中具有真实 TCP 或 QUIC provider slot 的协议名。 */
    [[nodiscard]] auto Handles(std::string_view Name) -> bool;

    [[nodiscard]] auto PrepareSpecialTcp(Input Value, Prism::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>;

    [[nodiscard]] auto PrepareStandardTcp(Input Value, Prism::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>;

    [[nodiscard]] auto PrepareTcp(Input Value, Prism::Contract::ProtocolType Type)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>;

    [[nodiscard]] auto PrepareQuic(Input Value,
        const Prism::Composition::Protocol::ProtocolDescriptor& Descriptor, State& Catalog)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>;

    [[nodiscard]] auto Prepare(Input Value, State& Catalog)
        -> std::expected<PreparedInstance, Prism::Contract::ProviderFailure>;


}
