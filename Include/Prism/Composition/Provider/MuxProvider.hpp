/** @file MuxProvider.hpp @brief 按 binding ID 准备并绑定真实 mux root provider。 */
#pragma once

#include <Prism/Contract/Ingress/ProtocolConfiguration.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Provider/ProviderCatalogInputs.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Composition::Provider
{
    inline constexpr Prism::Composition::Protocol::ProviderKey MuxProviderKey{
        Prism::Composition::Protocol::ProviderCategory::Mux,
        Prism::Composition::Protocol::ProviderIdentity{
            Prism::Composition::Protocol::MuxSlot::Binding}};

    /**
     * @brief 单个正式协议 binding 的 prepared mux provider。
     * @details Generation 仅固定配置值；UseState 是不拥有 snapshot 的代次活动计数，
     *          Bind 后由 RootBinding 保存，单个真实 root admission 才预约 GenerationUseLease。
     */
    struct PreparedMux final
    {
        Prism::Composition::Protocol::ProviderKey Key{MuxProviderKey};
        std::string Id;
        std::string ProtocolId;
        Prism::Mux::Mode Wire{Prism::Mux::Mode::Auto};
        Prism::Contract::StreamServices Services;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
    };

    /**
     * @brief 持有一个正式 RootBinding；BoundCatalog 是它的最终关闭者。
     * @details 只有 RootBinding 独立报告真实物理退休才释放配置 pin；历史 Drain Failure 仍向 caller 返回。
     *          未退休或无 getter 时保留同一 owner 和 pin 供重试。
     */
    struct BoundMux final
    {
        Prism::Composition::Protocol::ProviderKey Key{MuxProviderKey};
        std::string Id;
        std::string ProtocolId;
        Prism::Mux::Mode Wire{Prism::Mux::Mode::Auto};
        std::shared_ptr<Prism::Mux::RootBinding> Owner;
        Prism::Foundation::GenerationPin Generation;
        Prism::Fault::Failure DrainFailure_;

        auto Close() const noexcept -> void;

        /** @brief 只接受 RootBinding 的独立物理回执；未退休或无 getter 都不释放 pin。 */
        [[nodiscard]] auto PhysicalRetirement() const noexcept
            -> Prism::Composition::Provider::PhysicalRetirementState;

        /** @brief 返回 root registry 已保存的持久首因；不把本轮可重试取消当成历史错误。 */
        [[nodiscard]] auto DrainFailure() const noexcept
            -> std::optional<Prism::Fault::Failure>;

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };

    /** @brief 一个 binding 的 owning 冷准备输入；配置借用到同步返回，代次与服务由结果接管。 */
    struct MuxPreparationInput final
    {
        const Prism::Contract::ProtocolConfiguration& Protocol;
        const Prism::Contract::ProtocolBindingConfiguration& Binding;
        Prism::Contract::StreamServices Services;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
    };

    /** @brief 整个代次的 mux 准备快照；配置列表只在 PrepareMuxes 调用期间借用。 */
    struct MuxCatalogPreparation final
    {
        const std::vector<Prism::Contract::ProtocolBindingConfiguration>& Bindings;
        const std::vector<ConfiguredInstance>& Protocols;
        const Prism::Contract::StreamServices& Services;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
    };

    /** @brief 按冷配置顺序选择已有受支持 mux wire；未配置受支持 mux 时返回空。 */
    [[nodiscard]] auto ConfiguredMuxMode(
        const Prism::Contract::ProtocolConfiguration& Protocol,
        const Prism::Contract::ProtocolBindingConfiguration& Binding)
        -> std::optional<Prism::Mux::Mode>;

    /** @brief 从 binding 配置构造不可变的 typed mux preparation。 */
    [[nodiscard]] auto PrepareMux(MuxPreparationInput Input)
        -> std::expected<std::optional<PreparedMux>, Prism::Contract::ProviderFailure>;

    /** @brief 冷解析全部 configured mux binding，并拒绝悬空、重复或非 TCP 关联。 */
    [[nodiscard]] auto PrepareMuxes(MuxCatalogPreparation Input)
        -> std::expected<std::vector<PreparedMux>, Prism::Contract::ProviderFailure>;

    /** @brief 消耗 prepared 值构造 RootBinding；取消时不发布可用 mux owner。 */
    [[nodiscard]] auto BindMux(PreparedMux Value, const bool Cancelled)
        -> std::expected<BoundMux, Prism::Contract::ProviderFailure>;

    /** @brief 查询同一协议实例下配置的 mux root；只用于冷候选构造。 */
    [[nodiscard]] auto MuxesForProtocol(
        const std::string_view ProtocolId,
        const std::vector<BoundMux>& Values)
        -> std::vector<BoundMux>;
}
