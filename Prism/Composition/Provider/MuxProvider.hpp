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
#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
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

        auto Close() const noexcept -> void
        {
            if (Owner)
            {
                Owner->Close();
            }
        }

        /** @brief 只接受 RootBinding 的独立物理回执；未退休或无 getter 都不释放 pin。 */
        [[nodiscard]] auto PhysicalRetirement() const noexcept
            -> Prism::Composition::Provider::PhysicalRetirementState
        {
            if (!Owner)
            {
                if (!Generation)
                {
                    return Prism::Composition::Provider::PhysicalRetirementState::Retired;
                }
                return Prism::Composition::Provider::PhysicalRetirementState::Unknown;
            }
            if constexpr (requires { Owner->IsRetired(); })
            {
                if (Owner->IsRetired() && !Generation)
                {
                    return Prism::Composition::Provider::PhysicalRetirementState::Retired;
                }
                return Prism::Composition::Provider::PhysicalRetirementState::Active;
            }
            return Prism::Composition::Provider::PhysicalRetirementState::Unknown;
        }

        /** @brief 返回 root registry 已保存的持久首因；不把本轮可重试取消当成历史错误。 */
        [[nodiscard]] auto DrainFailure() const noexcept
            -> std::optional<Prism::Fault::Failure>
        {
            if (DrainFailure_.Failed()) return DrainFailure_;
            if (Owner)
            {
                const auto Failure = Owner->DrainFailure();
                if (Failure.Failed()) return Failure;
            }
            return {};
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Owner)
            {
                if (DrainFailure_.Failed()) co_return std::unexpected(DrainFailure_);
                Generation.reset();
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            if (Owner)
            {
                const auto Result = co_await Owner->Drain();
                const bool Retired = Owner->IsRetired();
                const auto Durable = Owner->DrainFailure();
                if (Durable.Failed() && (!DrainFailure_.Failed() ||
                    (DrainFailure_.Code == Prism::Fault::Code::Canceled &&
                     Durable.Code != Prism::Fault::Code::Canceled)))
                {
                    DrainFailure_ = Durable;
                }
                else if (!Result && Result.error().Code != Prism::Fault::Code::Canceled &&
                    (!DrainFailure_.Failed() ||
                     (DrainFailure_.Code == Prism::Fault::Code::Canceled &&
                      Result.error().Code != Prism::Fault::Code::Canceled)))
                {
                    DrainFailure_ = Result.error();
                }
                if constexpr (requires { Owner->IsRetired(); })
                {
                    if (Retired)
                    {
                        Owner.reset();
                        Generation.reset();
                    }
                }
                if (DrainFailure_.Failed())
                    co_return std::unexpected(DrainFailure_);
                if (!Result)
                {
                    if (Result.error().Code == Prism::Fault::Code::Canceled && Retired)
                        co_return std::expected<void, Prism::Fault::Failure>{};
                    co_return std::unexpected(Result.error());
                }
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
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
    [[nodiscard]] inline auto ConfiguredMuxMode(
        const Prism::Contract::ProtocolConfiguration& Protocol,
        const Prism::Contract::ProtocolBindingConfiguration& Binding)
        -> std::optional<Prism::Mux::Mode>
    {
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Protocol.Builtin);
        if (Descriptor && Descriptor->Id == Prism::Contract::ProtocolType::AnyTls)
        {
            return std::nullopt;
        }
        for (const auto& Name : Binding.MuxModes)
        {
            const auto Mode = Prism::Mux::ParseMode(Name);
            if (Mode && (*Mode == Prism::Mux::Mode::H2Mux || *Mode == Prism::Mux::Mode::Yamux))
            {
                return Mode;
            }
        }
        for (const auto& Name : Binding.MuxModes)
        {
            const auto Mode = Prism::Mux::ParseMode(Name);
            if (Mode && *Mode == Prism::Mux::Mode::Smux)
            {
                return Mode;
            }
        }
        return std::nullopt;
    }

    /** @brief 从 binding 配置构造不可变的 typed mux preparation。 */
    [[nodiscard]] inline auto PrepareMux(MuxPreparationInput Input)
        -> std::expected<std::optional<PreparedMux>, Prism::Contract::ProviderFailure>
    {
        const auto Mode = ConfiguredMuxMode(Input.Protocol, Input.Binding);
        if (!Mode)
        {
            if (!Input.Binding.MuxModes.empty())
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Input.Protocol.Id, "Bindings.Mux.Modes"});
            }
            return std::optional<PreparedMux>{};
        }
        if (!Input.Services.Egress)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingEgress, Input.Protocol.Id, "Bindings.Mux.Egress"});
        }
        if (!Input.Services.Bytes)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidConfiguration, Input.Protocol.Id,
                "Bindings.Mux.BytePool"});
        }
        if (!Input.Generation || !Input.UseState)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::GenerationMismatch,
                Input.Protocol.Id, "Generation"});
        }
        return std::optional<PreparedMux>{PreparedMux{
            MuxProviderKey, Input.Binding.Id, Input.Protocol.Id, *Mode,
            std::move(Input.Services), std::move(Input.Generation), std::move(Input.UseState)}};
    }

    /** @brief 冷解析全部 configured mux binding，并拒绝悬空、重复或非 TCP 关联。 */
    [[nodiscard]] inline auto PrepareMuxes(MuxCatalogPreparation Input)
        -> std::expected<std::vector<PreparedMux>, Prism::Contract::ProviderFailure>
    {
        std::vector<PreparedMux> Result;
        std::unordered_set<std::string> Seen;
        for (const auto& Binding : Input.Bindings)
        {
            if (!Seen.emplace(Binding.Id).second)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::DuplicateInstance, Binding.Id, "Bindings.Id"});
            }
            const auto Protocol = std::find_if(Input.Protocols.begin(), Input.Protocols.end(),
                [&Binding](const ConfiguredInstance& Value)
                {
                    return Value.Protocol.Id == Binding.ProtocolId;
                });
            if (Protocol == Input.Protocols.end())
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Binding.ProtocolId, "Bindings.ProtocolId"});
            }
            const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(
                Protocol->Protocol.Builtin);
            if (!Descriptor || Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Binding.ProtocolId, "Bindings.Protocol"});
            }
            auto Prepared = PrepareMux(MuxPreparationInput{
                Protocol->Protocol, Binding, Input.Services, Input.Generation, Input.UseState});
            if (!Prepared)
            {
                return std::unexpected(Prepared.error());
            }
            if (!Prepared->has_value())
            {
                continue;
            }
            if (!Descriptor->SupportsTcp)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::UnsupportedInstance,
                    Binding.ProtocolId, "Bindings.Mux.Protocol"});
            }
            Result.push_back(std::move(**Prepared));
        }
        return Result;
    }

    /** @brief 消耗 prepared 值构造 RootBinding；取消时不发布可用 mux owner。 */
    [[nodiscard]] inline auto BindMux(PreparedMux Value, const bool Cancelled)
        -> std::expected<BoundMux, Prism::Contract::ProviderFailure>
    {
        if (Cancelled)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Value.Id, "Bind"});
        }
        if (Value.Key != MuxProviderKey)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::UnsupportedInstance, Value.Id, "Bindings.Mux.Slot"});
        }
        Prism::Mux::RootOptions Options;
        Options.Wire = Value.Wire;
        Options.Services = std::move(Value.Services);
        Options.GenerationUseState = std::move(Value.UseState);
        auto Root = std::make_shared<Prism::Mux::RootBinding>(std::move(Options));
        return BoundMux{Value.Key, std::move(Value.Id), std::move(Value.ProtocolId), Value.Wire,
            std::move(Root), std::move(Value.Generation)};
    }

    /** @brief 查询同一协议实例下配置的 mux root；只用于冷候选构造。 */
    [[nodiscard]] inline auto MuxesForProtocol(
        const std::string_view ProtocolId,
        const std::vector<BoundMux>& Values)
        -> std::vector<BoundMux>
    {
        std::vector<BoundMux> Result;
        for (const auto& Value : Values)
        {
            if (Value.Key == MuxProviderKey && Value.ProtocolId == ProtocolId && Value.Owner)
            {
                Result.push_back(Value);
            }
        }
        return Result;
    }
}
