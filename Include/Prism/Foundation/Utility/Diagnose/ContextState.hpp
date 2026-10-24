/** @file ContextState.hpp
 * @brief 无分配派生的不可变观察上下文与四槽 per-call 借用。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/Detail/ContextStorage.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldCodec.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/RenderEpoch.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>

namespace Prism::Diagnose
{
    namespace Detail { class ContextDecoder; class ContextSnapshot; }
    enum class ContextError : std::uint8_t
    {
        ContextCapacityExceeded, ///< 第五个不同 per-call 字段被拒绝。
        ResourceUnavailable, ///< 长期上下文池无法取得槽。
    };
    /**
     * @brief 不可变、值语义诊断上下文。
     * @details 长期字段由 process ContextPool 的唯一槽拥有，替换只保存当前值。
     *          per-call 文本可借用到同步提交返回；提交队列持有独立字节快照。
     *          池耗尽形成 Failed 上下文，后续提交明确 Failed，不改变业务结果。
     *          取消与半关闭不适用；最终释放者是最后一个 ContextState，释放无 executor 依赖。
     */
    class ContextState final
    {
    public:
        static constexpr std::size_t InlineBindingCapacity = 4U;
        [[nodiscard]] static auto Empty() noexcept -> ContextState { return {}; }
        /** @brief 将不可变 sink/render epoch 绑定到该代上下文。 */
        [[nodiscard]] auto WithRenderEpoch(RenderEpochPin Epoch) const noexcept -> ContextState
        {
            auto Result = *this;
            Result.Epoch_ = std::move(Epoch);
            return Result;
        }
        /** @brief 返回上下文固定持有的 generation epoch；未绑定时为空。 */
        [[nodiscard]] auto RenderEpoch() const noexcept -> const RenderEpochPin &
        {
            return Epoch_;
        }
        /** @brief 派生独立长期上下文；输入在返回前复制，失败可由 Failed 查询。 */
        template <typename Definition, typename Value>
            requires FieldValueCompatible<FieldKey<Definition>, Value>
        [[nodiscard]] auto With(const FieldKey<Definition> Key, Value&& Input) const noexcept -> ContextState
        {
            static_assert(static_cast<std::size_t>(Definition::Id) < FieldCatalog::Count);
            static_assert(Definition::MaxLength <= Detail::ContextStorage::TextBytes);
            auto Result = *this;
            if (Failed_) { return Result; }
            auto Storage = Auxiliary_.Clone();
            if (!Storage)
            {
                Result.Failed_ = true;
                return Result;
            }
            for (std::size_t Index = 0U; Index < InlineCount_; ++Index) { Storage->Set(Inline_[Index]); }
            Result.Inline_ = {};
            Result.InlineCount_ = 0U;
            if constexpr (Definition::ContextIdentity)
            {
                const auto Id = Detail::ToUnsigned(Input);
                if constexpr (Definition::Id == FieldId::Worker)
                {
                    Storage->Prefix = Storage->Prefix.WithWorker(Prism::WorkerId{Id});
                }
                else { Storage->Prefix = Storage->Prefix.WithSession(Prism::SessionId{Id}); }
            }
            else { Storage->Set(MakeBinding(Key, std::forward<Value>(Input))); }
            Result.Auxiliary_ = std::move(Storage);
            return Result;
        }
        /** @brief 四槽 per-call 派生；文本只接受左值并借用到同步提交返回。 */
        template <typename Definition, typename Value>
            requires(FieldValueCompatible<FieldKey<Definition>, Value> && !Definition::ContextIdentity &&
                (!IsTextFieldKind(Definition::Kind) || std::is_lvalue_reference_v<Value>))
        [[nodiscard]] auto TryWith(const FieldKey<Definition> Key, Value&& Input) const noexcept
            -> std::expected<ContextState, ContextError>
        {
            static_assert(static_cast<std::size_t>(Definition::Id) < FieldCatalog::Count);
            if (Failed_) { return std::unexpected(ContextError::ResourceUnavailable); }
            auto Result = *this;
            const auto Binding = MakeBinding(Key, std::forward<Value>(Input));
            for (std::size_t Index = 0U; Index < InlineCount_; ++Index)
            {
                if (Result.Inline_[Index].Id == Binding.Id)
                {
                    Result.Inline_[Index] = Binding;
                    return Result;
                }
            }
            if (InlineCount_ == InlineBindingCapacity)
            {
                return std::unexpected(ContextError::ContextCapacityExceeded);
            }
            Result.Inline_[Result.InlineCount_++] = Binding;
            return Result;
        }
        /** @brief 长期槽未能取得时为 true；保持观察失败与业务失败分离。 */
        [[nodiscard]] auto Failed() const noexcept -> bool { return Failed_; }
        /** @brief 返回上下文拥有的固定前缀视图，借用期限不超过该 owner。 */
        [[nodiscard]] auto CompactPrefix() const noexcept -> std::string_view
        {
            if (Auxiliary_) { return Auxiliary_->Prefix.View(); }
            return {};
        }
        /** @brief 读取实际已设置的 worker 身份，未设置不生成默认零身份。 */
        [[nodiscard]] auto WorkerId() const noexcept -> std::optional<Prism::WorkerId>
        {
            if (Auxiliary_) { return Auxiliary_->Prefix.Worker(); }
            return {};
        }
        /** @brief 读取实际已设置的 session 身份。 */
        [[nodiscard]] auto SessionId() const noexcept -> std::optional<Prism::SessionId>
        {
            if (Auxiliary_) { return Auxiliary_->Prefix.Session(); }
            return {};
        }
        /** @brief 合并长期与 per-call 覆盖字段，返回实际不同字段数。 */
        [[nodiscard]] auto FieldCount() const noexcept -> std::size_t;
    private:
        friend class Detail::ContextDecoder;
        friend class Detail::ContextSnapshot;
        template <typename Definition, typename Value>
        [[nodiscard]] static auto MakeBinding(const FieldKey<Definition> Key, Value&& Input) noexcept
            -> Detail::FieldBinding
        {
            Detail::FieldBinding Result;
            Result.Id = Key.Id;
            Result.Kind = Definition::Kind;
            if constexpr (IsTextFieldKind(Definition::Kind))
            {
                Result.Payload.Text = Text::BorrowView(Input);
                Result.BorrowedText = true;
            }
            else if constexpr (Definition::Kind == FieldValueKind::Boolean)
            {
                Result.Payload.Boolean = static_cast<bool>(Input);
            }
            else { Result.Payload.Unsigned = Detail::ToUnsigned(Input); }
            return Result;
        }
        [[nodiscard]] auto ContainsInline(const FieldId Id) const noexcept -> bool;
        std::array<Detail::FieldBinding, InlineBindingCapacity> Inline_{};
        Detail::ContextOwner Auxiliary_{};
        RenderEpochPin Epoch_{};
        std::uint8_t InlineCount_{0U};
        bool Failed_{false};
    };
    static_assert(sizeof(ContextState) <= 128U);
}
