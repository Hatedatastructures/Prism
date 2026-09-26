/**
 * @file ContextState.hpp
 * @brief 不可变 Diagnose 上下文和值快照入口。
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <Preview/Foundation/Utility/Diagnose/FieldCatalog.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldCodec.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/PrefixCache.hpp>

namespace Preview::Diagnose
{

    namespace Detail
    {
        class ContextDecoder;
    }

    /**
     * @brief 派生 per-call 上下文失败的原因。
     * @details 当新增字段超过固定 inline 容量时返回容量错误；长期上下文使用动态拥有区，不受此限制。
     */
    enum class ContextError : std::uint8_t
    {
        ContextCapacityExceeded, ///< 新字段无法放入已满的 per-call inline 区。
    };

    namespace Detail
    {

        /**
         * @brief 字段的无分配载荷。
         * @details 联合体只保存数值、布尔值或文本视图，不拥有文本存储；文本视图的有效期由上下文提升流程或调用方保证。
         */
        union FieldPayload final
        {
            std::uint64_t Unsigned; ///< 数值、枚举值或强类型 ID 的无符号表示。
            bool Boolean;           ///< 布尔字段值。
            std::string_view Text;  ///< 借用文本，或指向 Auxiliary 所有文本的视图。

            /** @brief 默认激活 Unsigned 成员并将数值载荷初始化为 0。 */
            constexpr FieldPayload() noexcept : Unsigned(0U)
            {
            }
        };

        /**
         * @brief 将字段定义绑定到其编码载荷。
         * @details BorrowedText 标记 Text 是否指向调用方内存；持久化前必须复制并转为拥有文本。
         */
        struct FieldBinding final
        {
            FieldId Id{};                                  ///< 字段目录中的稳定 ID。
            FieldValueKind Kind{FieldValueKind::Unsigned}; ///< Payload 当前有效成员的类型。
            bool BorrowedText{false};                      ///< Text 是否仍借用调用方内存。
            bool Truncated{false};                         ///< 文本是否已按字段定义的长度上限截断。
            FieldPayload Payload{};                        ///< 字段的实际编码值。
        };

        /**
         * @brief 判断值能否安全地存入 per-call 字段区。
         * @details 非文本值会被复制；文本值必须来自左值，以免 string_view 指向即将销毁的临时对象。
         * @tparam Definition 字段元数据，提供字段值种类。
         * @tparam Value 调用实参的推导类型；引用限定用于拒绝临时文本。
         */
        template <typename Definition, typename Value>
        inline constexpr bool SafeTryWithValue =
            (!IsTextFieldKind(Definition::Kind)) || std::is_lvalue_reference_v<Value>;

    } // namespace Detail

    /**
     * @brief Preview Diagnose 的不可变、值语义上下文。
     * @details 派生操作返回新状态，不修改父状态。长期字段保存在共享的写时复制拥有区；per-call 字段保存在固定容量的 inline 区。
     *          提交解码时会生成独立快照，使异步后端不依赖调用方临时数据。该类型不管理日志 backend 生命周期。
     */
    class ContextState final
    {
    public:
        /** @brief 单个 per-call 上下文可容纳的不同 inline 字段数。 */
        static constexpr std::size_t InlineBindingCapacity = 4U;

        /**
         * @brief 创建不携带字段或身份前缀的根上下文。
         * @return 空的 ContextState。
         */
        [[nodiscard]] static auto Empty() noexcept -> ContextState
        {
            return {};
        }

        /**
         * @brief 按值派生长期上下文。
         * @tparam Definition 字段定义，提供字段 ID、值类型和编码策略。
         * @tparam Value 输入值类型，必须满足该字段的 FieldValueCompatible 约束。
         * @param Key 要写入的字段 key。
         * @param Input 字段值；文本会复制、脱敏并按字段上限截断后由新上下文拥有。
         * @return 包含新字段或更新字段的新上下文；原上下文保持不变。
         * @details 派生时先把已有 per-call 字段提升到长期存储，再执行写时复制。Worker/Session 身份字段更新缓存前缀，不作为普通字段绑定保存。
         */
        template <typename Definition, typename Value>
            requires FieldValueCompatible<FieldKey<Definition>, Value>
        [[nodiscard]] auto With(const FieldKey<Definition> Key, Value &&Input) const -> ContextState
        {
            auto Result = *this;
            auto AuxiliaryValue = CloneAuxiliary();
            PromoteBorrowedText(Result, *AuxiliaryValue);
            PromoteInlineFields(Result, *AuxiliaryValue);

            if constexpr (Definition::ContextIdentity)
            {
                const auto IdValue = Detail::ToUnsigned(Input);
                if constexpr (Definition::Id == FieldId::Worker)
                {
                    AuxiliaryValue->Prefix = AuxiliaryValue->Prefix.WithWorker(Preview::WorkerId{IdValue});
                }
                else
                {
                    AuxiliaryValue->Prefix = AuxiliaryValue->Prefix.WithSession(Preview::SessionId{IdValue});
                }
            }
            else
            {
                auto Binding = MakeBinding(Key, std::forward<Value>(Input));
                if constexpr (IsTextFieldKind(Definition::Kind))
                {
                    auto Encoded = EncodeFieldValue(Key, std::forward<Value>(Input));
                    auto TextValue = std::make_shared<const std::string>(std::move(Encoded.Text));
                    Binding.Payload.Text = *TextValue;
                    Binding.BorrowedText = false;
                    Binding.Truncated = Encoded.Truncated;
                    AuxiliaryValue->OwnedText.push_back(std::move(TextValue));
                }
                SetPersistentBinding(Result, Binding, *AuxiliaryValue);
            }

            Result.Auxiliary_ = std::move(AuxiliaryValue);
            return Result;
        }

        /**
         * @brief 在固定 inline 区中派生 per-call 上下文。
         * @tparam Definition 字段定义；身份前缀字段不能通过此接口添加。
         * @tparam Value 输入值类型，必须满足字段兼容约束；文本还必须是左值。
         * @param Key 要写入的字段 key。
         * @param Input 字段值；文本不复制，调用方须保证其存储至少有效到本次日志提交完成。
         * @return 成功时返回包含字段的新上下文；若新增不同字段时 4 个槽位已满，返回 ContextCapacityExceeded。替换已有字段不增加占用数。
         * @details 非文本值按值存入 inline 区。此接口不会分配长期字段或文本存储。
         */
        template <typename Definition, typename Value>
            requires(FieldValueCompatible<FieldKey<Definition>, Value> && !Definition::ContextIdentity &&
                     Detail::SafeTryWithValue<Definition, Value>)
        [[nodiscard]] auto TryWith(const FieldKey<Definition> Key, Value &&Input) const
            -> std::expected<ContextState, ContextError>
        {
            auto Result = *this;
            auto Binding = MakeBinding(Key, std::forward<Value>(Input));
            for (std::size_t Index = 0; Index < Result.InlineCount_; ++Index)
            {
                if (Result.Inline_[Index].Id == Binding.Id)
                {
                    Result.Inline_[Index] = Binding;
                    return Result;
                }
            }

            if (Result.InlineCount_ >= InlineBindingCapacity)
            {
                return std::unexpected(ContextError::ContextCapacityExceeded);
            }
            Result.Inline_[Result.InlineCount_++] = Binding;
            return Result;
        }

        /**
         * @brief 获取已缓存的人类可读身份前缀。
         * @return 按 Worker、Session 顺序组成的前缀视图；没有身份时为空视图。
         * @details 返回视图不拥有存储；只要仍有持有该前缀缓存的上下文存活，就可读取该视图。前缀在身份字段派生时重建，读取时不重新格式化。
         */
        [[nodiscard]] auto CompactPrefix() const noexcept -> std::string_view
        {
            if (Auxiliary_)
            {
                return Auxiliary_->Prefix.View();
            }
            return {};
        }

        /**
         * @brief 获取当前上下文的 Worker 身份。
         * @return 已设置时返回 WorkerId，否则返回 std::nullopt。
         */
        [[nodiscard]] auto WorkerId() const noexcept -> std::optional<Preview::WorkerId>
        {
            if (Auxiliary_)
            {
                return Auxiliary_->Prefix.Worker();
            }
            return {};
        }

        /**
         * @brief 获取当前上下文的 Session 身份。
         * @return 已设置时返回 SessionId，否则返回 std::nullopt。
         */
        [[nodiscard]] auto SessionId() const noexcept -> std::optional<Preview::SessionId>
        {
            if (Auxiliary_)
            {
                return Auxiliary_->Prefix.Session();
            }
            return {};
        }

        /**
         * @brief 获取当前上下文绑定的普通字段数。
         * @return inline 区与长期区合并后的不同字段数；同一 ID 的替换只计一次。
         * @details 不包含仅用于构造身份前缀的 Worker/Session 身份，也不执行字段格式化。
         */
        [[nodiscard]] auto FieldCount() const noexcept -> std::size_t
        {
            auto Count = static_cast<std::size_t>(InlineCount_);
            if (Auxiliary_)
            {
                for (const auto &Binding : Auxiliary_->Overflow)
                {
                    if (!ContainsInline(Binding.Id))
                    {
                        ++Count;
                    }
                }
            }
            return Count;
        }

    private:
        /**
         * @brief 长期字段与身份前缀的共享拥有区。
         * @details With() 先复制该对象再修改副本；文本由 OwnedText 保持地址稳定，字段数不受 per-call inline 容量限制。
         */
        struct Auxiliary final
        {
            PrefixCache Prefix{}; ///< 已缓存的 Worker/Session 人类前缀。
            std::vector<std::shared_ptr<const std::string>> OwnedText{}; ///< 拥有的长期文本，保证地址稳定。
            std::vector<Detail::FieldBinding> Overflow{}; ///< 动态保存长期字段及从 inline 区提升的字段。
        };

        friend class Detail::ContextDecoder;

        /**
         * @brief 创建当前长期拥有区的可修改副本。
         * @return 当前 Auxiliary 的副本；尚无长期状态时返回空 Auxiliary。
         * @details 字符串对象通过 shared_ptr 共享，容器本身复制，从而让后续写入不影响父上下文。
         */
        [[nodiscard]] auto CloneAuxiliary() const -> std::shared_ptr<Auxiliary>
        {
            if (Auxiliary_)
            {
                return std::make_shared<Auxiliary>(*Auxiliary_);
            }
            return std::make_shared<Auxiliary>();
        }

        /**
         * @brief 将字段 key 与输入值编码为无拥有权的绑定。
         * @tparam Definition 字段定义，决定载荷种类。
         * @tparam Value 输入值类型；文本输入会被视为借用视图。
         * @param Key 要绑定的字段 key。
         * @param Input 要编码的字段值。
         * @return 保存数值、布尔值或文本视图的 FieldBinding；文本仍由调用方或后续提升流程负责其生命周期。
         */
        template <typename Definition, typename Value>
        [[nodiscard]] static auto MakeBinding(const FieldKey<Definition> Key, Value &&Input)
            -> Detail::FieldBinding
        {
            Detail::FieldBinding Result;
            Result.Id = Key.Id;
            Result.Kind = Definition::Kind;
            if constexpr (IsTextFieldKind(Definition::Kind))
            {
                Result.Payload.Text = std::string_view(std::forward<Value>(Input));
                Result.BorrowedText = true;
            }
            else if constexpr (Definition::Kind == FieldValueKind::Boolean)
            {
                Result.Payload.Boolean = static_cast<bool>(Input);
            }
            else
            {
                Result.Payload.Unsigned = Detail::ToUnsigned(Input);
            }
            return Result;
        }

        /**
         * @brief 检查指定字段是否已占用 inline 槽位。
         * @param Id 要查找的字段 ID。
         * @return inline 区中存在该 ID 时返回 true。
         */
        [[nodiscard]] auto ContainsInline(const FieldId Id) const noexcept -> bool
        {
            for (std::size_t Index = 0; Index < InlineCount_; ++Index)
            {
                if (Inline_[Index].Id == Id)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief 将一个绑定写入长期字段区。
         * @param Context 该绑定所属的上下文副本；当前实现不读取或修改此对象。
         * @param Binding 要保存或替换的字段绑定。
         * @param AuxiliaryValue 实际接收字段绑定的长期拥有区。
         * @details 已有相同字段 ID 时替换其值，否则追加一个绑定。
         */
        static auto SetPersistentBinding(ContextState &Context, const Detail::FieldBinding &Binding,
                                         Auxiliary &AuxiliaryValue) -> void
        {
            for (auto &Existing : AuxiliaryValue.Overflow)
            {
                if (Existing.Id == Binding.Id)
                {
                    Existing = Binding;
                    return;
                }
            }
            AuxiliaryValue.Overflow.push_back(Binding);
        }

        /**
         * @brief 将上下文的 inline 字段提升到长期字段区。
         * @param Context 要清空 inline 区的上下文副本。
         * @param AuxiliaryValue 接收提升字段的长期拥有区。
         * @details 字段按 ID 合并到 Overflow；处理后 inline 槽位归零。调用方应传入父状态的副本，避免修改原上下文。
         */
        static auto PromoteInlineFields(ContextState &Context, Auxiliary &AuxiliaryValue) -> void
        {
            for (std::size_t Index = 0; Index < Context.InlineCount_; ++Index)
            {
                SetPersistentBinding(Context, Context.Inline_[Index], AuxiliaryValue);
                Context.Inline_[Index] = {};
            }
            Context.InlineCount_ = 0U;
        }

        /**
         * @brief 将上下文内借用的文本转换为长期拥有文本。
         * @param Context 持有 inline 绑定的上下文副本。
         * @param AuxiliaryValue 关联的长期拥有区；新字符串由其 OwnedText 保持存活。
         * @details 只处理仍标记为借用的文本字段；复制时按字段策略脱敏和截断，然后让绑定改为引用新拥有字符串。
         */
        static auto PromoteBorrowedText(ContextState &Context, Auxiliary &AuxiliaryValue) -> void
        {
            const auto Promote = [&AuxiliaryValue](Detail::FieldBinding &Binding)
            {
                if (!Binding.BorrowedText || (!IsTextFieldKind(Binding.Kind)))
                {
                    return;
                }
                auto Encoded = CopyAndBound(Binding);
                auto TextValue = std::make_shared<const std::string>(std::move(Encoded.first));
                Binding.Payload.Text = *TextValue;
                Binding.BorrowedText = false;
                Binding.Truncated = Encoded.second;
                AuxiliaryValue.OwnedText.push_back(std::move(TextValue));
            };
            for (std::size_t Index = 0; Index < Context.InlineCount_; ++Index)
            {
                Promote(Context.Inline_[Index]);
            }
            for (auto &Binding : AuxiliaryValue.Overflow)
            {
                Promote(Binding);
            }
        }

        /**
         * @brief 复制文本并应用字段目录中的敏感信息与长度策略。
         * @param Binding 含有待复制文本视图的字段绑定。
         * @return 处理后的 UTF-8 文本及是否发生截断的标记；字段目录中没有该 ID 时仅复制原文本。
         */
        [[nodiscard]] static auto CopyAndBound(const Detail::FieldBinding &Binding)
            -> std::pair<std::string, bool>
        {
            const auto Descriptor = FieldCatalog::Find(Binding.Id);
            if (!Descriptor)
            {
                return {std::string(Binding.Payload.Text), false};
            }
            std::string Text(Binding.Payload.Text);
            if (Descriptor->Sensitive)
            {
                Text = Preview::Statistics::RedactSensitiveText(Text);
            }
            return Detail::TruncateUtf8(Text, Descriptor->MaxLength);
        }

        std::array<Detail::FieldBinding, InlineBindingCapacity>
            Inline_{};                                 ///< 最多 4 个 per-call 字段绑定；存储本身不分配。
        std::shared_ptr<const Auxiliary> Auxiliary_{}; ///< 长期字段、文本和身份前缀的不可变共享拥有区。
        std::uint8_t InlineCount_{0U};                 ///< Inline_ 中已使用的槽位数。
    };

    static_assert(sizeof(ContextState) <= 128U);

} // namespace Preview::Diagnose
