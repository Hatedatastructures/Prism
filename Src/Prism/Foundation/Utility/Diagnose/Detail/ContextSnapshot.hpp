/** @file ContextSnapshot.hpp
 * @brief 异步提交边界使用的固定拥有型上下文快照。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/Record.hpp>
#include <Prism/Foundation/Utility/Text/TraceSelection.hpp>

#include <cstddef>
#include <string>
#include <utility>

namespace Prism::Diagnose::Detail
{
    /** @brief 队列槽直接拥有全部字段，不 pin 业务 Session 或长期上下文。 */
    class ContextSnapshot final
    {
    public:
        /** @brief 同步复制有效字段；调用返回后无需保活输入。 */
        [[nodiscard]] auto Capture(const ContextState& Context) noexcept -> bool
        {
            Value_ = {};
            if (Context.Failed()) { return false; }
            if (Context.Auxiliary_)
            {
                Value_ = Context.Auxiliary_.Get();
                Value_.Rebind();
            }
            for (std::size_t Index = 0U; Index < Context.InlineCount_; ++Index)
            {
                Value_.Set(Context.Inline_[Index]);
            }
            return true;
        }

        /** @brief 仅在后台解码选中字段，创建短期渲染值。 */
        [[nodiscard]] auto Decode(const RenderMode Mode, const Text::TraceSelection& Selection) const
            -> CapturedContext
        {
            CapturedContext Result;
            Result.Mode = Mode;
            Result.Prefix = Value_.Prefix;
            if (Mode == RenderMode::CompactHuman) { return Result; }
            Result.Fields.reserve(FieldCatalog::Count);
            for (const auto& Descriptor : FieldCatalog::Descriptors())
            {
                if (!Selected(Descriptor, Mode, Selection)) { continue; }
                if (Descriptor.ContextIdentity)
                {
                    if (Mode != RenderMode::Structured) { AddIdentity(Result, Descriptor.Id); }
                    continue;
                }
                for (std::size_t Index = 0U; Index < Value_.Count; ++Index)
                {
                    const auto& Binding = Value_.Overflow[Index];
                    if (Binding.Id == Descriptor.Id)
                    {
                        Result.Fields.push_back(DecodeField(Binding));
                        break;
                    }
                }
            }
            return Result;
        }
    private:
        [[nodiscard]] static auto Selected(const FieldDescriptor& Descriptor, const RenderMode Mode,
            const Text::TraceSelection& Selection) noexcept -> bool
        {
            if (Mode == RenderMode::Structured) { return true; }
            if (Descriptor.Id == FieldId::Worker) { return Selection.IncludeWorker; }
            if (Descriptor.Id == FieldId::Session) { return Selection.IncludeSession; }
            if (Descriptor.Id == FieldId::Correlation) { return Selection.IncludeCorrelation; }
            if (Descriptor.Id == FieldId::Stream) { return Selection.IncludeStream; }
            return Descriptor.Visibility == FieldVisibility::HumanVisible;
        }
        auto AddIdentity(CapturedContext& Result, const FieldId Id) const -> void
        {
            CapturedField Field;
            Field.Id = Id;
            if (Id == FieldId::Worker)
            {
                const auto Value = Value_.Prefix.Worker();
                if (!Value) { return; }
                Field.Unsigned = Value->Value();
            }
            else
            {
                const auto Value = Value_.Prefix.Session();
                if (!Value) { return; }
                Field.Unsigned = Value->Value();
            }
            Result.Fields.push_back(std::move(Field));
        }
        [[nodiscard]] static auto DecodeField(const FieldBinding& Binding) -> CapturedField
        {
            CapturedField Result;
            Result.Id = Binding.Id;
            Result.Kind = Binding.Kind;
            Result.Truncated = Binding.Truncated;
            if (IsTextFieldKind(Binding.Kind)) { Result.Text = std::string(Binding.Payload.Text); }
            else if (Binding.Kind == FieldValueKind::Boolean) { Result.Boolean = Binding.Payload.Boolean; }
            else { Result.Unsigned = Binding.Payload.Unsigned; }
            return Result;
        }
        ContextStorage Value_{};
    };
}
