/**
 * @file ContextState.cpp
 * @brief 诊断上下文的固定字段计数实现。
 */
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>

#include <cstddef>

namespace Prism::Diagnose
{
    auto ContextState::FieldCount() const noexcept -> std::size_t
    {
        auto Count = static_cast<std::size_t>(InlineCount_);
        if (Auxiliary_)
        {
            for (std::size_t Index = 0U; Index < Auxiliary_->Count; ++Index)
            {
                if (!ContainsInline(Auxiliary_->Overflow[Index].Id)) { ++Count; }
            }
        }
        return Count;
    }

    auto ContextState::ContainsInline(const FieldId Id) const noexcept -> bool
    {
        for (std::size_t Index = 0U; Index < InlineCount_; ++Index)
        {
            if (Inline_[Index].Id == Id) { return true; }
        }
        return false;
    }
}
