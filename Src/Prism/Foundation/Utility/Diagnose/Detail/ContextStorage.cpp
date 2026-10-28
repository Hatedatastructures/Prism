/** @file ContextStorage.cpp @brief 有界诊断上下文存储池实现。 */
#include <Prism/Foundation/Utility/Diagnose/Context/Storage.hpp>
#include <Prism/Foundation/Utility/Text/Redaction.hpp>
#include <Prism/Foundation/Utility/Text/Truncate.hpp>

#include <bit>
#include <utility>

namespace Prism::Diagnose::Detail
{
    constinit ContextPool ProcessContextPool{};

    auto StoreFieldText(const std::string_view Input, const std::span<char> Output,
        const bool Sensitive) noexcept -> std::pair<std::size_t, bool>
    {
        Text::BoundedText Writer(Output);
        if (Sensitive) { Text::AppendRedactedText(Input, Writer); }
        else { Writer.Append(Input); }
        if (!Writer.Truncated()) { return {Writer.Size(), false}; }
        return {Text::FinishTruncatedUtf8(Output), true};
    }

    auto ContextStorage::Rebind() noexcept -> void
    {
        for (std::size_t Index = 0U; Index < Count; ++Index)
        {
            auto& Binding = Overflow[Index];
            if (IsTextFieldKind(Binding.Kind))
            {
                const auto Offset = ContextTextOffsets[static_cast<std::size_t>(Binding.Id)];
                Binding.Payload.Text = {Text.data() + Offset, Binding.Payload.Text.size()};
                Binding.BorrowedText = false;
            }
        }
    }

    auto ContextStorage::Set(FieldBinding Binding) noexcept -> void
    {
        std::size_t Index = 0U;
        while (Index < Count && Overflow[Index].Id != Binding.Id) { ++Index; }
        if (Index == Count) { ++Count; }
        if (IsTextFieldKind(Binding.Kind))
        {
            const auto Descriptor = FieldCatalog::Find(Binding.Id);
            const auto Offset = ContextTextOffsets[static_cast<std::size_t>(Binding.Id)];
            const auto Stored = StoreFieldText(Binding.Payload.Text,
                std::span(Text).subspan(Offset, Descriptor->MaxLength), Descriptor->Sensitive);
            Binding.Payload.Text = {Text.data() + Offset, Stored.first};
            Binding.Truncated = Binding.Truncated || Stored.second;
            Binding.BorrowedText = false;
        }
        Overflow[Index] = Binding;
    }

    auto ContextPool::TryAcquire() noexcept -> Slot*
    {
        const auto Start = Hint_.fetch_add(1U, std::memory_order_relaxed) % WordCount;
        for (std::size_t Offset = 0U; Offset < WordCount; ++Offset)
        {
            const auto WordIndex = (Start + Offset) % WordCount;
            auto Used = Used_[WordIndex].load(std::memory_order_relaxed);
            for (unsigned Attempt = 0U; Attempt < 4U && Used != UINT64_MAX; ++Attempt)
            {
                const auto Bit = std::countr_zero(~Used);
                const auto Mask = std::uint64_t{1U} << Bit;
                if (Used_[WordIndex].compare_exchange_strong(Used, Used | Mask,
                    std::memory_order_acquire, std::memory_order_relaxed))
                {
                    auto* Result = &Slots_[WordIndex * 64U + Bit];
                    Result->References.store(1U, std::memory_order_relaxed);
                    Result->Value = {};
                    return Result;
                }
            }
        }
        return nullptr;
    }

    auto ContextPool::Release(Slot* Value) noexcept -> void
    {
        if (Value && Value->References.fetch_sub(1U, std::memory_order_acq_rel) == 1U)
        {
            const auto Index = static_cast<std::size_t>(Value - Slots_.data());
            Used_[Index / 64U].fetch_and(~(std::uint64_t{1U} << (Index % 64U)),
                std::memory_order_release);
        }
    }

    ContextOwner::ContextOwner(ContextPool::Slot* Slot) noexcept : Slot_(Slot)
    {
    }

    ContextOwner::ContextOwner(const ContextOwner& Other) noexcept : Slot_(Other.Slot_)
    {
        if (Slot_) { Slot_->References.fetch_add(1U, std::memory_order_relaxed); }
    }

    ContextOwner::ContextOwner(ContextOwner&& Other) noexcept : Slot_(std::exchange(Other.Slot_, nullptr))
    {
    }

    auto ContextOwner::operator=(ContextOwner Other) noexcept -> ContextOwner&
    {
        std::swap(Slot_, Other.Slot_);
        return *this;
    }

    ContextOwner::~ContextOwner()
    {
        ContextPool::Get().Release(Slot_);
    }

    auto ContextOwner::Clone() const noexcept -> ContextOwner
    {
        ContextOwner Result(ContextPool::Get().TryAcquire());
        if (Result && Slot_)
        {
            Result.Get() = Slot_->Value;
            Result->Rebind();
        }
        return Result;
    }
}
