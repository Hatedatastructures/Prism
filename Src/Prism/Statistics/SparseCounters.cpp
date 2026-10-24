/** @file SparseCounters.cpp @brief 稀疏计数表容量、探测与退休实现。 */
#include <Prism/Statistics/SparseCounters.hpp>

#include <Prism/Foundation/Exception/Deviant.hpp>
#include <Prism/Foundation/Fault/Code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace Prism::Statistics
{
    namespace Detail
    {
        /** @brief 只在冷构造抛出的统计容量错误。 */
        class CounterCapacityError final : public Prism::Exception::Deviant
        {
        public:
            CounterCapacityError()
                : Deviant(Fault::make_error_code(Fault::Code::OversizedMsg), "统计表容量溢出") {}
            [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
            {
                return "Statistics";
            }
        };
    }

    SparseCounters::SparseCounters() : SparseCounters(Options{}) {}

    SparseCounters::SparseCounters(Options Value) : MaxEntries_(Value.MaxEntries)
    {
        if (MaxEntries_ == 0) MaxEntries_ = 65536;
        if (MaxEntries_ > std::numeric_limits<std::size_t>::max() / 2)
            throw Detail::CounterCapacityError();
        const auto Needed = MaxEntries_ * 2;
        while (Capacity_ < Needed)
        {
            if (Capacity_ > std::numeric_limits<std::size_t>::max() / 2)
                throw Detail::CounterCapacityError();
            Capacity_ *= 2;
        }
        Values_ = std::make_unique<Entry[]>(Capacity_);
    }

    auto SparseCounters::Prepare(std::span<const CounterKey> Keys) noexcept -> bool
    {
        std::size_t Missing = 0;
        for (std::size_t Index = 0; Index < Keys.size(); ++Index)
        {
            if (Find(Keys[Index]) != Capacity_) continue;
            bool Duplicate = false;
            for (std::size_t Previous = 0; Previous < Index; ++Previous)
                if (Keys[Previous] == Keys[Index]) { Duplicate = true; break; }
            if (!Duplicate) ++Missing;
            if (Missing > MaxEntries_ - Size_) { ++Dropped_; return false; }
        }
        for (const auto Key : Keys)
            if (Find(Key) == Capacity_) (void)Insert(Key);
        return true;
    }

    auto SparseCounters::Add(CounterKey Key, std::uint64_t Delta) noexcept -> bool
    {
        auto Index = Find(Key);
        if (Index == Capacity_) Index = Insert(Key);
        if (Index == Capacity_) { ++Dropped_; return false; }
        auto& Value = Values_[Index].Value;
        if (Delta > std::numeric_limits<std::uint64_t>::max() - Value)
        {
            ++Overflow_;
            return false;
        }
        Value += Delta;
        return true;
    }

    auto SparseCounters::Set(CounterKey Key, std::uint64_t Value) noexcept -> bool
    {
        auto Index = Find(Key);
        if (Index == Capacity_) Index = Insert(Key);
        if (Index == Capacity_) { ++Dropped_; return false; }
        Values_[Index].Value = Value;
        return true;
    }

    auto SparseCounters::Get(CounterKey Key) const noexcept -> std::uint64_t
    {
        const auto Index = Find(Key);
        return Index == Capacity_ ? 0 : Values_[Index].Value;
    }

    auto SparseCounters::CanAdd(CounterKey Key, std::uint64_t Delta) const noexcept -> bool
    {
        return Delta <= std::numeric_limits<std::uint64_t>::max() - Get(Key);
    }

    auto SparseCounters::Snapshot() const -> std::vector<CounterEntry>
    {
        std::vector<CounterEntry> Result;
        Result.reserve(Size_);
        for (std::size_t Index = 0; Index < Capacity_; ++Index)
            if (Values_[Index].State == SlotState::Live)
                Result.push_back({Values_[Index].Key, Values_[Index].Value});
        return Result;
    }

    auto SparseCounters::Retire(CounterScope Owner) noexcept -> void
    {
        constexpr std::array Metrics{Metric::UpBytes, Metric::DownBytes, Metric::Events, Metric::Errors,
            Metric::Active, Metric::Started, Metric::Completed, Metric::Canceled};
        for (const auto MetricValue : Metrics)
        {
            const auto Index = Find({Owner.ScopeValue, Owner.Id, MetricValue, Owner.ParentSession});
            if (Index == Capacity_) continue;
            auto& Value = Values_[Index];
            Value.State = SlotState::Retired;
            Value.Value = 0;
            --Size_;
        }
    }

    auto SparseCounters::Clear() noexcept -> void
    {
        for (std::size_t Index = 0; Index < Capacity_; ++Index) Values_[Index] = {};
        Size_ = 0;
        Dropped_ = 0;
        Overflow_ = 0;
    }

    auto SparseCounters::Hash(CounterKey Key) const noexcept -> std::size_t
    {
        auto Value = Key.Id ^ (Key.ParentSession.Value() * 0x9e3779b97f4a7c15ULL);
        Value ^= Key.Generation.Value() * 0x94d049bb133111ebULL;
        Value ^= static_cast<std::uint64_t>(Key.ScopeValue) << 48;
        Value ^= static_cast<std::uint64_t>(Key.MetricValue) * 0xbf58476d1ce4e5b9ULL;
        Value ^= Value >> 30;
        Value *= 0xbf58476d1ce4e5b9ULL;
        Value ^= Value >> 27;
        Value *= 0x94d049bb133111ebULL;
        Value ^= Value >> 31;
        return static_cast<std::size_t>(Value) & (Capacity_ - 1);
    }

    auto SparseCounters::Find(CounterKey Key) const noexcept -> std::size_t
    {
        auto Index = Hash(Key);
        for (std::size_t Count = 0; Count < Capacity_; ++Count)
        {
            const auto& Value = Values_[Index];
            if (Value.State == SlotState::Empty) return Capacity_;
            if (Value.State == SlotState::Live && Value.Key == Key) return Index;
            Index = (Index + 1) & (Capacity_ - 1);
        }
        return Capacity_;
    }

    auto SparseCounters::Insert(CounterKey Key) noexcept -> std::size_t
    {
        if (Size_ == MaxEntries_) return Capacity_;
        auto Index = Hash(Key);
        for (std::size_t Count = 0; Count < Capacity_; ++Count)
        {
            auto& Value = Values_[Index];
            if (Value.State != SlotState::Live)
            {
                Value = {Key, 0, SlotState::Live};
                ++Size_;
                return Index;
            }
            Index = (Index + 1) & (Capacity_ - 1);
        }
        return Capacity_;
    }
}
