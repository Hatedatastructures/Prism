/** @file SparseCounters.hpp @brief 冷分配、值准入和按真实 scope 退休的唯一计数表。 */
#pragma once
#include <Prism/Statistics/Types.hpp>
#include <Prism/Foundation/Exception/Deviant.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <cstddef>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <vector>

namespace Prism::Statistics
{
    namespace Detail
    {
        /** @brief 只在冷构造抛出的统计容量错误。 */
        class CounterCapacityError final : public Prism::Exception::Deviant
        {
        public:
            CounterCapacityError() : Deviant(Fault::make_error_code(Fault::Code::OversizedMsg), "统计表容量溢出") {}
            [[nodiscard]] auto TypeName() const noexcept -> std::string_view override { return "Statistics"; }
        };
    }
    /** @brief 一个实际 owner 的完整键范围，stream 必须携带父 session。 */
    struct CounterScope final
    {
        Scope ScopeValue;
        NumericId Id;
        Prism::SessionId ParentSession{};
    };
    /** @brief 只由控制 executor 使用；构造拥有节点，更新与退休不分配、不抛。 */
    class SparseCounters final
    {
    public:
        struct Options final { std::size_t MaxEntries{65536}; };
        SparseCounters() : SparseCounters(Options{}) {}
        explicit SparseCounters(Options Value) : MaxEntries_(Value.MaxEntries)
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
        /** @brief 先核对完整键集合的容量，再一次准入；失败不创建部分计数事实。 */
        [[nodiscard]] auto Prepare(std::span<const CounterKey> Keys) noexcept -> bool
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
        /** @brief 已准入键原地累加；数值溢出保持旧值并独立计入 Overflow。 */
        [[nodiscard]] auto Add(CounterKey Key, std::uint64_t Delta) noexcept -> bool
        {
            auto Index = Find(Key);
            if (Index == Capacity_) Index = Insert(Key);
            if (Index == Capacity_) { ++Dropped_; return false; }
            auto& Value = Values_[Index].Value;
            if (Delta > std::numeric_limits<std::uint64_t>::max() - Value)
            { ++Overflow_; return false; }
            Value += Delta;
            return true;
        }
        [[nodiscard]] auto Set(CounterKey Key, std::uint64_t Value) noexcept -> bool
        {
            auto Index = Find(Key);
            if (Index == Capacity_) Index = Insert(Key);
            if (Index == Capacity_) { ++Dropped_; return false; }
            Values_[Index].Value = Value;
            return true;
        }
        [[nodiscard]] auto Get(CounterKey Key) const noexcept -> std::uint64_t
        { const auto Index = Find(Key); if (Index == Capacity_) return 0; return Values_[Index].Value; }
        /** @brief 控制域预查累加容量，保证同一批更新在提交前完整拒绝数值溢出。 */
        [[nodiscard]] auto CanAdd(CounterKey Key, std::uint64_t Delta) const noexcept -> bool
        { return Delta <= std::numeric_limits<std::uint64_t>::max() - Get(Key); }
        /** @brief 控制查询返回拥有值；只在查询边界分配，不保活业务 owner。 */
        [[nodiscard]] auto Snapshot() const -> std::vector<CounterEntry>
        {
            std::vector<CounterEntry> Result;
            Result.reserve(Size_);
            for (std::size_t Index = 0; Index < Capacity_; ++Index)
                if (Values_[Index].State == SlotState::Live)
                    Result.push_back({Values_[Index].Key, Values_[Index].Value});
            return Result;
        }
        /** @brief 实际 scope 退休后归还全部节点；墓碑保持探测链，不新增历史表。 */
        auto Retire(CounterScope Owner) noexcept -> void
        {
            constexpr std::array Metrics{Metric::UpBytes, Metric::DownBytes, Metric::Events, Metric::Errors,
                Metric::Active, Metric::Started, Metric::Completed, Metric::Canceled};
            for (const auto Metric : Metrics)
            {
                const auto Index = Find({Owner.ScopeValue, Owner.Id, Metric, Owner.ParentSession});
                if (Index == Capacity_) continue;
                auto& Value = Values_[Index];
                Value.State = SlotState::Retired;
                Value.Value = 0;
                --Size_;
            }
        }
        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Size_; }
        [[nodiscard]] auto Dropped() const noexcept -> std::uint64_t { return Dropped_; }
        [[nodiscard]] auto Overflow() const noexcept -> std::uint64_t { return Overflow_; }
        auto Clear() noexcept -> void
        {
            for (std::size_t Index = 0; Index < Capacity_; ++Index) Values_[Index] = {};
            Size_ = 0; Dropped_ = 0; Overflow_ = 0;
        }
    private:
        enum class SlotState : std::uint8_t { Empty, Live, Retired };
        struct Entry final { CounterKey Key{}; std::uint64_t Value{0}; SlotState State{SlotState::Empty}; };
        [[nodiscard]] auto Hash(CounterKey Key) const noexcept -> std::size_t
        {
            auto Value = Key.Id ^ (Key.ParentSession.Value() * 0x9e3779b97f4a7c15ULL);
            Value ^= Key.Generation.Value() * 0x94d049bb133111ebULL;
            Value ^= static_cast<std::uint64_t>(Key.ScopeValue) << 48;
            Value ^= static_cast<std::uint64_t>(Key.MetricValue) * 0xbf58476d1ce4e5b9ULL;
            Value ^= Value >> 30; Value *= 0xbf58476d1ce4e5b9ULL;
            Value ^= Value >> 27; Value *= 0x94d049bb133111ebULL;
            Value ^= Value >> 31;
            return static_cast<std::size_t>(Value) & (Capacity_ - 1);
        }
        [[nodiscard]] auto Find(CounterKey Key) const noexcept -> std::size_t
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
        [[nodiscard]] auto Insert(CounterKey Key) noexcept -> std::size_t
        {
            if (Size_ == MaxEntries_) return Capacity_;
            auto Index = Hash(Key);
            for (std::size_t Count = 0; Count < Capacity_; ++Count)
            {
                auto& Value = Values_[Index];
                if (Value.State != SlotState::Live)
                { Value = {Key, 0, SlotState::Live}; ++Size_; return Index; }
                Index = (Index + 1) & (Capacity_ - 1);
            }
            return Capacity_;
        }
        std::size_t MaxEntries_{65536};
        std::size_t Capacity_{1};
        std::size_t Size_{0};
        std::unique_ptr<Entry[]> Values_;
        std::uint64_t Dropped_{0};
        std::uint64_t Overflow_{0};
    };
}
