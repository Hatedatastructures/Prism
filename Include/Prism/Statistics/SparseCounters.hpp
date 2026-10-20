/** @file SparseCounters.hpp @brief 冷分配、值准入和按真实 scope 退休的唯一计数表。 */
#pragma once
#include <Prism/Statistics/Types.hpp>
#include <cstddef>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace Prism::Statistics
{
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
        SparseCounters();
        explicit SparseCounters(Options Value);
        /** @brief 先核对完整键集合的容量，再一次准入；失败不创建部分计数事实。 */
        [[nodiscard]] auto Prepare(std::span<const CounterKey> Keys) noexcept -> bool;
        /** @brief 已准入键原地累加；数值溢出保持旧值并独立计入 Overflow。 */
        [[nodiscard]] auto Add(CounterKey Key, std::uint64_t Delta) noexcept -> bool;
        [[nodiscard]] auto Set(CounterKey Key, std::uint64_t Value) noexcept -> bool;
        [[nodiscard]] auto Get(CounterKey Key) const noexcept -> std::uint64_t;
        /** @brief 控制域预查累加容量，保证同一批更新在提交前完整拒绝数值溢出。 */
        [[nodiscard]] auto CanAdd(CounterKey Key, std::uint64_t Delta) const noexcept -> bool;
        /** @brief 控制查询返回拥有值；只在查询边界分配，不保活业务 owner。 */
        [[nodiscard]] auto Snapshot() const -> std::vector<CounterEntry>;
        /** @brief 实际 scope 退休后归还全部节点；墓碑保持探测链，不新增历史表。 */
        auto Retire(CounterScope Owner) noexcept -> void;
        [[nodiscard]] auto Size() const noexcept -> std::size_t { return Size_; }
        [[nodiscard]] auto Dropped() const noexcept -> std::uint64_t { return Dropped_; }
        [[nodiscard]] auto Overflow() const noexcept -> std::uint64_t { return Overflow_; }
        auto Clear() noexcept -> void;
    private:
        enum class SlotState : std::uint8_t { Empty, Live, Retired };
        struct Entry final { CounterKey Key{}; std::uint64_t Value{0}; SlotState State{SlotState::Empty}; };
        [[nodiscard]] auto Hash(CounterKey Key) const noexcept -> std::size_t;
        [[nodiscard]] auto Find(CounterKey Key) const noexcept -> std::size_t;
        [[nodiscard]] auto Insert(CounterKey Key) noexcept -> std::size_t;
        std::size_t MaxEntries_{65536};
        std::size_t Capacity_{1};
        std::size_t Size_{0};
        std::unique_ptr<Entry[]> Values_;
        std::uint64_t Dropped_{0};
        std::uint64_t Overflow_{0};
    };
}
