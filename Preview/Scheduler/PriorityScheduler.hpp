/**
 * @file PriorityScheduler.hpp
 * @brief worker-affine四档优先级调度器
 * @details 优先级比较使用有效带：等待时间逐档提升，超过 starvation deadline
 *          的请求进入 Control；同一有效带内仍以账户轮转保证服务公平。
 */
#pragma once

#include <Preview/Scheduler/Detail/FixedTable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace Preview::Scheduler
{

    class PriorityScheduler final
    {
    public:
        PriorityScheduler() noexcept = default;

        explicit PriorityScheduler(Budget BudgetValue) noexcept : Budget_(BudgetValue) {}

        PriorityScheduler(const PriorityScheduler &) = delete;
        auto operator=(const PriorityScheduler &) -> PriorityScheduler & = delete;
        PriorityScheduler(PriorityScheduler &&) = delete;
        auto operator=(PriorityScheduler &&) -> PriorityScheduler & = delete;

        /** @brief 提交或更新请求。 */
        [[nodiscard]] auto Submit(Request RequestValue) noexcept -> Result
        {
            if (RequestValue.Cancelled)
            {
                return MakeResult(RequestValue, ResultStatus::Cancelled);
            }
            if (!PrepareRequest(RequestValue))
            {
                return MakeResult(RequestValue, ResultStatus::InvalidRequest);
            }
            if (!WorkerMatches(RequestValue))
            {
                return MakeResult(RequestValue, ResultStatus::WorkerMismatch);
            }

            const auto Existing = Table_.Find(RequestValue.RequestId);
            if (Existing != Detail::NoIndex)
            {
                return UpdateExisting(RequestValue, Existing);
            }
            if (Table_.Size() >= EffectiveQueueSize())
            {
                return MakeResult(RequestValue, ResultStatus::QueueFull);
            }

            auto AccountIndex = Table_.FindAccount(RequestValue.AccountId);
            if (AccountIndex == Detail::NoIndex)
            {
                if (Table_.AccountCount() >= EffectiveAccountSize())
                {
                    return MakeResult(RequestValue, ResultStatus::QueueFull);
                }
                AccountIndex = Table_.CreateAccount(RequestValue.AccountId, RequestValue.Weight);
            }
            else if (Table_.AccountAt(AccountIndex).ActiveCount >= EffectiveStreamSize())
            {
                return MakeResult(RequestValue, ResultStatus::QueueFull);
            }
            if (AccountIndex == Detail::NoIndex)
            {
                return MakeResult(RequestValue, ResultStatus::QueueFull);
            }

            Table_.AccountAt(AccountIndex).Weight =
                (std::max)(Table_.AccountAt(AccountIndex).Weight, RequestValue.Weight);

            const auto EntryIndex = Table_.Add(RequestValue, AccountIndex);
            if (EntryIndex == Detail::NoIndex)
            {
                return MakeResult(RequestValue, ResultStatus::QueueFull);
            }
            return MakeResult(RequestValue, RequestValue.RateBlocked ? ResultStatus::RateBlocked
                                                                       : ResultStatus::Accepted);
        }

        /**
         * @brief 选择最高有效服务带中的一个账户流
         * @param Now worker 单调时钟值
         * @return 带最小服务量的请求结果
         */
        [[nodiscard]] auto Next(std::uint64_t Now = 0) noexcept -> Result
        {
            const auto Best = SelectBestBand(Now);
            if (Best == PriorityBand::Background && !HasReadyInBand(Best, Now))
            {
                return MakeEmpty(ResultStatus::Empty);
            }
            const auto AccountIndex = SelectAccount(Best, Now);
            if (AccountIndex == Detail::NoIndex)
            {
                return MakeEmpty(ResultStatus::Empty);
            }
            const auto EntryIndex = SelectEntry(EntrySelection{AccountIndex, Best, Now});
            if (EntryIndex == Detail::NoIndex)
            {
                return MakeEmpty(ResultStatus::Empty);
            }

            auto &EntryValue = Table_.EntryAt(EntryIndex);
            const auto Grant = CalculateGrant(EntryValue.Value);
            if (Grant == 0)
            {
                return MakeEmpty(ResultStatus::Empty);
            }
            Table_.AccountAt(AccountIndex).Cursor = EntryIndex;
            Table_.SetState(EntryIndex, Detail::EntryState::InFlight);
            EntryValue.Value.RateBlocked = false;
            EntryValue.Value.RemainingBytes -= Grant;

            auto ResultValue = MakeResult(EntryValue.Value, ResultStatus::Ready);
            ResultValue.GrantedBytes = Grant;
            ResultValue.RemainingBytes = EntryValue.Value.RemainingBytes;
            return ResultValue;
        }

        /** @brief 回收上一个 turn。 */
        [[nodiscard]] auto Requeue(Result ResultValue) noexcept -> Result
        {
            const auto EntryIndex = Table_.Find(ResultValue.RequestId);
            if (EntryIndex == Detail::NoIndex)
            {
                return MakeResult(ResultValue, ResultStatus::NotFound);
            }
            auto &EntryValue = Table_.EntryAt(EntryIndex);
            if (EntryValue.State != Detail::EntryState::InFlight)
            {
                return MakeResult(EntryValue.Value, ResultStatus::Duplicate);
            }
            if (ResultValue.Cancelled)
            {
                const auto RequestValue = EntryValue.Value;
                Table_.Remove(EntryIndex);
                return MakeResult(RequestValue, ResultStatus::Cancelled);
            }
            if (ResultValue.RateBlocked)
            {
                if (ResultValue.RemainingBytes != 0)
                {
                    EntryValue.Value.RemainingBytes = ResultValue.RemainingBytes;
                }
                EntryValue.Value.RateBlocked = true;
                Table_.SetState(EntryIndex, Detail::EntryState::RateBlocked);
                return MakeResult(EntryValue.Value, ResultStatus::RateBlocked);
            }

            EntryValue.Value.RemainingBytes = ResultValue.RemainingBytes;
            EntryValue.Value.RateBlocked = false;
            if (EntryValue.Value.RemainingBytes == 0)
            {
                const auto RequestValue = EntryValue.Value;
                Table_.Remove(EntryIndex);
                return MakeResult(RequestValue, ResultStatus::Completed);
            }
            Table_.SetState(EntryIndex, Detail::EntryState::Ready);
            return MakeResult(EntryValue.Value, ResultStatus::Accepted);
        }

        /** @brief Submit 的语义别名，供队列型调用方使用。 */
        [[nodiscard]] auto Enqueue(Request RequestValue) noexcept -> Result
        {
            return Submit(RequestValue);
        }

        /** @brief Next 的语义别名。 */
        [[nodiscard]] auto Dequeue(std::uint64_t Now = 0) noexcept -> Result
        {
            return Next(Now);
        }

        /** @brief Requeue 的语义别名。 */
        [[nodiscard]] auto Complete(Result ResultValue) noexcept -> Result
        {
            return Requeue(ResultValue);
        }

        /** @brief 取消一个请求。 */
        [[nodiscard]] auto Cancel(Preview::RequestId RequestIdValue) noexcept -> Result
        {
            const auto EntryIndex = Table_.Find(RequestIdValue);
            if (EntryIndex == Detail::NoIndex)
            {
                return MakeEmpty(ResultStatus::NotFound);
            }
            const auto RequestValue = Table_.EntryAt(EntryIndex).Value;
            Table_.Remove(EntryIndex);
            return MakeResult(RequestValue, ResultStatus::Cancelled);
        }

        /** @brief 解开 rate-blocked 状态，且不会插入重复 ready 节点。 */
        [[nodiscard]] auto Unblock(Preview::RequestId RequestIdValue) noexcept -> Result
        {
            const auto EntryIndex = Table_.Find(RequestIdValue);
            if (EntryIndex == Detail::NoIndex)
            {
                return MakeEmpty(ResultStatus::NotFound);
            }
            auto &EntryValue = Table_.EntryAt(EntryIndex);
            if (EntryValue.State == Detail::EntryState::Ready)
            {
                return MakeResult(EntryValue.Value, ResultStatus::Updated);
            }
            if (EntryValue.State != Detail::EntryState::RateBlocked)
            {
                return MakeResult(EntryValue.Value, ResultStatus::Duplicate);
            }
            EntryValue.Value.RateBlocked = false;
            Table_.SetState(EntryIndex, Detail::EntryState::Ready);
            return MakeResult(EntryValue.Value, ResultStatus::Accepted);
        }

        /** @brief 固定槽位 scheduler 的预热边界。 */
        auto Warmup() noexcept -> void {}

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Table_.Size();
        }

        [[nodiscard]] auto ReadyCount() const noexcept -> std::size_t
        {
            return Table_.ReadyCount();
        }

        [[nodiscard]] auto BlockedCount() const noexcept -> std::size_t
        {
            return Table_.BlockedCount();
        }

        [[nodiscard]] auto Capacity() const noexcept -> std::size_t
        {
            return EffectiveQueueSize();
        }

    private:
        struct EntrySelection final
        {
            std::size_t AccountIndex{Detail::NoIndex};
            PriorityBand Band{PriorityBand::Background};
            std::uint64_t Now{0};
        };

        static auto PrepareRequest(Request &RequestValue) noexcept -> bool
        {
            if (RequestValue.RemainingBytes == 0)
            {
                RequestValue.RemainingBytes = RequestValue.Bytes;
            }
            if (RequestValue.Bytes == 0)
            {
                RequestValue.Bytes = RequestValue.RemainingBytes;
            }
            return static_cast<bool>(RequestValue.RequestId) &&
                   static_cast<bool>(RequestValue.AccountId) &&
                   static_cast<bool>(RequestValue.StreamId) && RequestValue.RemainingBytes != 0;
        }

        [[nodiscard]] auto WorkerMatches(const Request &RequestValue) const noexcept -> bool
        {
            return !Budget_.WorkerId || Budget_.WorkerId == RequestValue.WorkerId;
        }

        [[nodiscard]] auto EffectiveQueueSize() const noexcept -> std::size_t
        {
            return std::clamp(Budget_.MaxQueueSize, std::size_t{1}, Detail::FixedTable::MaxEntries);
        }

        [[nodiscard]] auto EffectiveAccountSize() const noexcept -> std::size_t
        {
            return std::clamp(Budget_.MaxAccounts, std::size_t{1}, Detail::FixedTable::MaxAccounts);
        }

        [[nodiscard]] auto EffectiveStreamSize() const noexcept -> std::size_t
        {
            return std::clamp(Budget_.MaxStreamsPerAccount, std::size_t{1},
                              Detail::FixedTable::MaxEntries);
        }

        [[nodiscard]] auto EffectiveBand(const Request &RequestValue,
                                         std::uint64_t Now) const noexcept -> PriorityBand
        {
            if (RequestValue.StarvationDeadline != 0 &&
                Now >= RequestValue.StarvationDeadline)
            {
                return PriorityBand::Control;
            }
            const auto Age = Now > RequestValue.EnqueuedAt ? Now - RequestValue.EnqueuedAt : 0;
            if (Budget_.StarvationDeadline != 0 && Age >= Budget_.StarvationDeadline)
            {
                return PriorityBand::Control;
            }
            if (Budget_.AgingInterval == 0)
            {
                return RequestValue.Priority;
            }
            const auto Promotions = Age / Budget_.AgingInterval;
            const auto Current = static_cast<std::uint8_t>(RequestValue.Priority);
            const auto Shift = static_cast<std::uint8_t>((std::min)(
                Promotions, static_cast<std::uint64_t>(Current)));
            return static_cast<PriorityBand>(Current - Shift);
        }

        [[nodiscard]] auto HasReadyInBand(PriorityBand BandValue, std::uint64_t Now) const noexcept
            -> bool
        {
            for (std::size_t Index = 0; Index < Detail::FixedTable::MaxEntries; ++Index)
            {
                const auto &EntryValue = Table_.EntryAt(Index);
                if (EntryValue.State == Detail::EntryState::Ready &&
                    EffectiveBand(EntryValue.Value, Now) == BandValue)
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] auto SelectBestBand(std::uint64_t Now) const noexcept -> PriorityBand
        {
            auto Best = PriorityBand::Background;
            for (std::size_t Index = 0; Index < Detail::FixedTable::MaxEntries; ++Index)
            {
                const auto &EntryValue = Table_.EntryAt(Index);
                if (EntryValue.State != Detail::EntryState::Ready)
                {
                    continue;
                }
                const auto Candidate = EffectiveBand(EntryValue.Value, Now);
                if (static_cast<std::uint8_t>(Candidate) < static_cast<std::uint8_t>(Best))
                {
                    Best = Candidate;
                }
            }
            return Best;
        }

        [[nodiscard]] auto SelectAccount(PriorityBand BandValue,
                                         std::uint64_t Now) noexcept -> std::size_t
        {
            const auto Limit = EffectiveAccountSize();
            for (std::size_t Offset = 0; Offset < Limit; ++Offset)
            {
                const auto Index = (AccountCursor_ + Offset) % Limit;
                const auto &AccountValue = Table_.AccountAt(Index);
                if (!AccountValue.Used || AccountValue.ReadyCount == 0)
                {
                    continue;
                }
                if (SelectEntry(EntrySelection{Index, BandValue, Now}) != Detail::NoIndex)
                {
                    AccountCursor_ = (Index + 1) % Limit;
                    return Index;
                }
            }
            return Detail::NoIndex;
        }

        [[nodiscard]] auto SelectEntry(EntrySelection SelectionValue) const noexcept
            -> std::size_t
        {
            const auto &AccountValue = Table_.AccountAt(SelectionValue.AccountIndex);
            const auto Start = AccountValue.Cursor == Detail::NoIndex
                                   ? std::size_t{0}
                                   : (AccountValue.Cursor + 1) % Detail::FixedTable::MaxEntries;
            for (std::size_t Offset = 0; Offset < Detail::FixedTable::MaxEntries; ++Offset)
            {
                const auto Index = (Start + Offset) % Detail::FixedTable::MaxEntries;
                const auto &EntryValue = Table_.EntryAt(Index);
                if (EntryValue.State == Detail::EntryState::Ready &&
                    EntryValue.AccountIndex == SelectionValue.AccountIndex &&
                    EffectiveBand(EntryValue.Value, SelectionValue.Now) == SelectionValue.Band)
                {
                    return Index;
                }
            }
            return Detail::NoIndex;
        }

        [[nodiscard]] auto CalculateGrant(const Request &RequestValue) const noexcept
            -> std::uint64_t
        {
            std::uint64_t Burst = RequestValue.MaxBurstBytes;
            if (Burst != 0 && Budget_.MaxBurstBytes != 0)
            {
                Burst = (std::min)(Burst, static_cast<std::uint64_t>(Budget_.MaxBurstBytes));
            }
            if (Burst == 0)
            {
                Burst = Budget_.MaxBurstBytes;
            }
            if (Burst == 0)
            {
                Burst = RequestValue.QuantumBytes;
            }
            if (Burst == 0)
            {
                Burst = Budget_.QuantumBytes;
            }
            if (Burst == 0)
            {
                Burst = RequestValue.RemainingBytes;
            }
            const auto Minimum = static_cast<std::uint64_t>(Budget_.MinimumServiceBytes);
            Burst = (std::max)(Burst, Minimum);
            return (std::min)(RequestValue.RemainingBytes, Burst);
        }

        [[nodiscard]] auto UpdateExisting(Request RequestValue, std::size_t EntryIndex) noexcept
            -> Result
        {
            auto &EntryValue = Table_.EntryAt(EntryIndex);
            if (EntryValue.State == Detail::EntryState::InFlight)
            {
                return MakeResult(EntryValue.Value, ResultStatus::Duplicate);
            }
            EntryValue.Value = RequestValue;
            auto &AccountValue = Table_.AccountAt(EntryValue.AccountIndex);
            AccountValue.Weight = (std::max)(AccountValue.Weight, RequestValue.Weight);
            Table_.SetState(EntryIndex, RequestValue.RateBlocked ? Detail::EntryState::RateBlocked
                                                                  : Detail::EntryState::Ready);
            return MakeResult(RequestValue, RequestValue.RateBlocked ? ResultStatus::RateBlocked
                                                                       : ResultStatus::Updated);
        }

        static auto MakeEmpty(ResultStatus StatusValue) noexcept -> Result
        {
            Result ResultValue;
            ResultValue.Status = StatusValue;
            return ResultValue;
        }

        static auto MakeResult(const Request &RequestValue, ResultStatus StatusValue) noexcept
            -> Result
        {
            Result ResultValue;
            ResultValue.Status = StatusValue;
            ResultValue.RequestId = RequestValue.RequestId;
            ResultValue.AccountId = RequestValue.AccountId;
            ResultValue.StreamId = RequestValue.StreamId;
            ResultValue.WorkerId = RequestValue.WorkerId;
            ResultValue.Priority = RequestValue.Priority;
            ResultValue.RemainingBytes = RequestValue.RemainingBytes;
            ResultValue.RateBlocked = RequestValue.RateBlocked;
            ResultValue.Cancelled = RequestValue.Cancelled;
            return ResultValue;
        }

        static auto MakeResult(const Result &ResultValue, ResultStatus StatusValue) noexcept
            -> Result
        {
            auto FinalValue = ResultValue;
            FinalValue.Status = StatusValue;
            return FinalValue;
        }

        Budget Budget_{};
        Detail::FixedTable Table_{};
        std::size_t AccountCursor_{0};
    };

} // namespace Preview::Scheduler
