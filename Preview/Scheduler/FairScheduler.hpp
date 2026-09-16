/**
 * @file FairScheduler.hpp
 * @brief worker-affine account->stream 分层 DRR 调度器
 * @details 账户先按 Weight 获得字节 deficit，账户内部再按 stream quantum
 *          轮转。rate-blocked 请求只保留在槽位表中，不占用 ready 集合。
 */
#pragma once

#include <Preview/Scheduler/Detail/FixedTable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace Preview::Scheduler
{

    class FairScheduler final
    {
    public:
        FairScheduler() noexcept = default;

        explicit FairScheduler(Budget BudgetValue) noexcept : Budget_(BudgetValue) {}

        FairScheduler(const FairScheduler &) = delete;
        auto operator=(const FairScheduler &) -> FairScheduler & = delete;
        FairScheduler(FairScheduler &&) = delete;
        auto operator=(FairScheduler &&) -> FairScheduler & = delete;

        /**
         * @brief 提交或更新一个请求
         * @param RequestValue 请求值
         * @return 接受、更新、阻塞或容量错误
         */
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
         * @brief 取得一个服务 turn
         * @param Now worker 单调时钟值，FairScheduler 保留该参数以统一 worker 合约
         * @return 带 GrantedBytes 的请求结果
         */
        [[nodiscard]] auto Next(std::uint64_t Now = 0) noexcept -> Result
        {
            (void)Now;
            const auto AccountIndex = SelectAccount();
            if (AccountIndex == Detail::NoIndex)
            {
                return MakeEmpty(ResultStatus::Empty);
            }
            const auto EntryIndex = SelectEntry(AccountIndex);
            if (EntryIndex == Detail::NoIndex)
            {
                return MakeEmpty(ResultStatus::Empty);
            }

            auto &AccountValue = Table_.AccountAt(AccountIndex);
            auto &EntryValue = Table_.EntryAt(EntryIndex);
            const auto Previous = AccountValue.Cursor;
            if (Previous != EntryIndex)
            {
                EntryValue.ConsecutiveTurns = 0;
            }
            AddDeficit(AccountValue, EntryValue);
            const auto Grant = CalculateGrant(AccountValue, EntryValue);
            if (Grant == 0)
            {
                return MakeEmpty(ResultStatus::Empty);
            }

            AccountValue.Deficit -= Grant;
            EntryValue.Deficit = Grant >= EntryValue.Deficit ? 0 : EntryValue.Deficit - Grant;

            AccountValue.Cursor = EntryIndex;
            ++AccountValue.ConsecutiveTurns;
            ++EntryValue.ConsecutiveTurns;
            Table_.SetState(EntryIndex, Detail::EntryState::InFlight);
            EntryValue.Value.RateBlocked = false;
            EntryValue.Value.RemainingBytes -= Grant;

            auto ResultValue = MakeResult(EntryValue.Value, ResultStatus::Ready);
            ResultValue.GrantedBytes = Grant;
            ResultValue.RemainingBytes = EntryValue.Value.RemainingBytes;
            return ResultValue;
        }

        /**
         * @brief 回收上一个 turn
         * @param ResultValue worker 实际处理后的结果
         * @return 重新 ready、进入 rate-blocked、完成或取消
         */
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

        /**
         * @brief 取消请求
         * @param RequestIdValue 请求 ID
         * @return 取消成功或未找到
         */
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

        /**
         * @brief 将 rate-blocked 请求重新放回 ready 集合
         * @param RequestIdValue 请求 ID
         * @return 接受、重复解阻塞或未找到
         */
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

        /** @brief 预热边界；固定槽位实现无需在热路径分配。 */
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

        [[nodiscard]] auto MaxTurns(const Request &RequestValue) const noexcept -> std::uint32_t
        {
            return RequestValue.MaxConsecutiveTurns == 0 ? Budget_.MaxConsecutiveTurns
                                                          : RequestValue.MaxConsecutiveTurns;
        }

        [[nodiscard]] auto AccountQuantum(const Request &RequestValue) const noexcept
            -> std::uint64_t
        {
            if (Budget_.AccountQuantumBytes != 0)
            {
                return Budget_.AccountQuantumBytes;
            }
            if (RequestValue.QuantumBytes != 0)
            {
                return RequestValue.QuantumBytes;
            }
            if (Budget_.QuantumBytes != 0)
            {
                return Budget_.QuantumBytes;
            }
            return 1;
        }

        [[nodiscard]] auto StreamQuantum(const Request &RequestValue) const noexcept
            -> std::uint64_t
        {
            if (RequestValue.QuantumBytes != 0)
            {
                return RequestValue.QuantumBytes;
            }
            if (Budget_.QuantumBytes != 0)
            {
                return Budget_.QuantumBytes;
            }
            return 1;
        }

        [[nodiscard]] auto MaxBurst(const Request &RequestValue,
                                    const std::uint64_t Available) const noexcept -> std::uint64_t
        {
            if (RequestValue.MaxBurstBytes != 0 && Budget_.MaxBurstBytes != 0)
            {
                return (std::min)(static_cast<std::uint64_t>(RequestValue.MaxBurstBytes),
                                  static_cast<std::uint64_t>(Budget_.MaxBurstBytes));
            }
            if (RequestValue.MaxBurstBytes != 0)
            {
                return RequestValue.MaxBurstBytes;
            }
            if (Budget_.MaxBurstBytes != 0)
            {
                return Budget_.MaxBurstBytes;
            }
            return Available;
        }

        static auto SaturatingAdd(std::uint64_t Left, std::uint64_t Right) noexcept
            -> std::uint64_t
        {
            if (Right > std::numeric_limits<std::uint64_t>::max() - Left)
            {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return Left + Right;
        }

        static auto SaturatingMultiply(std::uint64_t Left, std::uint64_t Right) noexcept
            -> std::uint64_t
        {
            if (Left != 0 && Right > std::numeric_limits<std::uint64_t>::max() / Left)
            {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return Left * Right;
        }

        auto AddDeficit(Detail::Account &AccountValue, Detail::Entry &EntryValue) const noexcept
            -> void
        {
            const auto AccountWeight = AccountValue.Weight == 0 ? 1U : AccountValue.Weight;
            const auto AccountValueBytes = SaturatingMultiply(
                AccountQuantum(EntryValue.Value), AccountWeight);
            AccountValue.Deficit = SaturatingAdd(AccountValue.Deficit, AccountValueBytes);
            EntryValue.Deficit = SaturatingAdd(EntryValue.Deficit, StreamQuantum(EntryValue.Value));
        }

        [[nodiscard]] auto CalculateGrant(const Detail::Account &AccountValue,
                                          const Detail::Entry &EntryValue) const noexcept
            -> std::uint64_t
        {
            const auto Weight = AccountValue.Weight == 0 ? 1U : AccountValue.Weight;
            const auto WeightedQuantum = SaturatingMultiply(
                AccountQuantum(EntryValue.Value), Weight);
            const auto StreamCredit = (std::max)(EntryValue.Deficit, WeightedQuantum);
            const auto Burst = MaxBurst(EntryValue.Value, StreamCredit);
            return (std::min)({EntryValue.Value.RemainingBytes, AccountValue.Deficit,
                               StreamCredit, Burst});
        }

        [[nodiscard]] auto SelectAccount() noexcept -> std::size_t
        {
            const auto Limit = EffectiveAccountSize();
            for (std::size_t Offset = 0; Offset < Limit; ++Offset)
            {
                const auto Index = (AccountCursor_ + Offset) % Limit;
                const auto &AccountValue = Table_.AccountAt(Index);
                if (AccountValue.Used && AccountValue.ReadyCount != 0)
                {
                    AccountCursor_ = (Index + 1) % Limit;
                    return Index;
                }
            }
            return Detail::NoIndex;
        }

        [[nodiscard]] auto SelectEntry(std::size_t AccountIndex) const noexcept -> std::size_t
        {
            const auto &AccountValue = Table_.AccountAt(AccountIndex);
            const auto Start = AccountValue.Cursor == Detail::NoIndex
                                   ? std::size_t{0}
                                   : (AccountValue.Cursor + 1) % Detail::FixedTable::MaxEntries;
            std::size_t Fallback = Detail::NoIndex;
            for (std::size_t Offset = 0; Offset < Detail::FixedTable::MaxEntries; ++Offset)
            {
                const auto Index = (Start + Offset) % Detail::FixedTable::MaxEntries;
                const auto &EntryValue = Table_.EntryAt(Index);
                if (EntryValue.State != Detail::EntryState::Ready ||
                    EntryValue.AccountIndex != AccountIndex)
                {
                    continue;
                }
                if (Fallback == Detail::NoIndex)
                {
                    Fallback = Index;
                }
                const auto Turns = MaxTurns(EntryValue.Value);
                if (AccountValue.ReadyCount > 1 && Turns != 0 &&
                    EntryValue.ConsecutiveTurns >= Turns)
                {
                    continue;
                }
                return Index;
            }
            return Fallback;
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
