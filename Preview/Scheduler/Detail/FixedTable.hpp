/**
 * @file FixedTable.hpp
 * @brief Scheduler 的固定容量账户/请求存储
 * @details 表内所有槽位在对象构造时即存在。ready、in-flight 和 rate-blocked
 *          是互斥状态；因此同一个请求不会同时出现在两个可调度集合中。
 */
#pragma once

#include <Preview/Scheduler/Types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace Preview::Scheduler::Detail
{

    inline constexpr std::size_t NoIndex{static_cast<std::size_t>(-1)};

    enum class EntryState : std::uint8_t
    {
        Free,
        Ready,
        InFlight,
        RateBlocked,
    };

    struct Entry final
    {
        Request Value{};
        EntryState State{EntryState::Free};
        std::size_t AccountIndex{NoIndex};
        std::size_t NextInAccount{NoIndex};
        std::uint64_t Deficit{0};
        std::uint32_t ConsecutiveTurns{0};
    };

    struct Account final
    {
        Preview::AccountId AccountId{};
        bool Used{false};
        std::size_t Head{NoIndex};
        std::size_t Tail{NoIndex};
        std::size_t Cursor{NoIndex};
        std::size_t ActiveCount{0};
        std::size_t ReadyCount{0};
        std::uint32_t Weight{1};
        std::uint64_t Deficit{0};
        std::uint32_t ConsecutiveTurns{0};
    };

    class FixedTable final
    {
    public:
        static constexpr std::size_t MaxEntries{1024};
        static constexpr std::size_t MaxAccounts{128};

        FixedTable() noexcept = default;

        FixedTable(const FixedTable &) = delete;
        auto operator=(const FixedTable &) -> FixedTable & = delete;
        FixedTable(FixedTable &&) = delete;
        auto operator=(FixedTable &&) -> FixedTable & = delete;

        [[nodiscard]] auto Find(Preview::RequestId RequestIdValue) const noexcept -> std::size_t
        {
            for (std::size_t Index = 0; Index < Entries_.size(); ++Index)
            {
                if (Entries_[Index].State != EntryState::Free &&
                    Entries_[Index].Value.RequestId == RequestIdValue)
                {
                    return Index;
                }
            }
            return NoIndex;
        }

        [[nodiscard]] auto FindAccount(Preview::AccountId AccountIdValue) const noexcept
            -> std::size_t
        {
            for (std::size_t Index = 0; Index < Accounts_.size(); ++Index)
            {
                if (Accounts_[Index].Used && Accounts_[Index].AccountId == AccountIdValue)
                {
                    return Index;
                }
            }
            return NoIndex;
        }

        [[nodiscard]] auto FindFreeEntry() const noexcept -> std::size_t
        {
            for (std::size_t Index = 0; Index < Entries_.size(); ++Index)
            {
                if (Entries_[Index].State == EntryState::Free)
                {
                    return Index;
                }
            }
            return NoIndex;
        }

        [[nodiscard]] auto FindFreeAccount() const noexcept -> std::size_t
        {
            for (std::size_t Index = 0; Index < Accounts_.size(); ++Index)
            {
                if (!Accounts_[Index].Used)
                {
                    return Index;
                }
            }
            return NoIndex;
        }

        auto CreateAccount(Preview::AccountId AccountIdValue, std::uint32_t WeightValue) noexcept
            -> std::size_t
        {
            const auto Index = FindFreeAccount();
            if (Index == NoIndex)
            {
                return NoIndex;
            }
            auto &AccountValue = Accounts_[Index];
            AccountValue = Account{};
            AccountValue.AccountId = AccountIdValue;
            AccountValue.Used = true;
            AccountValue.Weight = WeightValue == 0 ? 1U : WeightValue;
            ++AccountCount_;
            return Index;
        }

        auto Add(Request RequestValue, std::size_t AccountIndex) noexcept -> std::size_t
        {
            const auto Index = FindFreeEntry();
            if (Index == NoIndex || AccountIndex >= Accounts_.size() ||
                !Accounts_[AccountIndex].Used)
            {
                return NoIndex;
            }

            auto &EntryValue = Entries_[Index];
            EntryValue = Entry{};
            EntryValue.Value = RequestValue;
            EntryValue.AccountIndex = AccountIndex;
            EntryValue.State = RequestValue.RateBlocked ? EntryState::RateBlocked
                                                         : EntryState::Ready;
            auto &AccountValue = Accounts_[AccountIndex];
            if (AccountValue.Tail == NoIndex)
            {
                AccountValue.Head = Index;
            }
            else
            {
                Entries_[AccountValue.Tail].NextInAccount = Index;
            }
            AccountValue.Tail = Index;
            ++AccountValue.ActiveCount;
            if (EntryValue.State == EntryState::Ready)
            {
                ++AccountValue.ReadyCount;
                ++ReadyCount_;
            }
            else
            {
                ++BlockedCount_;
            }
            ++EntryCount_;
            return Index;
        }

        auto SetState(std::size_t EntryIndex, EntryState StateValue) noexcept -> void
        {
            if (EntryIndex >= Entries_.size())
            {
                return;
            }
            auto &EntryValue = Entries_[EntryIndex];
            if (EntryValue.State == EntryState::Free || EntryValue.State == StateValue)
            {
                return;
            }
            auto &AccountValue = Accounts_[EntryValue.AccountIndex];
            RemoveStateCount(EntryValue.State, AccountValue);
            EntryValue.State = StateValue;
            AddStateCount(StateValue, AccountValue);
        }

        auto Remove(std::size_t EntryIndex) noexcept -> void
        {
            if (EntryIndex >= Entries_.size())
            {
                return;
            }
            auto &EntryValue = Entries_[EntryIndex];
            if (EntryValue.State == EntryState::Free)
            {
                return;
            }

            const auto AccountIndex = EntryValue.AccountIndex;
            auto &AccountValue = Accounts_[AccountIndex];
            RemoveStateCount(EntryValue.State, AccountValue);
            std::size_t Previous = NoIndex;
            auto Current = AccountValue.Head;
            while (Current != NoIndex)
            {
                if (Current == EntryIndex)
                {
                    if (Previous == NoIndex)
                    {
                        AccountValue.Head = Entries_[Current].NextInAccount;
                    }
                    else
                    {
                        Entries_[Previous].NextInAccount = Entries_[Current].NextInAccount;
                    }
                    if (AccountValue.Tail == Current)
                    {
                        AccountValue.Tail = Previous;
                    }
                    break;
                }
                Previous = Current;
                Current = Entries_[Current].NextInAccount;
            }
            if (AccountValue.Cursor == EntryIndex)
            {
                AccountValue.Cursor = Previous;
            }
            if (AccountValue.ActiveCount > 0)
            {
                --AccountValue.ActiveCount;
            }
            if (EntryCount_ > 0)
            {
                --EntryCount_;
            }
            EntryValue = Entry{};
            if (AccountValue.ActiveCount == 0)
            {
                AccountValue = Account{};
                if (AccountCount_ > 0)
                {
                    --AccountCount_;
                }
            }
        }

        [[nodiscard]] auto EntryAt(std::size_t EntryIndex) noexcept -> Entry &
        {
            return Entries_[EntryIndex];
        }

        [[nodiscard]] auto EntryAt(std::size_t EntryIndex) const noexcept -> const Entry &
        {
            return Entries_[EntryIndex];
        }

        [[nodiscard]] auto AccountAt(std::size_t AccountIndex) noexcept -> Account &
        {
            return Accounts_[AccountIndex];
        }

        [[nodiscard]] auto AccountAt(std::size_t AccountIndex) const noexcept -> const Account &
        {
            return Accounts_[AccountIndex];
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return EntryCount_;
        }

        [[nodiscard]] auto AccountCount() const noexcept -> std::size_t
        {
            return AccountCount_;
        }

        [[nodiscard]] auto ReadyCount() const noexcept -> std::size_t
        {
            return ReadyCount_;
        }

        [[nodiscard]] auto BlockedCount() const noexcept -> std::size_t
        {
            return BlockedCount_;
        }

    private:
        auto RemoveStateCount(EntryState StateValue, Account &AccountValue) noexcept -> void
        {
            if (StateValue == EntryState::Ready)
            {
                if (ReadyCount_ > 0)
                {
                    --ReadyCount_;
                }
            }
            else if (StateValue == EntryState::RateBlocked)
            {
                if (BlockedCount_ > 0)
                {
                    --BlockedCount_;
                }
            }
            if (StateValue == EntryState::Ready && AccountValue.ReadyCount > 0)
            {
                --AccountValue.ReadyCount;
            }
        }

        auto AddStateCount(EntryState StateValue, Account &AccountValue) noexcept -> void
        {
            if (StateValue == EntryState::Ready)
            {
                ++ReadyCount_;
                ++AccountValue.ReadyCount;
            }
            else if (StateValue == EntryState::RateBlocked)
            {
                ++BlockedCount_;
            }
        }

        std::array<Entry, MaxEntries> Entries_{};
        std::array<Account, MaxAccounts> Accounts_{};
        std::size_t EntryCount_{0};
        std::size_t AccountCount_{0};
        std::size_t ReadyCount_{0};
        std::size_t BlockedCount_{0};
    };

} // namespace Preview::Scheduler::Detail
