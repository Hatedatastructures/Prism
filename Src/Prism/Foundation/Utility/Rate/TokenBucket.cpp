/** @file TokenBucket.cpp
 * @brief 无锁令牌桶补发与消费状态机实现。
 */
#include <Prism/Foundation/Utility/Rate/TokenBucket.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace Prism::Rate
{
    TokenBucket::TokenBucket(const std::size_t Capacity,
        const std::chrono::milliseconds RefillInterval, const std::size_t RefillCount)
        : Capacity_(std::min<std::size_t>(Capacity, KTokensMax))
    {
        if (RefillInterval.count() > 0)
        {
            RefillIntervalMs_ = static_cast<std::uint64_t>(RefillInterval.count());
        }
        else
        {
            RefillIntervalMs_ = 1;
        }
        if (RefillCount > 0)
        {
            RefillCount_ = std::min<std::size_t>(RefillCount, KTokensMax);
        }
        else
        {
            RefillCount_ = 1;
        }
        State_.Initialize(MakeState(static_cast<std::uint64_t>(Capacity_), 0, false));
    }

    auto TokenBucket::TryTake(const std::size_t Count, const std::uint64_t Now) -> bool
    {
        auto Current = State_.Load();
        while (true)
        {
            auto Next = Current;
            bool Changed = false;
            const auto Initialized = IsInitialized(Current);
            const auto CurrentTokens = TokensFrom(Current);
            const auto CurrentLast = LastRefillFrom(Current);

            if (!Initialized)
            {
                // 首次调用只确定时间基准，不追溯构造前的时间。
                Next = MakeState(CurrentTokens, Now, true);
                Changed = true;
            }
            else if (Now > CurrentLast)
            {
                const auto Elapsed = Now - CurrentLast;
                const auto Intervals = Elapsed / RefillIntervalMs_;
                if (Intervals > 0)
                {
                    const auto Add = SaturatingMultiply(Intervals, RefillCount_, KTokensMax);
                    const auto Refilled =
                        SaturatingAdd(CurrentTokens, Add, static_cast<std::uint64_t>(Capacity_));
                    const auto Delta = SaturatingMultiply(Intervals, RefillIntervalMs_,
                        std::numeric_limits<std::uint64_t>::max());
                    Next = MakeState(Refilled,
                        SaturatingAdd(CurrentLast, Delta, std::numeric_limits<std::uint64_t>::max()),
                        true);
                    Changed = true;
                }
            }

            const auto Tokens = TokensFrom(Next);
            if (Tokens >= Count)
            {
                Next = MakeState(Tokens - Count, LastRefillFrom(Next), true);
                Changed = true;
            }
            else if (!Changed)
            {
                return false;
            }

            if (State_.CompareExchange(Current, Next))
            {
                return Tokens >= Count;
            }
        }
    }

    auto TokenBucket::MakeState(const std::uint64_t Tokens, const std::uint64_t LastRefill,
        const bool Initialized) noexcept -> Detail::TokenBucketStateWord
    {
        const auto TokenBits = Detail::TokenBucketStateWord{Tokens & KTokensMax} << KTokenShift;
        return TokenBits | Detail::TokenBucketStateWord{LastRefill} |
            (Initialized ? KInitializedBit : Detail::TokenBucketStateWord{0});
    }

    auto TokenBucket::TokensFrom(const Detail::TokenBucketStateWord State) noexcept -> std::uint64_t
    {
        return static_cast<std::uint64_t>((State >> KTokenShift) & KTokensMask);
    }

    auto TokenBucket::LastRefillFrom(const Detail::TokenBucketStateWord State) noexcept -> std::uint64_t
    {
        return static_cast<std::uint64_t>(State);
    }

    auto TokenBucket::IsInitialized(const Detail::TokenBucketStateWord State) noexcept -> bool
    {
        return (State & KInitializedBit) != 0;
    }

    auto TokenBucket::SaturatingAdd(const std::uint64_t Left, const std::uint64_t Right,
        const std::uint64_t Limit) noexcept -> std::uint64_t
    {
        if (Left >= Limit || Right > Limit - Left)
        {
            return Limit;
        }
        return Left + Right;
    }

    auto TokenBucket::SaturatingMultiply(const std::uint64_t Left, const std::uint64_t Right,
        const std::uint64_t Limit) noexcept -> std::uint64_t
    {
        if (Left == 0 || Right == 0)
        {
            return 0;
        }
        if (Left > Limit / Right)
        {
            return Limit;
        }
        return Left * Right;
    }
}
