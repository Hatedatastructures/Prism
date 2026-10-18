/**
 * @file TokenBucket.hpp
 * @brief 令牌桶限速（T5-4 O4）
 * @details 惰性补发 + 128 位无锁状态 CAS：
 *          - 容量 Capacity，每 RefillInterval 补 RefillCount 个令牌
 *          - TryTake 时按经过时间补发（一次性），再扣减
 *          - 一个 128 位状态同时保存令牌数、初始化标记和完整的绝对补发时刻
 *          - 补发、容量封顶和消费在同一个 CAS 状态转换中提交
 * @note 时间戳由调用方注入（便于测试）；速率字段构造后只读；
 *       要求单调非递减时间轴；时钟回拨保持已认领的绝对补发调度点，
 *       完整 uint64 时间轴不会因相对字段溢出而重复补发；当前实现要求
 *       x86_64 GCC/Clang 的 cmpxchg16b 能力
 */

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

#if !defined(__SIZEOF_INT128__) || !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
#error "Prism::Rate::TokenBucket requires x86_64 GCC/Clang with 128-bit CAS support"
#endif

#if defined(__clang__)
#define PRISM_TOKEN_BUCKET_CX16 [[gnu::target("cx16"), gnu::noinline]]
#else
#define PRISM_TOKEN_BUCKET_CX16 [[gnu::target("cx16")]]
#endif

namespace Prism::Rate
{

    namespace Detail
    {
        using TokenBucketStateWord = unsigned __int128;

        /**
         * @brief 使用 cmpxchg16b 提供不依赖 libatomic 的 128 位状态原子。
         */
        struct alignas(16) TokenBucketAtomicState final
        {
            PRISM_TOKEN_BUCKET_CX16 auto Load() const noexcept -> TokenBucketStateWord
            {
                return __sync_val_compare_and_swap(&Value, TokenBucketStateWord{0}, TokenBucketStateWord{0});
            }

            PRISM_TOKEN_BUCKET_CX16 auto CompareExchange(TokenBucketStateWord& Expected,
                TokenBucketStateWord Desired) noexcept -> bool
            {
                const auto Actual = __sync_val_compare_and_swap(&Value, Expected, Desired);
                if (Actual == Expected)
                {
                    return true;
                }
                Expected = Actual;
                return false;
            }

            void Initialize(TokenBucketStateWord Desired) noexcept
            {
                Value = Desired;
            }

            alignas(16) mutable volatile TokenBucketStateWord Value{0};
        };
    } // namespace Detail

    /**
     * @class TokenBucket
     * @brief 令牌桶
     * @details 无锁 CAS 循环：读完整状态 → 计算补发/扣减 → 单次 CAS 提交；失败后
     *          使用 CAS 返回的最新状态重算。令牌数与补发调度没有中间可见状态。
     *          支持突发（桶满时全部可用）。
     */
    class TokenBucket
    {
    private:
        static constexpr std::uint64_t KTokensMax{0xFFFFFFFFULL}; ///< 令牌上限（2^32-1）
        static constexpr unsigned KTokenShift{64};                ///< 令牌字段位移
        static constexpr unsigned KInitializedShift{96};          ///< 初始化位
        static constexpr Detail::TokenBucketStateWord KInitializedBit = Detail::TokenBucketStateWord{1}
            << KInitializedShift;
        static constexpr Detail::TokenBucketStateWord KTokensMask = Detail::TokenBucketStateWord{KTokensMax};

    public:
        /**
         * @brief 构造
         * @param Capacity 桶容量（最大令牌数，钳制 ≤ 2^32-1）
         * @param RefillInterval 补发间隔
         * @param RefillCount 每间隔补发数
         */
        explicit TokenBucket(std::size_t Capacity, std::chrono::milliseconds RefillInterval,
            std::size_t RefillCount)
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

        /**
         * @brief 尝试取令牌
         * @param n 需求令牌数
         * @param Now 当前时间戳（毫秒，完整 uint64 时间轴）
         * @return 成功返回 true（失败不消耗）
         * @note 要求单调非递减时间轴；时钟回拨保持上一次补发调度点，
         *       补发调度不会因时间字段溢出而重复推进
         */
        [[nodiscard]] auto TryTake(std::size_t Count, std::uint64_t Now) -> bool
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

        /**
         * @brief 当前令牌数（近似）
         */
        [[nodiscard]] auto Available() const -> std::size_t
        {
            return static_cast<std::size_t>(TokensFrom(State_.Load()));
        }

        /**
         * @brief 桶容量
         */
        [[nodiscard]] auto Capacity() const -> std::size_t
        {
            return Capacity_;
        }

    private:
        static auto MakeState(std::uint64_t Tokens, std::uint64_t LastRefill, bool Initialized) noexcept
            -> Detail::TokenBucketStateWord
        {
            const auto TokenBits = Detail::TokenBucketStateWord{Tokens & KTokensMax} << KTokenShift;
            return TokenBits | Detail::TokenBucketStateWord{LastRefill} |
                (Initialized ? KInitializedBit : Detail::TokenBucketStateWord{0});
        }

        static auto TokensFrom(Detail::TokenBucketStateWord State) noexcept -> std::uint64_t
        {
            return static_cast<std::uint64_t>((State >> KTokenShift) & KTokensMask);
        }

        static auto LastRefillFrom(Detail::TokenBucketStateWord State) noexcept -> std::uint64_t
        {
            return static_cast<std::uint64_t>(State);
        }

        static auto IsInitialized(Detail::TokenBucketStateWord State) noexcept -> bool
        {
            return (State & KInitializedBit) != 0;
        }

        static auto SaturatingAdd(std::uint64_t Left, std::uint64_t Right, std::uint64_t Limit) noexcept
            -> std::uint64_t
        {
            if (Left >= Limit || Right > Limit - Left)
            {
                return Limit;
            }
            return Left + Right;
        }

        static auto SaturatingMultiply(std::uint64_t Left, std::uint64_t Right, std::uint64_t Limit) noexcept
            -> std::uint64_t
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

        std::size_t Capacity_;                   ///< 桶容量（钳制 ≤ 2^32-1）
        std::uint64_t RefillIntervalMs_;         ///< 补发间隔（ms）
        std::size_t RefillCount_;                ///< 每间隔补发数
        Detail::TokenBucketAtomicState State_{}; ///< 令牌数/初始化位/补发时刻的原子状态
    };

} // namespace Prism::Rate

#undef PRISM_TOKEN_BUCKET_CX16
