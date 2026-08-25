/**
 * @file TokenBucket.hpp
 * @brief 令牌桶限速（T5-4 O4）
 * @details 惰性补发 + 单 CAS 更新：
 *          - 容量 Capacity，每 refill_interval 补 RefillCount 个令牌
 *          - TryTake 时按经过时间补发（一次性），再扣减
 *          - 状态打包为单原子：高 32 位令牌数 + 低 32 位相对补发时刻
 *            （相对 base_ 基准；平台无 128 位 CAS 时的 64 位降级方案）
 * @note 时间戳由调用方注入（便于测试）；速率字段构造后只读；
 *       要求单调非递减时间轴：时钟回拨与相对时刻 32 位字段溢出均已钳制，
 *       不会污染高 32 位令牌字段
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace Preview::Rate
{

    /**
     * @class TokenBucket
     * @brief 令牌桶
     * @details 无锁单 CAS：读状态 → 计算补发/扣减 → 单次 CAS 提交（失败重试）。
     *          tokens 与 last_refill 打包为单原子状态，无中间状态泄漏。
     *          支持突发（桶满时全部可用）。
     */
    class TokenBucket
    {
    public:
        /**
         * @brief 构造
         * @param Capacity 桶容量（最大令牌数，钳制 ≤ 2^32-1）
         * @param refill_interval 补发间隔
         * @param RefillCount 每间隔补发数
         */
        explicit TokenBucket(std::size_t Capacity, std::chrono::milliseconds refill_interval,
                              std::size_t RefillCount)
            : capacity_(std::min<std::size_t>(Capacity, KTokensMax))
        {
            if (refill_interval.count() > 0)
            {
                RefillIntervalMs_ = static_cast<std::uint64_t>(refill_interval.count());
            }
            else
            {
                RefillIntervalMs_ = 1;
            }
            if (RefillCount > 0)
            {
                RefillCount_ = RefillCount;
            }
            else
            {
                RefillCount_ = 1;
            }
            state_.store(static_cast<std::uint64_t>(capacity_) << KTokensShift,
                         std::memory_order_relaxed);
        }

        /**
         * @brief 尝试取令牌
         * @param n 需求令牌数
         * @param now 当前时间戳（毫秒，任意时间轴，首次调用确定为基准）
         * @return 成功返回 true（失败不消耗）
         * @note 要求单调非递减时间轴；时钟回拨钳制为 0，
         *       相对补发时刻 32 位字段溢出封顶，均不污染令牌字段
         */
        [[nodiscard]] auto TryTake(std::size_t n, std::uint64_t now) -> bool
        {
            // 时间基准首次调用确定（strong CAS 竞争安全），此后只读；
            // 存 now+1 以区分“基准为 0”与“未初始化”；相对差值与绝对量级无关
            auto base = base_.load(std::memory_order_relaxed);
            if (base == 0)
            {
                base_.compare_exchange_strong(base, now + 1, std::memory_order_relaxed,
                                              std::memory_order_relaxed);
                base = base_.load(std::memory_order_relaxed);
            }
            const auto RelNow = (now + 1) > base ? (now + 1) - base : 0; // 时钟回拨钳制为 0

            auto State = state_.load(std::memory_order_relaxed);
            while (true)
            {
                const auto tokens = State >> KTokensShift;
                const auto RelLast = State & KRelMask;

                // 惰性补发：按经过的完整间隔补令牌（RelLast==0 = 创建时刻 0）
                auto NextTokens = tokens;
                auto NextRel = RelLast;
                if (RelNow > RelLast)
                {
                    const auto elapsed = RelNow - RelLast;
                    const auto intervals = elapsed / RefillIntervalMs_;
                    if (intervals > 0)
                    {
                        const auto Add = intervals * RefillCount_;
                        NextTokens = tokens + Add;
                        if (NextTokens > capacity_)
                        {
                            NextTokens = capacity_;
                        }
                        const auto delta = intervals * RefillIntervalMs_;
                        NextRel = delta >= KRelMask
                                       ? KRelMask
                                       : (RelLast <= KRelMask - delta ? RelLast + delta
                                                                         : KRelMask);
                        // 相对时刻封顶：禁止溢出污染高 32 位 tokens 字段
                    }
                }

                if (NextTokens < n)
                {
                    // 不足：CAS 原子提交补发状态（防并发覆盖他线程扣减；失败则放弃本次补偿）
                    if (NextTokens != tokens || NextRel != RelLast)
                    {
                        const auto packed = ((NextTokens & KTokensMax) << KTokensShift) |
                                            (NextRel & KRelMask);
                        auto cur = state_.load(std::memory_order_relaxed);
                        static_cast<void>(
                            state_.compare_exchange_strong(cur, packed, std::memory_order_relaxed));
                    }
                    return false;
                }

                // 提交扣减（单 CAS，tokens 与补发时刻一并提交）
                const auto NewState =
                    (((NextTokens - n) & KTokensMax) << KTokensShift) |
                    (NextRel & KRelMask);
                if (state_.compare_exchange_weak(State, NewState, std::memory_order_relaxed,
                                                 std::memory_order_relaxed))
                {
                    return true;
                }
                // CAS 失败：State 已被重载为最新值，重试
            }
        }

        /**
         * @brief 当前令牌数（近似）
         */
        [[nodiscard]] auto Available() const -> std::size_t
        {
            return static_cast<std::size_t>(state_.load(std::memory_order_relaxed) >> KTokensShift);
        }

        /**
         * @brief 桶容量
         */
        [[nodiscard]] auto Capacity() const -> std::size_t
        {
            return capacity_;
        }

    private:
        static constexpr std::uint64_t KTokensShift{32};               ///< 令牌字段位移
        static constexpr std::uint64_t KTokensMax{0xFFFFFFFFULL};      ///< 令牌字段上限（2^32-1）
        static constexpr std::uint64_t KRelMask{0xFFFFFFFFULL};        ///< 相对补发时刻掩码（低 32 位）

        std::size_t capacity_;                      ///< 桶容量（钳制 ≤ 2^32-1）
        std::uint64_t RefillIntervalMs_;          ///< 补发间隔（ms）
        std::size_t RefillCount_;                  ///< 每间隔补发数
        std::atomic<std::uint64_t> state_{0};       ///< 单原子状态：高 32 位令牌数 \| 低 32 位相对补发时刻
        std::atomic<std::uint64_t> base_{0};        ///< 时间基准（0 = 未初始化；存 now+1，首次 TryTake 确定）
    };

} // namespace Preview::Rate
