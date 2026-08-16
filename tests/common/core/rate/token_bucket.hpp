/**
 * @file token_bucket.hpp
 * @brief 令牌桶限速（T5-4 O4）
 * @details 惰性补发 + 单 CAS 更新：
 *          - 容量 capacity，每 refill_interval 补 refill_count 个令牌
 *          - try_take 时按经过时间补发（一次性），再扣减
 *          - 状态（令牌数 + 上次补发时刻）用 1 CAS 原子更新
 * @note 时间戳由调用方注入（便于测试）；速率字段构造后只读
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace psmtest::rate
{

    /**
     * @class token_bucket
     * @brief 令牌桶
     * @details 无锁单 CAS：读状态 → 计算补发/扣减 → CAS 提交（失败重试）。
     *          支持突发（桶满时全部可用）。
     */
    class token_bucket
    {
    public:
        /**
         * @brief 构造
         * @param capacity 桶容量（最大令牌数）
         * @param refill_interval 补发间隔
         * @param refill_count 每间隔补发数
         */
        explicit token_bucket(std::size_t capacity, std::chrono::milliseconds refill_interval,
                              std::size_t refill_count)
            : capacity_(capacity), refill_interval_ms_(static_cast<std::uint64_t>(
                                       refill_interval.count() > 0 ? refill_interval.count() : 1)),
              refill_count_(refill_count > 0 ? refill_count : 1)
        {
            tokens_.store(capacity, std::memory_order_relaxed);
        }

        /**
         * @brief 尝试取令牌
         * @param n 需求令牌数
         * @param now 当前时间戳（毫秒）
         * @return 成功返回 true（失败不消耗）
         */
        [[nodiscard]] auto try_take(std::size_t n, std::uint64_t now) -> bool
        {
            auto tokens = tokens_.load(std::memory_order_relaxed);
            auto last = last_refill_.load(std::memory_order_relaxed);
            while (true)
            {
                // 惰性补发：按经过的完整间隔补令牌（last==0 = 创建时刻 0）
                auto next_tokens = tokens;
                auto next_last = last;
                if (now > last)
                {
                    const auto elapsed = now - last;
                    const auto intervals = elapsed / refill_interval_ms_;
                    if (intervals > 0)
                    {
                        const auto add = intervals * refill_count_;
                        next_tokens = tokens + add;
                        if (next_tokens > capacity_)
                        {
                            next_tokens = capacity_;
                        }
                        next_last = last + intervals * refill_interval_ms_;
                    }
                }

                if (next_tokens < n)
                {
                    // 不足：提交补发状态（使下次判断更准确）
                    if (next_tokens != tokens || next_last != last)
                    {
                        tokens_.store(next_tokens, std::memory_order_relaxed);
                        last_refill_.store(next_last, std::memory_order_relaxed);
                    }
                    return false;
                }

                // 提交扣减（单 CAS）
                const auto new_tokens = next_tokens - n;
                if (tokens_.compare_exchange_weak(tokens, new_tokens, std::memory_order_relaxed,
                                                  std::memory_order_relaxed))
                {
                    last_refill_.store(next_last, std::memory_order_relaxed);
                    return true;
                }
                last = last_refill_.load(std::memory_order_relaxed);
            }
        }

        /**
         * @brief 当前令牌数（近似）
         */
        [[nodiscard]] auto available() const -> std::size_t
        {
            return tokens_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 桶容量
         */
        [[nodiscard]] auto capacity() const -> std::size_t
        {
            return capacity_;
        }

    private:
        std::size_t capacity_;                       ///< 桶容量
        std::uint64_t refill_interval_ms_;           ///< 补发间隔（ms）
        std::size_t refill_count_;                   ///< 每间隔补发数
        std::atomic<std::uint64_t> tokens_{0};       ///< 当前令牌数
        std::atomic<std::uint64_t> last_refill_{0};  ///< 上次补发时刻（0 = 未初始化）
    };

} // namespace psmtest::rate
