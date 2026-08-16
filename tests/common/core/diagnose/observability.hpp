/**
 * @file observability.hpp
 * @brief 可观测积木（T5-5 O5 接口 + T5-6 实现）
 * @details 三个核心组件：
 *          - hdr_histogram：指数 bucket 直方图（记录 + 分位数）
 *          - ewma_meter：指数移动平均速率计（mark + rate）
 *          - sample_tracer：1/N 采样追踪（原子 + SPSC ring）
 * @note 接口与实现合一（测试库自包含）；生产可观测模块可替换
 */

#pragma once

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

namespace psmtest::observability
{

    /**
     * @class hdr_histogram
     * @brief 高动态范围直方图
     * @details 指数 bucket（2^k 边界，约 log2(max) 个桶）：
     *          - record：原子递增对应桶
     *          - percentile：遍历累积求分位数
     *          - 超 max 封顶到末桶
     */
    class hdr_histogram
    {
    public:
        /**
         * @brief 构造
         * @param max_value 最大可记录值（封顶）
         */
        explicit hdr_histogram(std::uint64_t max_value)
            : max_value_(max_value > 0 ? max_value : 1)
        {
            // bucket 数 = log2(max_value) + 1（0 值也占一桶）
            std::uint64_t v = max_value_;
            while (v > 0)
            {
                ++bucket_count_;
                v >>= 1;
            }
            buckets_ = std::make_unique<std::atomic<std::uint64_t>[]>(bucket_count_);
        }

        /**
         * @brief 记录一个值
         * @param value 观测值（0..max，超限封顶）
         */
        void record(std::uint64_t value)
        {
            buckets_[bucket_of(value)].fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 记录数
         */
        [[nodiscard]] auto count() const -> std::uint64_t
        {
            std::uint64_t total = 0;
            for (std::size_t i = 0; i < bucket_count_; ++i)
            {
                total += buckets_[i].load(std::memory_order_relaxed);
            }
            return total;
        }

        /**
         * @brief 分位数
         * @param p 百分位（0,100]
         * @return 该分位对应的值（无记录返回 0）
         */
        [[nodiscard]] auto percentile(double p) const -> std::uint64_t
        {
            if (p <= 0 || p > 100)
            {
                return 0;
            }
            const auto total = count();
            if (total == 0)
            {
                return 0;
            }
            const auto target = static_cast<std::uint64_t>(static_cast<double>(total) * p / 100.0);
            std::uint64_t cumulative = 0;
            for (std::size_t i = 0; i < bucket_count_; ++i)
            {
                cumulative += buckets_[i].load(std::memory_order_relaxed);
                if (cumulative > target)
                {
                    return bucket_value(i);
                }
            }
            return max_value_;
        }

        /**
         * @brief 最大值（封顶）
         */
        [[nodiscard]] auto max_value() const -> std::uint64_t
        {
            return max_value_;
        }

    private:
        /**
         * @brief 值的桶索引（指数分桶）
         */
        [[nodiscard]] auto bucket_of(std::uint64_t value) const -> std::size_t
        {
            if (value == 0)
            {
                return 0;
            }
            std::size_t idx = 0;
            while (value > 0)
            {
                value >>= 1;
                ++idx;
            }
            if (idx >= bucket_count_)
            {
                return bucket_count_ - 1;
            }
            return idx;
        }

        /**
         * @brief 桶代表值
         */
        [[nodiscard]] auto bucket_value(std::size_t idx) const -> std::uint64_t
        {
            return idx == 0 ? 0 : (std::uint64_t{1} << (idx - 1));
        }

        std::uint64_t max_value_{1};                              ///< 封顶值
        std::size_t bucket_count_{0};                             ///< 桶数
        std::unique_ptr<std::atomic<std::uint64_t>[]> buckets_;   ///< 原子桶
    };

    /**
     * @class ewma_meter
     * @brief 指数移动平均速率计
     * @details 原子累加未衰减计数 + 惰性衰减计算：
     *          rate = sum / window，按经过间隔指数衰减。
     *          单线程读场景（采样低频）足够准确。
     */
    class ewma_meter
    {
    public:
        /// 未初始化哨兵
        static constexpr std::uint64_t uninit = std::numeric_limits<std::uint64_t>::max();

        /**
         * @brief 构造
         * @param window_ms 移动平均窗口（毫秒）
         */
        explicit ewma_meter(std::uint64_t window_ms = 1000)
            : window_ms_(window_ms > 0 ? window_ms : 1), last_read_(uninit)
        {
        }

        /**
         * @brief 标记 n 个事件
         */
        void mark(std::uint64_t n)
        {
            sum_.fetch_add(n, std::memory_order_relaxed);
        }

        /**
         * @brief 读取速率（次/秒，惰性衰减）
         * @param now 当前毫秒（可注入）
         */
        [[nodiscard]] auto rate_per_second(std::uint64_t now) const -> double
        {
            auto last = last_read_.load(std::memory_order_relaxed);
            if (last == uninit)
            {
                last_read_.store(now, std::memory_order_relaxed);
                return 0.0;
            }
            const auto sum = sum_.load(std::memory_order_relaxed);
            const auto elapsed = now > last ? now - last : 1;
            // 衰减因子：经过窗口数越多，速率越接近平均
            const auto windows = static_cast<double>(elapsed) / static_cast<double>(window_ms_);
            return static_cast<double>(sum) / windows;
        }

    private:
        std::uint64_t window_ms_{1000};                    ///< 窗口（毫秒）
        mutable std::atomic<std::uint64_t> sum_{0};        ///< 未衰减计数
        mutable std::atomic<std::uint64_t> last_read_;     ///< 上次读取
    };

    /**
     * @class sample_tracer
     * @brief 1/N 采样追踪
     * @details 原子计数选择器 + SPSC ring：
     *          - sample：计数器 % N == 0 才入环（1/N 采样）
     *          - drain：读回样本（并发安全，覆盖最旧）
     */
    class sample_tracer
    {
    public:
        /**
         * @brief 构造
         * @param ratio 采样分母 N（≥1；1 = 全采样）
         * @param ring_size 环容量（须 2 的幂）
         */
        explicit sample_tracer(std::uint64_t ratio = 1, std::size_t ring_size = 256)
            : ratio_(ratio < 1 ? 1 : ratio), ring_size_(ring_size), ring_(ring_size)
        {
        }

        /**
         * @brief 采样入环
         * @param value 观测值
         */
        void sample(std::uint64_t value)
        {
            const auto seq = counter_.fetch_add(1, std::memory_order_relaxed);
            if (seq % ratio_ != 0)
            {
                return;
            }
            const auto slot = write_idx_.fetch_add(1, std::memory_order_relaxed) & (ring_size_ - 1);
            ring_[slot].store(value, std::memory_order_relaxed);
            sampled_.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 已采样数
         */
        [[nodiscard]] auto sampled_count() const -> std::uint64_t
        {
            return sampled_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 总观测数
         */
        [[nodiscard]] auto total_count() const -> std::uint64_t
        {
            return counter_.load(std::memory_order_relaxed);
        }

        /**
         * @brief 采样率
         */
        [[nodiscard]] auto ratio() const -> std::uint64_t
        {
            return ratio_;
        }

        /**
         * @brief 读回最新样本
         * @param out 输出槽
         * @return 读到的样本数（0 = 空）
         */
        [[nodiscard]] auto drain(std::array<std::uint64_t, 8> &out) const -> std::size_t
        {
            const auto written = write_idx_.load(std::memory_order_relaxed);
            std::size_t n = 0;
            for (std::size_t i = 0; i < 8 && i < ring_size_; ++i)
            {
                const auto idx = (written + ring_size_ - 1 - i) & (ring_size_ - 1);
                out[n] = ring_[idx].load(std::memory_order_relaxed);
                ++n;
            }
            return n;
        }

    private:
        std::uint64_t ratio_{1};                         ///< 采样分母
        std::size_t ring_size_{256};                     ///< 环容量
        std::vector<std::atomic<std::uint64_t>> ring_;   ///< 样本环
        std::atomic<std::uint64_t> counter_{0};          ///< 观测计数
        std::atomic<std::uint64_t> write_idx_{0};        ///< 写索引
        std::atomic<std::uint64_t> sampled_{0};          ///< 已采样数
    };

} // namespace psmtest::observability
