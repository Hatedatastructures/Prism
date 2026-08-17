/**
 * @file throttle.hpp
 * @brief 限速与封禁中间件（T5-4 O4）
 * @details - throttle_middleware：令牌桶限速（取不到令牌 → blocked）
 *          - ban_middleware：失败计数超阈值 → 动态封禁（窗口过期自动解封）
 * @note 对应生产 throttle_middleware / ban_middleware
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/rate/token_bucket.hpp>

namespace preview::middleware::builtin
{

    namespace net = boost::asio;

    /**
     * @class throttle_middleware
     * @brief 限速中间件
     * @details 每连接消耗 1 令牌；不足 → blocked（管线终止）。
     *          令牌桶由调用方持有（跨连接共享）。
     */
    class throttle_middleware final : public middleware
    {
    public:
        /**
         * @brief 构造
         * @param bucket 令牌桶（调用方持有）
         * @param now_fn 时钟函数（毫秒；nullptr = 用 steady_clock）
         */
        explicit throttle_middleware(preview::rate::token_bucket *bucket,
                                     std::uint64_t (*now_fn)() = nullptr)
            : bucket_(bucket), now_fn_(now_fn)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "throttle";
        }

        /**
         * @brief 限速检查
         * @return success / blocked / not_supported
         */
        auto handle(preview::shared_transmission & /*inbound*/, context & /*ctx*/)
            -> net::awaitable<preview::fault::code> override
        {
            if (!bucket_)
            {
                co_return preview::fault::code::not_supported;
            }
            std::uint64_t now = 0;
            if (now_fn_)
            {
                now = now_fn_();
            }
            else
            {
                now = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
            }
            if (!bucket_->try_take(1, now))
            {
                co_return preview::fault::code::blocked;
            }
            co_return preview::fault::code::success;
        }

    private:
        preview::rate::token_bucket *bucket_; ///< 令牌桶（非拥有）
        std::uint64_t (*now_fn_)();           ///< 时钟函数
    };

    /**
     * @class ban_middleware
     * @brief 封禁中间件
     * @details 按键记录失败计数；窗口内超阈值 → 封禁（窗口过期解封）。
     *          封禁判定在 handle 前置：被封禁 → blocked。
     */
    class ban_middleware final : public middleware
    {
    public:
        /**
         * @brief 构造
         * @param max_failures 窗口内失败阈值
         * @param window 窗口时长（毫秒）
         * @param now_fn 时钟函数（毫秒）
         */
        explicit ban_middleware(std::size_t max_failures, std::uint64_t window_ms,
                                std::uint64_t (*now_fn)())
            : max_failures_(max_failures), window_ms_(window_ms), now_fn_(now_fn)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "ban";
        }

        /**
         * @brief 封禁判定（按 ctx 远端键）
         * @return success / blocked
         */
        auto handle(preview::shared_transmission & /*inbound*/, context &ctx)
            -> net::awaitable<preview::fault::code> override
        {
            std::string key = "unknown";
            if (!ctx.raw_identity.empty())
            {
                key = ctx.raw_identity;
            }
            if (is_banned(key))
            {
                co_return preview::fault::code::blocked;
            }
            co_return preview::fault::code::success;
        }

        /**
         * @brief 记录失败（超阈值触发封禁）
         * @param key 键（如远端地址）
         */
        void record_failure(std::string_view key)
        {
            const auto now = now_fn_();
            auto &state = failures_[std::string(key)];
            if (state.count == 0 || now - state.first > window_ms_)
            {
                state.count = 1; // 新窗口
                state.first = now;
            }
            else
            {
                ++state.count;
            }
            if (state.count >= max_failures_)
            {
                banned_[std::string(key)] = now; // 封禁起点
            }
        }

        /**
         * @brief 是否被封禁
         * @param key 键
         */
        [[nodiscard]] auto is_banned(std::string_view key) const -> bool
        {
            const auto it = banned_.find(std::string(key));
            if (it == banned_.end())
            {
                return false;
            }
            const auto now = now_fn_();
            if (now - it->second > window_ms_)
            {
                return false; // 窗口过期自动解封
            }
            return true;
        }

    private:
        struct failure_state
        {
            std::size_t count{0};      ///< 窗口内失败数
            std::uint64_t first{0};    ///< 窗口起点
        };
        std::size_t max_failures_;                    ///< 失败阈值
        std::uint64_t window_ms_;                     ///< 窗口（毫秒）
        std::uint64_t (*now_fn_)();                   ///< 时钟函数
        mutable std::unordered_map<std::string, failure_state> failures_; ///< 失败计数
        mutable std::unordered_map<std::string, std::uint64_t> banned_;   ///< 封禁表
    };

} // namespace preview::middleware::builtin
