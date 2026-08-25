/**
 * @file throttle.hpp
 * @brief 限速与封禁中间件（T5-4 O4）
 * @details - ThrottleMiddleware：令牌桶限速（取不到令牌 → blocked）
 *          - BanMiddleware：失败计数超阈值 → 动态封禁（窗口过期自动解封）
 * @note 对应生产 ThrottleMiddleware / BanMiddleware
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

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>
#include <common/Core/Rate/TokenBucket.hpp>

namespace Preview::Middleware::Builtin
{

    namespace net = boost::asio;

    /**
     * @class ThrottleMiddleware
     * @brief 限速中间件
     * @details 每连接消耗 1 令牌；不足 → blocked（管线终止）。
     *          令牌桶由调用方持有（跨连接共享）。
     */
    class ThrottleMiddleware final : public Middleware
    {
    public:
        /**
         * @brief 构造
         * @param bucket 令牌桶（调用方持有）
         * @param NowFn 时钟函数（毫秒；nullptr = 用 steady_clock）
         */
        explicit ThrottleMiddleware(Preview::Rate::TokenBucket *bucket,
                                     std::uint64_t (*NowFn)() = nullptr)
            : bucket_(bucket), now_fn_(NowFn)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "throttle";
        }

        /**
         * @brief 限速检查
         * @return success / blocked / not_supported
         */
        auto Handle(Preview::SharedTransmission & /*inbound*/, Context & /*ctx*/)
            -> net::awaitable<Preview::Fault::Code> override
        {
            if (!bucket_)
            {
                co_return Preview::Fault::Code::not_supported;
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
            if (!bucket_->TryTake(1, now))
            {
                co_return Preview::Fault::Code::blocked;
            }
            co_return Preview::Fault::Code::success;
        }

    private:
        Preview::Rate::TokenBucket *bucket_; ///< 令牌桶（非拥有）
        std::uint64_t (*now_fn_)();           ///< 时钟函数
    };

    /**
     * @class BanMiddleware
     * @brief 封禁中间件
     * @details 按键记录失败计数；窗口内超阈值 → 封禁（窗口过期解封）。
     *          封禁判定在 Handle 前置：被封禁 → blocked。
     */
    class BanMiddleware final : public Middleware
    {
    public:
        /**
         * @brief 构造
         * @param MaxFailures 窗口内失败阈值
         * @param window 窗口时长（毫秒）
         * @param NowFn 时钟函数（毫秒）
         */
        explicit BanMiddleware(std::size_t MaxFailures, std::uint64_t WindowMs,
                                std::uint64_t (*NowFn)())
            : MaxFailures_(MaxFailures), WindowMs_(WindowMs), now_fn_(NowFn)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "ban";
        }

        /**
         * @brief 封禁判定（按 ctx 远端键）
         * @return success / blocked
         */
        auto Handle(Preview::SharedTransmission & /*inbound*/, Context &ctx)
            -> net::awaitable<Preview::Fault::Code> override
        {
            std::string key = "unknown";
            if (!ctx.RawIdentity.empty())
            {
                key = ctx.RawIdentity;
            }
            if (IsBanned(key))
            {
                co_return Preview::Fault::Code::blocked;
            }
            co_return Preview::Fault::Code::success;
        }

        /**
         * @brief 记录失败（超阈值触发封禁）
         * @param key 键（如远端地址）
         */
        void RecordFailure(std::string_view key)
        {
            const auto now = now_fn_();
            auto &State = failures_[std::string(key)];
            if (State.Count == 0 || now - State.first > WindowMs_)
            {
                State.Count = 1; // 新窗口
                State.first = now;
            }
            else
            {
                ++State.Count;
            }
            if (State.Count >= MaxFailures_)
            {
                banned_[std::string(key)] = now; // 封禁起点
            }
        }

        /**
         * @brief 是否被封禁
         * @param key 键
         */
        [[nodiscard]] auto IsBanned(std::string_view key) const -> bool
        {
            const auto it = banned_.find(std::string(key));
            if (it == banned_.end())
            {
                return false;
            }
            const auto now = now_fn_();
            if (now - it->second > WindowMs_)
            {
                return false; // 窗口过期自动解封
            }
            return true;
        }

    private:
        struct FailureState
        {
            std::size_t Count{0};      ///< 窗口内失败数
            std::uint64_t first{0};    ///< 窗口起点
        };
        std::size_t MaxFailures_;                    ///< 失败阈值
        std::uint64_t WindowMs_;                     ///< 窗口（毫秒）
        std::uint64_t (*now_fn_)();                   ///< 时钟函数
        mutable std::unordered_map<std::string, FailureState> failures_; ///< 失败计数
        mutable std::unordered_map<std::string, std::uint64_t> banned_;   ///< 封禁表
    };

} // namespace Preview::Middleware::Builtin
