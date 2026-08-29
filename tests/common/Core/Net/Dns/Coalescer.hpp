/**
 * @file Coalescer.hpp
 * @brief DNS 请求合并层（single-flight）
 * @details 对齐主项目 net/dns/detail/coalescer.hpp 分层：同一 "domain:qtype"
 *          键的并发查询只发起一次上游请求，其余协程挂起等待首个 flight 完成。
 *
 *          等待机制与主项目一致：flight 持有一个 expires_at(max) 的
 *          steady_timer，等待者 co_await 该定时器；leader 完成后写入结果并
 *          cancel 定时器唤醒全部等待者，等待者醒来后从 flight 内部结果槽
 *          读取（结果与 flight 同生命周期，无独立结果表的悬空窗口）。
 *
 *          索引用透明哈希 unordered_map（键 string_view 指向 flight 内部
 *          Key_，O(1) 定位、零键拷贝）；清理采用两阶段（PendingCleanup
 *          标记 + FlushCleanup 延迟删除），避免遍历 map 时迭代器失效。
 * @note 非线程安全，单 io_context 内使用
 */

#pragma once

#include "Config.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace Preview::Network::Dns
{

    template <typename Result>
    class Coalescer; // 前置声明：Flight 的友元授权

    /**
     * @class Flight
     * @brief 单次在途查询（leader + waiters 共享，内嵌结果槽）
     * @tparam Result 各查询共享的结果类型（如 Upstream::QueryResult）
     */
    template <typename Result>
    class Flight
    {
    public:
        /**
         * @brief 构造 flight
         * @param ex 定时器执行器
         * @param key 查询键（"domain:qtype"）
         */
        Flight(boost::asio::any_io_executor ex, std::string key)
            : Key_(std::move(key)), Timer_(std::move(ex))
        {
            Timer_.expires_at(std::chrono::steady_clock::time_point::max());
        }

        /**
         * @brief 查询键
         * @return "domain:qtype"
         */
        [[nodiscard]] auto Key() const -> const std::string &
        {
            return Key_;
        }

        /**
         * @brief 等待定时器（expires_at=max，由 leader cancel 唤醒）
         * @return 定时器引用
         */
        auto Timer() -> boost::asio::steady_timer &
        {
            return Timer_;
        }

        /**
         * @brief 是否已有结果
         * @return leader 已完成时为 true
         */
        [[nodiscard]] auto Ready() const -> bool
        {
            return Ready_;
        }

        /**
         * @brief 当前等待者数量
         * @return waiter 计数
         */
        [[nodiscard]] auto Waiters() const -> std::size_t
        {
            return Waiters_;
        }

        /**
         * @brief 等待者计数增减
         * @param delta 通常为 +1（进入等待）或 -1（离开）
         */
        void AddWaiter(const std::ptrdiff_t delta)
        {
            Waiters_ = static_cast<std::size_t>(static_cast<std::ptrdiff_t>(Waiters_) + delta);
        }

        /**
         * @brief 是否处于待清理状态
         * @return CleanupFlight 已标记且无人等待时为 true
         */
        [[nodiscard]] auto PendingCleanup() const -> bool
        {
            return PendingCleanup_;
        }

        /**
         * @brief 设置待清理标记
         */
        void MarkPendingCleanup()
        {
            PendingCleanup_ = true;
        }

    private:
        friend class Coalescer<Result>;

        /// 写入结果并唤醒全部等待者（仅 leader / Coalescer 调用）
        void Complete(Result result)
        {
            Result_.emplace(std::move(result));
            Ready_ = true;
            Timer_.cancel();
        }

        /// 读取结果槽；leader 尚未完成时为 nullptr
        [[nodiscard]] auto PeekResult() const -> const Result *
        {
            return Result_ ? &*Result_ : nullptr;
        }

        /// 清空结果槽（FlushCleanup 删除 flight 时调用，防悬空引用）
        void ClearResult()
        {
            Result_.reset();
        }

        std::string Key_;
        boost::asio::steady_timer Timer_;
        std::optional<Result> Result_; ///< 结果内嵌槽（与 flight 同生命周期）
        bool Ready_{false};
        std::size_t Waiters_{0};
        bool PendingCleanup_{false};
    };

    /**
     * @class Coalescer
     * @brief single-flight 合并器（非线程安全，单 io_context 内使用）
     * @tparam Result 各查询共享的结果类型（如 Upstream::QueryResult）
     */
    template <typename Result>
    class Coalescer
    {
    public:
        using FlightType = Flight<Result>;
        using FlightPtr = std::shared_ptr<FlightType>;
        using FlightMap = std::unordered_map<std::string_view, FlightPtr,
                                             TransparentStringHash, TransparentStringEqual>;

        /**
         * @brief 构造合并器
         * @param ex 用于 flight 定时器的执行器
         */
        explicit Coalescer(boost::asio::any_io_executor ex)
            : Executor_(std::move(ex))
        {
        }

        /**
         * @brief 查找或创建 flight
         * @param domain 已规范化域名
         * @param qtype 查询类型数值
         * @return {flight, is_new}；is_new=false 表示已有 leader 在途，
         *         调用方应作为 waiter 挂起而非重复打上游
         */
        auto FindCreate(std::string_view domain, const std::uint16_t qtype)
            -> std::pair<FlightPtr, bool>
        {
            std::string key(domain);
            key += ':';
            key += std::to_string(qtype);

            if (auto it = Flights_.find(std::string_view(key)); it != Flights_.end())
            {
                return {it->second, false};
            }
            auto flight = std::make_shared<FlightType>(Executor_, std::move(key));
            // 索引键 string_view 指向 flight 内部 Key_（flight 存活期间地址稳定）
            Flights_.emplace(flight->Key(), flight);
            return {std::move(flight), true};
        }

        /**
         * @brief 写入结果并唤醒等待者（结果进入 flight 内部槽）
         * @param flight 目标 flight
         * @param result 查询结果
         */
        void SetResult(const FlightPtr &flight, Result result)
        {
            flight->Complete(std::move(result));
        }

        /**
         * @brief 读取结果
         * @param flight 目标 flight
         * @return 结果指针；尚未写入返回 nullptr
         */
        [[nodiscard]] auto GetResult(const FlightType &flight) const -> const Result *
        {
            return flight.PeekResult();
        }

        /**
         * @brief 标记可清理的 flight（仅 ready 且无等待者）
         * @param flight 目标 flight
         */
        void CleanupFlight(const FlightPtr &flight)
        {
            if (flight->Ready() && flight->Waiters() == 0)
            {
                flight->MarkPendingCleanup();
            }
        }

        /**
         * @brief 两阶段清理：删除所有已标记的 flight（连同结果槽）
         * @note 必须在持有 flight shared_ptr 的调用栈之外周期性调用，
         *       避免遍历中 erase 导致迭代器失效
         */
        void FlushCleanup()
        {
            for (auto it = Flights_.begin(); it != Flights_.end();)
            {
                if (it->second->PendingCleanup())
                {
                    it->second->ClearResult();
                    it = Flights_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        /**
         * @brief 当前在途 flight 数量
         * @return map 大小
         */
        [[nodiscard]] auto Size() const -> std::size_t
        {
            return Flights_.size();
        }

    private:
        boost::asio::any_io_executor Executor_;
        FlightMap Flights_; ///< 索引：键 view 指向 flight 内部 Key_
    };

} // namespace Preview::Network::Dns
