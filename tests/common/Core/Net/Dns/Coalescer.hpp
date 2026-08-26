/**
 * @file Coalescer.hpp
 * @brief DNS 请求合并层（single-flight）
 * @details 对齐主项目 net/dns/detail/coalescer.hpp 分层：同一 "domain:qtype"
 *          键的并发查询只发起一次上游请求，其余协程挂起等待首个 flight 完成。
 *
 *          等待机制与主项目一致：flight 持有一个 expires_at(max) 的
 *          steady_timer，等待者 co_await 该定时器；leader 完成后设置结果并
 *          cancel 定时器唤醒全部等待者，等待者醒来后从 flight 读取结果。
 *
 *          清理采用两阶段（PendingCleanup 标记 + FlushCleanup 延迟删除），
 *          避免遍历 map 时迭代器失效。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Network::Dns
{

    /**
     * @class Flight
     * @brief 单次在途查询（leader + waiters 共享）
     */
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
         * @brief 标记结果就绪并唤醒全部等待者
         */
        void Complete()
        {
            Ready_ = true;
            Timer_.cancel();
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
        std::string Key_;
        boost::asio::steady_timer Timer_;
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
        using FlightMap = std::map<std::string, std::shared_ptr<Flight>, std::less<>>;

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
            -> std::pair<std::shared_ptr<Flight>, bool>
        {
            std::string key(domain);
            key += ':';
            key += std::to_string(qtype);

            if (auto it = Flights_.find(key); it != Flights_.end())
            {
                return {it->second, false};
            }
            auto flight = std::make_shared<Flight>(Executor_, std::move(key));
            // map 键与 flight 内部 Key_ 各持一份拷贝，保证 string_view 引用稳定
            const auto [it, ok] =
                Flights_.emplace(flight->Key(), flight);
            return {it->second, ok};
        }

        /**
         * @brief 按 flight 键查找
         * @param key "domain:qtype"
         * @return 对应 flight；不存在返回 nullptr
         */
        [[nodiscard]] auto Find(std::string_view key) const -> std::shared_ptr<Flight>
        {
            if (const auto it = Flights_.find(key); it != Flights_.end())
            {
                return it->second;
            }
            return nullptr;
        }

        /**
         * @brief 写入结果并唤醒等待者
         * @param flight 目标 flight
         * @param result 查询结果（拷贝进共享槽）
         */
        void SetResult(const std::shared_ptr<Flight> &flight, Result result)
        {
            Results_[flight->Key()] = std::move(result);
            flight->Complete();
        }

        /**
         * @brief 读取结果
         * @param flight 目标 flight
         * @return 结果指针；尚未写入返回 nullptr
         */
        [[nodiscard]] auto GetResult(const Flight &flight) const -> const Result *
        {
            const auto it = Results_.find(flight.Key());
            return it == Results_.end() ? nullptr : &it->second;
        }

        /**
         * @brief 清除某 flight 的结果槽
         * @param flight 目标 flight
         */
        void DropResult(const Flight &flight)
        {
            Results_.erase(flight.Key());
        }

        /**
         * @brief 标记可清理的 flight（仅 ready 且无等待者）
         * @param flight 目标 flight
         */
        void CleanupFlight(const std::shared_ptr<Flight> &flight)
        {
            if (flight->Ready() && flight->Waiters() == 0)
            {
                flight->MarkPendingCleanup();
            }
        }

        /**
         * @brief 两阶段清理：删除所有已标记的 flight 及其结果槽
         * @note 必须在持有 flight shared_ptr 的调用栈之外周期性调用，
         *       避免遍历中 erase 导致迭代器失效
         */
        void FlushCleanup()
        {
            for (auto it = Flights_.begin(); it != Flights_.end();)
            {
                if (it->second->PendingCleanup())
                {
                    Results_.erase(it->first);
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
        FlightMap Flights_;
        std::map<std::string, Result> Results_;
    };

} // namespace Preview::Network::Dns
