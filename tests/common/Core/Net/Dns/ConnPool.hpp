/**
 * @file ConnPool.hpp
 * @brief DNS 传输连接池（per-server 空闲连接复用）
 * @details 消除 TCP/DoT/DoH 每查询的建连 + 握手开销（DoT/DoH 各 1-2 RTT）：
 *          - 查询前 Acquire 弹出一条健康空闲连接（LIFO，最热者优先）；
 *          - 查询成功后 Release 归还；失败连接直接丢弃不入池；
 *          - 闲置超 TTL 或超过每服务器上限的连接在归还/维护时淘汰；
 *          - 从池中取出的连接可能已被对端静默关闭（keep-alive 超时），
 *            调用方对"复用连接上的首次失败"做一次新建重试（见 Upstream）
 * @note 非线程安全，单 io_context 内使用；仅缓存已成功完成至少一次
 *       收发的连接，未经使用的建连失败不产生池污染
 */

#pragma once

#include "Transport.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    /**
     * @class ConnPool
     * @brief 泛型连接池（按 Link 类型实例化，桶键 = host|port）
     * @tparam Link 满足 PoolableTransport 的传输类型
     */
    template <PoolableTransport Link>
    class ConnPool
    {
    public:
        /// Acquire 结果：Conn 为空表示池中无可用连接（调用方新建）
        struct Lease
        {
            std::shared_ptr<Link> Conn;
            bool FromPool{false};
        };

        /**
         * @brief 构造连接池
         * @param maxPerServer 每服务器最大闲置连接数（超出即淘汰）
         * @param idleTtl 空闲连接存活时长
         */
        explicit ConnPool(const std::size_t maxPerServer,
                          const std::chrono::milliseconds idleTtl)
            : MaxPerServer_(maxPerServer), IdleTtl_(idleTtl)
        {
        }

        /**
         * @brief 取一条空闲连接
         * @param key 桶键（如 "host|port"）
         * @return 命中返回已弹出的连接；闲置过期项顺路淘汰
         */
        [[nodiscard]] auto Acquire(const std::string &key) -> Lease
        {
            const auto It = Buckets_.find(key);
            if (It == Buckets_.end())
            {
                return {};
            }
            auto &idle = It->second;
            while (!idle.empty())
            {
                auto entry = std::move(idle.back());
                idle.pop_back();
                if (std::chrono::steady_clock::now() - entry.Since < IdleTtl_)
                {
                    return {std::move(entry.Conn), true};
                }
                // 过期：连接随 entry 离开作用域自动析构
            }
            Buckets_.erase(It);
            return {};
        }

        /**
         * @brief 归还健康连接
         * @details 池已满或该键不在册（容量 0）时直接丢弃
         */
        void Release(const std::string &key, std::shared_ptr<Link> conn)
        {
            if (!conn || !conn->IsOpen() || MaxPerServer_ == 0)
            {
                return;
            }
            auto &idle = Buckets_[key];
            if (idle.size() >= MaxPerServer_)
            {
                return;
            }
            idle.push_back({std::move(conn), std::chrono::steady_clock::now()});
        }

        /**
         * @brief 闲置连接总数（全部桶）
         */
        [[nodiscard]] auto IdleCount() const -> std::size_t
        {
            std::size_t total = 0;
            for (const auto &[key, idle] : Buckets_)
            {
                total += idle.size();
            }
            return total;
        }

        /**
         * @brief 清理全部过期闲置连接（供维护循环周期调用）
         * @return 清理数量
         */
        auto ClearExpired() -> std::size_t
        {
            const auto Now = std::chrono::steady_clock::now();
            std::size_t evicted = 0;
            for (auto It = Buckets_.begin(); It != Buckets_.end();)
            {
                auto &idle = It->second;
                auto Keep = std::remove_if(idle.begin(), idle.end(),
                                           [&](const IdleEntry &e)
                                           {
                                               const bool stale = Now - e.Since >= IdleTtl_;
                                               evicted += stale ? 1 : 0;
                                               return stale;
                                           });
                idle.erase(Keep, idle.end());
                It = idle.empty() ? Buckets_.erase(It) : std::next(It);
            }
            return evicted;
        }

    private:
        struct IdleEntry
        {
            std::shared_ptr<Link> Conn;
            std::chrono::steady_clock::time_point Since; ///< 归还时刻（闲置计时起点）
        };

        std::size_t MaxPerServer_;
        std::chrono::milliseconds IdleTtl_;
        std::unordered_map<std::string, std::vector<IdleEntry>> Buckets_;
    };

} // namespace Preview::Network::Dns
