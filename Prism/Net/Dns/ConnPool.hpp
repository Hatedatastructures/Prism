/**
 * @file ConnPool.hpp
 * @brief DNS 传输连接池（per-server 空闲连接复用，有界预算）
 * @details 消除 TCP/DoT/DoH 每查询的建连 + 握手开销（DoT/DoH 各 1-2 RTT）：
 *          - 查询前 Acquire 弹出一条健康空闲连接（LIFO，最热者优先）；
 *          - 查询成功后 Release 归还；失败连接直接丢弃不入池；
 *          - 退休条件明确：闲置超 TTL、每键超过 MaxPerServer、全池超过
 *            MaxTotal 一律不保留；维护循环 ClearExpired 周期清理；
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

namespace Prism::Network::Dns
{

    /**
     * @struct ConnPoolOptions
     * @brief 连接池预算；启动期校验并冻结
     */
    struct ConnPoolOptions
    {
        std::size_t MaxPerServer{4};                    ///< 每服务器最大闲置连接数（0 = 禁用池）
        std::size_t MaxTotal{64};                       ///< 全池闲置连接总数上限
        std::chrono::milliseconds IdleTtl{30000};       ///< 空闲连接存活时长
    };

    /**
     * @class ConnPool
     * @brief 泛型连接池（按 Link 类型实例化，桶键 = host|port）
     * @tparam Link 满足 PoolableTransport 的传输类型
     * @details Acquire 将一条闲置 Link 的 shared owner 转交给调用方，Release 只保存仍打开且未超预算
     *          的连接；过期、拒绝或池析构时本池只释放 shared owner，不调用 Link::Close/Cancel/WriteShutdown。
     *          native 资源在最后 Link owner 释放时按具体 Link 的 RAII 析构契约退出；本池不启动 I/O，
     *          执行器由 Link 自身持有，调用方必须在同一 io_context 串行访问本池。
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
         * @param options 每键上限、全池总量上限与闲置存活时长
         */
        explicit ConnPool(const ConnPoolOptions options = {}) : Options_(options)
        {
        }

        /**
         * @brief 取一条空闲连接
         * @param Key 桶键（如 "host|port"）
         * @return 命中返回已弹出的连接；闲置过期项顺路淘汰
         */
        [[nodiscard]] auto Acquire(const std::string &Key) -> Lease
        {
            const auto It = Buckets_.find(Key);
            if (It == Buckets_.end())
            {
                return {};
            }
            auto &Idle = It->second;
            while (!Idle.empty())
            {
                auto EntryValue = std::move(Idle.back());
                Idle.pop_back();
                --TotalIdle_;
                if (std::chrono::steady_clock::now() - EntryValue.Since < Options_.IdleTtl)
                {
                    return {std::move(EntryValue.Conn), true};
                }
                // 过期：连接随 entry 离开作用域自动析构
            }
            Buckets_.erase(It);
            return {};
        }

        /**
         * @brief 归还健康连接
         * @details 连接不健康、每键已满或全池已达 MaxTotal 时直接丢弃；
         *          丢弃只析构连接，不产生新的等待或历史。
         */
        void Release(const std::string &Key, std::shared_ptr<Link> Connection)
        {
            if (!Connection || !Connection->IsOpen() || Options_.MaxPerServer == 0 ||
                TotalIdle_ >= Options_.MaxTotal)
            {
                return;
            }
            auto It = Buckets_.find(Key);
            if (It == Buckets_.end())
            {
                It = Buckets_.emplace(Key, std::vector<IdleEntry>{}).first;
            }
            auto &Idle = It->second;
            if (Idle.size() >= Options_.MaxPerServer)
            {
                return;
            }
            Idle.push_back({std::move(Connection), std::chrono::steady_clock::now()});
            ++TotalIdle_;
        }

        /**
         * @brief 闲置连接总数（全部桶）
         */
        [[nodiscard]] auto IdleCount() const -> std::size_t
        {
            return TotalIdle_;
        }

        /**
         * @brief 全池闲置连接总量上限
         * @return 构造时冻结的 MaxTotal
         */
        [[nodiscard]] auto Capacity() const -> std::size_t
        {
            return Options_.MaxTotal;
        }

        /**
         * @brief 清理全部过期闲置连接（供维护循环周期调用）
         * @return 清理数量
         */
        auto ClearExpired() -> std::size_t
        {
            const auto Now = std::chrono::steady_clock::now();
            std::size_t Evicted = 0;
            for (auto It = Buckets_.begin(); It != Buckets_.end();)
            {
                auto &Idle = It->second;
                const auto Before = Idle.size();
                const auto Keep = std::remove_if(Idle.begin(), Idle.end(),
                                                 [&](const IdleEntry &EntryValue)
                                                 { return IsExpired(EntryValue, Now); });
                Idle.erase(Keep, Idle.end());
                const auto Removed = Before - Idle.size();
                Evicted += Removed;
                TotalIdle_ -= Removed;
                if (Idle.empty())
                {
                    It = Buckets_.erase(It);
                }
                else
                {
                    ++It;
                }
            }
            return Evicted;
        }

    private:
        struct IdleEntry
        {
            std::shared_ptr<Link> Conn;
            std::chrono::steady_clock::time_point Since; ///< 归还时刻（闲置计时起点）
        };

        /// 条目是否已超过闲置存活时长
        [[nodiscard]] auto IsExpired(const IdleEntry &EntryValue,
                                     const std::chrono::steady_clock::time_point Now) const -> bool
        {
            return Now - EntryValue.Since >= Options_.IdleTtl;
        }

        ConnPoolOptions Options_;
        std::unordered_map<std::string, std::vector<IdleEntry>> Buckets_;
        std::size_t TotalIdle_{0}; ///< 全池闲置连接总量（预算计数）
    };

} // namespace Prism::Network::Dns
