/**
 * @file racer.hpp
 * @brief Happy Eyeballs (RFC 8305) 并发竞速连接器
 * @details 实现 RFC 8305 的地址竞速算法，当 DNS 返回
 * 多个 IP 地址时并发尝试连接，第一个成功的连接 wins。
 * 第一个 IP 立即尝试，后续 IP 延迟 250ms 后尝试，
 * 可有效降低连接延迟并保持 IPv6 优先。
 * @note 该类不是线程安全的，应在单个 strand 中使用
 */
#pragma once

#include <chrono>
#include <span>

#include <boost/asio.hpp>

#include <prism/channel/connection/pool.hpp>

namespace psm::channel::eyeball
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using pooled_connection = psm::channel::pooled_connection;
    using connection_pool = psm::channel::connection_pool;

    /**
     * @class address_racer
     * @brief Happy Eyeballs 地址竞速器
     * @details 实现 RFC 8305 的并发连接算法。第一个端点
     * 立即开始连接，后续端点延迟 250ms。第一个成功的连接
     * 被返回，其他连接尝试被取消。
     * @note 单线程 io_context 上 winner 写入与 timer cancel
     * 之间无挂起点，不需要互斥锁。
     * @warning 子协程直接捕获连接池引用而非 this，
     * 因为 racer 可能是局部变量。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class address_racer
    {
    public:
        /**
         * @brief 构造竞速器
         * @param pool 连接池引用，用于建立连接
         * @details 竞速器不拥有连接池，调用方需确保连接池的生命周期
         * 覆盖竞速操作的整个周期。
         */
        explicit address_racer(connection_pool &pool);

        /**
         * @brief 并发竞速连接多个端点
         * @details 实现 RFC 8305 核心算法：单端点直接连接，
         * 多端点按 250ms 间隔依次启动，第一个成功的连接 wins。
         * @param endpoints 候选端点列表，通常按优先级排序
         * @return 成功连接，或空连接（全部失败时）
         * @note 如果 endpoints 为空，返回空连接
         */
        [[nodiscard]] auto race(std::span<const tcp::endpoint> endpoints)
            -> net::awaitable<pooled_connection>;

    private:
        struct race_context; // 竞速共享状态（定义在 racer.cpp）

        connection_pool &pool_; // 连接池引用，用于建立 TCP 连接

        static constexpr auto secondary_delay = std::chrono::milliseconds(250); // 后续端点延迟时间，RFC 8305 建议值 250ms

        /**
         * @brief 单端点竞速协程
         * @details 对单个端点发起延迟连接，连接成功时设置 winner。
         * @param ep 目标端点
         * @param delay 启动延迟（0ms 为立即，250ms*i 为后续端点）
         * @param ctx 竞速共享状态
         * @return net::awaitable<void> 异步操作
         */
        auto race_endpoint(tcp::endpoint ep, std::chrono::milliseconds delay, std::shared_ptr<race_context> ctx)
            -> net::awaitable<void>;
    }; // class address_racer
} // namespace psm::channel::eyeball
