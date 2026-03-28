/**
 * @file racer.hpp
 * @brief Happy Eyeballs (RFC 8305) 并发竞速连接器
 * @details 实现 RFC 8305 的地址竞速算法，当 DNS 返回多个 IP 地址时，
 * 并发尝试连接，第一个成功的连接 wins。第一个 IP 立即尝试，
 * 后续 IP 延迟 250ms 后尝试。该算法可有效降低连接延迟，
 * 同时保持对 IPv6 优先的支持。
 *
 * @section algorithm 算法原理
 *
 * Happy Eyeballs 算法解决了以下问题：
 * - IPv6 连接可能存在"黑洞"（IPv6 路由配置错误导致连接挂起）
 * - 单地址连接失败时需要等待超时才能尝试下一个地址
 * - 用户感知的连接延迟过长
 *
 * 算法步骤：
 * 1. 如果只有一个候选端点，直接连接
 * 2. 第一个端点（通常是 IPv6）立即开始连接
 * 3. 后续端点按 250ms 间隔依次开始连接
 * 4. 第一个成功建立连接的端点 wins
 * 5. 其他正在进行的连接尝试被取消，已完成的连接被归还
 *
 * @section timing 时间线示例
 *
 * 假设有 3 个端点 [IPv6_A, IPv4_B, IPv4_C]：
 *
 * @code
 * 时间  |  IPv6_A  |  IPv4_B  |  IPv4_C
 * ------|----------|----------|----------
 * 0ms   |  开始    |          |
 * 250ms |  ...     |  开始    |
 * 500ms |  ...     |  ...     |  开始
 * @endcode
 *
 * 如果 IPv6_A 在 100ms 成功，则：
 * - IPv4_B 的定时器被取消，连接不会开始
 * - IPv4_C 的定时器被取消，连接不会开始
 * - 返回 IPv6_A 的连接
 *
 * @section usage 使用示例
 *
 * @code
 * // 在 router 中使用
 * auto router::connect_with_retry(std::span<const tcp::endpoint> endpoints)
 *     -> net::awaitable<pooled_connection>
 * {
 *     eyeball::address_racer racer(pool_);
 *     co_return co_await racer.race(endpoints);
 * }
 * @endcode
 *
 * @note 该类不是线程安全的，应在单个 strand 上下文中使用
 * @see RFC 8305: https://datatracker.ietf.org/doc/html/rfc8305
 */
#pragma once

#include <chrono>
#include <span>
#include <atomic>

#include <boost/asio.hpp>

#include <forward-engine/channel/connection/pool.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::channel::eyeball
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using pooled_connection = ngx::channel::pooled_connection;
    using connection_pool = ngx::channel::connection_pool;

    /**
     * @class address_racer
     * @brief Happy Eyeballs 地址竞速器
     * @details 实现 RFC 8305 的并发连接算法。当有多个候选端点时，
     * 第一个端点立即开始连接，后续端点延迟 250ms 后开始连接。
     * 第一个成功建立的连接将被返回，其他连接尝试会被取消。
     *
     * @section features 算法特点
     *
     * - **降低连接延迟**：第一个成功的连接立即返回，无需等待所有尝试
     * - **容错性**：一个端点失败不会影响其他端点的尝试
     * - **IPv6 优先**：如果 DNS 返回 IPv6 地址在前，优先尝试 IPv6
     * - **资源友好**：成功的连接会被使用，失败的连接会被正确归还
     *
     * @section scenarios 使用场景
     *
     * - DNS 返回多个 A/AAAA 记录
     * - 多 CDN 节点选择
     * - 跨运营商线路选择
     * - 双栈（IPv4/IPv6）环境下的快速连接
     *
     * @section impl 实现细节
     *
     * 内部使用 co_spawn 启动多个并发协程，每个协程：
     * 1. 等待各自的延迟定时器
     * 2. 检查是否已有获胜者
     * 3. 尝试连接
     * 4. 如果成功且是第一个，设置 winner 标志并保存连接
     * 5. 如果不是第一个但连接成功，归还连接到池
     *
     * @note 单线程 io_context 上 winner 写入结果与 timer cancel 之间
     * 无 co_await 挂起点，主协程不可能在写入前读取，因此不需要互斥锁。
     *
     * @warning 子协程直接捕获连接池引用（而非 this），因为 address_racer
     * 可能是调用方的局部变量，主协程返回后 racer 即被销毁，detached 子协程
     * 必须通过直接引用而非 this 访问连接池。
     *
     * 主协程通过 completion_timer 等待：
     * - 任意一个连接成功时，timer 被取消
     * - 所有连接失败时，timer 在最后一个协程完成时被取消
     */
    class address_racer
    {
    public:
        /**
         * @brief 构造竞速器
         * @param pool 连接池引用，用于建立连接
         * @details 竞速器不拥有连接池，调用方需确保连接池的生命周期
         *          覆盖竞速操作的整个周期
         */
        explicit address_racer(connection_pool &pool);

        /**
         * @brief 并发竞速连接多个端点
         * @details 实现 RFC 8305 的核心算法：
         *
         * **算法流程**：
         * 1. 如果只有一个端点，直接连接（避免不必要的复杂性）
         * 2. 为每个端点启动一个协程
         * 3. 第一个端点的协程立即尝试连接
         * 4. 后续端点的协程先等待延迟，然后尝试连接
         * 5. 第一个成功的连接触发完成
         * 6. 其他连接尝试被取消或归还
         *
         * **延迟策略**：
         * - 第 1 个端点：0ms（立即）
         * - 第 2 个端点：250ms
         * - 第 3 个端点：500ms
         * - 第 N 个端点：(N-1) * 250ms
         *
         * **资源管理**：
         * - 成功的连接返回给调用方
         * - 其他成功的连接归还到连接池（可被复用）
         * - 失败的连接由连接池内部处理
         *
         * @param endpoints 候选端点列表，通常按优先级排序（IPv6 优先）
         * @return 成功连接的套接字，或空连接（全部失败时）
         *
         * @note 如果 endpoints 为空，返回空连接
         * @note 调用方应确保 endpoints 的生命周期覆盖整个竞速过程
         */
        [[nodiscard]] auto race(std::span<const tcp::endpoint> endpoints)
            -> net::awaitable<pooled_connection>;

    private:
        /// 连接池引用，用于建立 TCP 连接
        connection_pool &pool_;

        /**
         * @brief 后续端点的延迟时间
         * @details RFC 8305 建议值为 250ms（推荐范围 100-500ms）
         *          这个值需要在以下两个目标之间平衡：
         *          - 太短：无法给 IPv6 足够的连接时间
         *          - 太长：用户感知的延迟增加
         */
        static constexpr auto secondary_delay = std::chrono::milliseconds(250);
    };
}
