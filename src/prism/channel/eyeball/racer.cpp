/**
 * @file racer.cpp
 * @brief Happy Eyeballs 并发竞速连接器实现
 * @details 实现 RFC 8305 的核心算法，通过协程实现真正的并发连接竞速。
 *
 * @section impl 实现架构
 *
 * 核心数据结构：
 * - winner: 原子标志，标识是否已有成功连接
 * - result_conn: 保存成功连接的指针
 * - pending_count: 跟踪未完成的连接尝试数量
 * - completion_timer: 用于等待竞速完成的定时器
 *
 * 协程模型：
 * - 主协程：启动所有子协程，等待完成
 * - 子协程：各自负责一个端点的延迟和连接
 *
 * @section thread_safety 线程安全
 *
 * 单线程 io_context 上协程交错仅发生在 co_await 挂起点。
 * winner 写入结果与 cancel timer 之间无挂起点，因此不需要互斥锁。
 *
 * @section flow 执行流程
 *
 * 1. 检查边界条件（空列表、单端点）
 * 2. 创建共享状态对象
 * 3. 为每个端点启动一个协程
 * 4. 主协程等待 completion_timer
 * 5. 子协程完成后取消 timer
 * 6. 返回成功连接（如果有）
 */

#include <prism/channel/eyeball/racer.hpp>

#include <prism/trace.hpp>

#include <memory>

namespace psm::channel::eyeball
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    // ═════════════════════════════════════════════════════════════════════════
    // 构造函数
    // ═════════════════════════════════════════════════════════════════════════

    address_racer::address_racer(connection_pool &pool)
        : pool_(pool)
    {
        trace::debug("[Racer] instance created");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 核心竞速算法
    // ═════════════════════════════════════════════════════════════════════════

    auto address_racer::race(std::span<const tcp::endpoint> endpoints)
        -> net::awaitable<pooled_connection>
    {
        // ─────────────────────────────────────────────────────────────────────
        // 边界条件处理
        // ─────────────────────────────────────────────────────────────────────

        // 无候选端点：直接返回空连接
        if (endpoints.empty())
        {
            trace::warn("[Racer] no endpoints to race");
            co_return pooled_connection{};
        }

        // 单端点：直接连接，避免不必要的并发开销
        if (endpoints.size() == 1)
        {
            trace::debug("[Racer] single endpoint, direct connect");
            auto [code, conn] = co_await pool_.async_acquire(endpoints[0]);
            co_return conn;
        }

        trace::debug("[Racer] racing {} endpoints", endpoints.size());

        // ─────────────────────────────────────────────────────────────────────
        // 初始化竞速状态
        // ─────────────────────────────────────────────────────────────────────

        // 获取当前协程的执行器
        auto executor = co_await net::this_coro::executor;

        // 获胜标志：原子变量，第一个成功连接的协程将其设为 true
        auto winner = std::make_shared<std::atomic<bool>>(false);

        // 结果连接：保存成功建立的连接
        auto result_conn = std::make_shared<pooled_connection>();

        // 待完成计数：跟踪还有多少协程在进行
        // 当计数降为 1 时，最后一个协程负责取消完成定时器
        auto pending_count = std::make_shared<std::atomic<std::size_t>>(endpoints.size());

        // 完成定时器：主协程通过等待此定时器来阻塞
        // 初始设置为永不超时，依赖子协程取消来唤醒
        auto completion_timer = std::make_shared<net::steady_timer>(executor);
        completion_timer->expires_at(net::steady_timer::time_point::max());

        // ─────────────────────────────────────────────────────────────────────
        // 启动并发连接协程
        // ─────────────────────────────────────────────────────────────────────

        for (std::size_t i = 0; i < endpoints.size(); ++i)
        {
            // 计算延迟时间
            // - 第 1 个端点：立即开始（延迟 0ms）
            // - 第 2+ 个端点：按序递增延迟（250ms, 500ms, 750ms...）
            auto delay = (i == 0)
                             ? std::chrono::milliseconds(0)
                             : secondary_delay * static_cast<long>(i);

            // 捕获端点（拷贝，确保生命周期）
            const auto ep = endpoints[i];

            // 启动子协程
            // 使用 co_spawn + detached 实现真正的并发
            // 注意：直接捕获 pool_ 引用而非 this，因为 racer 是局部变量，
            // 主协程返回后 racer 被销毁，detached 子协程不能再通过 this 访问
            net::co_spawn(
                executor,
                [&pool = pool_,    // 直接捕获连接池引用（生命周期由 router/worker 保证）
                 ep,               // 目标端点
                 winner,           // 获胜标志
                 result_conn,      // 结果连接
                 pending_count,    // 待完成计数
                 completion_timer, // 完成定时器
                 delay]() -> net::awaitable<void>
                {
                    // ═════════════════════════════════════════════════════════
                    // 阶段 1：延迟等待
                    // ═════════════════════════════════════════════════════════

                    if (delay.count() > 0)
                    {
                        // 创建延迟定时器
                        net::steady_timer delay_timer(co_await net::this_coro::executor);
                        delay_timer.expires_after(delay);

                        // 等待延迟（可被取消）
                        boost::system::error_code ec;
                        co_await delay_timer.async_wait(
                            net::redirect_error(net::use_awaitable, ec));

                        if (ec)
                        {
                            // 定时器被取消（表示已有获胜者或竞速被取消）
                            trace::debug("[Racer] endpoint {} delay timer cancelled",
                                         ep.address().to_string());

                            // 减少待完成计数
                            // 如果是最后一个，取消完成定时器
                            if (pending_count->fetch_sub(1) == 1)
                            {
                                completion_timer->cancel();
                            }
                            co_return;
                        }
                    }

                    // ═════════════════════════════════════════════════════════
                    // 阶段 2：检查获胜状态
                    // ═════════════════════════════════════════════════════════

                    // 延迟结束后，再次检查是否已有获胜者
                    // 这避免了在延迟期间其他协程已经成功的情况
                    if (winner->load(std::memory_order_acquire))
                    {
                        trace::debug("[Racer] endpoint {} skipped, winner exists",
                                     ep.address().to_string());

                        if (pending_count->fetch_sub(1) == 1)
                        {
                            completion_timer->cancel();
                        }
                        co_return;
                    }

                    // ═════════════════════════════════════════════════════════
                    // 阶段 3：尝试连接
                    // ═════════════════════════════════════════════════════════

                    trace::debug("[Racer] attempting connection to {}",
                                 ep.address().to_string());

                    // 通过连接池建立连接
                    auto [code, conn] = co_await pool.async_acquire(ep);

                    // ═════════════════════════════════════════════════════════
                    // 阶段 4：处理连接结果
                    // ═════════════════════════════════════════════════════════

                    if (conn.valid())
                    {
                        // 连接成功，尝试成为获胜者
                        // exchange 是原子的，只有第一个成功者会得到 false
                        if (!winner->exchange(true, std::memory_order_acq_rel))
                        {
                            // 我们是第一个成功的！
                            // 保存连接并取消完成定时器
                            // 单线程 io_context 上此写入与 timer cancel 之间无
                            // co_await 挂起点，不需要互斥锁
                            *result_conn = std::move(conn);

                            trace::info("[Racer] endpoint {} won the race",
                                        ep.address().to_string());

                            completion_timer->cancel();
                        }
                        else
                        {
                            // 其他协程已经获胜
                            // 归还这个成功的连接到池中（可被复用）
                            trace::debug("[Racer] endpoint {} connected but not winner, returning to pool",
                                         ep.address().to_string());
                            conn.reset(); // 归还到池
                        }
                    }
                    else
                    {
                        // 连接失败
                        trace::debug("[Racer] endpoint {} failed: {}",
                                     ep.address().to_string(),
                                     static_cast<int>(code));
                    }

                    // ═════════════════════════════════════════════════════════
                    // 阶段 5：更新完成状态
                    // ═════════════════════════════════════════════════════════

                    // 减少待完成计数
                    // 如果是最后一个完成的协程，取消完成定时器以唤醒主协程
                    if (pending_count->fetch_sub(1) == 1)
                    {
                        completion_timer->cancel();
                    }
                }(),
                net::detached); // 协程独立运行，不等待结果
        }

        // ─────────────────────────────────────────────────────────────────────
        // 等待竞速完成
        // ─────────────────────────────────────────────────────────────────────

        // 等待完成定时器被取消（表示有成功或全部完成）
        boost::system::error_code wait_ec;
        co_await completion_timer->async_wait(
            net::redirect_error(net::use_awaitable, wait_ec));

        // 返回结果连接（可能为空）
        co_return std::move(*result_conn);
    }
}
