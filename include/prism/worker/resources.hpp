/**
 * @file resources.hpp
 * @brief worker 资源集合（D2+D3 混合方案核心）
 * @details 持有所有 per-worker 资源（io_context / connection_pool / router /
 * outbound / traffic_state / probe_tracker / task_registry），通过 shared_ptr
 * 共享，借用方持 weak_ptr 安全借用。析构时通过 task_registry::cancel_and_wait
 * 保证所有 detached 协程退出，避免悬挂访问已销毁资源。
 *
 * 设计要点：
 *   - 资源统一归属：所有 per-worker 资源集中在本类，外部模块通过
 *     worker::borrow::lock() 借出 worker::handle 后访问。
 *   - 健康度标志：alive_ 在 run() 异常时置 false，balancer::select 跳过。
 *   - 析构顺序固定：tasks_ 必须最后析构（其他成员可能被 detached 协程引用），
 *     由声明顺序自然保证。
 *
 * 典型生命周期：
 *   main 启动 → 构造 resources（shared_ptr）→ 启动 worker 线程 run()
 *   → 接受连接 → session 持 worker::borrow → 收到 SIGINT → stop()
 *   → worker 线程 join → resources 析构（tasks 先 cancel 后清理）
 *
 * @note 单 worker 单实例，资源生命周期由本类统一管理
 * @warning 析构顺序固定，不可调整成员声明顺序
 */
#pragma once

#include <prism/account/directory.hpp>
#include <prism/account/stats/traffic.hpp>
#include <prism/config/config.hpp>
#include <prism/foundation/coroutine/registry.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/instance/outbound/direct.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/route/table.hpp>
#include <prism/net/resolve/dns/gateway.hpp>
#include <prism/stealth/tracker.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>


namespace psm::worker
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @struct options
     * @brief resources 构造参数
     * @details 收敛 resources 构造函数参数为单一 struct，
     * 与 router_options / session_params 等保持一致风格。
     * ssl_ctx 由调用方构造（避免 context 模块依赖 instance::worker::tls）。
     */
    struct options
    {
        const psm::config &cfg;                                    ///< 服务器配置
        std::shared_ptr<account::directory> account_store;        ///< 账户目录
        std::shared_ptr<ssl::context> ssl_ctx;                    ///< 已构造的 TLS 上下文
        memory::resource_pointer mr = memory::current_resource(); ///< 内存资源
    };

    /**
     * @struct stats
     * @brief worker 资源聚合统计
     * @details 聚合 tasks / pool / traffic 三类统计字段，供 balancer /
     * HTTP API 一次性查询。所有数值为松散一致快照。
     */
    struct stats
    {
        coroutine::task_stats tasks;                            ///< 协程统计
        connect::pool_stats pool;                               ///< 连接池统计
        psm::stats::traffic_snapshot traffic;                   ///< 流量统计
        std::chrono::steady_clock::time_point started_at;       ///< 启动时间
        bool alive{true};                                       ///< 健康度标志
    };

    /**
     * @class resources
     * @brief worker 资源集合
     * @details 持有所有 per-worker 资源，通过 shared_ptr 共享。借用方持
     * weak_ptr 安全借用，worker 死亡时 lock() 返 nullptr，调用方判空后退出。
     * @note 单 worker 单实例，资源生命周期由本类统一管理
     * @warning 成员声明顺序固定（tasks_ 必须最后析构）
     */
    class resources : public std::enable_shared_from_this<resources>
    {
    public:
        /**
         * @brief 构造 worker 资源集合
         * @param opts 构造参数（配置 + 账户目录 + 内存资源）
         * @details 初始化所有 per-worker 资源，包括：
         *   - io_context（单线程事件循环）
         *   - connection_pool（连接复用）
         *   - router（DNS 解析 + 反向路由）
         *   - ssl_ctx（TLS 上下文）
         *   - outbound::direct（直连出站代理）
         *   - traffic_state（流量统计）
         *   - probe_tracker（探测追踪）
         *   - task_registry（detached 协程治理）
         *
         * 同时解析反向代理路由表和正向代理端点，注册 traffic_state 全局实例。
         */
        explicit resources(options opts);

        /**
         * @brief 析构
         * @details 先取消所有 detached 协程（cancel_and_wait），
         * 再按声明逆序析构成员。tasks_ 最后析构保证其他成员被引用期间不被销毁。
         */
        ~resources() noexcept;

        resources(const resources &) = delete;
        auto operator=(const resources &) -> resources & = delete;
        resources(resources &&) = delete;
        auto operator=(resources &&) -> resources & = delete;

        /**
         * @brief 启动事件循环（阻塞）
         * @details 启动连接池后台清理与 metrics 观测协程（通过 spawn_tracked），
         * 然后阻塞在 ioc_.run()。异常时标记 alive_=false 后重新抛出。
         */
        auto run() -> void;

        /**
         * @brief 停止事件循环
         * @details 触发 ioc_.stop()，使阻塞在 run() 的线程退出。
         * 实际的 detached 协程清理在析构时由 cancel_and_wait 完成。
         */
        auto stop() -> void;

        /**
         * @brief 借用自身（weak_ptr）
         * @return 弱引用，调用方需 lock() 后使用，nullptr 表示 worker 已析构
         * @note 非 const：weak_from_this 的 const 重载返 weak_ptr<const T>，
         *       无法转换；调用方持 shared_ptr 可访问非 const 方法。
         */
        [[nodiscard]] auto borrow() noexcept -> std::weak_ptr<resources>;

        // ── 资源访问器（生命周期由本类保证）──────────────────

        [[nodiscard]] auto ioc() noexcept -> net::io_context & { return ioc_; }
        [[nodiscard]] auto pool() noexcept -> connect::connection_pool & { return pool_; }
        [[nodiscard]] auto router() noexcept -> connect::router & { return *router_; }
        [[nodiscard]] auto outbound() noexcept -> outbound::proxy & { return *outbound_; }
        [[nodiscard]] auto traffic() noexcept -> psm::stats::traffic::traffic_state & { return traffic_; }
        [[nodiscard]] auto tracker() noexcept -> stealth::probe_tracker & { return tracker_; }
        [[nodiscard]] auto tasks() noexcept -> coroutine::task_registry & { return tasks_; }
        [[nodiscard]] auto ssl_ctx() const noexcept -> std::shared_ptr<ssl::context> { return ssl_ctx_; }
        [[nodiscard]] auto memory_pool() noexcept -> memory::resource_pointer { return memory_pool_; }

        /**
         * @brief 获取 DNS 网关
         * @return DNS 网关引用
         * @details P4 拆分 router 后新增，封装 DNS 解析 + 端口组装 + IPv6 策略。
         */
        [[nodiscard]] auto dns_gateway() noexcept -> resolve::dns::gateway & { return *dns_gateway_; }

        /**
         * @brief 获取反向路由表
         * @return 路由表引用
         * @details P4 拆分 router 后新增，仅管理 host → tcp::endpoint 映射。
         */
        [[nodiscard]] auto routes() noexcept -> connect::route_table & { return route_table_; }

        /**
         * @brief 健康状态
         * @return true 健康；false 已崩溃或正在关闭
         * @details run() 异常时置 false，balancer::select 据此跳过本 worker。
         */
        [[nodiscard]] auto alive() const noexcept -> bool
        {
            return alive_.load(std::memory_order_acquire);
        }

        /**
         * @brief 获取聚合统计快照
         * @return tasks / pool / traffic 三类统计的聚合视图
         */
        [[nodiscard]] auto stats() const noexcept -> stats;

    private:
        // 声明顺序决定析构顺序：tasks_ 必须最后析构
        // dns_gateway_ 和 router_ 用 unique_ptr 以便析构时提前 reset（cancel timer 后 poll ioc_）
        net::io_context ioc_;
        memory::resource_pointer memory_pool_;
        connect::connection_pool pool_;
        std::unique_ptr<connect::router> router_;
        std::unique_ptr<resolve::dns::gateway> dns_gateway_;
        connect::route_table route_table_;
        std::shared_ptr<ssl::context> ssl_ctx_;
        std::unique_ptr<outbound::direct> outbound_;
        psm::stats::traffic::traffic_state traffic_;
        stealth::probe_tracker tracker_;
        coroutine::task_registry tasks_;
        std::chrono::steady_clock::time_point started_at_;
        std::atomic<bool> alive_{true};
    };

    using handle = std::shared_ptr<resources>;
    using borrow = std::weak_ptr<resources>;

} // namespace psm::worker
