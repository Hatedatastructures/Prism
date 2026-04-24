/**
 * @file context.hpp
 * @brief Agent 运行时上下文类型定义
 * @details 声明代理服务运行时的上下文结构，包括服务器
 * 上下文、工作线程上下文和会话上下文。这些上下文结构
 * 贯穿整个请求处理生命周期，为各层组件提供配置、资源
 * 和状态访问入口。
 */
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <prism/agent/config.hpp>
#include <prism/config.hpp>
#include <prism/resolve/router.hpp>
#include <prism/agent/account/entry.hpp>
#include <prism/memory/pool.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/outbound/proxy.hpp>

namespace psm::agent
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using shared_transmission = channel::transport::shared_transmission;
    namespace account
    {
        class directory;
    }

    /**
     * @struct server_context
     * @brief 服务器全局上下文
     * @details 聚合服务器级别的共享资源，包括配置、
     * SSL 上下文和账户注册表。该结构在服务器启动时创建，
     * 被所有工作线程共享。配置对象通过 shared_ptr 管理，
     * 支持原子交换实现配置热加载。
     * @note 配置通过 config() 方法访问，swap_config() 原子交换。
     * @warning SSL 上下文和账户注册表使用 shared_ptr
     * 管理，确保跨线程共享安全。
     */
    struct server_context
    {
        std::atomic<std::shared_ptr<const psm::config>> cfg;    // 配置对象（可原子交换）
        std::shared_ptr<ssl::context> ssl_ctx;             // SSL 上下文
        std::shared_ptr<account::directory> account_store; // 账户注册表

        /**
         * @brief 获取当前配置（无锁读取）
         * @return 配置对象的常量引用
         */
        [[nodiscard]] auto config() const -> const psm::config &
        {
            return *cfg.load();
        }

        /**
         * @brief 原子交换配置（热加载用）
         * @param new_cfg 新配置对象
         */
        void swap_config(std::shared_ptr<const psm::config> new_cfg)
        {
            cfg.store(std::move(new_cfg));
        }
    }; // struct server_context

    /**
     * @struct worker_context
     * @brief 工作线程上下文
     * @details 封装单个工作线程的独立资源，包括
     * io_context 引用、路由器、内存池和出站代理。
     * 每个工作线程拥有独立的 worker_context 实例，
     * 实现线程间的资源隔离和避免锁竞争。
     * @note io_context 的生命周期由工作线程管理
     * @warning 内存池资源指针用于 PMR 分配，应确保
     * 线程安全
     */
    struct worker_context
    {
        net::io_context &io_context;          // I/O 上下文引用
        resolve::router &router;              // 路由器引用
        memory::resource_pointer memory_pool; // 内存池资源指针
        outbound::proxy *outbound{nullptr};   // 出站代理指针（由 worker 拥有）
    }; // struct worker_context

    /**
     * @struct session_context
     * @brief 会话上下文
     * @details 聚合单个连接会话所需的所有资源和状态，
     * 是请求处理流程的核心数据结构。包含服务器上下文
     * 和工作线程上下文的引用、帧内存池、凭据验证器、
     * 缓冲区配置以及入站出站传输对象。该结构在会话
     * 创建时初始化，随会话生命周期销毁。
     * @note 帧内存池用于会话期间的临时分配，会话结束
     * 后自动回收。
     * @warning 凭据验证器可能为空，使用前应检查有效性。
     * 入站和出站传输对象由会话管理，确保正确释放。
     */
    struct session_context
    {
        session_context(const session_context &) = delete;
        session_context &operator=(const session_context &) = delete;
        session_context(session_context &&) = default;
        session_context &operator=(session_context &&) = delete;

        session_context(const std::uint64_t sid, const server_context &srv, worker_context &w,
                        memory::frame_arena &arena, account::directory *dir, std::function<bool(std::string_view)> verifier,
                        const std::uint32_t buf_size, shared_transmission in)
            : session_id(sid), server(srv), worker(w), frame_arena(arena),
              credential_verifier(std::move(verifier)), account_directory_ptr(dir),
              buffer_size(buf_size), inbound(std::move(in)) {}

        std::uint64_t session_id{0};                               // 会话唯一标识符
        const server_context &server;                              // 服务器上下文常量引用
        worker_context &worker;                                    // 工作线程上下文引用
        memory::frame_arena &frame_arena;                          // 帧内存池引用
        std::function<bool(std::string_view)> credential_verifier; // 凭据验证函数
        account::directory *account_directory_ptr{nullptr};        // 账户注册表指针
        std::uint32_t buffer_size;                                 // 数据传输缓冲区大小（字节）
        shared_transmission inbound;                               // 入站传输对象
        shared_transmission outbound;                              // 出站传输对象
        outbound::proxy *outbound_proxy{nullptr};                  // 出站代理指针（由 worker 设置）
        account::lease account_lease;                              // 账户连接租约
        std::function<void()> active_stream_cancel;                // 活跃流取消回调
        std::function<void()> active_stream_close;                 // 活跃流关闭回调
    }; // struct session_context
} // namespace psm::agent
