/**
 * @file context.hpp
 * @brief Context 模块类型定义
 * @details 声明三层上下文结构：server（全局共享）、worker（工作线程）、
 * session（会话级）。使用纯前向声明，不依赖任何实现模块头文件，
 * 确保零循环依赖。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <prism/transport/transmission.hpp>
#include <prism/account/entry.hpp>
#include <prism/protocol/types.hpp>

// ═══════════════════════════════════════════════════════════════════
// 前向声明（零实现模块依赖）
// ═══════════════════════════════════════════════════════════════════

namespace psm
{
    struct config;
}

namespace psm::connect
{
    class router;
}

namespace psm::account
{
    class directory;
    class lease;
}

namespace psm::outbound
{
    class proxy;
}

namespace psm::stats::traffic
{
    class traffic_state;
}

namespace psm::memory
{
    class frame_arena;
    using resource_pointer = std::pmr::memory_resource *;
}

namespace psm::context
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using shared_transmission = transport::shared_transmission;

    // ═══════════════════════════════════════════════════════════════════
    // server — 服务器全局资源（线程共享）
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @struct server
     * @brief 服务器全局上下文
     * @details 聚合服务器级别的共享资源，包括配置、
     * SSL 上下文和账户注册表。该结构在服务器启动时创建，
     * 被所有工作线程共享。配置对象通过 shared_ptr 管理，
     * 支持原子交换实现配置热加载。
     */
    struct server
    {
        std::atomic<std::shared_ptr<const psm::config>> cfg;    // 配置对象（可原子交换）
        std::shared_ptr<ssl::context> ssl_ctx;                  // SSL 上下文
        std::shared_ptr<account::directory> account_store;      // 账户注册表

        /**
         * @brief 获取当前配置（无锁读取）
         * @return 配置对象的常量引用
         */
        [[nodiscard]] auto config() const
            -> const psm::config &
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
    };

    // ═══════════════════════════════════════════════════════════════════
    // worker — 工作线程资源（每线程一个）
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @struct worker
     * @brief 工作线程上下文
     * @details 封装单个工作线程的独立资源，包括
     * io_context 引用、路由器、内存池和出站代理。
     * 每个工作线程拥有独立的 worker 实例，
     * 实现线程间的资源隔离和避免锁竞争。
     */
    struct worker
    {
        net::io_context &io_context;           // I/O 上下文引用
        connect::router &router;               // 路由器引用
        memory::resource_pointer memory_pool;  // 内存池资源指针
        outbound::proxy *outbound{nullptr};    // 出站代理指针（由 worker 拥有）
        stats::traffic::traffic_state *traffic{nullptr}; // 流量统计状态指针
    };

    // ═══════════════════════════════════════════════════════════════════
    // session — 会话状态（每连接一个）
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @struct session
     * @brief 会话上下文
     * @details 聚合单个连接会话所需的所有资源和状态，
     * 是请求处理流程的核心数据结构。包含服务器上下文
     * 和工作线程上下文的引用、帧内存池、凭据验证器、
     * 缓冲区配置以及入站出站传输对象。该结构在会话
     * 创建时初始化，随会话生命周期销毁。
     */
    struct session
    {
        session(const session &) = delete;
        session &operator=(const session &) = delete;
        session(session &&) = default;
        session &operator=(session &&) = delete;

        session(std::uint64_t sid, server &srv, worker &wrk,
                memory::frame_arena &arena,
                std::function<bool(std::string_view)> verifier,
                const std::uint32_t buf_size, shared_transmission in)
            : session_id(sid), server_ctx(srv), worker_ctx(wrk), frame_arena(arena),
              credential_verifier(std::move(verifier)),
              buffer_size(buf_size), inbound(std::move(in)) {}

        std::uint64_t session_id{0};                                    // 会话唯一标识符
        server &server_ctx;                                             // 服务器上下文引用
        worker &worker_ctx;                                             // 工作线程上下文引用
        memory::frame_arena &frame_arena;                               // 帧内存池引用
        std::function<bool(std::string_view)> credential_verifier;      // 凭据验证函数
        account::directory *account_directory{nullptr};                 // 账户注册表指针
        std::uint32_t buffer_size;                                      // 数据传输缓冲区大小（字节）
        shared_transmission inbound;                                    // 入站传输对象
        shared_transmission outbound;                                   // 出站传输对象
        outbound::proxy *outbound_proxy{nullptr};                       // 出站代理指针
        protocol::protocol_type detected_protocol{protocol::protocol_type::unknown}; // 识别出的协议类型
        account::lease account_lease;                                   // 账户连接租约
        std::function<void()> stream_cancel;                          // 活跃流取消回调
        std::function<void()> stream_close;                           // 活跃流关闭回调
    };

} // namespace psm::context
