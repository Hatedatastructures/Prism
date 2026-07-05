/**
 * @file context.hpp
 * @brief Context 模块类型定义
 * @details 声明三层上下文结构：server（全局共享）、worker（工作线程）、
 * session（会话级）。使用纯前向声明，不依赖任何实现模块头文件，
 * 确保零循环依赖。
 */
#pragma once

#include <prism/account/entry.hpp>
#include <prism/context/metadata.hpp>
#include <prism/worker/resources.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <array>

namespace psm::stealth { class probe_tracker; }

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>


// 前向声明（零实现模块依赖）

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

namespace psm::coroutine
{

    class task_registry;
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

    // server — 服务器全局资源（线程共享）

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

    // worker — 工作线程资源（每线程一个）

    /**
     * @struct worker_ref
     * @brief 工作线程上下文（借用视图）
     * @details 封装单个工作线程对 psm::worker::resources 的借用关系。resources
     * 是 weak_ptr，借用方使用前需 lock() 检查是否仍有效，nullptr 表示
     * resources 已析构（worker 死亡），调用方应安全退出。
     * io_context 引用仍保留，因为 session/handler 在 lock 检查前就需要
     * 访问 executor 创建 socket 等资源。memory_pool 保留以兼容 PMR 容器。
     * @note 改名为 worker_ref（原 worker），与 psm::worker::resources（资源伞）
     *       区分：本 struct 是借用视图，resources 是拥有者。
     */
    struct worker_ref
    {
        net::io_context &io_context;            // I/O 上下文引用（psm::worker::resources 拥有）
        psm::worker::borrow resources;          // psm::worker::resources 弱引用，调用方需 lock() 检查
        memory::resource_pointer memory_pool;   // 内存池资源指针
    };

    // session — 会话状态（每连接一个）

    /**
     * @struct session_opts
     * @brief 会话构造参数
     * @details 收敛 session 构造函数的参数，
     * 避免过长的参数列表。
     */
    struct session_opts
    {
        std::uint64_t conn_id = 0;                                    ///< 连接唯一标识符
        server &server_ctx;                                            ///< 服务器上下文引用
        worker_ref &worker_ctx;                                            ///< 工作线程上下文引用
        memory::frame_arena &arena;                                    ///< 帧内存池引用
        std::uint32_t buffer_size = 0;                                 ///< 数据传输缓冲区大小（字节）
        shared_transmission inbound;                                   ///< 入站传输对象
        std::array<std::byte, 16> src_ip_raw{};                        ///< 来源 IP 哈希（stealth 层用）
    };

    // 前向声明（request_metadata 完整定义在 metadata.hpp）
    // 已通过 #include <prism/context/metadata.hpp> 提供，此处保留注释作为索引

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
        auto operator=(const session &) -> session & = delete;
        session(session &&) = default;
        auto operator=(session &&) -> session & = delete;

        explicit session(session_opts opts)
            : conn_id(opts.conn_id), server_ctx(opts.server_ctx), worker_ctx(opts.worker_ctx),
              frame_arena(opts.arena),
              buffer_size(opts.buffer_size), inbound(std::move(opts.inbound)),
              src_ip_raw(opts.src_ip_raw) {}

        explicit session(session_opts opts, std::shared_ptr<request_metadata> meta)
            : session(std::move(opts))
        {
            this->meta = std::move(meta);
        }

        std::uint64_t conn_id{0};                                        // 连接唯一标识符
        server &server_ctx;                                             // 服务器上下文引用
        worker_ref &worker_ctx;                                             // 工作线程上下文引用
        memory::frame_arena &frame_arena;                               // 帧内存池引用
        std::uint32_t buffer_size;                                      // 数据传输缓冲区大小（字节）
        shared_transmission inbound;                                    // 入站传输对象
        shared_transmission outbound;                                   // 出站传输对象
        protocol::protocol_type detected_protocol{protocol::protocol_type::unknown}; // 识别出的协议类型
        account::lease account_lease;                                   // 账户连接租约
        std::array<std::byte, 16> src_ip_raw{};                        // 来源 IP 哈希（stealth 层用）
        std::shared_ptr<request_metadata> meta;                         ///< 业务数据载体（L2 各层 fill/读）
    };

} // namespace psm::context
