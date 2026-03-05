#pragma once

#include <forward-engine/agent/config.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/agent/validator.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>

namespace ngx::agent
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @struct server_context
     * @brief 全局上下文 (Server Context)
     * @details 包含整个代理服务生命周期内共享的、只读或线程安全的资源。
     * 通常由 `main` 函数创建，并传递给所有 `worker`。
     */
    struct server_context
    {
        const config &cfg;                        ///< 全局配置（只读）
        std::shared_ptr<ssl::context> ssl_ctx;    ///< SSL 上下文（线程安全）
        std::shared_ptr<validator> acc_validator; ///< 账户验证器（线程安全）
    };

    /**
     * @struct worker_context
     * @brief 工作线程上下文 (Worker Context)
     * @details 包含单个工作线程独享的资源。每个 `worker` 实例拥有一个 `worker_context`。
     * 这些资源非线程安全，只能在当前线程内访问。
     */
    struct worker_context
    {
        net::io_context &io_context;          ///< IO 上下文
        distributor &distributor;             ///< 路由分发器
        memory::resource_pointer memory_pool; ///< 线程局部内存池
    };

    /**
     * @struct session_context
     * @brief 会话上下文 (Session Context)
     * @details 包含单个客户端会话的运行时状态和资源引用。
     * 由 `session` 对象持有，并在协议处理管线中传递
     */
    struct session_context
    {
        const server_context &server;                               ///< 引用全局上下文
        worker_context &worker;                                     ///< 引用工作线程上下文
        memory::frame_arena &frame_arena;                           ///< 帧内存池（用于当前请求）
        std::function<bool(std::string_view)> credential_verifier;  ///< 凭据验证回调函数
        validator *account_validator_ptr{nullptr};                  ///< 账户验证器指针
        std::uint32_t buffer_size;                                  ///< 当前会话的缓冲区大小
        transport::transmission_pointer inbound;                    ///< 入站传输层
        transport::transmission_pointer outbound;                   ///< 出站传输层
    };

} // namespace ngx::agent
