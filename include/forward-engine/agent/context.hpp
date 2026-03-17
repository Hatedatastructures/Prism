/**
 * @file context.hpp
 * @brief Agent 运行时上下文类型定义
 * @details 声明代理服务运行时的上下文结构，包括服务器上下文、
 * 工作线程上下文和会话上下文。这些上下文结构贯穿整个请求处理
 * 生命周期，为各层组件提供配置、资源和状态访问入口。
 */
#pragma once

#include <forward-engine/agent/config.hpp>
#include <forward-engine/agent/distribution/router.hpp>
#include <forward-engine/agent/account/entry.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/channel/transport/transmission.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <optional>

/**
 * @namespace ngx::agent
 * @brief Agent 运行时域
 * @details 包含代理运行时的配置、会话、路由、前端监听器以及
 * 协议管道构建模块。该命名空间是正向代理引擎的核心组件集合，
 * 负责连接管理、流量转发和协议适配。
 */
namespace ngx::agent
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    namespace account
    {
        class directory;
    }

    /**
     * @struct server_context
     * @brief 服务器全局上下文
     * @details 聚合服务器级别的共享资源，包括配置引用、SSL 上下文
     * 和账户注册表。该结构在服务器启动时创建，被所有工作线程共享。
     * 配置对象以常量引用形式存储，确保运行时配置不可变。
     * @note 配置对象的生命周期必须长于 server_context。
     * @warning SSL 上下文和账户注册表使用 shared_ptr 管理，
     * 确保跨线程共享安全。
     */
    struct server_context
    {
        // 配置对象的常量引用，包含所有运行时参数
        const config &cfg;

        // SSL 上下文，用于 TLS 握手和加密通信
        std::shared_ptr<ssl::context> ssl_ctx;

        // 账户注册表，管理用户凭据和连接配额
        std::shared_ptr<account::directory> account_store;
    };

    /**
     * @struct worker_context
     * @brief 工作线程上下文
     * @details 封装单个工作线程的独立资源，包括 io_context 引用、
     * 路由器和内存池。每个工作线程拥有独立的 worker_context 实例，
     * 实现线程间的资源隔离和避免锁竞争。io_context 驱动该线程上
     * 所有异步操作，路由器负责请求分发决策。
     * @note io_context 的生命周期由工作线程管理。
     * @warning 内存池资源指针用于 PMR 分配，应确保线程安全。
     */
    struct worker_context
    {
        // I/O 上下文引用，驱动该线程的异步操作
        net::io_context &io_context;

        // 路由器引用，负责请求分发和后端选择
        distribution::router &router;

        // 内存池资源指针，用于 PMR 内存分配
        memory::resource_pointer memory_pool;
    };

    /**
     * @struct session_context
     * @brief 会话上下文
     * @details 聚合单个连接会话所需的所有资源和状态，是请求处理
     * 流程的核心数据结构。包含服务器上下文和工作线程上下文的引用、
     * 帧内存池、凭据验证器、缓冲区配置以及入站出站传输对象。
     * 该结构在会话创建时初始化，随会话生命周期销毁。
     * @note 帧内存池用于会话期间的临时分配，会话结束后自动回收。
     * @warning 凭据验证器可能为空，使用前应检查有效性。
     * 入站和出站传输对象由会话管理，确保正确释放。
     * account_lease 用于持有账户连接租约，确保连接限制生效。
     */
    struct session_context
    {
        // 服务器上下文的常量引用，提供全局资源访问
        const server_context &server;

        // 工作线程上下文引用，提供线程级资源访问
        worker_context &worker;

        // 帧内存池引用，用于会话期间的临时内存分配
        memory::frame_arena &frame_arena;

        // 凭据验证函数，用于校验客户端身份
        std::function<bool(std::string_view)> credential_verifier;

        // 账户注册表指针，用于配额检查和流量统计
        account::directory *account_directory_ptr{nullptr};

        // 数据传输缓冲区大小（字节）
        std::uint32_t buffer_size;

        // 入站传输对象，处理来自客户端的数据
        ngx::channel::transport::transmission_pointer inbound;

        // 出站传输对象，处理发往目标服务器的数据
        ngx::channel::transport::transmission_pointer outbound;

        // 账户连接租约，持有期间保持连接计数，会话结束时自动释放
        account::lease account_lease;

        // 活跃流取消回调（由 TLS 等加密协议处理器设置）
        // 用于取消底层流的异步操作，当 ctx.inbound 被 move 后仍能正确清理
        std::function<void()> active_stream_cancel;

        // 活跃流关闭回调（由 TLS 等加密协议处理器设置）
        // 用于关闭底层流连接，当 ctx.inbound 被 move 后仍能正确清理
        std::function<void()> active_stream_close;
    };

}
