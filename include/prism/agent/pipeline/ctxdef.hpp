/**
 * @file context_decomposed.hpp
 * @brief 拆分后的上下文类型定义
 * @details 将原来的 session_context God Object 拆分为三个独立结构，
 * 按职责分离：连接元数据、共享资源、传输层状态。
 * pipeline_context 组合这三个结构，作为 pipeline 函数的统一参数。
 */
#pragma once

#include <cstdint>
#include <functional>
#include <string_view>

#include <prism/agent/account/entry.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/memory/pool.hpp>
#include <prism/channel/transport/transmission.hpp>

namespace psm::agent
{
    struct server_context; // 前置声明
    struct worker_context; // 前置声明
    struct config;         // 前置声明
}

namespace psm::agent::pipeline
{
    namespace channel = psm::channel;
    namespace memory = psm::memory;
    using shared_transmission = channel::transport::shared_transmission;

    /**
     * @struct connection_meta
     * @brief 连接的不可变元数据
     * @details 包含会话 ID 和缓冲区大小等只读信息。
     * 这些信息在连接创建时确定，生命周期内不变。
     */
    struct connection_meta
    {
        std::uint64_t session_id{0};  // 会话唯一标识符
        std::uint32_t buffer_size{0}; // 数据传输缓冲区大小（字节）
    };

    /**
     * @struct resource_context
     * @brief 会话级共享资源引用
     * @details 包含服务器配置、worker 资源、内存池、账户目录等
     * 非 owning 引用。这些资源由上层（server/worker）管理生命周期。
     */
    struct resource_context
    {
        const server_context *server{nullptr};                     // 服务器上下文
        worker_context *worker{nullptr};                           // 工作线程上下文
        memory::frame_arena *frame_arena{nullptr};                 // 帧内存池
        account::directory *account_directory{nullptr};            // 账户注册表
        std::function<bool(std::string_view)> credential_verifier; // 凭据验证器
    };

    /**
     * @struct transport_context
     * @brief 传输层状态与连接管理
     * @details 包含入站/出站传输对象、流生命周期回调和账户租约。
     * 这些成员在会话生命周期内可被修改（如 inbound 被替换为
     * TLS/Reality/ShadowTLS 包装层）。
     */
    struct transport_context
    {
        shared_transmission inbound;                // 入站传输
        shared_transmission outbound;               // 出站传输
        std::function<void()> active_stream_cancel; // 活跃流取消回调
        std::function<void()> active_stream_close;  // 活跃流关闭回调
        account::lease account_lease;               // 账户连接租约
    };

    /**
     * @struct pipeline_context
     * @brief Pipeline 阶段统一上下文
     * @details 组合 connection_meta、resource_context、transport_context，
     * 替代原来的 session_context。按职责分组，减少认知负担。
     * @note 禁止拷贝（持有引用），禁止 move 赋值（生命周期绑定）。
     */
    struct pipeline_context
    {
        pipeline_context(const pipeline_context &) = delete;
        pipeline_context &operator=(const pipeline_context &) = delete;
        pipeline_context(pipeline_context &&) = default;
        pipeline_context &operator=(pipeline_context &&) = delete;

        pipeline_context() = default;

        connection_meta meta;
        resource_context resources;
        transport_context transport;
    };
} // namespace psm::agent::pipeline
