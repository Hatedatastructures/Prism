/**
 * @file handler.hpp
 * @brief HTTP 协议处理器
 * @details 替代旧 process.hpp 的 free function handle()，
 * 改成继承 protocol_handler 的子类，内部方法访问 this->prefix_ 做 trace。
 */

#pragma once

#include <prism/proto/protocol/handler.hpp>

namespace psm::protocol::http
{
    /**
     * @class handler
     * @brief HTTP 代理协议处理器
     * @details 管理 HTTP 代理的完整流程：握手（读取请求头 + 认证）→
     * 解析目标 → 拨号上游 → 隧道转发。trace 通过显式 prefix_ 成员，
     * 不依赖 thread_local。
     */
    class handler final : public protocol_handler
    {
    public:
        explicit handler(protocol::handler_params params) noexcept;

        auto run() -> net::awaitable<void> override;

    private:
        context::session& ctx_;
        std::span<const std::byte> data_;
        std::shared_ptr<trace::trace_context> prefix_;
    };
} // namespace psm::protocol::http
