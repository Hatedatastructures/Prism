/**
 * @file handler.hpp
 * @brief HTTP 协议处理器
 * @details 替代旧 process.hpp 的 free function handle()，
 * 改成继承 protocol_handler 的子类，内部方法访问 this->prefix_ 做 trace。
 */

#pragma once

#include <prism/protocol/handler.hpp>

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
        /**
         * @brief 构造函数
         * @param params 协议处理器参数（会话资源 + 预读数据）
         */
        explicit handler(protocol::handler_params params) noexcept;

        /**
         * @brief 执行 HTTP 代理处理（读取请求头 + 认证 → 解析目标 → 拨号 → 隧道转发）
         * @return 异步操作
         */
        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;     ///< 会话资源（含 worker 级 + session 级）
        std::span<const std::byte> data_; ///< 预读数据
    };
} // namespace psm::protocol::http
