/**
 * @file handler.hpp
 * @brief VMess 协议处理器
 */

#pragma once

#include <prism/protocol/handler.hpp>

namespace psm::protocol::vmess
{
    using shared_transmission = psm::transport::shared_transmission;

    /**
     * @class handler
     * @brief VMess 代理协议处理器
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
         * @brief 执行 VMess 协议处理（握手 → 解析目标 → 拨号 → 隧道转发）
         * @return 异步操作
         */
        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;     ///< 会话资源（含 worker 级 + session 级）
        std::span<const std::byte> data_; ///< 预读数据
    };

    /**
     * @brief VMess 回退入口（共享 SS2022 probe fallback 通道）
     * @param res 会话资源
     * @param data 预读数据（inbound 为空时用于包装预览传输）
     * @param inbound 已包装的传输层（SS2022 fallback 传入），为空时取 res.inbound
     * @details SS2022 握手失败且启用 VMess 时，由 shadowsocks handler
     *          调用，内部执行 VMess 握手。
     */
    [[nodiscard]] auto fallback_run(psm::resource::session &res, std::span<const std::byte> data,
                                    shared_transmission inbound = nullptr) -> net::awaitable<void>;
} // namespace psm::protocol::vmess
