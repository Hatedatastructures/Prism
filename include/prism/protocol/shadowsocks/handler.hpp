/**
 * @file handler.hpp
 * @brief Shadowsocks 2022 协议处理器
 */

#pragma once

#include <prism/protocol/handler.hpp>

namespace psm::protocol::shadowsocks
{
    /**
     * @class handler
     * @brief Shadowsocks 2022 代理协议处理器
     */
    class handler final : public protocol_handler
    {
    public:
        explicit handler(protocol::handler_params params) noexcept;
        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;
        std::span<const std::byte> data_;
    };
} // namespace psm::protocol::shadowsocks
