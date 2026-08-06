/**
 * @file handler.hpp
 * @brief SOCKS5 协议处理器
 */

#pragma once

#include <prism/protocol/handler.hpp>

namespace psm::protocol::socks5
{
    /**
     * @class handler
     * @brief SOCKS5 代理协议处理器
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
} // namespace psm::protocol::socks5
