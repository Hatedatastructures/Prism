/**
 * @file handler.hpp
 * @brief SOCKS5 协议处理器
 */

#pragma once

#include <prism/proto/protocol/handler.hpp>

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
        context::session& ctx_;
        std::span<const std::byte> data_;
        std::shared_ptr<trace::trace_context> prefix_;
    };
} // namespace psm::protocol::socks5
