/**
 * @file vmess.hpp
 * @brief VMess 协议处理器
 */

#pragma once

#include <common/core/runtime/adapter/handler.hpp>
#include <common/protocols/vmess/vmess.hpp>
#include <common/protocols/vmess/dgram.hpp>
#include <common/core/runtime/adapter/common.hpp>

namespace preview::runtime::handler
{

    class Vmess final : public ProtocolHandler
    {
    public:
        explicit Vmess(preview::vmess::server_config cfg) : cfg_(std::move(cfg)) {}

        auto accept(preview::shared_transmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, msg, conn] = co_await preview::vmess::accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != preview::error::none || !conn) co_return r;
            r.target.host = msg.dst.host;
            r.target.port = std::to_string(msg.dst.port);
            r.identity = preview::runtime::detail::uuid_hex(cfg_.uuid);
            if (msg.cmd == preview::vmess::cmd_udp)
            {
                r.is_dgram = true;
                r.transmission = std::make_shared<preview::vmess::dgram<>>(std::move(conn));
            }
            else
            {
                r.transmission = std::move(conn);
            }
            co_return r;
        }

        [[nodiscard]] auto name() const -> std::string_view override { return "vmess"; }

    private:
        preview::vmess::server_config cfg_;
    };

} // namespace preview::runtime::handler
