/**
 * @file vless.hpp
 * @brief VLESS 协议处理器
 */

#pragma once

#include <common/core/runtime/adapter/handler.hpp>
#include <common/protocols/vless/vless.hpp>
#include <common/core/error.hpp>
#include <common/core/runtime/adapter/common.hpp>

namespace preview::runtime::handler
{

    class Vless final : public ProtocolHandler
    {
    public:
        explicit Vless(preview::vless::server_config cfg) : cfg_(std::move(cfg)) {}

        auto accept(preview::shared_transmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, req, conn] = co_await preview::vless::accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != preview::error::none || !conn) co_return r;
            r.target.host = req.target.host;
            r.target.port = std::to_string(req.target.port);
            r.identity = preview::runtime::detail::uuid_hex(req.uuid);
            r.is_dgram = (req.cmd == preview::vless::command::udp);
            r.transmission = std::move(conn);
            co_return r;
        }

        [[nodiscard]] auto name() const -> std::string_view override { return "vless"; }

    private:
        preview::vless::server_config cfg_;
    };

} // namespace preview::runtime::handler
