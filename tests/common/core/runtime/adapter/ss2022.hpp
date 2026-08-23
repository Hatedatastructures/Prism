/**
 * @file ss2022.hpp
 * @brief Shadowsocks2022 协议处理器
 */

#pragma once

#include <common/core/runtime/adapter/handler.hpp>
#include <common/protocols/shadowsocks2022/shadowsocks2022.hpp>

namespace preview::runtime::handler
{

    class Ss2022 final : public ProtocolHandler
    {
    public:
        explicit Ss2022(preview::shadowsocks2022::server_config cfg) : cfg_(std::move(cfg)) {}

        auto accept(preview::shared_transmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, msg, conn] = co_await preview::shadowsocks2022::accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != preview::error::none || !conn) co_return r;
            r.target.host = msg.dst.host;
            r.target.port = std::to_string(msg.dst.port);
            // identity 留空：SS2022 无客户端标识，禁止把密码写进统计
            r.transmission = std::move(conn);
            co_return r;
        }

        [[nodiscard]] auto name() const -> std::string_view override { return "ss2022"; }

    private:
        preview::shadowsocks2022::server_config cfg_;
    };

} // namespace preview::runtime::handler
