/**
 * @file trojan.hpp
 * @brief Trojan 协议处理器
 */

#pragma once

#include <common/core/runtime/adapter/handler.hpp>
#include <common/protocols/trojan/trojan.hpp>
#include <common/protocols/trojan/dgram.hpp>

namespace preview::runtime::handler
{

    class Trojan final : public ProtocolHandler
    {
    public:
        explicit Trojan(preview::trojan::server_config cfg) : cfg_(std::move(cfg)) {}

        auto accept(preview::shared_transmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto [err, req, conn] = co_await preview::trojan::accept(std::move(inbound), cfg_);
            AcceptResult r;
            r.err = err;
            if (err != preview::error::none || !conn) co_return r;
            r.target.host = req.target.host;
            r.target.port = std::to_string(req.target.port);
            // identity 留空：Trojan 无客户端标识，禁止把密码写进统计
            if (req.cmd == preview::trojan::command::udp_associate)
            {
                r.is_dgram = true;
                r.transmission = std::make_shared<preview::trojan::dgram<>>(std::move(conn));
            }
            else
            {
                r.transmission = std::move(conn);
            }
            co_return r;
        }

        [[nodiscard]] auto name() const -> std::string_view override { return "trojan"; }

    private:
        preview::trojan::server_config cfg_;
    };

} // namespace preview::runtime::handler
