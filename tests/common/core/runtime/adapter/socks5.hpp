/**
 * @file socks5.hpp
 * @brief SOCKS5 协议处理器
 */

#pragma once

#include <common/core/diagnose/log.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/runtime/adapter/handler.hpp>
#include <common/protocols/socks5/socks5.hpp>

namespace preview::runtime::handler
{
    /// fault 错误码 → SOCKS5 BND 应答码
    [[nodiscard]] inline auto to_reply_code(preview::fault::code ec)
        -> preview::socks5::reply_code
    {
        if (!preview::fault::failed(ec))
        {
            return preview::socks5::reply_code::success;
        }
        switch (ec)
        {
        case preview::fault::code::connection_refused:
            return preview::socks5::reply_code::connection_refused;
        case preview::fault::code::unreachable:
        case preview::fault::code::net_noreply:
            return preview::socks5::reply_code::network_unreachable;
        case preview::fault::code::host_noreply:
            return preview::socks5::reply_code::host_unreachable;
        default:
            return preview::socks5::reply_code::general_failure;
        }
    }

    /// 拨号完成后补发 CONNECT 应答（defer_connect_reply 语义）
    [[nodiscard]] inline auto send_deferred_reply(std::shared_ptr<preview::socks5::conn<>> keep,
                                                  preview::fault::code ec) -> net::awaitable<void>
    {
        const auto reply_err = co_await keep->send_connect_reply(to_reply_code(ec));
        if (reply_err != preview::error::none)
        {
            // 应答写失败：客户端可能已断开，记录并收口（不静默丢失）
            preview::diagnose::warn("socks5 connect reply write failed; closing");
        }
        if (reply_err != preview::error::none || preview::fault::failed(ec))
        {
            keep->close();
        }
    }

    class Socks5 final : public ProtocolHandler
    {
    public:
        explicit Socks5(preview::socks5::server_config cfg) : cfg_(std::move(cfg)) {}

        auto accept(preview::shared_transmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto local = cfg_;
            local.defer_connect_reply = true;
            auto [err, req, conn] = co_await preview::socks5::accept(std::move(inbound), local);
            AcceptResult r;
            r.err = err;
            if (err != preview::error::none || !conn) co_return r;
            r.target.host = req.target.host;
            r.target.port = std::to_string(req.target.port);
            // identity 留空：RFC 1929 用户名在 conn 内部校验，未回填 request（后续可在 conn 层暴露）
            if (req.cmd == preview::socks5::command::udp_associate)
            {
                // UDP 数据面：由 udp_service 完成 bind 后发送 BND 应答
                r.is_dgram = true;
                r.transmission = std::move(conn);
                co_return r;
            }
            auto keep = conn;
            r.transmission = std::move(conn);
            r.post_dial = [keep](preview::fault::code ec) -> net::awaitable<void>
            {
                co_await send_deferred_reply(keep, ec);
            };
            co_return r;
        }

        [[nodiscard]] auto name() const -> std::string_view override { return "socks5"; }

    private:
        preview::socks5::server_config cfg_;
    };

} // namespace preview::runtime::handler
