/**
 * @file socks5.hpp
 * @brief SOCKS5 协议处理器
 */

#pragma once

#include <common/Core/Diagnose/Log.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Runtime/Adapter/Handler.hpp>
#include <common/Protocols/Socks5/Socks5.hpp>

namespace Preview::Runtime::Handler
{
    /// fault 错误码 → SOCKS5 BND 应答码
    [[nodiscard]] inline auto ToReplyCode(Preview::Fault::Code ec)
        -> Preview::Socks5::ReplyCode
    {
        if (!Preview::Fault::Failed(ec))
        {
            return Preview::Socks5::ReplyCode::success;
        }
        switch (ec)
        {
        case Preview::Fault::Code::connection_refused:
            return Preview::Socks5::ReplyCode::connection_refused;
        case Preview::Fault::Code::unreachable:
        case Preview::Fault::Code::net_noreply:
            return Preview::Socks5::ReplyCode::network_unreachable;
        case Preview::Fault::Code::host_noreply:
            return Preview::Socks5::ReplyCode::host_unreachable;
        default:
            return Preview::Socks5::ReplyCode::general_failure;
        }
    }

    /// 拨号完成后补发 CONNECT 应答（DeferConnectReply 语义）
    [[nodiscard]] inline auto SendDeferredReply(std::shared_ptr<Preview::Socks5::Conn<>> keep,
                                                  Preview::Fault::Code ec) -> net::awaitable<void>
    {
        const auto ReplyErr = co_await keep->SendConnectReply(ToReplyCode(ec));
        if (ReplyErr != Preview::Error::none)
        {
            // 应答写失败：客户端可能已断开，记录并收口（不静默丢失）
            Preview::Diagnose::Warn("socks5 Connect Reply Write Failed; closing");
        }
        if (ReplyErr != Preview::Error::none || Preview::Fault::Failed(ec))
        {
            keep->Close();
        }
    }

    class Socks5 final : public ProtocolHandler
    {
    public:
        explicit Socks5(Preview::Socks5::ServerConfig cfg) : cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission inbound)
            -> net::awaitable<AcceptResult> override
        {
            auto local = cfg_;
            local.DeferConnectReply = true;
            auto [err, req, Conn] = co_await Preview::Socks5::Accept(std::move(inbound), local);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::none || !Conn) co_return r;
            r.Target.Host = req.Target.Host;
            r.Target.Port = std::to_string(req.Target.Port);
            // identity 留空：RFC 1929 用户名在 Conn 内部校验，未回填 Request（后续可在 Conn 层暴露）
            if (req.Cmd == Preview::Socks5::Command::UdpAssociate)
            {
                // UDP 数据面：由 udp_service 完成 Bind 后发送 BND 应答
                r.IsDgram = true;
                r.Transmission = std::move(Conn);
                co_return r;
            }
            auto keep = Conn;
            r.Transmission = std::move(Conn);
            r.post_dial = [keep](Preview::Fault::Code ec) -> net::awaitable<void>
            {
                co_await SendDeferredReply(keep, ec);
            };
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "socks5"; }

    private:
        Preview::Socks5::ServerConfig cfg_;
    };

} // namespace Preview::Runtime::Handler
