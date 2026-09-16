/**
 * @file Socks5.hpp
 * @brief SOCKS5 协议处理器
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Preview/Foundation/Utility/Diagnose/Log.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Runtime/Contract/Handler.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>

namespace Preview::Runtime::Handler
{
    namespace Net = boost::asio;

    /// fault 错误码 → SOCKS5 BND 应答码
    [[nodiscard]] inline auto ToReplyCode(Preview::Fault::Code ec)
        -> Preview::Socks5::ReplyCode
    {
        if (!Preview::Fault::Failed(ec))
        {
            return Preview::Socks5::ReplyCode::Success;
        }
        switch (ec)
        {
        case Preview::Fault::Code::ConnectionRefused:
            return Preview::Socks5::ReplyCode::ConnectionRefused;
        case Preview::Fault::Code::Unreachable:
        case Preview::Fault::Code::NetNoreply:
            return Preview::Socks5::ReplyCode::NetworkUnreachable;
        case Preview::Fault::Code::HostNoreply:
            return Preview::Socks5::ReplyCode::HostUnreachable;
        default:
            return Preview::Socks5::ReplyCode::GeneralFailure;
        }
    }

    /// 拨号完成后补发 CONNECT 应答（DeferConnectReply 语义）
    [[nodiscard]] inline auto SendDeferredReply(std::shared_ptr<Preview::Socks5::Conn<>> Keep,
                                                  Preview::Fault::Code ec) -> Net::awaitable<void>
    {
        const auto ReplyErr = co_await Keep->SendConnectReply(ToReplyCode(ec));
        if (ReplyErr != Preview::Error::None)
        {
            // 应答写失败：客户端可能已断开，记录并收口（不静默丢失）
            Preview::Diagnose::Warn("socks5 Connect Reply Write Failed; closing");
        }
        if (ReplyErr != Preview::Error::None || Preview::Fault::Failed(ec))
        {
            Keep->Close();
        }
    }

    class Socks5 final : public ProtocolHandler
    {
    public:
        explicit Socks5(Preview::Socks5::ServerConfig cfg) : Cfg_(std::move(cfg)) {}

        auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<AcceptResult> override
        {
            auto Local = Cfg_;
            Local.DeferConnectReply = true;
            auto [err, req, Conn] = co_await Preview::Socks5::Accept(std::move(Inbound), Local);
            AcceptResult r;
            r.err = err;
            if (err != Preview::Error::None || !Conn) co_return r;
            r.Target.Host = req.Target.Host;
            r.Target.Port = std::to_string(req.Target.Port);
            r.ProtocolAuthenticated = Cfg_.EnableAuth;
            r.AccountId = Conn->AccountId();
            r.identity = std::string(Conn->Identity());
            r.AccountLease = Conn->TakeAuthLease();
            r.AccountLeaseRequired = static_cast<bool>(r.AccountLease);
            if (req.Cmd == Preview::Socks5::Command::UdpAssociate)
            {
                // UDP 数据面：由 udp_service 完成 Bind 后发送 BND 应答
                r.IsDgram = true;
                r.Transmission = std::move(Conn);
                Preview::Composition::Adapters::MaterializeTypedDataPlane(r, true);
                if (!Preview::Composition::Adapters::EnforceProtocolAuthentication(r))
                {
                    co_return r;
                }
                co_return r;
            }
            auto Keep = Conn;
            r.Transmission = std::move(Conn);
            r.PostDial = [Keep](Preview::Fault::Code ec) -> Net::awaitable<void>
            {
                co_await SendDeferredReply(Keep, ec);
            };
            Preview::Composition::Adapters::MaterializeTypedDataPlane(r, r.IsDgram);
            if (!Preview::Composition::Adapters::EnforceProtocolAuthentication(r))
            {
                co_return r;
            }
            co_return r;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "socks5"; }

    private:
        Preview::Socks5::ServerConfig Cfg_;
    };

} // namespace Preview::Runtime::Handler
