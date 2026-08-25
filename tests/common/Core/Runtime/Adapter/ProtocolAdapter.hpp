/**
 * @file protocol_adapter.hpp
 * @brief 协议接入缝（唯一桥接层）— 统一适配 ProtocolHandler 到 runtime
 * @details 以 Handler::ProtocolHandler 为唯一协议接口，MakeProtocolAccept
 *          把对象式 handler 适配为 SessionOptions::ProtocolAcceptFn：
 *          统一处理 AcceptResult → Middleware::Context 的装配与错误映射。
 *          协议便捷工厂（make_accept_*）是薄封装，不再重复 ctx 装配逻辑。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <memory>
#include <utility>

#include <common/Core/Diagnose/Log.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Runtime/Adapter/Handler.hpp>
#include <common/Core/Runtime/Adapter/Socks5.hpp>
#include <common/Core/Runtime/Adapter/Vless.hpp>
#include <common/Core/Runtime/Adapter/Trojan.hpp>
#include <common/Core/Runtime/Adapter/Vmess.hpp>
#include <common/Core/Runtime/Adapter/Ss2022.hpp>

namespace Preview::Runtime
{

    namespace net = boost::asio;

    /**
     * @brief 把对象式 ProtocolHandler 适配为 Session 的协议接入回调
     * @param h 协议处理器（共享所有权，随回调存活）
     * @return Session 协议接入回调
     * @details 成功后把 AcceptResult 装配进 Middleware::Context：
     *          Target / identity / IsDgram / post_dial，并把数据面传输
     *          替换到 inbound。失败或无传输时统一走错误映射，不留下半状态。
     */
    [[nodiscard]] inline auto MakeProtocolAccept(std::shared_ptr<Handler::ProtocolHandler> h)
        -> SessionOptions::ProtocolAcceptFn
    {
        return [h = std::move(h)](SharedTransmission &in, Middleware::Context &ctx)
            -> net::awaitable<Fault::Code>
        {
            auto r = co_await h->Accept(std::move(in));
            if (!r.Transmission)
            {
                if (r.err != Error::none)
                {
                    // 消费 handler Name()：错误日志标识失败协议，便于定位
                    Preview::Diagnose::Warn("Protocol handler {} Accept Failed", h->Name());
                }
                co_return r.err == Error::none ? Fault::Code::io_error
                                              : Fault::ToCode(make_error_code(r.err));
            }
            ctx.Target = r.Target;
            ctx.identity = r.identity;
            ctx.IsDgram = r.IsDgram;
            if (r.post_dial)
            {
                ctx.post_dial = std::move(r.post_dial);
            }
            in = std::move(r.Transmission);
            co_return Fault::Code::success;
        };
    }

    /// SOCKS5 便捷工厂
    [[nodiscard]] inline auto MakeAcceptSocks5(Socks5::ServerConfig cfg = {})
        -> SessionOptions::ProtocolAcceptFn
    {
        return MakeProtocolAccept(std::make_shared<Handler::Socks5>(std::move(cfg)));
    }

    /// VLESS 便捷工厂
    [[nodiscard]] inline auto MakeAcceptVless(Vless::ServerConfig cfg = {})
        -> SessionOptions::ProtocolAcceptFn
    {
        return MakeProtocolAccept(std::make_shared<Handler::Vless>(std::move(cfg)));
    }

    /// Trojan 便捷工厂
    [[nodiscard]] inline auto MakeAcceptTrojan(Trojan::ServerConfig cfg = {})
        -> SessionOptions::ProtocolAcceptFn
    {
        return MakeProtocolAccept(std::make_shared<Handler::Trojan>(std::move(cfg)));
    }

    /// VMess 便捷工厂
    [[nodiscard]] inline auto MakeAcceptVmess(Vmess::ServerConfig cfg = {})
        -> SessionOptions::ProtocolAcceptFn
    {
        return MakeProtocolAccept(std::make_shared<Handler::Vmess>(std::move(cfg)));
    }

    /// Shadowsocks2022 便捷工厂（本缝仅 TCP；SS2022 UDP 为独立 socket 通道）
    [[nodiscard]] inline auto MakeAcceptSs2022(Shadowsocks2022::ServerConfig cfg = {})
        -> SessionOptions::ProtocolAcceptFn
    {
        return MakeProtocolAccept(std::make_shared<Handler::Ss2022>(std::move(cfg)));
    }

} // namespace Preview::Runtime