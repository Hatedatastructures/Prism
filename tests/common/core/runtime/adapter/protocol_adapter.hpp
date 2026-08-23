/**
 * @file protocol_adapter.hpp
 * @brief 协议接入缝（唯一桥接层）— 统一适配 ProtocolHandler 到 runtime
 * @details 以 handler::ProtocolHandler 为唯一协议接口，make_protocol_accept
 *          把对象式 handler 适配为 session_options::protocol_accept_fn：
 *          统一处理 AcceptResult → middleware::context 的装配与错误映射。
 *          协议便捷工厂（make_accept_*）是薄封装，不再重复 ctx 装配逻辑。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <memory>
#include <utility>

#include <common/core/diagnose/log.hpp>
#include <common/core/error.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transmission.hpp>
#include <common/core/runtime/adapter/handler.hpp>
#include <common/core/runtime/adapter/socks5.hpp>
#include <common/core/runtime/adapter/vless.hpp>
#include <common/core/runtime/adapter/trojan.hpp>
#include <common/core/runtime/adapter/vmess.hpp>
#include <common/core/runtime/adapter/ss2022.hpp>

namespace preview::runtime
{

    namespace net = boost::asio;

    /**
     * @brief 把对象式 ProtocolHandler 适配为 session 的协议接入回调
     * @param h 协议处理器（共享所有权，随回调存活）
     * @return session 协议接入回调
     * @details 成功后把 AcceptResult 装配进 middleware::context：
     *          target / identity / is_dgram / post_dial，并把数据面传输
     *          替换到 inbound。失败或无传输时统一走错误映射，不留下半状态。
     */
    [[nodiscard]] inline auto make_protocol_accept(std::shared_ptr<handler::ProtocolHandler> h)
        -> session_options::protocol_accept_fn
    {
        return [h = std::move(h)](shared_transmission &in, middleware::context &ctx)
            -> net::awaitable<fault::code>
        {
            auto r = co_await h->accept(std::move(in));
            if (!r.transmission)
            {
                if (r.err != error::none)
                {
                    // 消费 handler name()：错误日志标识失败协议，便于定位
                    preview::diagnose::warn("protocol handler {} accept failed", h->name());
                }
                co_return r.err == error::none ? fault::code::io_error
                                              : fault::to_code(make_error_code(r.err));
            }
            ctx.target = r.target;
            ctx.identity = r.identity;
            ctx.is_dgram = r.is_dgram;
            if (r.post_dial)
            {
                ctx.post_dial = std::move(r.post_dial);
            }
            in = std::move(r.transmission);
            co_return fault::code::success;
        };
    }

    /// SOCKS5 便捷工厂
    [[nodiscard]] inline auto make_accept_socks5(socks5::server_config cfg = {})
        -> session_options::protocol_accept_fn
    {
        return make_protocol_accept(std::make_shared<handler::Socks5>(std::move(cfg)));
    }

    /// VLESS 便捷工厂
    [[nodiscard]] inline auto make_accept_vless(vless::server_config cfg = {})
        -> session_options::protocol_accept_fn
    {
        return make_protocol_accept(std::make_shared<handler::Vless>(std::move(cfg)));
    }

    /// Trojan 便捷工厂
    [[nodiscard]] inline auto make_accept_trojan(trojan::server_config cfg = {})
        -> session_options::protocol_accept_fn
    {
        return make_protocol_accept(std::make_shared<handler::Trojan>(std::move(cfg)));
    }

    /// VMess 便捷工厂
    [[nodiscard]] inline auto make_accept_vmess(vmess::server_config cfg = {})
        -> session_options::protocol_accept_fn
    {
        return make_protocol_accept(std::make_shared<handler::Vmess>(std::move(cfg)));
    }

    /// Shadowsocks2022 便捷工厂（本缝仅 TCP；SS2022 UDP 为独立 socket 通道）
    [[nodiscard]] inline auto make_accept_ss2022(shadowsocks2022::server_config cfg = {})
        -> session_options::protocol_accept_fn
    {
        return make_protocol_accept(std::make_shared<handler::Ss2022>(std::move(cfg)));
    }

} // namespace preview::runtime