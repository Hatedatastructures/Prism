/**
 * @file scheme.cpp
 * @brief Restls 伪装方案实现
 * @details Restls 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 * 握手采用 Path C 代理架构（复用 ShadowTLS 双工转发），
 * 认证基于 BLAKE3 keyed mode。
 */

#include <prism/stealth/restls/scheme.hpp>
#include <prism/stealth/restls/handshake.hpp>
#include <prism/stealth/restls/transport.hpp>
#include <prism/config.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/connect/util.hpp>
#include <prism/protocol/protocol_type.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/trace.hpp>
#include <prism/fault/code.hpp>

#include <boost/asio.hpp>

namespace psm::stealth::restls
{
    namespace net = boost::asio;

    auto scheme::active(const psm::config &cfg) const noexcept
        -> bool
    {
        return cfg.stealth.restls.enabled();
    }

    auto scheme::name() const noexcept
        -> std::string_view
    {
        return "restls";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.restls.server_names);
    }

    auto scheme::guess(const psm::config &cfg) const
        -> verify_result
    {
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "Restls: rely on SNI match"};
    }

    auto scheme::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        auto *rel = ctx.inbound->lowest_layer<transport::reliable>();
        if (!rel)
        {
            trace::debug("[Restls] Cannot access reliable transport, pass to next scheme");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        // 执行 Restls 握手
        handshake_detail detail;
        auto hs_result = co_await restls::handshake(
            rel->native_socket(),
            ctx.cfg->stealth.restls,
            std::move(ctx.preread),
            detail);

        if (!fault::succeeded(hs_result.error))
        {
            result.detected = protocol::protocol_type::tls;
            result.error = hs_result.error;
            trace::debug("[Restls] handshake failed, pass to next scheme");
            co_return result;
        }

        trace::debug("[Restls] handshake succeeded, tls13={}", detail.tls13);

        // 释放底层 socket
        auto raw_socket_opt = rel->release_socket();
        if (!raw_socket_opt)
        {
            trace::warn("[Restls] Cannot release socket from reliable transport");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }
        auto raw_socket = std::move(*raw_socket_opt);

        // 创建 restls_transport
        auto restls_trans = std::make_shared<restls_transport>(
            std::move(raw_socket),
            std::span<const std::uint8_t, 32>(detail.restls_secret),
            std::span<const std::uint8_t, 32>(detail.server_random),
            std::span<const std::uint8_t>(detail.client_finished),
            std::move(detail.script),
            std::span<const std::byte>(), // 无初始预读数据
            detail.tls13);

        // 检测内层协议
        result.detected = protocol::protocol_type::shadowsocks;
        result.transport = restls_trans;
        result.scheme = "restls";

        trace::debug("[Restls] restls_transport created, inner protocol: {}",
                     protocol::to_string_view(result.detected));

        co_return result;
    }
} // namespace psm::stealth::restls
