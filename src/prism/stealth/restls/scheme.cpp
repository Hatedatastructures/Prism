/**
 * @file scheme.cpp
 * @brief Restls 伪装方案实现
 * @details Restls 通过模拟真实 TLS 流量来隐藏代理特征。
 * Restls 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 *
 * **当前状态**：基础框架已实现，认证逻辑待完善。
 * Restls 协议规范参照: https://github.com/3andne/restls
 */

#include <prism/stealth/restls/scheme.hpp>
#include <prism/config.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/connect/util.hpp>
#include <prism/protocol/protocol_type.hpp>
#include <prism/trace.hpp>
#include <prism/fault/code.hpp>

#include <boost/asio.hpp>

namespace psm::stealth::restls
{
    namespace net = boost::asio;

    auto scheme::active(const psm::config &cfg) const noexcept -> bool
    {
        return cfg.stealth.restls.enabled();
    }

    auto scheme::name() const noexcept -> std::string_view
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
        // Restls 无 ClientHello 独占特征，依赖 SNI 匹配
        // SNI 路由阶段已过滤，这里只需要返回基础分
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "Restls: rely on SNI match"};
    }

    auto scheme::handshake(stealth::handshake_context ctx) -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 获取底层 reliable transmission
        // 穿透 snapshot/preview 包装层找到底层 TCP socket
        auto *rel = connect::find_reliable(ctx.inbound);
        if (!rel)
        {
            trace::debug("[Restls] Cannot access reliable transport (wrapped by another scheme), pass to next scheme");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        // TODO: 实现完整的 Restls 握手流程
        // 1. 读取客户端 TLS ClientHello
        // 2. 建立到后端 TLS 服务器的连接
        // 3. 在 TLS 应用数据中验证客户端身份
        // 4. 认证成功后，使用 restls-script 控制流量模式

        // 当前返回 not_restls，传递给下一个 scheme
        result.detected = protocol::protocol_type::tls;
        result.transport = std::move(ctx.inbound);
        trace::debug("[Restls] Restls not detected, pass to next scheme");

        co_return result;
    }
} // namespace psm::stealth::restls