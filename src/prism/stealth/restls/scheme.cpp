/**
 * @file scheme.cpp
 * @brief Restls 伪装方案实现
 * @details Restls 通过模拟真实 TLS 流量来隐藏代理特征。
 *
 * **当前状态**：基础框架已实现，认证逻辑待完善。
 * Restls 协议规范参照: https://github.com/3andne/restls
 */

#include <prism/stealth/restls/scheme.hpp>
#include <prism/stealth/restls/constants.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace.hpp>
#include <prism/fault/code.hpp>

#include <boost/asio.hpp>

namespace psm::stealth::restls
{
    namespace net = boost::asio;

    auto scheme::is_enabled(const psm::config &cfg) const noexcept -> bool
    {
        return cfg.stealth.restls.enabled();
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "restls";
    }

    auto scheme::execute(scheme_context ctx) -> net::awaitable<scheme_result>
    {
        scheme_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 获取底层 reliable transmission
        // 如果 inbound 已被 preview 等包装，dynamic_cast 会失败
        // 这不是致命错误，只是说明 Restls 无法在此环境下执行
        auto *rel = dynamic_cast<channel::transport::reliable *>(ctx.session->inbound.get());
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