/**
 * @file BootstrapJson.hpp
 * @brief Operations bootstrap 身份与一次性缓存策略的 JSON/HTTP 边界。
 */
#pragma once

#include <Prism/Operations/Models.hpp>

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Operations::HttpDetail
{

    /** @brief 已装配路由能力；数据可用性由每次查询返回的实时状态表达。 */
    inline constexpr std::array<std::string_view, 25> BootstrapCapabilities{
        "overview.read", "ingresses.read", "groups.read", "protocols.read", "operations.read",
        "health.read",
        "metrics.read",
        "workers.read",
        "accounts.read",
        "accounts.revoke",
        "sessions.read",
        "sessions.cancel",
        "streams.read",
        "streams.reset",
        "tasks.read",
        "tasks.cancel",
        "generations.read",
        "events.read",
        "operations.status",
        "configuration.read",
        "configuration.reload.validate",
        "configuration.reload.apply",
        "configuration.reload.persist",
        "workers.drain",
        "process.drain"};

    /** @brief 序列化真实进程身份和唯一启动期凭据；不写入日志或错误响应。 */
    [[nodiscard]] auto SerializeBootstrap(const BootstrapIdentity &Identity)
        -> std::optional<std::string>;

    /** @brief 对包含命令凭据的成功 Bootstrap 响应禁止缓存。 */
    [[nodiscard]] auto MakeNoStoreResponse(const int Status, std::string Body)
        -> std::string;

} // namespace Prism::Operations::HttpDetail
