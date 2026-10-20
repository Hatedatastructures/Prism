/** @file Response.hpp @brief 管理资源同源响应与明确缓存策略。 */
#pragma once

#include <Prism/Operations/Web/Catalog.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace Prism::Operations::Web
{
    /**
     * @brief 在同步调用内借用已验证 catalog；返回独立拥有的 HTTP 正文。
     * @details 调用者先验证 Host、Origin、loopback 和 GET method；本函数不执行文件读取、I/O 或取消。
     *          API 路径及未知路径返回空值，调用方必须交回明确的 API/404 分发，禁止 SPA 兜底。
     */
    [[nodiscard]] auto MakeResourceResponse(const Catalog& Resources, std::string_view Target)
        -> std::optional<std::string>;
} // namespace Prism::Operations::Web
