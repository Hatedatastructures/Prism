/** @file Response.hpp @brief 管理资源同源响应与明确缓存策略。 */
#pragma once

#include <Preview/Operations/Web/Catalog.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace Preview::Operations::Web
{
    /**
     * @brief 在同步调用内借用已验证 catalog；返回独立拥有的 HTTP 正文。
     * @details 调用者先验证 Host、Origin、loopback 和 GET method；本函数不执行文件读取、I/O 或取消。
     *          API 路径及未知路径返回空值，调用方必须交回明确的 API/404 分发，禁止 SPA 兜底。
     */
    [[nodiscard]] inline auto MakeResourceResponse(const Catalog& Resources, std::string_view Target)
        -> std::optional<std::string>
    {
        const auto Asset = Resources.Lookup(Target);
        if (!Asset)
            return std::nullopt;
        std::string Result;
        Result.reserve(Asset->Body.size() + 512);
        Result.append("HTTP/1.1 200 OK\r\nContent-Type: ").append(Asset->ContentType);
        Result.append("\r\nContent-Length: ").append(std::to_string(Asset->Body.size()));
        Result.append("\r\nConnection: close\r\nX-Content-Type-Options: nosniff");
        Result.append("\r\nReferrer-Policy: no-referrer\r\nCache-Control: ");
        if (Asset->Immutable)
            Result.append("public, max-age=31536000, immutable");
        else
            Result.append("no-store");
        if (Asset->ContentType == "text/html; charset=utf-8")
        {
            Result.append("\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; ");
            Result.append("style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; ");
            Result.append("font-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'");
        }
        Result.append("\r\n\r\n").append(Asset->Body);
        return Result;
    }
} // namespace Preview::Operations::Web
