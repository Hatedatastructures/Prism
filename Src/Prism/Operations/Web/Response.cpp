/** @file Response.cpp @brief 已验证资源的 HTTP 响应编码。 */
#include <Prism/Operations/Web/Response.hpp>

namespace Prism::Operations::Web
{
    auto MakeResourceResponse(const Catalog& Resources, const std::string_view Target)
        -> std::optional<std::string>
    {
        const auto Asset = Resources.Lookup(Target);
        if (!Asset) return std::nullopt;
        std::string Result;
        Result.reserve(Asset->Body.size() + 512);
        Result.append("HTTP/1.1 200 OK\r\nContent-Type: ").append(Asset->ContentType);
        Result.append("\r\nContent-Length: ").append(std::to_string(Asset->Body.size()));
        Result.append("\r\nConnection: close\r\nX-Content-Type-Options: nosniff");
        Result.append("\r\nReferrer-Policy: no-referrer\r\nCache-Control: ");
        if (Asset->Immutable) Result.append("public, max-age=31536000, immutable");
        else Result.append("no-store");
        if (Asset->ContentType == "text/html; charset=utf-8")
        {
            Result.append("\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; ");
            Result.append("style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; ");
            Result.append("font-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'");
        }
        Result.append("\r\n\r\n").append(Asset->Body);
        return Result;
    }
} // namespace Prism::Operations::Web
