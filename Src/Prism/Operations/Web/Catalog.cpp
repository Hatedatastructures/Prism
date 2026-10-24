/** @file Catalog.cpp @brief 后台资源清单查询与启动校验路径。 */
#include <Prism/Operations/Web/Catalog.hpp>

#include <array>
#include <utility>

namespace Prism::Operations::Web
{
    auto IsResourcePath(const std::string_view Value) noexcept -> bool
    {
        if (Value.empty() || Value.size() > 256 || Value.front() == '/') return false;
        std::size_t Start = 0;
        for (std::size_t Index = 0; Index <= Value.size(); ++Index)
        {
            if (Index == Value.size() || Value[Index] == '/')
            {
                const auto Segment = Value.substr(Start, Index - Start);
                if (Segment.empty() || Segment == "." || Segment == "..") return false;
                Start = Index + 1;
                continue;
            }
            const auto Character = Value[Index];
            if ((Character >= 'a' && Character <= 'z') || (Character >= 'A' && Character <= 'Z') ||
                (Character >= '0' && Character <= '9') || Character == '.' || Character == '-' ||
                Character == '_') continue;
            return false;
        }
        return true;
    }

    auto ContentTypeFor(const std::string_view Value) noexcept -> std::string_view
    {
        if (Value.ends_with(".html")) return "text/html; charset=utf-8";
        if (Value.ends_with(".js")) return "text/javascript; charset=utf-8";
        if (Value.ends_with(".css")) return "text/css; charset=utf-8";
        if (Value.ends_with(".svg")) return "image/svg+xml";
        if (Value.ends_with(".png")) return "image/png";
        if (Value.ends_with(".ico")) return "image/x-icon";
        if (Value.ends_with(".woff2")) return "font/woff2";
        return {};
    }

    auto IsPage(const std::string_view Value) noexcept -> bool
    {
        constexpr std::array Pages{"/", "/ingresses", "/workers", "/accounts", "/user-groups",
            "/sessions", "/events", "/configuration", "/operations"};
        for (const auto Page : Pages)
            if (Value == Page) return true;
        return false;
    }

    Catalog::Catalog(std::vector<Resource> Assets) : Assets_(std::move(Assets))
    {
    }

    auto Catalog::Lookup(std::string_view Target) const noexcept -> const Resource*
    {
        if (Target.starts_with("/Operations")) return nullptr;
        const auto Query = Target.find('?');
        if (Query != std::string_view::npos) Target = Target.substr(0, Query);
        if (IsPage(Target)) Target = "/index.html";
        if (Target.empty() || Target.front() != '/' || !IsResourcePath(Target.substr(1))) return nullptr;
        const auto Path = Target.substr(1);
        for (const auto& Asset : Assets_)
            if (Asset.Path == Path) return &Asset;
        return nullptr;
    }

    auto Catalog::Size() const noexcept -> std::size_t
    {
        return Assets_.size();
    }
}
