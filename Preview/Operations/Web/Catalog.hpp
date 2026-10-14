/** @file Catalog.hpp @brief 后台资源固定清单及精确同源页面查询。 */
#pragma once

#include <Preview/Operations/Web/Resource.hpp>

#include <array>
#include <optional>
#include <string_view>
#include <utility>

namespace Preview::Operations::Web
{
    /** @brief 字段只允许可直接用于 HTTP 的构建路径，不把请求转换为文件路径。 */
    [[nodiscard]] inline auto IsResourcePath(std::string_view Value) noexcept -> bool
    {
        if (Value.empty() || Value.size() > 256 || Value.front() == '/')
            return false;
        std::size_t Start = 0;
        for (std::size_t Index = 0; Index <= Value.size(); ++Index)
        {
            if (Index == Value.size() || Value[Index] == '/')
            {
                const auto Segment = Value.substr(Start, Index - Start);
                if (Segment.empty() || Segment == "." || Segment == "..")
                    return false;
                Start = Index + 1;
                continue;
            }
            const auto Character = Value[Index];
            if ((Character >= 'a' && Character <= 'z') || (Character >= 'A' && Character <= 'Z') ||
                (Character >= '0' && Character <= '9') || Character == '.' || Character == '-' ||
                Character == '_')
                continue;
            return false;
        }
        return true;
    }

    /** @brief 由文件后缀确定唯一媒体类型；拒绝可注入响应头的清单值。 */
    [[nodiscard]] inline auto ContentTypeFor(std::string_view Value) noexcept -> std::string_view
    {
        if (Value.ends_with(".html"))
            return "text/html; charset=utf-8";
        if (Value.ends_with(".js"))
            return "text/javascript; charset=utf-8";
        if (Value.ends_with(".css"))
            return "text/css; charset=utf-8";
        if (Value.ends_with(".svg"))
            return "image/svg+xml";
        if (Value.ends_with(".png"))
            return "image/png";
        if (Value.ends_with(".ico"))
            return "image/x-icon";
        if (Value.ends_with(".woff2"))
            return "font/woff2";
        return {};
    }

    /** @brief 仅正式的七条页面路径可以返回 index；未知资源与 API 保持各自错误。 */
    [[nodiscard]] inline auto IsPage(std::string_view Value) noexcept -> bool
    {
        constexpr std::array Pages{"/", "/workers", "/accounts", "/sessions", "/events", "/configuration",
            "/operations"};
        for (const auto Page : Pages)
            if (Value == Page)
                return true;
        return false;
    }

    /**
     * @brief 拥有不可变清单和正文，所有网络请求只查询本对象。
     * @details 构造是启动冷路径；Lookup 输入只在同步调用期间借用，返回指针随 catalog 存活。
     *          本对象没有 executor、取消、半关闭或文件句柄；最终释放者是管理 listener 的进程 owner。
     */
    class Catalog final
    {
    public:
        explicit Catalog(std::vector<Resource> Assets) : Assets_(std::move(Assets))
        {
        }

        [[nodiscard]] auto Lookup(std::string_view Target) const noexcept -> const Resource*
        {
            if (Target.starts_with("/Operations"))
                return nullptr;
            const auto Query = Target.find('?');
            if (Query != std::string_view::npos)
                Target = Target.substr(0, Query);
            if (IsPage(Target))
                Target = "/index.html";
            if (Target.empty() || Target.front() != '/' || !IsResourcePath(Target.substr(1)))
                return nullptr;
            const auto Path = Target.substr(1);
            for (const auto& Asset : Assets_)
                if (Asset.Path == Path)
                    return &Asset;
            return nullptr;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Assets_.size();
        }

    private:
        std::vector<Resource> Assets_;
    };
} // namespace Preview::Operations::Web
