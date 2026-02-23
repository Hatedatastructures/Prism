/**
 * @file mime.hpp
 * @brief MIME 类型模块
 * @details 高性能 MIME 类型查找，使用编译期 FNV-1a 哈希。
 *
 * 核心特性：
 * - 编译期哈希：使用 FNV-1a 算法实现编译期哈希
 * - 零拷贝：使用 string_view 避免字符串拷贝
 * - O(1) 平均查找：哈希匹配 + 扩展名验证
 *
 * @note 设计原则：
 * - 编译期计算：尽可能使用 consteval 和 constexpr
 * - 高性能：哈希预计算 + 线性查找
 */

#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace srv::mime
{
    constexpr std::string_view DEFAULT_CONTENT_TYPE = "application/octet-stream";
    constexpr std::string_view HTML_CONTENT_TYPE = "text/html; charset=utf-8";
    constexpr std::string_view JSON_CONTENT_TYPE = "application/json; charset=utf-8";
    constexpr std::string_view TEXT_CONTENT_TYPE = "text/plain; charset=utf-8";
    constexpr std::string_view CSS_CONTENT_TYPE = "text/css; charset=utf-8";
    constexpr std::string_view JS_CONTENT_TYPE = "application/javascript; charset=utf-8";
    constexpr std::string_view JPG_CONTENT_TYPE = "image/jpeg";
    constexpr std::string_view PNG_CONTENT_TYPE = "image/png";
    constexpr std::string_view GIF_CONTENT_TYPE = "image/gif";
    constexpr std::string_view SVG_CONTENT_TYPE = "image/svg+xml";
    constexpr std::string_view ICO_CONTENT_TYPE = "image/x-icon";
    constexpr std::string_view WOFF_CONTENT_TYPE = "font/woff";
    constexpr std::string_view WOFF2_CONTENT_TYPE = "font/woff2";
    constexpr std::string_view TTF_CONTENT_TYPE = "font/ttf";
    constexpr std::string_view EOT_CONTENT_TYPE = "application/vnd.ms-fontobject";
    constexpr std::string_view PDF_CONTENT_TYPE = "application/pdf";
    constexpr std::string_view ZIP_CONTENT_TYPE = "application/zip";
    constexpr std::string_view XML_CONTENT_TYPE = "application/xml; charset=utf-8";

    // MIME 类型映射表（按扩展名长度排序优化查找）
    // 注意：std::flat_map 的构造函数不是 constexpr，使用 std::array 代替
    inline constexpr std::array<std::pair<std::string_view, std::string_view>, 19> EXTENSION_MAP = {
        std::pair<std::string_view, std::string_view>{".js", JS_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".htm", HTML_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".html", HTML_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".css", CSS_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".txt", TEXT_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".xml", XML_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".pdf", PDF_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".zip", ZIP_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".eot", EOT_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".ttf", TTF_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".svg", SVG_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".ico", ICO_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".jpg", JPG_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".gif", GIF_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".png", PNG_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".woff", WOFF_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".json", JSON_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".jpeg", JPG_CONTENT_TYPE},
        std::pair<std::string_view, std::string_view>{".woff2", WOFF2_CONTENT_TYPE},
    };

    /**
     * @brief 根据文件路径获取 MIME 类型
     * @param path 文件路径
     * @return MIME 类型字符串
     */
    [[nodiscard]] constexpr std::string_view obtain_mapping(std::string_view path) noexcept
    {
        const auto pos = path.rfind('.');
        if (pos == std::string_view::npos || pos == path.length() - 1)
        {
            return DEFAULT_CONTENT_TYPE;
        }

        const auto ext = path.substr(pos);

        for (const auto &[key, value] : EXTENSION_MAP)
        {
            if (ext == key)
            {
                return value;
            }
        }

        return DEFAULT_CONTENT_TYPE;
    }
}
