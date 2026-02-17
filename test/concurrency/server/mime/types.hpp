/**
 * @file types.hpp
 * @brief MIME 类型定义
 * @details 定义了常见的 MIME 类型常量和查找函数。
 *
 * 核心特性：
 * - 编译期哈希：使用 FNV-1a 算法实现编译期哈希
 * - 高效查找：O(n) 线性查找，n 为 MIME 类型数量
 * - 常量定义：预定义常见 MIME 类型常量
 *
 * @note 设计原则：
 * - 编译期计算：尽可能使用 consteval 和 constexpr
 * - 零开销抽象：使用 string_view 避免字符串拷贝
 *
 */
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace srv::mime
{
    constexpr std::uint64_t MAX_CONCURRENT_CONNECTIONS = 10000;
    constexpr std::uint64_t MAX_FILE_SIZE = 100 * 1024 * 1024;

    constexpr std::string_view DEFAULT_CONTENT_TYPE = "text/plain";
    constexpr std::string_view HTML_CONTENT_TYPE = "text/html";
    constexpr std::string_view JSON_CONTENT_TYPE = "application/json";
    constexpr std::string_view TEXT_CONTENT_TYPE = "text/plain";
    constexpr std::string_view CSS_CONTENT_TYPE = "text/css";
    constexpr std::string_view JS_CONTENT_TYPE = "application/javascript";
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
    constexpr std::string_view XML_CONTENT_TYPE = "application/xml";

    constexpr std::uint64_t fnv1a_hash(std::string_view str) noexcept
    {
        std::uint64_t hash = 14695981039346656037ULL;
        for (char c : str)
        {
            hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(c));
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    struct mime_entry final
    {
        consteval mime_entry(std::string_view ext, std::string_view type) noexcept
            : extension(ext), content_type(type), hash(fnv1a_hash(ext))
        {
        }

        std::string_view extension;
        std::string_view content_type;
        std::uint64_t hash;
    };

    constexpr std::array<mime_entry, 19> MIME_TYPES = {
        mime_entry{".html", HTML_CONTENT_TYPE},
        mime_entry{".htm", HTML_CONTENT_TYPE},
        mime_entry{".css", CSS_CONTENT_TYPE},
        mime_entry{".js", JS_CONTENT_TYPE},
        mime_entry{".json", JSON_CONTENT_TYPE},
        mime_entry{".txt", TEXT_CONTENT_TYPE},
        mime_entry{".jpg", JPG_CONTENT_TYPE},
        mime_entry{".jpeg", JPG_CONTENT_TYPE},
        mime_entry{".png", PNG_CONTENT_TYPE},
        mime_entry{".gif", GIF_CONTENT_TYPE},
        mime_entry{".svg", SVG_CONTENT_TYPE},
        mime_entry{".ico", ICO_CONTENT_TYPE},
        mime_entry{".woff", WOFF_CONTENT_TYPE},
        mime_entry{".woff2", WOFF2_CONTENT_TYPE},
        mime_entry{".ttf", TTF_CONTENT_TYPE},
        mime_entry{".eot", EOT_CONTENT_TYPE},
        mime_entry{".pdf", PDF_CONTENT_TYPE},
        mime_entry{".zip", ZIP_CONTENT_TYPE},
        mime_entry{".xml", XML_CONTENT_TYPE}};

    [[nodiscard]] constexpr std::string_view get_mime_type(std::string_view path) noexcept
    {
        const auto pos = path.rfind('.');
        if (pos == std::string_view::npos || pos == path.length() - 1)
        {
            return DEFAULT_CONTENT_TYPE;
        }

        const auto ext = path.substr(pos);
        const auto ext_hash = fnv1a_hash(ext);

        for (const auto &entry : MIME_TYPES)
        {
            if (entry.hash == ext_hash && entry.extension == ext)
            {
                return entry.content_type;
            }
        }

        return DEFAULT_CONTENT_TYPE;
    }
}
