/**
 * @file mime.hpp
 * @brief MIME 类型模块
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
 * @see processor.hpp
 */
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace srv::mime
{
    /// @brief 最大并发连接数
    constexpr std::uint64_t MAX_CONCURRENT_CONNECTIONS = 10000;
    /// @brief 最大文件大小限制（100MB）
    constexpr std::uint64_t MAX_FILE_SIZE = 100 * 1024 * 1024;

    /// @brief 默认 MIME 类型
    constexpr std::string_view DEFAULT_CONTENT_TYPE = "text/plain";
    /// @brief HTML 文档 MIME 类型
    constexpr std::string_view HTML_CONTENT_TYPE = "text/html";
    /// @brief JSON 数据 MIME 类型
    constexpr std::string_view JSON_CONTENT_TYPE = "application/json";
    /// @brief 纯文本 MIME 类型
    constexpr std::string_view TEXT_CONTENT_TYPE = "text/plain";
    /// @brief CSS 样式表 MIME 类型
    constexpr std::string_view CSS_CONTENT_TYPE = "text/css";
    /// @brief JavaScript 脚本 MIME 类型
    constexpr std::string_view JS_CONTENT_TYPE = "application/javascript";
    /// @brief JPEG 图像 MIME 类型
    constexpr std::string_view JPG_CONTENT_TYPE = "image/jpeg";
    /// @brief PNG 图像 MIME 类型
    constexpr std::string_view PNG_CONTENT_TYPE = "image/png";
    /// @brief GIF 图像 MIME 类型
    constexpr std::string_view GIF_CONTENT_TYPE = "image/gif";
    /// @brief SVG 矢量图 MIME 类型
    constexpr std::string_view SVG_CONTENT_TYPE = "image/svg+xml";
    /// @brief ICO 图标 MIME 类型
    constexpr std::string_view ICO_CONTENT_TYPE = "image/x-icon";
    /// @brief WOFF 字体 MIME 类型
    constexpr std::string_view WOFF_CONTENT_TYPE = "font/woff";
    /// @brief WOFF2 字体 MIME 类型
    constexpr std::string_view WOFF2_CONTENT_TYPE = "font/woff2";
    /// @brief TTF 字体 MIME 类型
    constexpr std::string_view TTF_CONTENT_TYPE = "font/ttf";
    /// @brief EOT 字体 MIME 类型
    constexpr std::string_view EOT_CONTENT_TYPE = "application/vnd.ms-fontobject";
    /// @brief PDF 文档 MIME 类型
    constexpr std::string_view PDF_CONTENT_TYPE = "application/pdf";
    /// @brief ZIP 压缩包 MIME 类型
    constexpr std::string_view ZIP_CONTENT_TYPE = "application/zip";
    /// @brief XML 文档 MIME 类型
    constexpr std::string_view XML_CONTENT_TYPE = "application/xml";

    /**
     * @brief FNV-1a 哈希算法
     * @param str 输入字符串
     * @return 哈希值
     */
    constexpr std::uint64_t fnv1a_hash(const std::string_view str) noexcept
    {
        std::uint64_t hash = 14695981039346656037ULL;
        for (char c : str)
        {
            hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(c));
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    /**
     * @struct entry
     * @brief MIME 类型条目结构体
     * @details 存储文件扩展名与 MIME 类型的映射关系，包含预计算的哈希值
     */
    struct entry final
    {
        /**
         * @brief 编译期构造函数
         * @param ext 文件扩展名（包含点号，如 ".html"）
         * @param type 对应的 MIME 类型
         */
        consteval entry(std::string_view ext, std::string_view type) noexcept
            : extension(ext), content_type(type), hash(fnv1a_hash(ext))
        {
        }

        /// @brief 文件扩展名（包含点号）
        std::string_view extension;
        /// @brief MIME 类型字符串
        std::string_view content_type;
        /// @brief 扩展名的预计算 FNV-1a 哈希值
        std::uint64_t hash;
    };

    /// @brief MIME 类型映射表，包含常见文件扩展名与 MIME 类型的对应关系
    constexpr std::array<entry, 19> TYPES =
        {
            entry{".html", HTML_CONTENT_TYPE},
            entry{".htm", HTML_CONTENT_TYPE},
            entry{".css", CSS_CONTENT_TYPE},
            entry{".js", JS_CONTENT_TYPE},
            entry{".json", JSON_CONTENT_TYPE},
            entry{".txt", TEXT_CONTENT_TYPE},
            entry{".jpg", JPG_CONTENT_TYPE},
            entry{".jpeg", JPG_CONTENT_TYPE},
            entry{".png", PNG_CONTENT_TYPE},
            entry{".gif", GIF_CONTENT_TYPE},
            entry{".svg", SVG_CONTENT_TYPE},
            entry{".ico", ICO_CONTENT_TYPE},
            entry{".woff", WOFF_CONTENT_TYPE},
            entry{".woff2", WOFF2_CONTENT_TYPE},
            entry{".ttf", TTF_CONTENT_TYPE},
            entry{".eot", EOT_CONTENT_TYPE},
            entry{".pdf", PDF_CONTENT_TYPE},
            entry{".zip", ZIP_CONTENT_TYPE},
            entry{".xml", XML_CONTENT_TYPE}};

    /**
     * @brief 根据文件路径获取映射的 MIME 类型
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
        const auto ext_hash = fnv1a_hash(ext);

        for (const auto &e : TYPES)
        {
            if (e.hash == ext_hash && e.extension == ext)
            {
                return e.content_type;
            }
        }

        return DEFAULT_CONTENT_TYPE;
    }
}
