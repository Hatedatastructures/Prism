/**
 * @file static_file.hpp
 * @brief 静态文件处理器定义
 * @details 负责处理静态文件请求，包括路径解析、安全验证、文件读取和 HTTP 响应构建。
 *
 * 核心特性：
 * - 路径安全验证：防止目录遍历攻击
 * - MIME 类型检测：根据文件扩展名自动设置 Content-Type
 * - 缓存控制：支持 Last-Modified、ETag、Cache-Control 头部
 * - 文件大小限制：防止大文件导致内存问题
 *
 * @note 设计原则：
 * - 安全优先：严格验证文件路径
 * - 性能优化：使用 string_view 避免不必要的字符串拷贝
 * - 错误处理：异常安全，所有异常被捕获并返回 false
 *
 */
#pragma once

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <chrono>
#include <array>
#include <cstdio>

#include "../mime/types.hpp"
#include "../stats/metrics.hpp"
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/memory.hpp>

namespace srv::handler
{
    namespace fs = std::filesystem;
    using namespace srv::mime;
    using namespace srv::stats;

    class static_file_handler final
    {
    public:
        static_file_handler() = default;

        [[nodiscard]] bool serve_file(std::string_view path, ngx::protocol::http::response &resp, detailed_stats &stats) const
        {
            const auto full_path = resolve_path(path);
            if (!validate_path(full_path))
            {
                stats.increment_not_found();
                return false;
            }

            if (!fs::exists(full_path) || !fs::is_regular_file(full_path))
            {
                stats.increment_not_found();
                return false;
            }

            const auto file_size = fs::file_size(full_path);
            if (file_size > static_cast<std::uintmax_t>(MAX_FILE_SIZE))
            {
                return false;
            }

            try
            {
                std::ifstream file(full_path, std::ios::binary);
                if (!file.is_open())
                {
                    return false;
                }

                std::string body;
                body.resize(static_cast<std::size_t>(file_size));
                file.read(body.data(), static_cast<std::streamsize>(file_size));

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, get_mime_type(path));
                resp.set(ngx::protocol::http::field::content_length, std::to_string(file_size));
                resp.set(ngx::protocol::http::field::last_modified, get_last_modified(full_path));
                resp.set(ngx::protocol::http::field::etag, generate_etag(full_path, file_size));
                resp.set(ngx::protocol::http::field::cache_control, "public, max-age=3600");
                resp.body(std::move(body));

                stats.add_bytes_received(static_cast<std::uint64_t>(file_size));
                stats.add_bytes_sent(static_cast<std::uint64_t>(file_size));
                stats.increment_static_files();

                return true;
            }
            catch (...)
            {
                return false;
            }
        }

    private:
        [[nodiscard]] static std::string resolve_path(std::string_view path)
        {
            std::string result(path);

            if (result.empty() || result == "/")
            {
                result = "/index.html";
            }

            if (result.find("..") != std::string::npos)
            {
                return "/index.html";
            }

            const std::string base_dir = "public";
            if (result[0] == '/')
            {
                result = base_dir + result;
            }
            else
            {
                result = base_dir + "/" + result;
            }

            return result;
        }

        [[nodiscard]] static bool validate_path(const std::string &path)
        {
            const std::string base_dir = fs::absolute("public").string();
            const std::string full_path = fs::absolute(path).string();

            if (full_path.find(base_dir) != 0)
            {
                return false;
            }

            return true;
        }

        [[nodiscard]] static std::string get_last_modified(const std::string &path)
        {
            const auto ftime = fs::last_write_time(path);
            const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            const auto c_time = std::chrono::system_clock::to_time_t(sctp);

            std::array<char, 128> buffer{};
            std::strftime(buffer.data(), buffer.size(), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&c_time));
            return std::string(buffer.data());
        }

        [[nodiscard]] static std::string generate_etag(const std::string &path, std::uintmax_t size)
        {
            const auto ftime = fs::last_write_time(path);
            const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            const auto c_time = std::chrono::system_clock::to_time_t(sctp);

            std::array<char, 64> buffer{};
            std::snprintf(buffer.data(), buffer.size(), "\"%lx-%llx\"", static_cast<unsigned long>(c_time),
                          static_cast<unsigned long long>(size));
            return std::string(buffer.data());
        }
    };
}
