#pragma once

#include <filesystem>
#include <forward-engine/trace.hpp>
#include <string_view>
#include <fstream>
#include <forward-engine/protocol.hpp>
#include <forward-engine/memory.hpp>

namespace srv
{
    // 定义 web_root 为内联变量，防止重复定义
    inline const std::filesystem::path web_root = R"(c:\Users\C1373\Desktop\code\ForwardEngine\test\concurrency\server\v1\webroot)";
}

namespace srv::preload
{
    /**
     * @brief 获取文件资源
     * @param path 相对路径
     * @return memory::string 文件内容
     */
    inline ngx::memory::string load_file(const std::string_view path)
    {
        std::string_view path_view = path;
        if (path_view.starts_with('/'))
        {
            path_view.remove_prefix(1);
        }

        std::filesystem::path file_path = srv::web_root / path_view;
        std::error_code ec;

        if (std::filesystem::exists(file_path, ec) && std::filesystem::is_regular_file(file_path, ec))
        {
            std::ifstream file(file_path, std::ios::binary);
            if (file)
            {
                // 获取文件大小
                file.seekg(0, std::ios::end);
                const auto size = file.tellg();
                file.seekg(0, std::ios::beg);

                // 读取文件内容到 memory::string (使用当前内存资源)
                ngx::memory::string content(size, '\0', ngx::memory::current_resource());
                file.read(content.data(), size);
                return content;
            }
        }
        return ngx::memory::string(ngx::memory::current_resource());
    }

    /**
     * @brief 404 状态页面内容
     */
    inline ngx::memory::string not_found()
    {
        return load_file("/404.html");
    }

    /**
     * @brief 502 状态页面内容
     */
    inline ngx::memory::string bad_gateway()
    {
        return load_file("/502.html");
    }

    inline ngx::protocol::http::response error_404()
    {
        ngx::protocol::http::response response;
        response.status(ngx::protocol::http::status::not_found);
        response.set(ngx::protocol::http::field::content_type, srv::mime::obtain_mapping("404.html"));
        response.body(not_found());
        return response;
    }

    inline ngx::protocol::http::response error_502()
    {
        ngx::protocol::http::response response;
        response.status(ngx::protocol::http::status::bad_gateway);
        response.set(ngx::protocol::http::field::content_type, srv::mime::obtain_mapping("502.html"));
        response.body(bad_gateway());
        return response;
    }
}