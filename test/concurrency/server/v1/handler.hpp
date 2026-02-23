#pragma once

#include <string_view>
#include <filesystem>
#include <fstream>
#include <array>
#include <utility>
#include <boost/asio.hpp>
#include <forward-engine/protocol.hpp>
#include <forward-engine/trace.hpp>
#include <forward-engine/memory.hpp>
#include "mime.hpp"
#include "error.hpp"
namespace srv
{
    enum class site_kind
    {
        main_site,
        stats_site
    };
}

namespace srv::handler
{
    using namespace ngx;

    /**
     * @brief 前端网站服务
     * @details 处理来自客户端的 HTTP 请求，并返回 webroot 目录下的静态文件。
     * @param socket 客户端 TCP 套接字
     * @param req HTTP 请求对象
     * @param res HTTP 响应对象
     */
    auto frontend(boost::asio::ip::tcp::socket &socket, protocol::http::request req, protocol::http::response &res, srv::site_kind kind)
        -> boost::asio::awaitable<void>
    {
        namespace fs = std::filesystem;

        auto target = req.target();
        // 移除 query string
        if (const auto query_pos = target.find('?'); query_pos != std::string::npos)
        {
            target = target.substr(0, query_pos);
        }

        // 路径安全检查：防止目录遍历
        if (target.find("..") != std::string::npos)
        {
            res = srv::preload::error_404();
        }
        else
        {
            // 使用统一的 web_root 定义
            fs::path file_path = srv::web_root;

            auto resolve_path = [&](std::string_view target_view) -> fs::path
            {
                std::string_view path_view = target_view;
                if (path_view.starts_with('/'))
                {
                    path_view.remove_prefix(1);
                }

                if (path_view.empty())
                {
                    return kind == srv::site_kind::stats_site ? file_path / "stats/index.html"
                                                              : file_path / "main/index.html";
                }

                if (path_view == "stats" || path_view == "stats/")
                {
                    return file_path / "stats/index.html";
                }

                if (path_view == "main" || path_view == "main/")
                {
                    return file_path / "main/index.html";
                }

                if (path_view.starts_with("stats/") || path_view.starts_with("main/"))
                {
                    return file_path / path_view;
                }

                std::array<std::pair<std::string_view, std::string_view>, 8> route_map = {
                    std::pair<std::string_view, std::string_view>{"products", "products.html"},
                    std::pair<std::string_view, std::string_view>{"cart", "cart.html"},
                    std::pair<std::string_view, std::string_view>{"login", "login.html"},
                    std::pair<std::string_view, std::string_view>{"register", "register.html"},
                    std::pair<std::string_view, std::string_view>{"checkout", "checkout.html"},
                    std::pair<std::string_view, std::string_view>{"user-center", "user-center.html"},
                    std::pair<std::string_view, std::string_view>{"product-detail", "product-detail.html"},
                    std::pair<std::string_view, std::string_view>{"index", "index.html"},
                };

                for (const auto &[route, file] : route_map)
                {
                    if (path_view == route)
                    {
                        path_view = file;
                        break;
                    }
                }

                std::array<fs::path, 2> prefixes = {
                    kind == srv::site_kind::stats_site ? file_path / "stats" : file_path / "main",
                    kind == srv::site_kind::stats_site ? file_path / "main" : file_path / "stats",
                };

                for (const auto &prefix : prefixes)
                {
                    fs::path candidate = prefix / path_view;
                    std::error_code check_ec;
                    if (fs::exists(candidate, check_ec) && fs::is_regular_file(candidate, check_ec))
                    {
                        return candidate;
                    }
                }

                return file_path / path_view;
            };

            file_path = resolve_path(target);

            // 检查文件是否存在
            std::error_code ec;
            if (fs::exists(file_path, ec) && fs::is_regular_file(file_path, ec))
            {
                std::ifstream file(file_path, std::ios::binary);
                if (file)
                {
                    // 获取文件大小
                    file.seekg(0, std::ios::end);
                    const auto size = file.tellg();
                    file.seekg(0, std::ios::beg);

                    // 读取文件内容
                    memory::string content(size, '\0', memory::current_resource());
                    file.read(content.data(), size);

                    res.status(protocol::http::status::ok);
                    res.set(protocol::http::field::content_type, srv::mime::obtain_mapping(file_path.string()));
                    res.body(std::move(content));
                }
                else
                {
                    // 文件存在但无法读取，视为 404 或者 500
                    res = srv::preload::error_404();
                }
            }
            else
            {
                res = srv::preload::error_404();
            }
        }

        // 发送响应
        const auto response_data = protocol::http::serialize(res, memory::current_resource());
        co_await boost::asio::async_write(socket, boost::asio::buffer(response_data), boost::asio::use_awaitable);
    }

    boost::asio::awaitable<void> http(boost::asio::ip::tcp::socket &socket, srv::site_kind kind)
    {
        protocol::http::request req;
        auto req_code = co_await protocol::http::async_read(socket, req, memory::current_resource());
        if (gist::failed(req_code))
        {
            trace::error("http read failed: {}", gist::cached_message(req_code));
            co_return;
        }
        protocol::http::response res;
        co_await frontend(socket, req, res, kind);
        trace::debug("http finish");
    }
}
