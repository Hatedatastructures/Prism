#include <forward-engine/protocol/analysis.hpp>
#include <array>

namespace ngx::protocol
{
    namespace
    {
        /**
         * @brief 获取内存资源
         * @param req HTTP 请求
         * @param mr 提供的内存资源指针
         * @return 优先使用 mr，否则使用 req 的内存资源
         */
        [[nodiscard]] auto resolve_mr(const http::request &req, const memory::resource_pointer mr) noexcept
            -> memory::resource_pointer
        {
            if (mr)
            {
                return mr;
            }
            return req.target().get_allocator().resource();
        }

        /**
         * @brief 解析绝对 URI
         * @param uri 要解析的 URI
         * @param host 解析出的主机名
         * @param port 解析出的端口号
         * @param path 解析出的路径
         * @return 如果解析成功，返回 true；否则返回 false
         * @details 支持 HTTP 和 HTTPS 协议。
         */
        auto parse_absolute_uri(const std::string_view uri, memory::string &host, memory::string &port, memory::string &path)
            -> bool
        {
            std::string_view working = uri;
            std::string_view scheme;

            if (working.starts_with("http://"))
            {
                scheme = "http";
                working.remove_prefix(7);
            }
            else if (working.starts_with("https://"))
            {
                scheme = "https";
                working.remove_prefix(8);
            }
            else
            {
                return false;
            }

            const auto slash_pos = working.find('/');
            const std::string_view authority = (slash_pos == std::string_view::npos) ? working : working.substr(0, slash_pos);
            const std::string_view path_part = (slash_pos == std::string_view::npos) ? std::string_view("/") : working.substr(slash_pos);

            if (scheme == "https")
            {
                port.assign("443");
            }
            else
            {
                port.assign("80");
            }

            if (const auto pos = authority.find(':'); pos != std::string_view::npos)
            {
                host.assign(authority.substr(0, pos).begin(), authority.substr(0, pos).end());
                port.assign(authority.substr(pos + 1).begin(), authority.substr(pos + 1).end());
            }
            else
            {
                host.assign(authority.begin(), authority.end());
            }
            path.assign(path_part.begin(), path_part.end());
            return !host.empty();
        }
    }

    auto analysis::detect(const std::string_view peek_data)
        -> protocol_type
    {
        // HTTP 方法列表 (最短的 3 字节 GET/PUT)
        static constexpr std::array<std::string_view, 9> http_methods =
            {
                "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
                "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};

        if (peek_data.size() < 1)
            return protocol_type::unknown;

        // 1. 检查 SOCKS5 (0x05)
        if (peek_data[0] == 0x05)
        {
            return protocol_type::socks5;
        }

        // 2. 检查 TLS (0x16)
        if (peek_data[0] == 0x16)
        {
            return protocol_type::tls;
        }

        // 3. 检查 HTTP
        for (const auto &method : http_methods)
        {
            if (peek_data.size() >= method.size() && peek_data.substr(0, method.size()) == method)
            {
                return protocol_type::http;
            }
        }

        // 4. 未知
        return protocol_type::unknown;
    }

    auto analysis::resolve(const http::request &req, const memory::resource_pointer mr)
        -> analysis::target
    {
        target t(resolve_mr(req, mr));

        // A. `CONNECT` 只会出现在正向代理请求中，请求行已明确给出目标 `host:port`
        if (req.method() == http::verb::connect)
        {
            t.positive = true;
            parse(req.target(), t.host, t.port);
            if (t.port == "80")
                t.port.assign("443");
        }
        // B. 绝对 `URI`（`http://`/`https://`）只在正向代理里出现，请求行已包含完整目标
        else if (req.target().starts_with("http://") || req.target().starts_with("https://"))
        {
            t.positive = true;
            memory::string path(t.host.get_allocator().resource());
            parse_absolute_uri(req.target(), t.host, t.port, path);
        }
        // C. 相对路径请求通常是反向代理场景，真实目标由 `Host` 头和路由表决定
        else
        {
            t.positive = false;
            auto host_val = req.at(http::field::host);
            parse(host_val, t.host, t.port);
        }

        return t;
    }

    auto analysis::resolve(const std::string_view host_port, const memory::resource_pointer mr)
        -> analysis::target
    {
        target t(mr ? mr : memory::current_resource());
        t.positive = true;
        parse(host_port, t.host, t.port);
        return t;
    }

    void analysis::parse(const std::string_view src, memory::string &host, memory::string &port)
    {
        if (const auto pos = src.find(':'); pos != std::string_view::npos)
        {
            host.assign(src.substr(0, pos).begin(), src.substr(0, pos).end());
            port.assign(src.substr(pos + 1).begin(), src.substr(pos + 1).end());
            if (port.empty())
            {
                port.assign("80");
            }
        }
        else
        {
            host.assign(src.begin(), src.end());
        }
    }
}
