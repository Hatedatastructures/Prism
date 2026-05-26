#include <prism/recognition/target.hpp>

#include <array>

namespace psm::recognition
{

    namespace
    {
        // HTTP 方法列表，用于协议检测（最短 4 字节 "GET "）
        static constexpr std::array<std::string_view, 9> http_methods = {
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
            "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};

        // 获取内存资源，优先使用 mr，否则使用默认内存资源
        [[nodiscard]] auto resolve_mr(const memory::resource_pointer mr) noexcept
            -> memory::resource_pointer
        {
            if (mr)
                return mr;
            return memory::current_resource();
        }

        // 解析绝对 URI，支持 HTTP 和 HTTPS 协议
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
            std::string_view authority;
            if (slash_pos == std::string_view::npos)
            {
                authority = working;
            }
            else
            {
                authority = working.substr(0, slash_pos);
            }
            std::string_view path_part;
            if (slash_pos == std::string_view::npos)
            {
                path_part = std::string_view("/");
            }
            else
            {
                path_part = working.substr(slash_pos);
            }

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

    auto resolve(const protocol::http::proxy_request &req, const memory::resource_pointer mr)
        -> protocol::target
    {
        protocol::target t(resolve_mr(mr));

        // A. `CONNECT` 只会出现在正向代理请求中，请求行已明确给出目标 `host:port`
        if (req.method == "CONNECT")
        {
            t.positive = true;
            const auto raw = req.target;
            parse(raw, t.host, t.port);

            // CONNECT 通常用于 HTTPS 隧道，无显式端口时默认 443
            bool has_explicit_port = false;
            if (raw[0] == '[')
            {
                has_explicit_port = raw.find("]:") != std::string_view::npos;
            }
            else
            {
                has_explicit_port = raw.find(':') != std::string_view::npos &&
                                    raw.find(':') == raw.rfind(':');
            }
            if (!has_explicit_port)
            {
                t.port.assign("443");
            }
        }
        // B. 绝对 `URI`（`http://`/`https://`）只在正向代理里出现，请求行已包含完整目标
        else if (req.target.starts_with("http://") || req.target.starts_with("https://"))
        {
            t.positive = true;
            memory::string path(t.host.get_allocator().resource());
            parse_absolute_uri(req.target, t.host, t.port, path);
        }
        // C. 相对路径请求通常是反向代理场景，真实目标由 `Host` 头和路由表决定
        else
        {
            t.positive = false;
            auto host_val = req.host;
            parse(host_val, t.host, t.port);
        }

        return t;
    }

    auto resolve(const std::string_view host_port, const memory::resource_pointer mr)
        -> protocol::target
    {
        memory::resource_pointer effective_mr;
        if (mr)
        {
            effective_mr = mr;
        }
        else
        {
            effective_mr = memory::current_resource();
        }
        protocol::target t(effective_mr);
        t.positive = true;
        parse(host_port, t.host, t.port);
        return t;
    }

    void parse(const std::string_view src, memory::string &host, memory::string &port)
    {
        if (src.empty())
        {
            return;
        }

        if (src[0] == '[')
        {
            const auto closing_bracket = src.find(']');
            if (closing_bracket == std::string_view::npos)
            {
                host.assign(src.begin(), src.end());
                return;
            }

            host.assign(src.substr(1, closing_bracket - 1).begin(), src.substr(1, closing_bracket - 1).end());

            if (closing_bracket + 1 < src.size() && src[closing_bracket + 1] == ':')
            {
                port.assign(src.substr(closing_bracket + 2).begin(), src.substr(closing_bracket + 2).end());
            }
            else
            {
                port.assign("80");
            }
        }
        else
        {
            const auto last_colon = src.rfind(':');
            if (last_colon != std::string_view::npos)
            {
                const auto first_colon = src.find(':');
                if (first_colon == last_colon)
                {
                    host.assign(src.substr(0, last_colon).begin(), src.substr(0, last_colon).end());
                    port.assign(src.substr(last_colon + 1).begin(), src.substr(last_colon + 1).end());
                }
                else
                {
                    host.assign(src.begin(), src.end());
                    port.assign("80");
                }

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
}
