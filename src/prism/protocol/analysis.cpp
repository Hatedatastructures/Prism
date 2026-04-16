#include <prism/protocol/analysis.hpp>
#include <array>

namespace psm::protocol
{
    namespace
    {
        /// HTTP 方法列表，用于协议检测（最短 4 字节 "GET "）
        static constexpr std::array<std::string_view, 9> http_methods = {
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
            "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};

        /**
         * @brief 获取内存资源
         * @param mr 提供的内存资源指针
         * @return 优先使用 mr，否则使用默认内存资源
         */
        [[nodiscard]] auto resolve_mr(const memory::resource_pointer mr) noexcept
            -> memory::resource_pointer
        {
            return mr ? mr : memory::current_resource();
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
        if (peek_data.empty())
            return protocol_type::unknown;

        // 1. 检查 SOCKS5 (0x05)
        if (peek_data[0] == 0x05)
        {
            return protocol_type::socks5;
        }

        // 2. 检查 TLS (0x16 0x03)
        // TLS 记录格式: ContentType(1) + ProtocolVersion(2)，版本高字节固定 0x03
        // 必须检查两字节，否则 SS2022 的随机 salt 约有 1/256 概率首字节为 0x16
        if (peek_data.size() >= 2 && peek_data[0] == 0x16 && peek_data[1] == 0x03)
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

        // 4. SS2022 fallback
        // SS2022 数据全是 AEAD 加密随机字节（salt + 加密头），无特征可识别。
        // 排除 SOCKS5(0x05)、TLS(0x16)、HTTP 后，尝试 SS2022。
        // relay 的 handshake() 会通过 AEAD 解密验证来确认。
        return protocol_type::shadowsocks;
    }

    auto analysis::detect_tls(const std::string_view peek_data)
        -> protocol_type
    {
        for (const auto &method : http_methods)
        {
            if (peek_data.size() >= method.size() &&
                peek_data.substr(0, method.size()) == method)
            {
                return protocol_type::http;
            }
        }

        // VLESS 检测（最小 22 字节）
        // byte[0] = 0x00 (version), byte[17] = 0x00 (no additional info)
        // byte[18] in {0x01, 0x02, 0x7F} (valid command)
        // byte[21] in {0x01, 0x02, 0x03} (valid address type)
        if (peek_data.size() >= 22)
        {
            const auto b0 = static_cast<unsigned char>(peek_data[0]);
            const auto b17 = static_cast<unsigned char>(peek_data[17]);
            const auto b18 = static_cast<unsigned char>(peek_data[18]);
            const auto b21 = static_cast<unsigned char>(peek_data[21]);

            if (b0 == 0x00 && b17 == 0x00 && (b18 == 0x01 || b18 == 0x02 || b18 == 0x7F) &&
                (b21 == 0x01 || b21 == 0x02 || b21 == 0x03))
            {
                return protocol_type::vless;
            }
        }

        constexpr std::size_t trojan_min_length = 60;
        if (peek_data.size() >= trojan_min_length)
        {
            bool is_trojan = true;
            for (std::size_t i = 0; i < 56; ++i)
            {
                const auto c = static_cast<unsigned char>(peek_data[i]);
                const bool is_hex_digit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                                          (c >= 'A' && c <= 'F');
                if (!is_hex_digit)
                {
                    is_trojan = false;
                    break;
                }
            }

            if (is_trojan && peek_data[56] == '\r' && peek_data[57] == '\n')
            {
                const auto cmd = static_cast<unsigned char>(peek_data[58]);
                if (cmd == 0x01 || cmd == 0x03 || cmd == 0x7F)
                {
                    const auto atyp = static_cast<unsigned char>(peek_data[59]);
                    if (atyp == 0x01 || atyp == 0x03 || atyp == 0x04)
                    {
                        return protocol_type::trojan;
                    }
                }
            }
        }

        // SS2022 fallback：TLS 内层排除 HTTP/VLESS/Trojan 后，尝试 SS2022。
        // SS2022 数据全是 AEAD 加密随机字节，无法通过特征检测，只能排除法。
        // relay 的 handshake() 会通过 AEAD 解密验证来确认。
        return protocol_type::shadowsocks;
    }

    auto analysis::resolve(const http::proxy_request &req, const memory::resource_pointer mr)
        -> analysis::target
    {
        target t(resolve_mr(mr));

        // A. `CONNECT` 只会出现在正向代理请求中，请求行已明确给出目标 `host:port`
        if (req.method == "CONNECT")
        {
            t.positive = true;
            const auto raw = req.target;
            parse(raw, t.host, t.port);

            // CONNECT 通常用于 HTTPS 隧道，无显式端口时默认 443
            const bool has_explicit_port = (raw[0] == '[')
                                               ? (raw.find("]:") != std::string_view::npos)  // IPv6: [addr]:port
                                               : (raw.find(':') != std::string_view::npos && // IPv4/hostname: 有且仅有一个冒号
                                                  raw.find(':') == raw.rfind(':'));
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
