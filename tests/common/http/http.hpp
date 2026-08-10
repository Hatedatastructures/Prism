/**
 * @file http.hpp
 * @brief HTTP CONNECT 代理协议编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁无 I/O）：CONNECT 请求构造与解析、响应编解码。
 *          命名空间 psm_test::http，参考 mihomo adapter/outbound/http。
 */

#pragma once

#include <common/common.hpp>

namespace psm_test::http
{

    inline constexpr std::string_view status_ok = "200 Connection established";

    /**
     * @class client
     * @brief HTTP CONNECT 客户端（请求构造 + 响应解析）
     */
    class client
    {
    public:
        /**
         * @brief 构造 CONNECT 请求
         * @param host 目标主机
         * @param port 目标端口
         * @param extra_headers 附加头（每行不含 CRLF，可为空）
         */
        [[nodiscard]] auto connect_request(const std::string_view host, const std::uint16_t port,
                                           const std::string_view extra_headers = {}) const -> buffer
        {
            std::string req = "CONNECT " + std::string(host) + ":" + std::to_string(port)
                + " HTTP/1.1\r\nHost: " + std::string(host) + ":" + std::to_string(port) + "\r\n";
            if (!extra_headers.empty())
                req += std::string(extra_headers) + "\r\n";
            req += "\r\n";
            byte_writer w;
            w.write_bytes(req);
            return w.data();
        }

        /// 解析服务端响应首行（HTTP/1.1 2xx）
        [[nodiscard]] auto parse_response(const view data) const -> bool
        {
            const auto line = read_line(data);
            if (line.empty())
                return false;
            const auto sp1 = line.find(' ');
            if (sp1 == std::string::npos || line.substr(0, sp1) != "HTTP/1.1")
                return false;
            const auto sp2 = line.find(' ', sp1 + 1);
            const auto code = line.substr(sp1 + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp1 - 1);
            return code.size() == 3 && code[0] == '2';
        }

    private:
        static auto read_line(const view data) -> std::string
        {
            std::string line;
            for (const auto b : data)
            {
                if (b == '\r')
                    continue;
                if (b == '\n')
                    break;
                line.push_back(static_cast<char>(b));
                if (line.size() > 1024)
                    break;
            }
            return line;
        }
    };

    /**
     * @class server
     * @brief HTTP CONNECT 服务端（请求解析 + 响应构造）
     */
    class server
    {
    public:
        /// 解析结果
        struct connect_request
        {
            std::string host;
            std::uint16_t port{0};
            bool valid{false};
        };

        /// 解析 CONNECT 请求（首行 + Host 头）
        [[nodiscard]] auto parse_connect(const view data) const -> connect_request
        {
            connect_request req;
            std::string_view sv(reinterpret_cast<const char *>(data.data()), data.size());
            const auto header_end = sv.find("\r\n\r\n");
            if (header_end == std::string_view::npos)
                return req;
            const auto head = sv.substr(0, header_end);
            const auto line_end = head.find("\r\n");
            const auto line = head.substr(0, line_end);
            if (!line.starts_with("CONNECT "))
                return req;
            const auto target = line.substr(8);
            const auto sp = target.find(' ');
            const auto target_str = target.substr(0, sp);
            if (!split_host_port(target_str, req.host, req.port))
                return req;
            req.valid = true;
            return req;
        }

        /// 成功响应（200 + 空行）
        [[nodiscard]] static auto ok_response() -> buffer
        {
            byte_writer w;
            w.write_bytes("HTTP/1.1 " + std::string(status_ok) + "\r\n\r\n");
            return w.data();
        }

        /// 失败响应（502）
        [[nodiscard]] static auto fail_response() -> buffer
        {
            byte_writer w;
            w.write_bytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return w.data();
        }
    };

} // namespace psm_test::http
