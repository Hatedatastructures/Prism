/**
 * @file conn.hpp
 * @brief HTTP/1.1 CONNECT 握手连接（T3-5 / D4）
 * @details 服务端：读头 → 解析 →（可选认证）→ 200/400/407
 *          - read_request：读完整请求头（65536 上限防慢速 OOM）
 *          - check_basic：Proxy-Authorization 校验（Basic + authenticator）
 *          - send_response：标准响应（200/400/407/502）
 *          客户端：send_connect / read_response（状态码验证）
 * @note 参照主项目 src/prism/protocol/http/handler/conn.cpp
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <common/core/authenticator.hpp>
#include <common/core/crypto/base64.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/http/parser.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::http11
{

    namespace net = boost::asio;

    /**
     * @brief 标准响应（无 body）
     */
    namespace status
    {
        constexpr std::string_view ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        constexpr std::string_view bad_request = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        constexpr std::string_view proxy_auth_required = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                                         "Proxy-Authenticate: Basic\r\n"
                                                         "Content-Length: 0\r\n"
                                                         "\r\n";
        constexpr std::string_view bad_gateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    } // namespace status

    /// @brief 最大 HTTP 头部大小（防慢速 OOM 攻击）
    inline constexpr std::size_t max_hdr_size = 65536;

    /**
     * @brief 校验 Basic 认证头
     * @param authorization Proxy-Authorization 值（"Basic <base64>"）
     * @param auth 认证器
     * @return 认证结果（ok + identity）
     */
    [[nodiscard]] inline auto check_basic(const std::string_view authorization,
                                          const psmtest::authenticator &auth) -> psmtest::auth_result
    {
        constexpr std::string_view basic_prefix = "Basic ";
        if (authorization.size() <= basic_prefix.size() ||
            !authorization.starts_with(basic_prefix))
        {
            return {false, {}};
        }
        const auto decoded = psmtest::crypto::base64_decode(authorization.substr(basic_prefix.size()));
        const auto colon = decoded.find(':');
        if (colon == std::string_view::npos || colon == decoded.size() - 1)
        {
            return {false, {}};
        }
        const auto user = std::string_view(decoded).substr(0, colon);
        const auto pass = std::string_view(decoded).substr(colon + 1);
        return auth.check(user, pass);
    }

    /**
     * @class server_conn
     * @brief HTTP CONNECT 服务端握手连接
     * @details 包装传输层，提供请求读取与响应发送。
     *          握手成功后释放传输层（release）交由隧道使用。
     */
    class server_conn
    {
    public:
        /**
         * @brief 构造
         * @param transport 底层传输
         */
        explicit server_conn(shared_transmission transport) : transport_(std::move(transport))
        {
            buffer_.resize(4096);
        }

        /**
         * @brief 读取并解析完整请求头
         * @param out 解析结果
         * @return 成功或 io_error/parse_error
         */
        [[nodiscard]] auto read_request(http_request &out) -> net::awaitable<fault::code>
        {
            std::size_t used = 0;
            while (true)
            {
                const auto sv = std::string_view(buffer_.data(), used);
                if (sv.find("\r\n\r\n") != std::string_view::npos)
                {
                    const auto rc = parse_request(sv, out);
                    co_return rc == fault::code::success ? fault::code::success : fault::code::parse_error;
                }
                if (used >= buffer_.size())
                {
                    if (buffer_.size() >= max_hdr_size)
                    {
                        co_return fault::code::parse_error;
                    }
                    buffer_.resize(buffer_.size() * 2);
                }
                std::error_code ec;
                const auto n = co_await transport_->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(buffer_.data() + used), buffer_.size() - used), ec);
                if (ec || n == 0)
                {
                    co_return fault::code::io_error;
                }
                used += n;
            }
        }

        /**
         * @brief 发送标准响应
         * @param body 响应字节
         * @return 成功或 io_error
         */
        [[nodiscard]] auto send_response(const std::string_view body) -> net::awaitable<fault::code>
        {
            std::error_code ec;
            const auto span = std::span(reinterpret_cast<const std::byte *>(body.data()), body.size());
            co_await transport_->async_write(span, ec);
            co_return ec ? fault::code::io_error : fault::code::success;
        }

        /**
         * @brief 释放传输层（握手成功后交给隧道）
         * @return 底层传输
         */
        [[nodiscard]] auto release() -> shared_transmission
        {
            return std::move(transport_);
        }

    private:
        shared_transmission transport_; ///< 底层传输
        std::string buffer_;            ///< 读缓冲
    };

    /**
     * @brief 客户端发送 CONNECT 请求
     * @param transport 底层传输
     * @param host 目标主机
     * @param port 目标端口
     * @param authorization Basic 凭据（可选）
     * @return 成功或 io_error
     */
    [[nodiscard]] inline auto send_connect(shared_transmission transport, const std::string_view host,
                                           const std::uint16_t port,
                                           const std::string_view authorization = {})
        -> net::awaitable<fault::code>
    {
        const auto req = make_connect_request(host, port, authorization);
        std::error_code ec;
        const auto span = std::span(reinterpret_cast<const std::byte *>(req.data()), req.size());
        co_await transport->async_write(span, ec);
        co_return ec ? fault::code::io_error : fault::code::success;
    }

    /**
     * @brief 客户端读取响应并返回状态码
     * @param transport 底层传输
     * @param ec 错误码
     * @return 状态码（0 = 读失败）
     */
    [[nodiscard]] inline auto read_response(shared_transmission transport, std::error_code &ec)
        -> net::awaitable<int>
    {
        std::string buf;
        buf.resize(1024);
        std::size_t used = 0;
        while (true)
        {
            const auto sv = std::string_view(buf.data(), used);
            if (sv.find("\r\n\r\n") != std::string_view::npos)
            {
                co_return parse_status_code(sv);
            }
            if (used >= buf.size())
            {
                buf.resize(buf.size() * 2);
            }
            const auto n = co_await transport->async_read_some(
                std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data() + used), buf.size() - used),
                ec);
            if (ec || n == 0)
            {
                co_return 0;
            }
            used += n;
        }
    }

} // namespace psmtest::http11
