/**
 * @file Conn.hpp
 * @brief HTTP/1.1 CONNECT 握手连接（T3-5 / D4）
 * @details 服务端：读头 → 解析 →（可选认证）→ 200/400/407
 *          - ReadRequest：读完整请求头（65536 上限防慢速 OOM）
 *          - CheckBasic：Proxy-Authorization 校验（Basic + Authenticator）
 *          - SendResponse：标准响应（200/400/407/502）
 *          客户端：SendConnect / ReadResponse（状态码验证）
 * @note 参照主项目 src/prism/Protocol/http/handler/Conn.cpp
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

#include <common/Core/Authenticator.hpp>
#include <common/Core/ByteSpan.hpp>
#include <common/Core/Crypto/Base64.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Protocols/Http1/Parser.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Http11
{

    namespace net = boost::asio;

    /**
     * @brief 标准响应（无 body）
     */
    namespace status
    {
        constexpr std::string_view Ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        constexpr std::string_view BadRequest = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        constexpr std::string_view ProxyAuthRequired = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                                         "Proxy-Authenticate: Basic\r\n"
                                                         "Content-Length: 0\r\n"
                                                         "\r\n";
        constexpr std::string_view BadGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    } // namespace status

    /// @brief 最大 HTTP 头部大小（防慢速 OOM 攻击）
    inline constexpr std::size_t MaxHdrSize = 65536;

    /**
     * @brief 校验 Basic 认证头
     * @param authorization Proxy-Authorization 值（"Basic <base64>"）
     * @param Auth 认证器
     * @return 认证结果（Ok + identity）
     */
    [[nodiscard]] inline auto CheckBasic(std::string_view authorization,
                                          const Preview::Authenticator &Auth) -> Preview::AuthResult
    {
        constexpr std::string_view BasicPrefix = "Basic ";
        if (authorization.size() <= BasicPrefix.size() ||
            !authorization.starts_with(BasicPrefix))
        {
            return {false, {}};
        }
        const auto decoded = Preview::Crypto::Base64Decode(authorization.substr(BasicPrefix.size()));
        const auto colon = decoded.find(':');
        if (colon == std::string_view::npos || colon == decoded.size() - 1)
        {
            return {false, {}};
        }
        const auto user = std::string_view(decoded).substr(0, colon);
        const auto pass = std::string_view(decoded).substr(colon + 1);
        return Auth.Check(user, pass);
    }

    /**
     * @class ServerConn
     * @brief HTTP CONNECT 服务端握手连接
     * @details 包装传输层，提供请求读取与响应发送。
     *          握手成功后释放传输层（Release）交由隧道使用。
     */
    class ServerConn
    {
    public:
        /**
         * @brief 构造
         * @param transport 底层传输
         */
        explicit ServerConn(SharedTransmission transport) : transport_(std::move(transport))
        {
            buffer_.resize(4096);
        }

        /**
         * @brief 读取并解析完整请求头
         * @param out 解析结果
         * @return 成功或 io_error/parse_error
         */
        [[nodiscard]] auto ReadRequest(HttpRequest &out) -> net::awaitable<Fault::Code>
        {
            std::size_t used = 0;
            while (true)
            {
                const auto sv = std::string_view(buffer_.data(), used);
                if (sv.find("\r\n\r\n") != std::string_view::npos)
                {
                    const auto rc = ParseRequest(sv, out);
                    if (rc == Fault::Code::success)
                    {
                        co_return Fault::Code::success;
                    }
                    co_return Fault::Code::parse_error;
                }
                if (used >= buffer_.size())
                {
                    if (buffer_.size() >= MaxHdrSize)
                    {
                        co_return Fault::Code::parse_error;
                    }
                    buffer_.resize(buffer_.size() * 2);
                }
                std::error_code ec;
                const auto n = co_await transport_->AsyncReadSome(
                    AsBytesSpan(std::span(buffer_.data() + used, buffer_.size() - used)), ec);
                if (ec || n == 0)
                {
                    co_return Fault::Code::io_error;
                }
                used += n;
            }
        }

        /**
         * @brief 发送标准响应
         * @param body 响应字节
         * @return 成功或 io_error
         */
        [[nodiscard]] auto SendResponse(std::string_view body) -> net::awaitable<Fault::Code>
        {
            std::error_code ec;
            const auto span = AsBytesSpan(body);
            co_await transport_->AsyncWrite(span, ec);
            if (ec)
            {
                co_return Fault::Code::io_error;
            }
            co_return Fault::Code::success;
        }

        /**
         * @brief 释放传输层（握手成功后交给隧道）
         * @return 底层传输
         */
        [[nodiscard]] auto Release() -> SharedTransmission
        {
            return std::move(transport_);
        }

    private:
        SharedTransmission transport_; ///< 底层传输
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
    [[nodiscard]] inline auto SendConnect(SharedTransmission transport, std::string_view host,
                                           const std::uint16_t port,
                                           const std::string_view authorization = {})
        -> net::awaitable<Fault::Code>
    {
        const auto req = MakeConnectRequest(host, port, authorization);
        std::error_code ec;
        const auto span = AsBytesSpan(req);
        co_await transport->AsyncWrite(span, ec);
        if (ec)
        {
            co_return Fault::Code::io_error;
        }
        co_return Fault::Code::success;
    }

    /**
     * @brief 客户端读取响应并返回状态码
     * @param transport 底层传输
     * @param ec 错误码
     * @return 状态码（0 = 读失败）
     */
    [[nodiscard]] inline auto ReadResponse(SharedTransmission transport, std::error_code &ec)
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
                co_return ParseStatusCode(sv);
            }
            if (used >= buf.size())
            {
                if (buf.size() >= MaxHdrSize)
                {
                    ec = std::make_error_code(std::errc::message_size);
                    co_return 0; // 响应头超限（防恶意响应 OOM，与 Server 端一致）
                }
                buf.resize(buf.size() * 2);
            }
            const auto n = co_await transport->AsyncReadSome(
                    AsBytesSpan(std::span(buf.data() + used, buf.size() - used)), ec);
            if (ec || n == 0)
            {
                co_return 0;
            }
            used += n;
        }
    }

} // namespace Preview::Http11
