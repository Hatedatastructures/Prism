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
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <preview/Foundation/Authenticator.hpp>
#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Utility/Crypto/Base64.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Protocols/Http1/Parser.hpp>
#include <preview/Transport/Preview.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Http11
{

    namespace Net = boost::asio;

    /**
     * @brief 标准响应（无 body）
     */
    namespace Status
    {
        constexpr std::string_view Ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        constexpr std::string_view BadRequest = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        constexpr std::string_view ProxyAuthRequired = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                                         "Proxy-Authenticate: Basic\r\n"
                                                         "Content-Length: 0\r\n"
                                                         "\r\n";
        constexpr std::string_view BadGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    } // namespace Status

    /**
     * @brief 校验 Basic 认证头
     * @param Authorization Proxy-Authorization 值（"Basic <base64>"）
     * @param Auth 认证器
     * @return 认证结果（Ok + identity）
     */
    [[nodiscard]] inline auto CheckBasic(
        std::string_view Authorization,
        const Preview::Authenticator &Auth) -> Preview::AuthResult
    {
        constexpr std::string_view BasicPrefix = "Basic ";
        if (Authorization.size() <= BasicPrefix.size() ||
            !Authorization.starts_with(BasicPrefix))
        {
            return {false, {}};
        }
        const auto Decoded = Preview::Crypto::Base64Decode(Authorization.substr(BasicPrefix.size()));
        const auto Colon = Decoded.find(':');
        if (Colon == std::string_view::npos || Colon == Decoded.size() - 1)
        {
            return {false, {}};
        }
        const auto User = std::string_view(Decoded).substr(0, Colon);
        const auto Pass = std::string_view(Decoded).substr(Colon + 1);
        return Auth.Check(User, Pass);
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
         * @param Transport 底层传输
         */
        explicit ServerConn(SharedTransmission Transport) : Transport_(std::move(Transport))
        {
            Buffer_.resize(4096);
        }

        /**
         * @brief 读取并解析完整请求头
         * @param Request 解析结果
         * @return 成功或 io_error/parse_error
         */
        [[nodiscard]] auto ReadRequest(HttpRequest &Request) -> Net::awaitable<Fault::Code>
        {
            std::size_t Used = 0;
            while (true)
            {
                const auto Sv = std::string_view(Buffer_.data(), Used);
                const auto HeadersEnd = Sv.find("\r\n\r\n");
                if (HeadersEnd != std::string_view::npos)
                {
                    const auto Result = ParseRequest(Sv, Request);
                    if (Result == Fault::Code::Success)
                    {
                        const auto BodyOffset = HeadersEnd + 4;
                        if (BodyOffset < Used)
                        {
                            const auto Tail = AsBytesSpan(
                                std::string_view(Buffer_.data() + BodyOffset, Used - BodyOffset));
                            Preread_.assign(Tail.begin(), Tail.end());
                        }
                        co_return Fault::Code::Success;
                    }
                    co_return Fault::Code::ParseError;
                }
                if (Used >= Buffer_.size())
                {
                    if (Buffer_.size() >= MaxHdrSize)
                    {
                        co_return Fault::Code::ParseError;
                    }
                    Buffer_.resize(Buffer_.size() * 2);
                }
                std::error_code ErrorCode;
                const auto Count = co_await Transport_->async_read_some(
                    AsBytesSpan(std::span(Buffer_.data() + Used, Buffer_.size() - Used)), ErrorCode);
                if (ErrorCode || Count == 0)
                {
                    co_return Fault::Code::IoError;
                }
                if (Count > Buffer_.size() - Used)
                {
                    co_return Fault::Code::IoError;
                }
                Used += Count;
            }
        }

        /**
         * @brief 发送标准响应
         * @param Body 响应字节
         * @return 成功或 io_error
         */
        [[nodiscard]] auto SendResponse(std::string_view Body) -> Net::awaitable<Fault::Code>
        {
            std::error_code ErrorCode;
            const auto Bytes = AsBytesSpan(Body);
            co_await Transport_->AsyncWrite(Bytes, ErrorCode);
            if (ErrorCode)
            {
                co_return Fault::Code::IoError;
            }
            co_return Fault::Code::Success;
        }

        /**
         * @brief 释放传输层（握手成功后交给隧道）
         * @return 底层传输
         */
        [[nodiscard]] auto Release() -> SharedTransmission
        {
            if (Preread_.empty())
            {
                return std::move(Transport_);
            }
            return Preview::Transport::WrapWithPreview(
                std::move(Transport_), std::span<const std::byte>(Preread_.data(), Preread_.size()));
        }

    private:
        SharedTransmission Transport_; ///< 底层传输
        std::string Buffer_;            ///< 读缓冲
        std::vector<std::byte> Preread_; ///< 请求头之后已读入的隧道数据
    };

    /**
     * @struct ConnectParameters
     * @brief HTTP/1.1 CONNECT 请求参数
     * @details Transport 的所有权转移给异步请求；字符串字段仅在请求期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Transport;
        std::string_view Host;
        std::uint16_t Port;
        std::string_view Authorization;
    };

    /**
     * @brief 客户端发送 CONNECT 请求
     * @param Params CONNECT 请求参数
     * @return 成功或 io_error
     */
    [[nodiscard]] inline auto SendConnect(ConnectParameters Params)
        -> Net::awaitable<Fault::Code>
    {
        const auto Req = MakeConnectRequest(Params.Host, Params.Port, Params.Authorization);
        std::error_code ErrorCode;
        const auto Bytes = AsBytesSpan(Req);
        co_await Params.Transport->AsyncWrite(Bytes, ErrorCode);
        if (ErrorCode)
        {
            co_return Fault::Code::IoError;
        }
        co_return Fault::Code::Success;
    }

    /**
     * @brief 使用无认证头发送 HTTP/1.1 CONNECT 请求
     * @param Transport 底层传输（所有权移交）
     * @param Host 目标主机
     * @param Port 目标端口
     * @return 成功或 io_error
     */
    [[nodiscard]] inline auto SendConnect(
        SharedTransmission Transport,
        std::string_view Host,
        std::uint16_t Port) -> Net::awaitable<Fault::Code>
    {
        auto Result = co_await SendConnect(ConnectParameters{std::move(Transport), Host, Port, {}});
        co_return Result;
    }

    /**
     * @brief 客户端读取响应并返回状态码
     * @param Transport 底层传输
     * @param ErrorCode 错误码
     * @return 状态码（0 = 读失败）
     */
    [[nodiscard]] inline auto ReadResponse(
        SharedTransmission &Transport,
        std::error_code &ErrorCode) -> Net::awaitable<int>
    {
        std::string Buffer;
        Buffer.resize(1024);
        std::size_t Used = 0;
        while (true)
        {
            const auto DataView = std::string_view(Buffer.data(), Used);
            const auto HeadersEnd = DataView.find("\r\n\r\n");
            if (HeadersEnd != std::string_view::npos)
            {
                const auto BodyOffset = HeadersEnd + 4;
                if (BodyOffset < Used)
                {
                    Transport = Preview::Transport::WrapWithPreview(
                        std::move(Transport),
                        AsBytesSpan(std::string_view(Buffer.data() + BodyOffset, Used - BodyOffset)));
                }
                co_return ParseStatusCode(DataView);
            }
            if (Used >= Buffer.size())
            {
                if (Buffer.size() >= MaxHdrSize)
                {
                    ErrorCode = std::make_error_code(std::errc::message_size);
                    co_return 0; // 响应头超限（防恶意响应 OOM，与 Server 端一致）
                }
                Buffer.resize(Buffer.size() * 2);
            }
            const auto Count = co_await Transport->async_read_some(
                AsBytesSpan(std::span(Buffer.data() + Used, Buffer.size() - Used)), ErrorCode);
            if (ErrorCode || Count == 0)
            {
                co_return 0;
            }
            if (Count > Buffer.size() - Used)
            {
                ErrorCode = std::make_error_code(std::errc::value_too_large);
                co_return 0;
            }
            Used += Count;
        }
    }

} // namespace Preview::Http11
