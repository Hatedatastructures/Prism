/**
 * @file Conn.hpp
 * @brief HTTP/1.1 入站代理握手连接
 * @details 服务端：读头 → 解析 →（可选认证）→ 400/407；CONNECT 的
 *          200/502 响应由拨号后的 handler 发送
 *          - ReadRequest：读完整请求头（65536 上限防慢速 OOM）
 *          - SendResponse：标准响应（200/400/407/502）
 *          客户端：SendConnect / ReadResponse（状态码验证）
 * @note HTTP CONNECT 握手与隧道交接由当前 Prism HTTP/1.1 carrier 实现。
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

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Protocols/Http1/ForwardRequest.hpp>
#include <Prism/Transport/Preview.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11
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
     * @brief 向 HTTP 客户端发送完整响应
     * @param Transport 客户端侧传输
     * @param Body 完整响应字节
     * @return 成功或 io_error
     */
    [[nodiscard]] inline auto SendResponse(SharedTransmission Transport,
                                            std::string_view Body)
        -> Net::awaitable<Fault::Failure>
    {
        if (!Transport)
        {
            co_return Fault::Failure{Fault::Code::IoError};
        }
        const auto Result = co_await Transport->WriteExact(AsBytesSpan(Body));
        if (Result.Failure.Failed())
        {
            co_return Result.Failure;
        }
        if (Result.Bytes != Body.size())
        {
            co_return Fault::Failure{Fault::Code::IoError};
        }
        co_return Fault::Failure{Fault::Code::Success};
    }

    /**
     * @class ServerConn
     * @brief HTTP 入站代理服务端握手连接
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
        explicit ServerConn(SharedTransmission Transport,
                            std::shared_ptr<Prism::Memory::BytePool> Bytes)
            : Transport_(std::move(Transport)), Bytes_(std::move(Bytes))
        {
            Buffer_.resize(4096);
        }

        /**
         * @brief 读取并解析完整请求头
         * @param Request 解析结果
         * @return 请求解析状态或原样保留 Native 的读失败。
         */
        [[nodiscard]] auto ReadRequest(HttpRequest &Request)
            -> Net::awaitable<Fault::Failure>
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
                        Request_ = Request;
                        Used_ = Used;
                        const auto BodyOffset = HeadersEnd + 4;
                        if (BodyOffset < Used)
                        {
                            const auto Tail = AsBytesSpan(
                                std::string_view(Buffer_.data() + BodyOffset, Used - BodyOffset));
                            Preread_.assign(Tail.begin(), Tail.end());
                        }
                        co_return Fault::Failure{Fault::Code::Success};
                    }
                    co_return Fault::Failure{Fault::Code::ParseError};
                }
                if (Used >= Buffer_.size())
                {
                    if (Buffer_.size() >= MaxHdrSize)
                    {
                        co_return Fault::Failure{Fault::Code::ParseError};
                    }
                    Buffer_.resize(Buffer_.size() * 2);
                }
                const auto Part = co_await Transport_->ReadSome(
                    AsBytesSpan(std::span(Buffer_.data() + Used, Buffer_.size() - Used)));
                const auto Count = Part.Bytes;
                if (Part.Failure.Failed())
                {
                    co_return Part.Failure;
                }
                if (Count == 0)
                {
                    co_return Fault::Failure{Fault::Code::IoError};
                }
                if (Count > Buffer_.size() - Used)
                {
                    co_return Fault::Failure{Fault::Code::IoError};
                }
                Used += Count;
            }
        }

        /**
         * @brief 发送标准响应
         * @param Body 响应字节
         * @return 成功或 io_error
         */
        [[nodiscard]] auto SendResponse(std::string_view Body)
            -> Net::awaitable<Fault::Failure>
        {
            co_return co_await Prism::Http11::SendResponse(Transport_, Body);
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
            const auto Created = Prism::Transport::PreviewTransport::Create(
                Transport_, Prism::Transport::PrefixInput{
                    std::span<const std::byte>(Preread_.data(), Preread_.size()), Bytes_, {}});
            if (!Created)
            {
                return {};
            }
            Transport_.reset();
            return *Created;
        }

        /**
         * @brief 释放普通 HTTP 请求的转发流
         * @return 先回放 origin-form 请求行、源站头字段和首请求正文的传输
         * @details 普通代理请求的请求头已经被握手读取；认证信息与逐跳字段
         *          在序列化时移除。Content-Length、chunked、无正文请求只消费
         *          首个消息边界；CONNECT 仍由 Release() 保持原始隧道语义。
         */
        [[nodiscard]] auto ReleaseForward() -> SharedTransmission
        {
            if (!Transport_)
            {
                return {};
            }
            const auto Raw = std::string_view(Buffer_.data(), Used_);
            const auto HeaderRaw = Raw.substr(0, Request_.HdrEnd);
            const auto Forwarded = BuildForwardRequest(HeaderRaw, Request_);
            if (Forwarded.empty())
            {
                return {};
            }
            ForwardRequestOptions Options;
            Options.Inner = std::move(Transport_);
            Options.Header = Forwarded;
            Options.Preread = std::move(Preread_);
            const auto UpgradeRequested = Request_.Headers.HasUpgrade &&
                                          Request_.Headers.ConnectionContains("upgrade");
            Options.AwaitUpgrade = UpgradeRequested;
            if (Request_.Headers.HasTransferEncoding)
            {
                Options.BodyMode = ForwardBodyMode::Chunked;
            }
            else if (Request_.Headers.HasContentLength)
            {
                Options.BodyMode = ForwardBodyMode::ContentLength;
                Options.ContentLength = Request_.Headers.ContentLength;
            }
            return MakeForwardRequestTransport(std::move(Options));
        }

    private:
        SharedTransmission Transport_; ///< 底层传输
        std::string Buffer_;            ///< 读缓冲
        std::vector<std::byte> Preread_; ///< 请求头之后已读入的隧道数据
        HttpRequest Request_{};          ///< 最近一次握手解析结果
        std::size_t Used_{0};            ///< 握手阶段已读取的原始字节数
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
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
        const auto Bytes = AsBytesSpan(Req);
        const auto Result = co_await Params.Transport->WriteExact(Bytes);
        if (Result.Failure.Failed() || Result.Bytes != Bytes.size())
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
        std::error_code &ErrorCode,
        std::shared_ptr<Prism::Memory::BytePool> Bytes) -> Net::awaitable<int>
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
                    const auto Created = Prism::Transport::PreviewTransport::Create(
                        Transport, Prism::Transport::PrefixInput{
                            AsBytesSpan(std::string_view(Buffer.data() + BodyOffset, Used - BodyOffset)),
                            Bytes, {}});
                    if (!Created)
                    {
                        ErrorCode = Prism::Fault::ToNative(Created.error());
                        co_return 0;
                    }
                    Transport = *Created;
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
            const auto Part = co_await Transport->ReadSome(
                AsBytesSpan(std::span(Buffer.data() + Used, Buffer.size() - Used)));
            ErrorCode = Prism::Fault::ToNative(Part.Failure);
            const auto Count = Part.Bytes;
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

} // namespace Prism::Http11
