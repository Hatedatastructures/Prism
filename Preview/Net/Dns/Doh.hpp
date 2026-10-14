/**
 * @file Doh.hpp
 * @brief DoH 传输（HTTP/1.1 承载 DNS，RFC 8484，可入池）
 * @details 复用 TlsTransport 建连与字节流读写（组合而非继承），在其上实现
 *          HTTP 编解码；连接以 keep-alive 语义收发，配合 ConnPool 复用。
 *          每次收发的 deadline 由调用者传入的绝对 AttemptDeadline 决定，
 *          与 UDP/TCP/DoT 消费同一预算，不逐段重置。
 *          响应由 Foundation 的中立 framing owner 增量定界；DoH 启用有界正文捕获，
 *          只接受单个 Content-Length 或单一 chunked coding，并拒绝同一输入中的消息残余。
 *          状态行、头区、解码正文与 chunk/trailer overhead 使用独立上限。
 * @note 解析失败后本连接不再入池；DoH 不实现 HTTP pipelining，也不把残余字节带入下一查询。
 * @note 服务器仍可能按自身策略关闭 keep-alive 连接：从池中复用的
 *       连接首次收发失败由上层做一次新建重试（见 Upstream）
 */

#pragma once

#include "Config.hpp"
#include "Detail/TlsTransport.hpp"
#include "Format.hpp"
#include "Transport.hpp"

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Utility/Http/ForwardResponseFraming.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;

    /**
     * @struct DohOptions
     * @brief DoH 传输构造选项
     * @details 将执行器、TLS 上下文和 HTTP 参数收敛为一个配置对象，
     *          避免构造函数参数过多；超时由每次操作的绝对 deadline 决定。
     */
    struct DohOptions
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Ssl::context> Context;
        std::string HttpPath;
        std::string HostHeader;
    };

    /**
     * @class DohTransport
     * @brief DoH 传输（满足 TransportLink / PoolableTransport）
     */
    class DohTransport
    {
    public:
        /**
         * @brief 构造 DoH 传输
         * @param Options 执行器、TLS 上下文和 HTTP 参数
         */
        explicit DohTransport(DohOptions Options)
            : Tls_(std::move(Options.Executor), std::move(Options.Context)),
              HttpPath_(std::move(Options.HttpPath)), HostHeader_(std::move(Options.HostHeader))
        {
        }

        /**
         * @brief 建立底层 TLS 连接
         * @param Endpoint 上游端点
         * @param ServerConfig SNI 与证书校验策略
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 建连错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Connect(const Net::ip::tcp::endpoint &Endpoint, const Server &ServerConfig,
                                   const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            co_return co_await Tls_.Connect(Endpoint, ServerConfig, Deadline);
        }

        /**
         * @brief 发送 HTTP/1.1 POST（头 + DNS 报文合并单次写：一个 TLS 记录）
         * @param Wire DNS 查询报文；只借用到发送完成
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 发送错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Send(std::span<const std::uint8_t> Wire,
                                const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            std::string Request;
            Request.reserve(224 + HttpPath_.size() + HostHeader_.size() + Wire.size());
            Request += "POST ";
            Request += HttpPath_;
            Request += " HTTP/1.1\r\nHost: ";
            Request += HostHeader_;
            Request += "\r\nContent-Type: application/dns-message\r\n";
            Request += "Accept: application/dns-message\r\nContent-Length: ";
            Request += std::to_string(Wire.size());
            Request += "\r\nConnection: keep-alive\r\n\r\n";
            Request.append(reinterpret_cast<const char *>(Wire.data()), Wire.size());

            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Request.data()), Request.size());
            co_return co_await Tls_.WriteAll(Bytes, Deadline);
        }

        /**
         * @brief 读取并解析 HTTP 响应，剥离出 DNS 报文体的原始字节
         * @param Deadline 本次尝试的绝对截止时刻
         * @return DNS 应答字节或 HTTP/传输错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Receive(const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>
        {
            constexpr std::size_t MaxHeaderBytes = 65536U;
            constexpr std::size_t MaxBodyBytes = 65536U;
            constexpr std::size_t MaxFramingBytes = 65536U;
            Preview::Http11::ForwardResponseFraming Framing({
                .CaptureBody = true,
                .MaxHeaderBytes = MaxHeaderBytes,
                .MaxDecodedBodyBytes = MaxBodyBytes,
                .MaxFramingBytes = MaxFramingBytes,
            });

            while (!Framing.IsComplete())
            {
                std::array<std::uint8_t, 2048> Buffer{};
                const auto Chunk = co_await Tls_.ReadSome(
                    std::span<std::uint8_t>(Buffer.data(), Buffer.size()), Deadline);
                if (!Chunk)
                {
                    const auto Native = Chunk.error();
                    Close();
                    co_return std::unexpected(Native);
                }
                if (*Chunk == 0U)
                {
                    Close();
                    co_return std::unexpected(
                        Preview::make_error_code(Preview::Error::UnexpectedEof));
                }

                const auto Input = std::as_bytes(std::span(Buffer.data(), *Chunk));
                const auto Framed = Framing.Consume(Input);
                if (Framed.ErrorCode != Preview::Error::None)
                {
                    const auto Native = Preview::make_error_code(Framed.ErrorCode);
                    Close();
                    co_return std::unexpected(Native);
                }
                if (Framed.Accepted != Input.size())
                {
                    Close();
                    co_return std::unexpected(
                        Preview::make_error_code(Preview::Error::BadMessage));
                }

                if (Framing.HasFinalResponseHeaders())
                {
                    const auto &Fields = Framing.ResponseFields();
                    const bool HasSingleLength = Fields.HasContentLength &&
                                                 !Fields.HasTransferEncoding &&
                                                 Fields.ContentLengthFieldCount == 1U &&
                                                 Fields.ContentLength > 0U &&
                                                 Fields.ContentLength <= MaxBodyBytes;
                    const bool HasSingleChunked = Fields.HasTransferEncoding &&
                                                  !Fields.HasContentLength &&
                                                  Fields.TransferCodingCount == 1U &&
                                                  Fields.FinalTransferCodingChunked;
                    if (Framing.StatusCode() != 200 ||
                        (!HasSingleLength && !HasSingleChunked) ||
                        Fields.ContentTypeFieldCount != 1U ||
                        !Fields.ContentTypeIs("application/dns-message"))
                    {
                        Close();
                        co_return std::unexpected(
                            Preview::make_error_code(Preview::Error::BadMessage));
                    }
                }
            }

            co_return Framing.TakeDecodedBody();
        }

        /// 底层连接是否仍打开
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return Tls_.IsOpen();
        }

        /// 关闭底层连接
        auto Close() -> void
        {
            Tls_.Close();
        }

    private:
        TlsTransport Tls_;
        std::string HttpPath_;
        std::string HostHeader_;
    };

    static_assert(TransportLink<DohTransport> && PoolableTransport<DohTransport>);

} // namespace Preview::Network::Dns
