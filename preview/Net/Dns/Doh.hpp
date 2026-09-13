/**
 * @file Doh.hpp
 * @brief DoH 传输（HTTP/1.1 承载 DNS，RFC 8484，可入池）
 * @details 复用 TlsTransport 建连与收发（组合而非继承），在其上实现
 *          HTTP 编解码；连接以 keep-alive 语义收发，配合 ConnPool 复用。
 *          响应解析加固：
 *          - 状态码必须为 200（HTTP/1.0 / 1.1）
 *          - 响应头累计上限 64KB，防恶意服务器撑爆内存
 *          - Content-Length 仅在头区内解析（防正文伪造头），体上限 64KB
 * @note 服务器仍可能按自身策略关闭 keep-alive 连接：从池中复用的
 *       连接首次收发失败由上层做一次新建重试（见 Upstream）
 */

#pragma once

#include "Config.hpp"
#include "Format.hpp"
#include "Transport.hpp"

#include <boost/asio.hpp>

#include <algorithm>
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
     * @details 将执行器、超时、TLS 上下文和 HTTP 参数收敛为
     *          一个配置对象，避免构造函数参数过多。
     */
    struct DohOptions
    {
        Net::any_io_executor Executor;
        std::chrono::milliseconds Timeout;
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
         * @param options 执行器、超时、TLS 上下文和 HTTP 参数
         */
        explicit DohTransport(DohOptions Options)
            : Tls_(std::move(Options.Executor), Options.Timeout, std::move(Options.Context)),
              HttpPath_(std::move(Options.HttpPath)), HostHeader_(std::move(Options.HostHeader))
        {
        }

        auto Connect(const Net::ip::tcp::endpoint &Endpoint, const Server &ServerConfig)
            -> Net::awaitable<boost::system::error_code>
        {
            co_return co_await Tls_.Connect(Endpoint, ServerConfig);
        }

        /// 发送 HTTP/1.1 POST（头 + DNS 报文合并单次写：一个 TLS 记录）
        auto Send(std::span<const std::uint8_t> Wire) -> Net::awaitable<boost::system::error_code>
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

            boost::system::error_code ErrorCode;
            Tls_.Arm();
            co_await Net::async_write(Tls_.Stream(), Net::buffer(Request),
                                      Net::redirect_error(Net::use_awaitable, ErrorCode));
            Tls_.Disarm();
            co_return ErrorCode;
        }

        /// 读取并解析 HTTP 响应，剥离出 DNS 报文体的原始字节
        auto Receive() -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>
        {
            constexpr std::string_view Delim = "\r\n\r\n";
            constexpr std::size_t MaxHeaderBytes = 65536;
            constexpr std::size_t MaxBodyBytes = 65536;
            const auto Bad = []()
            {
                return boost::system::errc::make_error_code(boost::system::errc::bad_message);
            };

            // ── 1. 读到头区结束（\r\n\r\n），累计上限 64KB ──
            std::string Raw;
            boost::system::error_code ErrorCode;
            while (Raw.find(Delim) == std::string::npos)
            {
                std::array<std::uint8_t, 2048> Buffer{};
                Tls_.Arm();
                const auto Count = co_await Tls_.Stream().async_read_some(
                    Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ErrorCode));
                Tls_.Disarm();
                if (ErrorCode)
                {
                    co_return std::unexpected(ErrorCode);
                }
                Raw.append(reinterpret_cast<const char *>(Buffer.data()), Count);
                if (Raw.size() > MaxHeaderBytes)
                {
                    co_return std::unexpected(Bad());
                }
            }

            // ── 2. 状态码必须为 200 ──
            const auto HeaderEnd = Raw.find(Delim);
            const auto HeaderView =
                std::string_view(Raw).substr(0, HeaderEnd);
            if (!HeaderView.starts_with("HTTP/1.1 200") && !HeaderView.starts_with("HTTP/1.0 200"))
            {
                co_return std::unexpected(Bad());
            }

            // ── 3. Content-Length 仅在头区内解析（纯数字，体上限 64KB）──
            const auto ClKey = std::string_view("Content-Length:");
            auto ClPos = HeaderView.find(ClKey);
            if (ClPos == std::string_view::npos)
            {
                ClPos = HeaderView.find("content-length:"); // 小写形式同样自此处起解析
            }
            std::size_t ContentLength = 0;
            if (ClPos != std::string_view::npos)
            {
                auto Value = HeaderView.substr(ClPos + ClKey.size());
                const auto ValueEnd = Value.find("\r\n");
                if (ValueEnd != std::string_view::npos)
                {
                    Value = Value.substr(0, ValueEnd);
                }
                std::size_t Start = 0;
                while (Start < Value.size() && (Value[Start] == ' ' || Value[Start] == '\t'))
                {
                    ++Start; // 跳过冒号后的空白
                }
                for (auto Index = Start; Index < Value.size(); ++Index)
                {
                    const auto Character = Value[Index];
                    if (Character < '0' || Character > '9')
                    {
                        break;
                    }
                    ContentLength = ContentLength * 10 +
                                    static_cast<std::size_t>(Character - '0');
                    if (ContentLength > MaxBodyBytes)
                    {
                        co_return std::unexpected(Bad());
                    }
                }
            }
            if (ContentLength == 0)
            {
                co_return std::unexpected(Bad());
            }

            // ── 4. 头区后已到达的字节 + 补读剩余 ──
            std::vector<std::uint8_t> Body(
                Raw.begin() + static_cast<std::ptrdiff_t>(HeaderEnd + Delim.size()), Raw.end());
            if (Body.size() > ContentLength)
            {
                Body.resize(ContentLength);
            }
            while (Body.size() < ContentLength)
            {
                std::array<std::uint8_t, 2048> Buffer{};
                Tls_.Arm();
                const auto Count = co_await Tls_.Stream().async_read_some(
                    Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ErrorCode));
                Tls_.Disarm();
                if (ErrorCode)
                {
                    co_return std::unexpected(ErrorCode);
                }
                const auto Take = std::min<std::size_t>(
                    Count, ContentLength - Body.size());
                Body.insert(Body.end(), Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Take));
            }
            co_return Body;
        }

        auto IsOpen() const -> bool
        {
            return Tls_.IsOpen();
        }

        auto Close() -> void
        {
            Tls_.Close();
        }

        /// 暴露给池/上层：底层 TLS 流的 Arm/Disarm 由本类收发操作委托使用
        void Arm()
        {
            Tls_.Arm();
        }

        void Disarm()
        {
            Tls_.Disarm();
        }

    private:
        TlsTransport Tls_;
        std::string HttpPath_;
        std::string HostHeader_;
    };

    static_assert(TransportLink<DohTransport> && PoolableTransport<DohTransport>);

} // namespace Preview::Network::Dns
