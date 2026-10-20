/**
 * @file TlsTransport.hpp
 * @brief DoT 传输（TLS 承载 TCP 帧，可入池）与 DoH 复用的字节流读写
 * @details SNI 无条件发送（SkipCertCheck 的服务器同样可能要求 SNI）；
 *          证书校验策略由上层缓存的 ssl::context 决定。
 *          TLS 应用写与 DoH 分块读都消费同一个绝对 deadline；
 *          连接 owner 与 deadline handler 共享，不再有裸 this 回调。
 */

#pragma once

#include <Prism/Net/Dns/Transport.hpp>
#include <Prism/Net/Dns/Detail/Deadline.hpp>
#include <Prism/Net/Dns/Detail/Wire.hpp>

#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Network::Dns
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;

    namespace Detail
    {
        /** @brief TLS 任意长度读取；字节和终态可在同次完成中共存。 */
        struct TlsReadResult final
        {
            std::size_t Bytes{0};
            boost::system::error_code Failure;
        };

        enum class ExactReadState : std::uint8_t
        {
            Complete,
            CompleteWithTerminal,
            Failed
        };

        struct ExactRead final
        {
            std::size_t Bytes{0};
            boost::system::error_code Failure;
        };

        struct ExactReadOutcome final
        {
            ExactReadState State{ExactReadState::Failed};
            boost::system::error_code Failure;
        };

        /** @brief 仅在完整 DNS 帧上消费连接终态；取消与 deadline 仍是失败。 */
        [[nodiscard]] inline auto ClassifyExactRead(
            const ExactRead Read,
            const std::size_t ExpectedBytes) noexcept -> ExactReadOutcome
        {
            if (Read.Bytes == ExpectedBytes)
            {
                if (!Read.Failure)
                {
                    return {ExactReadState::Complete, {}};
                }
                if (Read.Failure != Net::error::operation_aborted &&
                    Read.Failure != Net::error::timed_out &&
                    Read.Failure != make_error_code(Error::Canceled) &&
                    Read.Failure != make_error_code(Error::Timeout))
                {
                    return {ExactReadState::CompleteWithTerminal, Read.Failure};
                }
            }
            if (Read.Failure)
            {
                return {ExactReadState::Failed, Read.Failure};
            }
            return {ExactReadState::Failed,
                boost::system::errc::make_error_code(boost::system::errc::bad_message)};
        }

        struct DnsFrameBodyRead final
        {
            std::vector<std::uint8_t> Body;
            std::size_t Bytes{0};
            boost::system::error_code Failure;
        };

        /** @brief 完整报文优先于同次远端终态；退休连接以免归还连接池。 */
        template <typename Retire>
        [[nodiscard]] inline auto FinishDnsFrameBody(
            DnsFrameBodyRead Read,
            Retire RetireLink) -> EcResult<std::vector<std::uint8_t>>
        {
            const auto Outcome = ClassifyExactRead(
                ExactRead{Read.Bytes, Read.Failure}, Read.Body.size());
            if (Outcome.State == ExactReadState::CompleteWithTerminal)
            {
                RetireLink();
                return std::move(Read.Body);
            }
            if (Outcome.State == ExactReadState::Failed)
            {
                return std::unexpected(Outcome.Failure);
            }
            return std::move(Read.Body);
        }
    } // namespace Detail

    /**
     * @class TlsTransport
     * @brief DoT 传输（TLS 承载 TCP 帧，可入池）
     */
    class TlsTransport
    {
    public:
        /**
         * @brief 构造 DoT 传输
         * @param Executor 流与定时器执行器
         * @param Context 共享 TLS 上下文
         */
        TlsTransport(Net::any_io_executor Executor, std::shared_ptr<Ssl::context> Context)
            : State_(std::make_shared<State>(Executor)), Ctx_(std::move(Context))
        {
        }

        /**
         * @brief 建立 TLS 连接并完成握手
         * @param Endpoint 上游端点
         * @param ServerConfig SNI 与证书校验策略
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 建连/握手错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Connect(const Net::ip::tcp::endpoint &Endpoint, const Server &ServerConfig,
                                   const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            const auto Connection = State_;
            const auto Context = Ctx_; // 共享上下文在挂起后仍由本地 owner 保持
            if (Deadline.Expired())
            {
                co_return make_error_code(Error::Timeout);
            }
            boost::system::error_code ErrorCode;
            Connection->Stream.emplace(Connection->Executor, *Context);
            std::string SniName = ServerConfig.Address;
            if (!ServerConfig.Hostname.empty())
            {
                SniName = ServerConfig.Hostname;
            }
            SSL_set_tlsext_host_name(Connection->Stream->native_handle(), SniName.c_str());
            if (!ServerConfig.SkipCertCheck)
            {
                Connection->Stream->set_verify_callback(Ssl::host_name_verification(SniName), ErrorCode);
                if (ErrorCode)
                {
                    co_return ErrorCode;
                }
            }
            const Detail::DeadlineScope<State> Scope(Connection, Deadline);
            co_await Connection->Stream->lowest_layer().async_connect(
                Endpoint, Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (!ErrorCode)
            {
                co_await Connection->Stream->async_handshake(
                    Ssl::stream_base::client, Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
            co_return Scope.Map(ErrorCode);
        }

        /**
         * @brief 发送长度前缀帧
         * @param Wire DNS 查询报文；只借用到发送完成
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 发送错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Send(std::span<const std::uint8_t> Wire,
                                const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            const auto FrameResult = Detail::MakeTcpFrame(Wire);
            if (!FrameResult)
            {
                co_return FrameResult.error();
            }
            co_return co_await WriteAll(std::span<const std::uint8_t>(*FrameResult), Deadline);
        }

        /**
         * @brief 接收长度前缀帧
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 应答字节或传输错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Receive(const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>
        {
            const auto Connection = State_;
            if (Deadline.Expired())
            {
                co_return std::unexpected(make_error_code(Error::Timeout));
            }
            boost::system::error_code ErrorCode;
            {
                const Detail::DeadlineScope<State> Scope(Connection, Deadline);
                std::array<std::uint8_t, 2> LengthBytes{};
                const auto LengthReadBytes = co_await Net::async_read(
                    *Connection->Stream, Net::buffer(LengthBytes),
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                ErrorCode = Scope.Map(ErrorCode);
                const auto LengthRead = Detail::ClassifyExactRead(
                    Detail::ExactRead{LengthReadBytes, ErrorCode}, LengthBytes.size());
                if (LengthRead.State == Detail::ExactReadState::Complete)
                {
                    const auto Length =
                        static_cast<std::size_t>((LengthBytes[0] << 8) | LengthBytes[1]);
                    if (Length == 0 || Length > Detail::MaxFrameBytes)
                    {
                        co_return std::unexpected(
                            boost::system::errc::make_error_code(boost::system::errc::bad_message));
                    }
                    std::vector<std::uint8_t> Body(Length);
                    const auto BodyReadBytes = co_await Net::async_read(
                        *Connection->Stream, Net::buffer(Body),
                        Net::redirect_error(Net::use_awaitable, ErrorCode));
                    ErrorCode = Scope.Map(ErrorCode);
                    co_return Detail::FinishDnsFrameBody(
                        Detail::DnsFrameBodyRead{
                            std::move(Body), BodyReadBytes, ErrorCode},
                        [this] { Close(); });
                }
                co_return std::unexpected(LengthRead.Failure);
            }
            co_return std::unexpected(ErrorCode);
        }

        /**
         * @brief 读取任意长度字节（DoH 分块读）
         * @param Buffer 接收缓冲；只借用到本次读完成
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 实际字节数与原始终态；两者可同时非零/非成功，deadline 到期返回 Timeout
         */
        [[nodiscard]] auto ReadSome(std::span<std::uint8_t> Buffer,
                                    const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<Detail::TlsReadResult>
        {
            const auto Connection = State_;
            if (!Connection->Stream)
            {
                co_return Detail::TlsReadResult{0, make_error_code(Error::NotOpen)};
            }
            if (Deadline.Expired())
            {
                co_return Detail::TlsReadResult{0, make_error_code(Error::Timeout)};
            }
            std::size_t Count = 0;
            boost::system::error_code ErrorCode;
            {
                const Detail::DeadlineScope<State> Scope(Connection, Deadline);
                Count = co_await Connection->Stream->async_read_some(
                    Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ErrorCode));
                ErrorCode = Scope.Map(ErrorCode);
            }
            co_return Detail::TlsReadResult{Count, ErrorCode};
        }

        /**
         * @brief 写入整段字节（DoT 帧与 DoH 请求共用）
         * @param Data 待写字节；只借用到写完成
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 写入错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto WriteAll(std::span<const std::uint8_t> Data,
                                    const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            const auto Connection = State_;
            if (!Connection->Stream)
            {
                co_return make_error_code(Error::NotOpen);
            }
            if (Deadline.Expired())
            {
                co_return make_error_code(Error::Timeout);
            }
            boost::system::error_code ErrorCode;
            const Detail::DeadlineScope<State> Scope(Connection, Deadline);
            co_await Net::async_write(*Connection->Stream, Net::buffer(Data),
                                      Net::redirect_error(Net::use_awaitable, ErrorCode));
            co_return Scope.Map(ErrorCode);
        }

        /// 底层 TCP 流是否仍打开
        [[nodiscard]] auto IsOpen() const -> bool
        {
            const auto &Stream = State_->Stream;
            if (!Stream)
            {
                return false;
            }
            return Stream->lowest_layer().is_open();
        }

        /// 关闭底层 TCP 流并作废本连接已排队的 deadline 回调
        auto Close() -> void
        {
            const auto Connection = State_;
            Detail::DisarmDeadline(Connection);
            if (Connection->Stream)
            {
                boost::system::error_code Ignore;
                Connection->Stream->lowest_layer().close(Ignore);
            }
        }

    private:
        /// 连接真实 owner：TLS 流与 deadline 定时器同生命周期
        struct State final
        {
            explicit State(const Net::any_io_executor &Executor)
                : Executor(Executor), Deadline(Executor)
            {
            }

            Net::any_io_executor Executor;
            std::optional<Ssl::stream<Net::ip::tcp::socket>> Stream;
            Detail::DeadlineState Deadline;

            /// deadline 到期取消本连接在途 I/O
            auto CancelPending(boost::system::error_code &Ignore) -> void
            {
                if (Stream)
                {
                    Stream->lowest_layer().cancel(Ignore);
                }
            }
        };

        std::shared_ptr<State> State_;
        std::shared_ptr<Ssl::context> Ctx_;
    };

    static_assert(TransportLink<TlsTransport> && PoolableTransport<TlsTransport>);

} // namespace Prism::Network::Dns
