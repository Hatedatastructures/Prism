/**
 * @file TcpTransport.hpp
 * @brief DNS TCP 帧传输（2 字节长度前缀，可入池）
 * @details 帧收发与建连共享一个绝对 deadline；单次 Receive 的两段读取不
 *          重置预算。socket 与 deadline 定时器由共享状态拥有，handler
 *          不借用裸 this。
 */

#pragma once

#include <Prism/Net/Dns/Transport.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Network::Dns
{

    namespace Net = boost::asio;

    /**
     * @class TcpTransport
     * @brief TCP 帧传输（2 字节长度前缀，可入池）
     */
    class TcpTransport
    {
    public:
        /**
         * @brief 构造 TCP 传输
         * @param Executor 套接字与定时器执行器
         */
        explicit TcpTransport(Net::any_io_executor Executor)
            : State_(std::make_shared<State>(Executor))
        {
        }

        /**
         * @brief 建立连接
         * @param Endpoint 上游端点
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 连接错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Connect(const Net::ip::tcp::endpoint &Endpoint, const Server & /*ServerConfig*/,
                                   const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            const auto Connection = State_;
            if (Deadline.Expired())
            {
                co_return make_error_code(Error::Timeout);
            }
            boost::system::error_code ErrorCode;
            const Detail::DeadlineScope<State> Scope(Connection, Deadline);
            co_await Connection->Sock.async_connect(
                Endpoint, Net::redirect_error(Net::use_awaitable, ErrorCode));
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
            const auto Connection = State_;
            const auto FrameResult = Detail::MakeTcpFrame(Wire);
            if (!FrameResult)
            {
                co_return FrameResult.error();
            }
            if (Deadline.Expired())
            {
                co_return make_error_code(Error::Timeout);
            }
            const auto &Frame = *FrameResult;
            boost::system::error_code ErrorCode;
            const Detail::DeadlineScope<State> Scope(Connection, Deadline);
            co_await Net::async_write(Connection->Sock, Net::buffer(Frame),
                                      Net::redirect_error(Net::use_awaitable, ErrorCode));
            co_return Scope.Map(ErrorCode);
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
                co_await Net::async_read(Connection->Sock, Net::buffer(LengthBytes),
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
                ErrorCode = Scope.Map(ErrorCode);
                if (!ErrorCode)
                {
                    const auto Length =
                        static_cast<std::size_t>((LengthBytes[0] << 8) | LengthBytes[1]);
                    if (Length == 0 || Length > Detail::MaxFrameBytes)
                    {
                        co_return std::unexpected(
                            boost::system::errc::make_error_code(boost::system::errc::bad_message));
                    }
                    std::vector<std::uint8_t> Body(Length);
                    co_await Net::async_read(Connection->Sock, Net::buffer(Body),
                                             Net::redirect_error(Net::use_awaitable, ErrorCode));
                    ErrorCode = Scope.Map(ErrorCode);
                    if (!ErrorCode)
                    {
                        co_return Body;
                    }
                }
            }
            co_return std::unexpected(ErrorCode);
        }

        /// 套接字是否仍打开
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return State_->Sock.is_open();
        }

        /// 关闭套接字并作废本连接已排队的 deadline 回调
        auto Close() -> void
        {
            const auto Connection = State_;
            Detail::DisarmDeadline(Connection);
            boost::system::error_code Ignore;
            Connection->Sock.close(Ignore);
        }

    private:
        /// 连接真实 owner：socket 与 deadline 定时器同生命周期
        struct State final
        {
            explicit State(const Net::any_io_executor &Executor) : Sock(Executor), Deadline(Executor) {}

            Net::ip::tcp::socket Sock;
            Detail::DeadlineState Deadline;

            /// deadline 到期取消本连接在途 I/O
            auto CancelPending(boost::system::error_code &Ignore) -> void
            {
                Sock.cancel(Ignore);
            }
        };

        std::shared_ptr<State> State_;
    };

    static_assert(TransportLink<TcpTransport> && PoolableTransport<TcpTransport>);

} // namespace Prism::Network::Dns
