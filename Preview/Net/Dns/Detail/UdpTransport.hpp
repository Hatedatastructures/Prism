/**
 * @file UdpTransport.hpp
 * @brief DNS 数据报传输（单发单收，不入池）
 * @details socket 与 deadline 定时器由共享状态拥有，操作协程与所有 handler
 *          都持同一 owner；对象析构、池淘汰或取消都不会让迟到回调触碰
 *          已释放内存。每次操作消费调用者传入的绝对 AttemptDeadline。
 */

#pragma once

#include <Preview/Net/Dns/Transport.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    namespace Net = boost::asio;

    /**
     * @class UdpTransport
     * @brief 数据报传输（单发单收，不入池）
     */
    class UdpTransport
    {
    public:
        /**
         * @brief 构造数据报传输
         * @param Executor 套接字与定时器执行器
         */
        explicit UdpTransport(Net::any_io_executor Executor)
            : State_(std::make_shared<State>(Executor))
        {
        }

        /**
         * @brief 建立已连接 UDP 套接字
         * @param Endpoint 上游端点（内核级过滤非对端数据报，防伪造）
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 连接错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Connect(const Net::ip::udp::endpoint &Endpoint, const Server & /*ServerConfig*/,
                                   const Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>
        {
            const auto Connection = State_; // 挂起后只使用共享 owner，不引用 this
            boost::system::error_code ErrorCode;
            boost::system::error_code Ignore;
            Connection->Sock.close(Ignore);
            Connection->Sock.open(Endpoint.protocol(), ErrorCode);
            if (ErrorCode)
            {
                co_return ErrorCode;
            }
            if (Deadline.Expired())
            {
                co_return make_error_code(Error::Timeout);
            }
            const Detail::DeadlineScope<State> Scope(Connection, Deadline);
            co_await Connection->Sock.async_connect(
                Endpoint, Net::redirect_error(Net::use_awaitable, ErrorCode));
            co_return Scope.Map(ErrorCode);
        }

        /**
         * @brief 发送查询报文
         * @param Wire 已编码查询报文；只借用到发送完成
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 发送错误；deadline 到期返回 Timeout
         */
        [[nodiscard]] auto Send(std::span<const std::uint8_t> Wire,
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
            co_await Connection->Sock.async_send(
                Net::buffer(Wire), Net::redirect_error(Net::use_awaitable, ErrorCode));
            co_return Scope.Map(ErrorCode);
        }

        /**
         * @brief 接收应答报文
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
            std::array<std::uint8_t, Detail::MaxUdpResponseBytes> Buffer{};
            std::size_t Count = 0;
            boost::system::error_code ErrorCode;
            {
                const Detail::DeadlineScope<State> Scope(Connection, Deadline);
                Count = co_await Connection->Sock.async_receive(
                    Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ErrorCode));
                ErrorCode = Scope.Map(ErrorCode);
            }
            if (ErrorCode)
            {
                co_return std::unexpected(ErrorCode);
            }
            co_return std::vector<std::uint8_t>(Buffer.begin(),
                                                Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
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

            Net::ip::udp::socket Sock;
            Detail::DeadlineState Deadline;

            /// deadline 到期取消本连接在途 I/O
            auto CancelPending(boost::system::error_code &Ignore) -> void
            {
                Sock.cancel(Ignore);
            }
        };

        std::shared_ptr<State> State_;
    };

    static_assert(TransportLink<UdpTransport>);

} // namespace Preview::Network::Dns
