/**
 * @file memory_stream.hpp
 * @brief 内存管道流（成对出现，测试用传输层）
 * @details 提供与真实 socket 一致的异步语义：
 *          - 双向数据流（两个端点各自可读可写）
 *          - shutdown() 半关：对端读返回 0（EOF），本端仍可读
 *          - close() 全关：对端写返回 broken_pipe
 *          - cancel()：挂起的读立即返回
 *          - set_timeout()：读超时（0 = 禁用）
 *          内部使用 Boost.Asio channel + strand 实现，天然线程安全。
 * @note 通过 make_memory_pair() 创建成对端点。
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transport/stream.hpp>
#include <common/core/transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace psmtest
{

    /// 内存管道流端点
    class memory_stream : public transmission
    {
    public:
        /// 默认读超时（0 = 禁用）
        static constexpr std::chrono::milliseconds default_timeout{0};

        /// 内部状态：入向队列（对端写、本端读）
        struct state
        {
            explicit state(net::any_io_executor ex)
                : read_channel(ex, 1), timer(ex)
            {
            }

            /// 数据到达 / EOF / 关闭 / 取消 通知（容量 1，无数据载荷）
            boost::asio::experimental::channel<void(boost::system::error_code)> read_channel;
            /// 读超时定时器
            net::steady_timer timer;
            /// 待读数据队列
            std::deque<std::vector<std::uint8_t>> rx_queue;
            /// 对端是否已半关（EOF）
            bool peer_eof{false};
            /// 本端是否已全关（对端写 → broken_pipe）
            bool closed{false};
            /// 读被取消（cancel 唤醒后返回 0）
            bool canceled{false};
            /// 当前读超时
            std::chrono::milliseconds timeout{default_timeout};
        };

        /// @brief 构造（未连接，需通过 make_memory_pair 成对使用）
        /// @param ex 执行器
        explicit memory_stream(net::any_io_executor ex)
            : in_(std::make_shared<state>(std::move(ex)))
        {
        }

        /// @brief 读取最多 buf.size() 字节
        /// @return 实际读取字节数；0 = 对端半关 / 超时 / 取消
        auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t>
        {
            using namespace boost::asio::experimental::awaitable_operators;

            while (true)
            {
                if (in_->canceled)
                {
                    in_->canceled = false;
                    co_return 0;
                }
                if (in_->closed)
                    co_return 0;
                if (!in_->rx_queue.empty())
                {
                    const auto &front = in_->rx_queue.front();
                    const auto n = std::min(buf.size(), front.size());
                    std::memcpy(buf.data(), front.data(), n);
                    if (n < front.size())
                        in_->rx_queue.front().erase(in_->rx_queue.front().begin(),
                                                    in_->rx_queue.front().begin() + static_cast<std::ptrdiff_t>(n));
                    else
                        in_->rx_queue.pop_front();
                    co_return n;
                }
                if (in_->peer_eof)
                    co_return 0;

                // 挂起等待数据 / EOF / 关闭 / 取消 / 超时
                in_->read_channel.reset();
                if (in_->timeout.count() > 0)
                {
                    in_->timer.expires_after(in_->timeout);
                    auto result = co_await (
                        in_->read_channel.async_receive(net::use_awaitable) ||
                        in_->timer.async_wait(net::use_awaitable));
                    if (result.index() == 1) // 超时
                        co_return 0;
                }
                else
                {
                    co_await in_->read_channel.async_receive(net::use_awaitable);
                }
            }
        }

        /// @brief 写入全部数据到对端
        /// @return 错误码（成功 = 空；对端全关 = broken_pipe）
        auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec>
        {
            const auto peer = peer_.lock();
            if (!peer || peer->closed)
                co_return net::error::broken_pipe;
            std::vector<std::uint8_t> data(buf.begin(), buf.end());
            peer->rx_queue.push_back(std::move(data));
            peer->read_channel.try_send(boost::system::error_code{});
            co_return boost::system::error_code{};
        }

        /// @brief 半关：发送 EOF（对端读返回 0），本端仍可读
        auto shutdown() -> net::awaitable<void>
        {
            const auto peer = peer_.lock();
            if (peer)
            {
                peer->peer_eof = true;
                peer->read_channel.try_send(boost::system::error_code{});
            }
            co_return;
        }

        /// @brief 全关：本端不可读，对端写返回 broken_pipe
        auto close() -> void override
        {
            in_->closed = true;
            in_->read_channel.try_send(boost::system::error_code{});
            const auto peer = peer_.lock();
            if (peer)
            {
                peer->peer_eof = true;
                peer->read_channel.try_send(boost::system::error_code{});
            }
        }

        /// @brief 取消挂起的读（立即返回 0）
        auto cancel() -> void override
        {
            in_->canceled = true;
            in_->read_channel.try_send(boost::system::error_code{});
        }

        /// @brief 设置读超时（0 = 禁用）
        auto set_timeout(std::chrono::milliseconds ms) -> void
        {
            in_->timeout = ms;
        }

        /// 流是否打开（未全关）
        [[nodiscard]] auto is_open() const -> bool
        {
            return !in_->closed;
        }

        /// @brief 异步读取（transmission 接口，字节视图）
        /// @details 桥接到 read_some 内部逻辑，ec 恒为空（超时/取消返回 0）。
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            const auto n = co_await read_some(std::span<std::uint8_t>(
                reinterpret_cast<std::uint8_t *>(buffer.data()), buffer.size()));
            co_return n;
        }

        /// @brief 异步写入（transmission 接口，字节视图）
        /// @details 桥接到 write_all，错误码存入 ec。
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            const auto err = co_await write_all(as_u8(buffer));
            if (err)
            {
                ec = err;
                co_return 0;
            }
            ec.clear();
            co_return buffer.size();
        }

        /// 获取执行器
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return in_->read_channel.get_executor();
        }

    private:
        std::shared_ptr<state> in_;
        std::weak_ptr<state> peer_;

        /// 内部：绑定对端（仅 make_memory_pair 使用）
        explicit memory_stream(std::shared_ptr<state> in, std::weak_ptr<state> peer)
            : in_(std::move(in)), peer_(std::move(peer))
        {
        }

        friend auto make_memory_pair(net::any_io_executor)
            -> std::pair<memory_stream, memory_stream>;
    };

    static_assert(stream<memory_stream>, "memory_stream 必须满足 stream concept");

    /// @brief 创建成对内存管道端点
    /// @param ex 执行器（通常来自 io_context）
    /// @return 两个互为对端的流
    [[nodiscard]] inline auto make_memory_pair(net::any_io_executor ex)
        -> std::pair<memory_stream, memory_stream>
    {
        auto a = std::make_shared<memory_stream::state>(ex);
        auto b = std::make_shared<memory_stream::state>(ex);
        return {memory_stream{a, b}, memory_stream{b, a}};
    }

} // namespace psmtest
