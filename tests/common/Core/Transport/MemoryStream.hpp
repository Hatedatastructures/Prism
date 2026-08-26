/**
 * @file MemoryStream.hpp
 * @brief 内存管道流（成对出现，测试用传输层）
 * @details 提供与真实 socket 一致的异步语义：
 *          - 双向数据流（两个端点各自可读可写）
 *          - Shutdown() 半关：对端读返回 0（EOF），本端仍可读
 *          - Close() 全关：对端写返回 broken_pipe
 *          - Cancel()：挂起的读立即返回
 *          - SetTimeout()：读超时（0 = 禁用）
 *          内部使用 Boost.Asio channel + 当前 Executor 串行化操作。
 * @note MemoryStream 只支持在创建它的 Executor 上使用；它不是跨线程安全的
 *       传输实现。测试中所有 Read/Write/Close/Cancel/SetTimeout 调用必须回到
 *       同一个 Executor，MakeMemoryPair() 会为两个端点绑定同一 Executor。
 * @note 通过 MakeMemoryPair() 创建成对端点。
 */

#pragma once

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

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Transport/Stream.hpp>

namespace Preview
{

    /// 内存管道流端点
    class MemoryStream : public Transmission
    {
    public:
        /// 默认读超时（0 = 禁用）
        static constexpr std::chrono::milliseconds DefaultTimeout{0};

        /// 内部状态：入向队列（对端写、本端读）
        struct State
        {
            explicit State(net::any_io_executor ex) : ReadChannel(ex, 1), timer(ex)
            {
            }

            /// 数据到达 / EOF / 关闭 / 取消 通知（容量 1，无数据载荷）
            boost::asio::experimental::channel<void(boost::system::error_code)> ReadChannel;
            /// 读超时定时器
            net::steady_timer timer;
            /// 待读数据队列
            std::deque<std::vector<std::uint8_t>> RxQueue;
            /// 对端是否已半关（EOF）
            bool PeerEof{false};
            /// 本端是否已全关（对端写 → broken_pipe）
            bool Closed{false};
            /// 读被取消（Cancel 唤醒后返回 0）
            bool Canceled{false};
            /// 读超时触发标记（async_read_some 据此设置 timed_out 错误）
            bool ReadTimedOut{false};
            /// 当前读超时
            std::chrono::milliseconds Timeout{DefaultTimeout};
        };

        /**
         * @brief 构造（未连接，需通过 MakeMemoryPair 成对使用）
         * @param ex 执行器
         */
        explicit MemoryStream(net::any_io_executor ex) : In_(std::make_shared<State>(std::move(ex)))
        {
        }

        /**
         * @brief 读取最多 buf.size() 字节
         * @return 实际读取字节数；0 = 对端半关 / 超时 / 取消
         */
        auto ReadSome(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t>
        {
            using namespace boost::asio::experimental::awaitable_operators;

            while (true)
            {
                if (In_->Canceled)
                {
                    In_->Canceled = false;
                    co_return 0;
                }
                if (In_->Closed)
                {
                    co_return 0;
                }
                if (!In_->RxQueue.empty())
                {
                    const auto &front = In_->RxQueue.front();
                    const auto N = std::min(buf.size(), front.size());
                    std::memcpy(buf.data(), front.data(), N);
                    if (N < front.size())
                    {
                        In_->RxQueue.front().erase(In_->RxQueue.front().begin(),
                                                    In_->RxQueue.front().begin() +
                                                        static_cast<std::ptrdiff_t>(N));
                    }
                    else
                    {
                        In_->RxQueue.pop_front();
                    }
                    co_return N;
                }
                if (In_->PeerEof)
                {
                    co_return 0;
                }

                // 挂起等待数据 / EOF / 关闭 / 取消 / 超时
                In_->ReadChannel.reset();
                if (In_->Timeout.count() > 0)
                {
                    In_->timer.expires_after(In_->Timeout);
                    auto Result = co_await (In_->ReadChannel.async_receive(net::use_awaitable) ||
                                            In_->timer.async_wait(net::use_awaitable));
                    if (Result.index() == 1) // 超时
                    {
                        In_->ReadTimedOut = true;
                        co_return 0;
                    }
                }
                else
                {
                    co_await In_->ReadChannel.async_receive(net::use_awaitable);
                }
            }
        }

        /**
         * @brief 写入全部数据到对端
         * @return 错误码（成功 = 空；对端全关 = broken_pipe）
         */
        auto WriteAll(std::span<const std::uint8_t> buf) -> net::awaitable<ProtocolEc>
        {
            const auto Peer = Peer_.lock();
            if (!Peer || Peer->Closed)
            {
                co_return net::error::broken_pipe;
            }
            std::vector<std::uint8_t> Data(buf.begin(), buf.end());
            Peer->RxQueue.push_back(std::move(Data));
            Peer->ReadChannel.try_send(boost::system::error_code{});
            co_return boost::system::error_code{};
        }

        /**
         * @brief 半关：发送 EOF（对端读返回 0），本端仍可读
         */
        auto Shutdown() -> void override
        {
            const auto Peer = Peer_.lock();
            if (Peer)
            {
                Peer->PeerEof = true;
                Peer->ReadChannel.try_send(boost::system::error_code{});
            }
        }

        /**
         * @brief 全关：本端不可读，对端写返回 broken_pipe
         */
        auto Close() -> void override
        {
            In_->Closed = true;
            In_->ReadChannel.try_send(boost::system::error_code{});
            const auto Peer = Peer_.lock();
            if (Peer)
            {
                Peer->PeerEof = true;
                Peer->ReadChannel.try_send(boost::system::error_code{});
            }
        }

        /**
         * @brief 取消挂起的读（立即返回 0）
         */
        auto Cancel() -> void override
        {
            In_->Canceled = true;
            In_->ReadChannel.try_send(boost::system::error_code{});
        }

        /**
         * @brief 设置读超时（0 = 禁用）
         */
        auto SetTimeout(std::chrono::milliseconds ms) -> void override
        {
            In_->Timeout = ms;
        }

        /**
         * @brief 流是否打开（未全关）
         * @return 打开返回 true
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !In_->Closed;
        }

        /**
         * @brief 异步读取（Transmission 接口，字节视图）
         * @details 桥接到 ReadSome 内部逻辑。超时返回
         * operation_timed_out，取消/EOF 返回 0（ec 为空）。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            In_->ReadTimedOut = false;
            const auto N = co_await ReadSome(AsU8(Buffer));
            if (In_->ReadTimedOut)
            {
                ec = std::make_error_code(std::errc::timed_out);
            }
            co_return N;
        }

        /**
         * @brief 异步写入（Transmission 接口，字节视图）
         * @details 桥接到 WriteAll，错误码存入 ec。
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            const auto Err = co_await WriteAll(AsU8(Buffer));
            if (Err)
            {
                ec = Err;
                co_return 0;
            }
            ec.clear();
            co_return Buffer.size();
        }

        /**
         * @brief 获取执行器
         * @return 关联的执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return In_->ReadChannel.get_executor();
        }

    private:
        std::shared_ptr<State> In_;
        std::weak_ptr<State> Peer_;

        /**
         * @brief 内部：绑定对端（仅 MakeMemoryPair 使用）
         */
        explicit MemoryStream(std::shared_ptr<State> in, std::weak_ptr<State> Peer)
            : In_(std::move(in)), Peer_(std::move(Peer))
        {
        }

        friend auto MakeMemoryPair(net::any_io_executor) -> std::pair<MemoryStream, MemoryStream>;
    };

    static_assert(Stream<MemoryStream>, "MemoryStream 必须满足 Stream concept");

    /**
     * @brief 创建成对内存管道端点
     * @param ex 执行器（通常来自 io_context）
     * @return 两个互为对端的流
     */
    [[nodiscard]] inline auto MakeMemoryPair(net::any_io_executor ex)
        -> std::pair<MemoryStream, MemoryStream>
    {
        auto A = std::make_shared<MemoryStream::State>(ex);
        auto B = std::make_shared<MemoryStream::State>(ex);
        return {MemoryStream{A, B}, MemoryStream{B, A}};
    }

} // namespace Preview
