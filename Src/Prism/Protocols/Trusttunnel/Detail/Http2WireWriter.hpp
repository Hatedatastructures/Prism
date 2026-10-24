/**
 * @file Http2WireWriter.hpp
 * @brief TrustTunnel HTTP/2 carrier wire 写入与帧刷新基础设施。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstddef>
#include <deque>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Trusttunnel::Detail
{

    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;
    using Http2WireResult = std::expected<void, Prism::Fault::Failure>;

    /**
     * @brief 串行化 HTTP/2 frame 写入，保证 carrier 上的 partial I/O 顺序。
     * @details 调用方只提交完整的已编码 frame 字节；底层 sink 失败后，当前
     *          writer 进入关闭态并唤醒所有排队请求。
     */
    class Http2WireWriter final : public std::enable_shared_from_this<Http2WireWriter>
    {
    public:
        using Sink = std::function<Net::awaitable<Http2WireResult>(std::span<const std::byte>)>;

        Http2WireWriter(Net::any_io_executor Executor, Sink WriteSink)
            : Executor_(std::move(Executor)), Sink_(std::move(WriteSink)), Idle_(
                  std::make_shared<IdleChannel>(Executor_, 1))
        {
        }

        Http2WireWriter(const Http2WireWriter &) = delete;
        auto operator=(const Http2WireWriter &) -> Http2WireWriter & = delete;

        [[nodiscard]] auto Write(std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>;

        auto Close() -> void;

        /** @brief 等待当前 frame 写协程及所有 waiter 真正退栈。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 只读writer协程与队列的实际排空事实。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return CloseSubmitted_.load(std::memory_order_acquire) &&
                Drained_.load(std::memory_order_acquire);
        }

    private:
        using Completion =
            Net::experimental::channel<void(boost::system::error_code, Http2WireResult)>;
        using IdleChannel = Net::experimental::channel<void(boost::system::error_code)>;

        struct LoopCompletion final
        {
            std::shared_ptr<Http2WireWriter> Owner;

            auto operator()(std::exception_ptr Exception) const -> void;
        };

        struct WriteRequest
        {
            WriteRequest(Net::any_io_executor Executor, std::span<const std::byte> Bytes)
                : Data(Bytes.begin(), Bytes.end()), Done(Executor, 1)
            {
            }

            std::vector<std::byte> Data;
            Completion Done;
        };

        auto Start() -> void;

        auto Loop() -> Net::awaitable<void>;

        auto CompleteLoop(std::exception_ptr Exception) -> void;

        auto RejectQueued(const Prism::Fault::Failure Failure) -> void;

        auto RefreshDrained() noexcept -> void;

        auto RecordFailure(const Prism::Fault::Failure Failure) noexcept -> void;

        [[nodiscard]] static auto FailureFromException(const std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure;

        Net::any_io_executor Executor_;
        Sink Sink_;
        std::shared_ptr<IdleChannel> Idle_;
        std::deque<std::shared_ptr<WriteRequest>> Queue_;
        std::shared_ptr<WriteRequest> Active_;
        Prism::Fault::FailureState FirstFailure_;
        std::atomic<bool> CloseSubmitted_{false};
        std::atomic<bool> Drained_{true};
        bool Running_{false};
        bool Closed_{false};
    };

    [[nodiscard]] auto WriteHttp2Wire(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>;

    /** @brief 创建绑定到加密 carrier 的 HTTP/2 wire writer。 */
    [[nodiscard]] auto MakeHttp2Wire(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted)
        -> std::shared_ptr<Http2WireWriter>;

    /** @brief 收集并串行刷新 HTTP/2 session 生成的 outbound frames。 */
    [[nodiscard]] auto FlushHttp2Frames(
        const std::shared_ptr<H2::Session> &Session,
        const std::shared_ptr<Http2WireWriter> &Wire) -> Net::awaitable<Http2WireResult>;

} // namespace Prism::Trusttunnel::Detail
