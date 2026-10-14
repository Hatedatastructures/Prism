/**
 * @file Http2WireWriter.hpp
 * @brief TrustTunnel HTTP/2 carrier wire 写入与帧刷新基础设施。
 */

#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Protocols/Http2/Session.hpp>
#include <Preview/Transport/Encrypted.hpp>

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

namespace Preview::Trusttunnel::Detail
{

    namespace Net = boost::asio;
    namespace H2 = Preview::Http2;
    using Http2WireResult = std::expected<void, Preview::Fault::Failure>;

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

        [[nodiscard]] auto Write(std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>
        {
            if (Data.empty())
            {
                co_return Http2WireResult{};
            }
            if (Closed_ || !Sink_)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }
            auto Request = std::make_shared<WriteRequest>(Executor_, Data);
            Queue_.push_back(Request);
            Drained_.store(false, std::memory_order_release);
            Start();
            boost::system::error_code WaitError;
            auto Receive = Request->Done.async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            auto Result = co_await std::move(Receive);
            if (WaitError)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(WaitError)));
            }
            co_return Result;
        }

        auto Close() -> void
        {
            Closed_ = true;
            CloseSubmitted_.store(true, std::memory_order_release);
            RejectQueued(Preview::Fault::FromNative(
                std::make_error_code(std::errc::not_connected)));
            RefreshDrained();
        }

        /** @brief 等待当前 frame 写协程及所有 waiter 真正退栈。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            co_await Net::dispatch(Executor_, Net::use_awaitable);
            while (Running_ || !Queue_.empty() || Active_)
            {
                if (!Running_ && !Queue_.empty() && !Closed_) Start();
                Idle_->reset();
                if (!Running_ && Queue_.empty() && !Active_) break;
                boost::system::error_code Error;
                co_await Idle_->async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    RecordFailure(Preview::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                    break;
                }
            }
            const auto Failure = FirstFailure_.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

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

            auto operator()(std::exception_ptr Exception) const -> void
            {
                Owner->CompleteLoop(Exception);
            }
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

        auto Start() -> void
        {
            if (Running_ || Closed_ || Queue_.empty())
            {
                return;
            }
            Running_ = true;
            Drained_.store(false, std::memory_order_release);
            auto Self = shared_from_this();
            const auto CompletionOwner = Self;
            try
            {
                Net::co_spawn(Executor_, [Self]() -> Net::awaitable<void>
                { co_await Self->Loop(); }, LoopCompletion{CompletionOwner});
            }
            catch (...)
            {
                CompleteLoop(std::current_exception());
            }
        }

        auto Loop() -> Net::awaitable<void>
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                Active_ = Request;
                Http2WireResult Result;
                if (Closed_ || !Sink_)
                {
                    Result = std::unexpected(Preview::Fault::FromNative(
                        std::make_error_code(std::errc::not_connected)));
                }
                else
                {
                    Result = co_await Sink_(Request->Data);
                }
                const bool Failed = !Result;
                if (Failed) RecordFailure(Result.error());
                (void)Request->Done.try_send(boost::system::error_code{}, std::move(Result));
                Active_.reset();
                if (Failed)
                {
                    Closed_ = true;
                    RejectQueued(FirstFailure_.Load());
                    break;
                }
            }
            co_return;
        }

        auto CompleteLoop(std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                RecordFailure(FailureFromException(Exception));
                Closed_ = true;
            }
            if (Active_)
            {
                const auto Failure = FirstFailure_.Load();
                (void)Active_->Done.try_send(
                    boost::system::error_code{}, std::unexpected(Failure));
                Active_.reset();
            }
            Running_ = false;
            if (Closed_)
            {
                RejectQueued(FirstFailure_.Load());
            }
            else if (!Queue_.empty())
            {
                Start();
                return;
            }
            RefreshDrained();
            (void)Idle_->try_send(boost::system::error_code{});
        }

        auto RejectQueued(const Preview::Fault::Failure Failure) -> void
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                (void)Request->Done.try_send(boost::system::error_code{}, std::unexpected(Failure));
            }
        }

        auto RefreshDrained() noexcept -> void
        {
            Drained_.store(!Running_ && Queue_.empty() && !Active_, std::memory_order_release);
        }

        auto RecordFailure(const Preview::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed())
            {
                // TrySet 输掉竞态只表示已有首因已发布；物理排空仍由 IsRetired 回报。
                (void)FirstFailure_.TrySet(Failure);
            }
        }

        [[nodiscard]] static auto FailureFromException(const std::exception_ptr Exception) noexcept
            -> Preview::Fault::Failure
        {
            if (!Exception) return {Preview::Fault::Code::IoError};
            try
            {
                std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error &Value)
            {
                return Preview::Fault::FromNative(static_cast<std::error_code>(Value.code()));
            }
            catch (const std::system_error &Value)
            {
                return Preview::Fault::FromNative(Value.code());
            }
            catch (const std::bad_alloc &)
            {
                return {Preview::Fault::Code::ResourceUnavailable,
                        std::make_error_code(std::errc::not_enough_memory)};
            }
            catch (...)
            {
                return {Preview::Fault::Code::IoError};
            }
        }

        Net::any_io_executor Executor_;
        Sink Sink_;
        std::shared_ptr<IdleChannel> Idle_;
        std::deque<std::shared_ptr<WriteRequest>> Queue_;
        std::shared_ptr<WriteRequest> Active_;
        Preview::Fault::FailureState FirstFailure_;
        std::atomic<bool> CloseSubmitted_{false};
        std::atomic<bool> Drained_{true};
        bool Running_{false};
        bool Closed_{false};
    };

    [[nodiscard]] inline auto WriteHttp2Wire(
        const std::shared_ptr<Preview::Transport::Encrypted> &Encrypted,
        const std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>
    {
        const auto Result = co_await Encrypted->WriteExact(Data);
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        if (Result.Bytes != Data.size())
            co_return std::unexpected(Preview::Fault::FromNative(
                std::make_error_code(std::errc::io_error)));
        co_return Http2WireResult{};
    }

    /** @brief 创建绑定到加密 carrier 的 HTTP/2 wire writer。 */
    [[nodiscard]] inline auto MakeHttp2Wire(
        const std::shared_ptr<Preview::Transport::Encrypted> &Encrypted)
        -> std::shared_ptr<Http2WireWriter>
    {
        return std::make_shared<Http2WireWriter>(
            Encrypted->Executor(),
            [Encrypted](std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>
            { return WriteHttp2Wire(Encrypted, Data); });
    }

    /** @brief 收集并串行刷新 HTTP/2 session 生成的 outbound frames。 */
    [[nodiscard]] inline auto FlushHttp2Frames(
        const std::shared_ptr<H2::Session> &Session,
        const std::shared_ptr<Http2WireWriter> &Wire) -> Net::awaitable<Http2WireResult>
    {
        std::vector<std::byte> Output;
        if (Session->Collect(Output) && !Output.empty())
        {
            co_return co_await Wire->Write(Output);
        }
        co_return Http2WireResult{};
    }

} // namespace Preview::Trusttunnel::Detail
