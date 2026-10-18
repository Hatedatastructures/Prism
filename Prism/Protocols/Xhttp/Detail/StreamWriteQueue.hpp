/**
 * @file StreamWriteQueue.hpp
 * @brief XHTTP Stream-one 写队列与 END_STREAM owner。
 * @details 未匹配前暂存 payload；绑定 stream 后按序写出。排队请求收到同一
 *          typed Failure，失败通知由逻辑传输接手并关闭本地写队列。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail::Detail
{
    /**
     * @class StreamWriteQueue
     * @brief XHTTP Stream-one 单 executor 写队列 owner。
     * @details 队列按构造 executor 串行提交 DATA 和 END_STREAM，复制借用 payload；
     *          Close 只结束队列，物理 carrier 仍由 XhttpTransport 的外层 owner 关闭。
     */
    class StreamWriteQueue final : public std::enable_shared_from_this<StreamWriteQueue>
    {
    public:
        using WriteResult = std::expected<void, Prism::Fault::Failure>;
        using WriteCallback = std::function<Net::awaitable<WriteResult>(
            std::int32_t, std::span<const std::byte>)>;
        using FinishCallback = std::function<Net::awaitable<WriteResult>(std::int32_t)>;
        using FailureCallback = std::function<void(Prism::Fault::Failure)>;

        StreamWriteQueue(
            Net::any_io_executor Executor,
            WriteCallback Write,
            FinishCallback Finish)
            : Ex_(std::move(Executor)), Write_(std::move(Write)),
              Finish_(std::move(Finish)), Idle_(std::make_shared<IdleChannel>(Ex_, 1))
        {
        }

        /**
         * @brief 按序提交 DATA 并等待本次写完成。
         * @param Data 本次借用载荷；入队前复制，调用者可在 awaitable 完成后复用。
         * @return 写入字节数或保留原生 category/value 的 Failure。
         * @details 未绑定 stream 时复制并计入暂存；executor 固定为构造输入。
         */
        [[nodiscard]] auto Write(std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<std::size_t, Prism::Fault::Failure>>
        {
            if (Data.empty())
                co_return std::size_t{0};
            if (Closed_ || Finished_ || !Write_)
                co_return std::unexpected(NotConnected());
            if (StreamId_ < 0)
            {
                try
                {
                    Pending_.insert(Pending_.end(), Data.begin(), Data.end());
                }
                catch (const std::bad_alloc &)
                {
                    co_return std::unexpected(ExceptionFailure());
                }
                co_return Data.size();
            }
            auto Result = co_await Enqueue(
                WriteCommand{StreamId_, Data, false, true});
            if (!Result) co_return std::unexpected(Result.error());
            co_return *Result;
        }

        /**
         * @brief 排入并等待 END_STREAM，结束本端写方向但保留读取方向。
         * @return 成功或传输/协议边界交付的原始 Failure。
         * @details 仅通过已绑定 stream 的 FinishCallback 提交，不关闭底层 carrier。
         */
        [[nodiscard]] auto Finish()
            -> Net::awaitable<WriteResult>
        {
            if (Closed_ || Finished_ || StreamId_ < 0 || !Finish_)
                co_return std::unexpected(NotConnected());
            Finished_ = true;
            const auto Result = co_await Enqueue(
                WriteCommand{StreamId_, {}, true, true});
            if (!Result) co_return std::unexpected(Result.error());
            co_return WriteResult{};
        }

        /** @brief 绑定唯一 h2 stream 并启动匹配前暂存；失败回调由逻辑传输接收。 */
        void BindStream(std::int32_t StreamId, FailureCallback Failure)
        {
            if (Closed_ || StreamId_ >= 0)
                return;
            StreamId_ = StreamId;
            Failure_ = std::move(Failure);
            if (Pending_.empty())
                return;
            auto Pending = std::move(Pending_);
            QueueWrite(QueuedWrite{StreamId_, std::move(Pending), false, {}});
        }

        /** @brief 停止接收新写入并完成排队请求；不拥有 socket 或最终 carrier close。 */
        void Close()
        {
            if (!Closed_)
            {
                Closed_ = true;
                Pending_.clear();
                FailQueued(NotConnected());
            }
            RefreshRetired();
            NotifyIdle();
        }

        /** @brief 等待 writer 与排队请求物理退栈，并返回写入首因。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Close();
            while (!IsRetired())
            {
                Idle_->reset();
                if (IsRetired()) break;
                boost::system::error_code Error;
                co_await Idle_->async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
            }
            const auto Failure = FirstFailure_.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 只读 writer loop、active request 与队列全部退栈的事实。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool
        {
            return Retired_.load(std::memory_order_acquire);
        }

    private:
        using CompletionChannel = Net::experimental::channel<
            void(boost::system::error_code, std::size_t, Prism::Fault::Failure)>;

        using IdleChannel = Net::experimental::channel<void(boost::system::error_code)>;

        struct WriteCommand final
        {
            std::int32_t StreamId;
            std::span<const std::byte> Data;
            bool EndStream;
            bool AwaitCompletion;
        };

        struct QueuedWrite final
        {
            std::int32_t StreamId;
            std::vector<std::byte> Data;
            bool EndStream;
            std::shared_ptr<CompletionChannel> Completion;
        };

        struct WriteRequest final
        {
            WriteRequest(
                Net::any_io_executor Executor,
                WriteCommand Command)
                : StreamId(Command.StreamId), Data(Command.Data.begin(), Command.Data.end()),
                  EndStream(Command.EndStream)
            {
                if (Command.AwaitCompletion)
                    Done = std::make_shared<CompletionChannel>(std::move(Executor), 1);
            }

            std::int32_t StreamId;
            std::vector<std::byte> Data;
            bool EndStream{false};
            std::shared_ptr<CompletionChannel> Done;
        };

        [[nodiscard]] static auto NotConnected() noexcept -> Prism::Fault::Failure
        {
            return Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected));
        }

        [[nodiscard]] static auto ExceptionFailure() noexcept -> Prism::Fault::Failure
        {
            return Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }

        [[nodiscard]] auto Enqueue(
            WriteCommand Command)
            -> Net::awaitable<std::expected<std::size_t, Prism::Fault::Failure>>
        {
            std::shared_ptr<WriteRequest> Request;
            try
            {
                Request = std::make_shared<WriteRequest>(Ex_, Command);
                WriteQueue_.push_back(Request);
                StartWriter();
            }
            catch (const std::bad_alloc &)
            {
                const auto Failure = ExceptionFailure();
                if (Request && Request->Done)
                    (void)Request->Done->try_send(
                        boost::system::error_code{}, 0, Failure);
                FailQueued(Failure);
                Closed_ = true;
                NotifyFailure(Failure);
                RefreshRetired();
                NotifyIdle();
                co_return std::unexpected(Failure);
            }
            if (!Request->Done)
                co_return Command.Data.size();
            boost::system::error_code WaitError;
            const auto [Written, Failure] = co_await Request->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            if (WaitError)
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(WaitError)));
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return Written;
        }

        void QueueWrite(QueuedWrite Value)
        {
            try
            {
                auto Request = std::make_shared<WriteRequest>(
                    Ex_, WriteCommand{Value.StreamId, Value.Data, Value.EndStream, false});
                Request->Done = std::move(Value.Completion);
                WriteQueue_.push_back(std::move(Request));
                StartWriter();
            }
            catch (const std::bad_alloc &)
            {
                const auto Failure = ExceptionFailure();
                FailQueued(Failure);
                Closed_ = true;
                NotifyFailure(Failure);
                RefreshRetired();
                NotifyIdle();
            }
        }

        void StartWriter()
        {
            if (WriterRunning_ || Closed_ || WriteQueue_.empty())
                return;
            WriterRunning_ = true;
            auto Self = shared_from_this();
            try
            {
                Net::co_spawn(
                    Ex_, [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
                    [Self](std::exception_ptr Exception)
                    { Self->CompleteWriteLoop(std::move(Exception)); });
            }
            catch (const std::bad_alloc &)
            {
                WriterRunning_ = false;
                throw;
            }
        }

        void FailQueued(Prism::Fault::Failure Failure)
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                if (Request->Done)
                    (void)Request->Done->try_send(
                        boost::system::error_code{}, 0, Failure);
            }
        }

        void NotifyFailure(Prism::Fault::Failure Failure) noexcept
        {
            if (!Failure.Failed()) return;
            (void)FirstFailure_.TrySet(Failure);
            if (!Failure_) return;
            auto Callback = std::move(Failure_);
            try
            {
                Callback(Failure);
            }
            catch (...)
            {
                (void)FirstFailure_.TrySet(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception()));
            }
        }

        auto WriteLoop() -> Net::awaitable<void>
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                ActiveRequest_ = Request;
                Prism::Fault::Failure Failure;
                std::size_t Written = 0;
                if (!Closed_ && Request->EndStream)
                {
                    if (Finish_)
                    {
                        const auto Result = co_await Finish_(Request->StreamId);
                        if (!Result) Failure = Result.error();
                    }
                    else
                    {
                        Failure = NotConnected();
                    }
                }
                else if (!Closed_ && Write_ && !Request->EndStream)
                {
                    const auto Result = co_await Write_(
                        Request->StreamId, std::span<const std::byte>(Request->Data));
                    if (!Result) Failure = Result.error();
                    if (!Failure.Failed()) Written = Request->Data.size();
                }
                else
                {
                    Failure = NotConnected();
                }
                if (Request->Done)
                    (void)Request->Done->try_send(
                        boost::system::error_code{}, Written, Failure);
                ActiveRequest_.reset();
                if (!Failure.Failed())
                    continue;
                Closed_ = true;
                FailQueued(Failure);
                NotifyFailure(Failure);
                break;
            }
            co_return;
        }

        auto CompleteWriteLoop(std::exception_ptr Exception) noexcept -> void
        {
            if (Exception)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
                if (ActiveRequest_ && ActiveRequest_->Done)
                    (void)ActiveRequest_->Done->try_send(
                        boost::system::error_code{}, 0, Failure);
                ActiveRequest_.reset();
                Closed_ = true;
                FailQueued(Failure);
                NotifyFailure(Failure);
            }
            WriterRunning_ = false;
            RefreshRetired();
            NotifyIdle();
        }

        auto RefreshRetired() noexcept -> void
        {
            Retired_.store(
                Closed_ && Pending_.empty() && !WriterRunning_ && WriteQueue_.empty() && !ActiveRequest_,
                std::memory_order_release);
        }

        auto NotifyIdle() noexcept -> void
        {
            (void)Idle_->try_send(boost::system::error_code{});
        }

        Net::any_io_executor Ex_;
        WriteCallback Write_;
        FinishCallback Finish_;
        FailureCallback Failure_;
        std::shared_ptr<IdleChannel> Idle_;
        std::vector<std::byte> Pending_;
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        std::shared_ptr<WriteRequest> ActiveRequest_;
        std::int32_t StreamId_{-1};
        bool WriterRunning_{false};
        bool Closed_{false};
        bool Finished_{false};
        std::atomic<bool> Retired_{false};
        Prism::Fault::FailureState FirstFailure_;
    };
} // namespace Prism::Xhttp::Detail::Detail
