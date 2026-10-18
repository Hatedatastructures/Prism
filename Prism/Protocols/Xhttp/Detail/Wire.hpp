/**
 * @file Wire.hpp
 * @brief XHTTP 物理字节串行写入 owner。
 * @details h2 driver、响应头和数据回调共享一个实例，所有写入按提交顺序
 *          排队，并由同一个执行器完成。
 */

#pragma once

#include <Prism/Protocols/Xhttp/Detail/Common.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstddef>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    /**
     * @class WireWriter
     * @brief XHTTP 底层字节串行写入器
     * @details Sink 由拥有物理连接的调用方提供。写入失败保留 Failure/Native，
     *          关闭写入器并完成排队请求；Drain 等待 detached writer 退栈。
     * @note Write/Close/Drain 及失败回调必须在构造时的 executor 上调用。
     */
    class WireWriter final : public Prism::Contract::CarrierActivity,
                              public std::enable_shared_from_this<WireWriter>
    {
    private:
        using Completion = Net::experimental::channel<
            void(boost::system::error_code, Prism::Fault::Failure)>;
        using IdleChannel = Net::experimental::channel<
            void(boost::system::error_code, Prism::Fault::Failure)>;

    public:
        using WriteResult = std::expected<void, Prism::Fault::Failure>;
        using Sink = std::function<Net::awaitable<WriteResult>(std::span<const std::byte>)>;
        using FailureCallback = std::function<void()>;

        WireWriter(Net::any_io_executor Executor,
                   Sink SinkFunction,
                   FailureCallback FailureFunction = {})
            : Ex_(std::move(Executor)), Sink_(std::move(SinkFunction)),
              Failure_(std::move(FailureFunction)),
              Idle_(std::make_shared<IdleChannel>(Ex_, 1))
        {
        }

        WireWriter(const WireWriter &) = delete;
        auto operator=(const WireWriter &) -> WireWriter & = delete;

        [[nodiscard]] auto Write(std::span<const std::byte> Data)
            -> Net::awaitable<WriteResult>
        {
            if (Data.empty())
            {
                co_return WriteResult{};
            }
            if (Closed_ || !Sink_)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }

            std::shared_ptr<RequestState> Request;
            bool Queued = false;
            try
            {
                Request = std::make_shared<RequestState>(Ex_, Data);
                Queue_.push_back(Request);
                Queued = true;
                Start();
            }
            catch (const std::bad_alloc &)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                if (Queued && !WriterRunning_)
                {
                    RecordFailure(Failure);
                    FailQueued(Failure, false);
                    SignalIdle();
                }
                else if (Request)
                {
                    (void)Request->Done.try_send(
                        boost::system::error_code{}, Failure);
                }
                co_return std::unexpected(Failure);
            }

            boost::system::error_code WaitEc;
            const auto Failure = co_await Request->Done.async_receive(
                Net::redirect_error(Net::use_awaitable, WaitEc));
            if (WaitEc)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(WaitEc)));
            }
            if (Failure.Failed())
                co_return std::unexpected(Failure);
            co_return WriteResult{};
        }

        /** @brief 停止接收新写入并失败完成所有排队请求。 */
        void Close()
        {
            Closed_ = true;
            FailQueued(Prism::Fault::FromNative(
                static_cast<std::error_code>(
                    boost::system::errc::make_error_code(boost::system::errc::not_connected))),
                false);
            SignalIdle();
            MarkRetiredIfDrained();
        }

        auto Seal() noexcept -> void override
        {
            Close();
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        /**
         * @brief 查询串行 writer 是否已完成物理退栈。
         * @return 已封止且无活动协程、请求队列或当前写入时为真；历史写入 Failure 不改变物理事实。
         */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        /** @brief 等待 writer coroutine 与已接纳写入在原 executor 全部退栈。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            Close();
            while (WriterRunning_ || !Queue_.empty())
            {
                boost::system::error_code WaitError;
                (void)co_await Idle_->async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitError));
                if (WaitError)
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(WaitError)));
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    private:
        struct RequestState final
        {
            RequestState(Net::any_io_executor Executor, std::span<const std::byte> Data)
                : Data(Data.begin(), Data.end()), Done(Executor, 1)
            {
            }

            std::vector<std::byte> Data;
            Completion Done;
        };

        void Start()
        {
            if (WriterRunning_ || Closed_ || Queue_.empty())
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = shared_from_this();
            try
            {
                Net::co_spawn(
                    Ex_, [Self]() -> Net::awaitable<void> { co_await Self->Loop(); },
                    [Self](std::exception_ptr Exception)
                    { Self->CompleteLoop(std::move(Exception)); });
            }
            catch (const std::bad_alloc &)
            {
                WriterRunning_ = false;
                throw;
            }
        }

        void FailQueued(Prism::Fault::Failure Failure, bool Record)
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                (void)Request->Done.try_send(boost::system::error_code{}, Failure);
                if (Record) RecordFailure(Failure);
            }
        }

        auto RecordFailure(Prism::Fault::Failure Failure) -> void
        {
            if (FirstFailure_.Succeeded() && Failure.Failed()) FirstFailure_ = Failure;
        }

        auto SignalIdle() -> void
        {
            if (!WriterRunning_ && Queue_.empty())
                (void)Idle_->try_send(boost::system::error_code{}, FirstFailure_);
        }

        auto MarkRetiredIfDrained() noexcept -> void
        {
            if (Closed_ && !WriterRunning_ && Queue_.empty() && !ActiveRequest_)
            {
                Retired_.store(true, std::memory_order_release);
            }
        }

        auto Loop() -> Net::awaitable<void>
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                ActiveRequest_ = Request;
                Prism::Fault::Failure Failure;
                if (Closed_ || !Sink_)
                {
                    Failure = Prism::Fault::FromNative(static_cast<std::error_code>(
                        boost::system::errc::make_error_code(boost::system::errc::not_connected)));
                }
                else
                {
                    const auto Result = co_await Sink_(Request->Data);
                    if (!Result) Failure = Result.error();
                }
                (void)Request->Done.try_send(boost::system::error_code{}, Failure);
                ActiveRequest_.reset();
                RecordFailure(Failure);
                if (Failure.Failed())
                {
                    Closed_ = true;
                    FailQueued(Failure, false);
                    NotifyFailure();
                    break;
                }
            }
            co_return;
        }

        auto CompleteLoop(std::exception_ptr Exception) noexcept -> void
        {
            if (Exception)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
                Closed_ = true;
                if (ActiveRequest_)
                {
                    (void)ActiveRequest_->Done.try_send(
                        boost::system::error_code{}, Failure);
                    ActiveRequest_.reset();
                }
                RecordFailure(Failure);
                FailQueued(Failure, false);
                NotifyFailure();
            }
            WriterRunning_ = false;
            SignalIdle();
            MarkRetiredIfDrained();
        }

        Net::any_io_executor Ex_;
        Sink Sink_;
        FailureCallback Failure_;
        std::deque<std::shared_ptr<RequestState>> Queue_;
        std::shared_ptr<IdleChannel> Idle_;
        std::atomic_bool Retired_{false};
        bool WriterRunning_{false};
        bool Closed_{false};
        bool FailureNotified_{false};
        Prism::Fault::Failure FirstFailure_{};
        std::shared_ptr<RequestState> ActiveRequest_;

        void NotifyFailure() noexcept
        {
            if (FailureNotified_ || !Failure_)
            {
                return;
            }
            FailureNotified_ = true;
            auto Callback = std::move(Failure_);
            try
            {
                Callback();
            }
            catch (...)
            {
                RecordFailure(Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
            }
        }
    };

} // namespace Prism::Xhttp::Detail
