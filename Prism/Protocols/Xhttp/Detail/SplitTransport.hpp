/**
 * @file SplitTransport.hpp
 * @brief XHTTP Stream-up/Packet-up 的逻辑双向传输
 * @details 读侧消费下行 GET 的 DATA，写侧提交上行 POST；Packet-up
 *          的每次写入由 owner 创建新的上行流。
 */

#pragma once

#include <Prism/Protocols/Xhttp/Detail/Common.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    /**
     * @class SplitTransport
     * @brief XHTTP Split 模式的逻辑双向传输
     * @details Close/Cancel 负责本地队列和读等待，CloseFn 由会话 owner
     *          负责关闭 Wire 与加密连接。
     */
    class SplitTransport final : public Transmission
    {
    public:
        using WriteResult = std::expected<void, Prism::Fault::Failure>;
        using WriteCb = std::function<Net::awaitable<WriteResult>(std::span<const std::byte>)>;
        using CloseCb = std::function<Prism::Fault::Failure()>;

        SplitTransport(
            Net::any_io_executor Executor,
            WriteCb WriteFunction,
            CloseCb CloseFunction)
            : Transmission(Executor),
              Ex_(std::move(Executor)),
              WriteFn_(std::move(WriteFunction)),
              CloseFn_(std::move(CloseFunction)),
              Notify_(Ex_, 64)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        /** @brief 读取一部分已解出的载荷；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(ReadInput{Owner(), Buffer}, std::move(Handler));
        }

        /** @brief 写入一部分载荷；保留写队列与终止错误语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(WriteInput{Owner(), Buffer}, std::move(Handler));
        }

        /**
         * @brief split 模式 wire 不携带独立写方向 END_STREAM，半关闭按已交付返回。
         * @note 调用者不得据此断言对端已收到半关闭；反向读取保持可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }

        /** @brief 本地封止并交付关闭；底层 carrier 由持有最终关闭权的 owner 执行。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return CloseLocal();
        }

        /** @brief 可重复取消：与本地封止同一路径，不宣称底层已经关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return OnClose();
        }

        void Push(std::span<const std::byte> Data)
        {
            if (Closed_ || Data.empty())
            {
                return;
            }
            std::vector<std::byte> Copy(Data.begin(), Data.end());
            if (!Notify_.try_send(boost::system::error_code{}, std::move(Copy)))
            {
                Close();
            }
        }

        void NotifyEof()
        {
            if (!Closed_ && !TerminalError_ && !Eof_ && !EofPending_)
            {
                if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
                {
                    EofPending_ = true;
                }
            }
        }

        /** @brief 记录首个 H2/transport terminal error；错误优先于 EOF 并唤醒读写等待。 */
        void NotifyError(std::error_code ErrorCode)
        {
            if (TerminalError_)
            {
                return;
            }
            TerminalError_ = ErrorCode;
            if (!TerminalError_)
                TerminalError_ = std::make_error_code(std::errc::protocol_error);
            Eof_ = false;
            EofPending_ = false;
            (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
            FailQueued(Prism::Fault::FromNative(TerminalError_));
        }

    private:
        /** @brief 完成交付前的真实 owner 借用；存活由本次传输预约保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<SplitTransport>
        {
            return std::static_pointer_cast<SplitTransport>(Transmission::shared_from_this());
        }

        /** @brief 本地封止：置位 Closed、取消通知并唤醒全部挂起写请求。 */
        auto CloseLocal() -> ControlResult
        {
            if (Closed_)
            {
                if (CloseFailure_.Failed())
                {
                    return std::unexpected(CloseFailure_);
                }
                return {};
            }
            Closed_ = true;
            Notify_.cancel();
            FailQueued(Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected)));
            const auto Failure = NotifyClose();
            if (Failure.Failed())
            {
                return std::unexpected(Failure);
            }
            return {};
        }

        /** @brief 原协程体：读取通知块，保留终止错误、EOF 与短读语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            // RST/终止协议错误立即使排队载荷失效；错误可见后不再交付旧字节。
            if (TerminalError_)
            {
                ErrorCode = TerminalError_;
                co_return 0;
            }
            while (RxOffset_ >= RxCurrent_.size())
            {
                if (TerminalError_)
                {
                    ErrorCode = TerminalError_;
                    co_return 0;
                }
                if (Closed_)
                {
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Eof_)
                {
                    ErrorCode.clear();
                    co_return 0;
                }
                if (EofPending_ && !Notify_.ready())
                {
                    EofPending_ = false;
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                boost::system::error_code ChannelError;
                auto Block = co_await Notify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, ChannelError));
                if (ChannelError)
                {
                    if (TerminalError_)
                    {
                        ErrorCode = TerminalError_;
                    }
                    else
                    {
                        ErrorCode = std::make_error_code(std::errc::not_connected);
                    }
                    co_return 0;
                }
                if (TerminalError_)
                {
                    ErrorCode = TerminalError_;
                    co_return 0;
                }
                if (Block.empty())
                {
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                RxCurrent_ = std::move(Block);
                RxOffset_ = 0;
            }
            const auto Count = (std::min)(Buffer.size(), RxCurrent_.size() - RxOffset_);
            std::memcpy(Buffer.data(), RxCurrent_.data() + RxOffset_, Count);
            RxOffset_ += Count;
            ErrorCode.clear();
            co_return Count;
        }

        /** @brief 原协程体：经写队列提交载荷，保留终止错误与失败语义。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>
        {
            if (Buffer.empty())
            {
                Failure = {};
                co_return 0;
            }
            if (TerminalError_)
            {
                Failure = Prism::Fault::FromNative(TerminalError_);
                co_return 0;
            }
            if (Closed_ || !WriteFn_)
            {
                Failure = Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected));
                co_return 0;
            }
            std::shared_ptr<WriteRequest> Request;
            try
            {
                Request = std::make_shared<WriteRequest>(Ex_, Buffer);
                WriteQueue_.push_back(Request);
                StartWriter();
            }
            catch (const std::bad_alloc &)
            {
                Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                FailQueued(Failure);
                co_return 0;
            }

            boost::system::error_code WaitError;
            const auto [Written, WriteFailure] = co_await Request->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            if (WaitError)
            {
                Failure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(WaitError));
                co_return 0;
            }
            Failure = WriteFailure;
            if (Failure.Failed()) co_return 0;
            co_return Written;
        }

        struct ReadInput final { std::shared_ptr<SplitTransport> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<SplitTransport> Owner; std::span<const std::byte> Buffer; };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.Owner->ReadPartial(Input.Buffer, Error),
                    Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                Prism::Fault::Failure Failure;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.Owner->WritePartial(Input.Buffer, Failure),
                    Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Failure}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        using CompletionChannel = Net::experimental::channel<
            void(boost::system::error_code, std::size_t, Prism::Fault::Failure)>;

        struct WriteRequest final
        {
            WriteRequest(Net::any_io_executor Executor, std::span<const std::byte> Bytes)
                : Data(Bytes.begin(), Bytes.end()), Done(std::make_shared<CompletionChannel>(Executor, 1))
            {
            }

            std::vector<std::byte> Data;
            std::shared_ptr<CompletionChannel> Done;
        };

        void StartWriter()
        {
            if (WriterRunning_ || Closed_ || WriteQueue_.empty())
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = std::static_pointer_cast<SplitTransport>(Transmission::shared_from_this());
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
                (void)Request->Done->try_send(
                    boost::system::error_code{}, 0, Failure);
            }
        }

        auto NotifyClose() -> Prism::Fault::Failure
        {
            if (CloseNotified_)
            {
                return CloseFailure_;
            }
            CloseNotified_ = true;
            if (CloseFn_)
            {
                try
                {
                    const auto Failure = CloseFn_();
                    if (CloseFailure_.Succeeded() && Failure.Failed())
                        CloseFailure_ = Failure;
                }
                catch (...)
                {
                    CloseFailure_ = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
                }
            }
            if (CloseFailure_.Failed()) NotifyError(Prism::Fault::ToNative(CloseFailure_));
            return CloseFailure_;
        }

        auto WriteLoop() -> Net::awaitable<void>
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                ActiveWriteRequest_ = Request;
                Prism::Fault::Failure Failure;
                std::size_t Written = 0;
                if (Closed_ || !WriteFn_)
                {
                    Failure = Prism::Fault::FromNative(
                        std::make_error_code(std::errc::not_connected));
                }
                else
                {
                    const auto Result = co_await WriteFn_(Request->Data);
                    if (!Result) Failure = Result.error();
                    if (!Failure.Failed()) Written = Request->Data.size();
                }
                (void)Request->Done->try_send(
                    boost::system::error_code{}, Written, Failure);
                ActiveWriteRequest_.reset();
                if (Failure.Failed())
                {
                    NotifyError(Prism::Fault::ToNative(Failure));
                    Closed_ = true;
                    FailQueued(Failure);
                    (void)NotifyClose();
                    break;
                }
            }
            co_return;
        }

        auto CompleteWriteLoop(std::exception_ptr Exception) noexcept -> void
        {
            if (Exception)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
                if (ActiveWriteRequest_)
                {
                    (void)ActiveWriteRequest_->Done->try_send(
                        boost::system::error_code{}, 0, Failure);
                    ActiveWriteRequest_.reset();
                }
                NotifyError(Prism::Fault::ToNative(Failure));
                Closed_ = true;
                FailQueued(Failure);
                NotifyClose();
            }
            WriterRunning_ = false;
        }

        using ChannelType =
            Net::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::byte>)>;

        Net::any_io_executor Ex_;
        WriteCb WriteFn_;
        CloseCb CloseFn_;
        ChannelType Notify_;
        std::vector<std::byte> RxCurrent_;
        std::size_t RxOffset_{0};
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        bool WriterRunning_{false};
        std::shared_ptr<WriteRequest> ActiveWriteRequest_;
        bool Closed_{false};
        bool CloseNotified_{false};
        Prism::Fault::Failure CloseFailure_;
        bool Eof_{false};
        bool EofPending_{false};
        std::error_code TerminalError_{};
    };

} // namespace Prism::Xhttp::Detail
