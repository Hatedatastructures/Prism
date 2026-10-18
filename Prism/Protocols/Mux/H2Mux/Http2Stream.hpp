/** @file Http2Stream.hpp @brief 标准 HTTP/2 虚拟流的流控、双向终态和 tracked retirement。 */
#pragma once
#include <Prism/Protocols/Mux/H2Mux/Http2State.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>
namespace Prism::Mux::H2Mux
{
    class Http2Stream final : public Prism::Transmission
    {
    public:
        Http2Stream(std::shared_ptr<Http2State> StateValue, const std::int32_t StreamIdValue)
            : Prism::Transmission(StateValue ? StateValue->Strand : Net::any_io_executor{}),
              Executor_(StateValue ? StateValue->Strand : Net::any_io_executor{}),
              State_(std::move(StateValue)), StreamId_(StreamIdValue), Notify_(State_->Strand),
              Terminations_(std::make_shared<Prism::Lifecycle::DrainBarrier>(State_->Tasks->Reclaimer()))
        {
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int32_t { return StreamId_; }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        /** @brief 读取一部分虚拟流数据；结果与借用经正式前门恰好交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(StreamRead{
                std::static_pointer_cast<Http2Stream>(Transmission::shared_from_this()), Buffer},
                std::move(Handler));
        }

        /** @brief 写入一部分虚拟流数据；保留 DATA 提交与 Flush 的完整写入语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(StreamWrite{
                std::static_pointer_cast<Http2Stream>(Transmission::shared_from_this()), Buffer},
                std::move(Handler));
        }

        /** @brief 关闭当前虚拟流；本地 END_STREAM 实际 Flush 前保持 admission slot。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!State_ || Closed_) return {};
            if (State_->CloseRequested.load(std::memory_order_acquire))
            {
                MarkConnectionClosed();
                TryQueueRetirement();
                return {};
            }
            Closed_ = true;
            Rx_.clear();
            Activity()->Seal();
            Notify_.try_send(boost::system::error_code{});
            if (!FinSent_)
            {
                FinSent_ = true;
                LocalEndPending_ = true;
                auto Request = MakeControlRequest(ControlKind::Fin, Prism::Http2::ErrorNoError);
                return SubmitControl(std::move(Request));
            }
            TryQueueRetirement();
            return {};
        }
        /** @brief 本地半关闭只发送当前流 END_STREAM；共享 Raw 与兄弟流保持开启。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!State_ || State_->Closed ||
                State_->CloseRequested.load(std::memory_order_acquire))
            {
                Prism::Transport::Detail::PostResult(
                    Executor(), std::move(Handler), {0, {Prism::Fault::Code::Canceled}});
                return;
            }
            if (Closed_ || FinSent_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(), std::move(Handler), Prism::IoResult{});
                return;
            }
            FinSent_ = true;
            LocalEndPending_ = true;
            auto Request = MakeControlRequest(ControlKind::Fin, Prism::Http2::ErrorNoError);
            const auto Scheduled = SubmitControl(std::move(Request));
            if (!Scheduled)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(), std::move(Handler), {0, Scheduled.error()});
                return;
            }
            Prism::Transport::Detail::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{});
        }

        /** @brief 取消只重置当前流；排队或 Flush 失败保留 typed cause 与 slot。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return StartReset(Prism::Http2::ErrorCancel);
        }
        /** @brief 接管本 stream 的 RESET；不向共享连接传播 sibling cancellation。 */
        [[nodiscard]] auto StartReset(const std::uint32_t ErrorCode) -> ControlResult
        {
            if (!State_) return {};
            if (State_->CloseRequested.load(std::memory_order_acquire))
            {
                SetConnectionClosed();
                return {};
            }
            if (State_->Closed) return {};
            if (LocalTerminal_ && RemoteClosed_)
            {
                const auto BaseClosed = CloseBase();
                if (BaseClosed) TryQueueRetirement();
                return BaseClosed;
            }
            if (ResetByPeer_)
            {
                Closed_ = true;
                LocalTerminal_ = true;
                const auto BaseClosed = CloseBase();
                if (BaseClosed) TryQueueRetirement();
                return BaseClosed;
            }
            if (ResetPending_) return {};
            Closed_ = true;
            Rx_.clear();
            const auto BaseClosed = CloseBase();
            Notify_.try_send(boost::system::error_code{});
            if (!BaseClosed) return BaseClosed;
            ResetPending_ = true;
            LocalEndPending_ = true;
            return SubmitControl(MakeControlRequest(ControlKind::Reset, ErrorCode));
        }

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
        {
            if (State_ && State_->Raw) State_->Raw->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_ && State_ && !State_->Closed && State_->Raw && State_->Raw->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            // Raw 是 H2 根与所有虚拟流共享的 carrier，不归当前 child 所有。
            return nullptr;
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
        {
            // Raw 是 H2 根与所有虚拟流共享的 carrier，不归当前 child 所有。
            return nullptr;
        }

        auto Push(std::span<const std::byte> Data) -> void
        {
            if (Closed_ || RemoteClosed_ || Data.empty()) return;
            Rx_.emplace_back(Data.begin(), Data.end());
            Notify_.try_send(boost::system::error_code{});
        }

        auto MarkIncomingPending(const bool Pending) -> void
        {
            IncomingPending_ = Pending;
            if (!Pending) TryQueueRetirement();
        }

        /** @brief 远端 END_STREAM 只封止接收；仍须完成本地终态及在途读写。 */
        auto SetRemoteClosed() -> void
        {
            RemoteClosed_ = true;
            Notify_.try_send(boost::system::error_code{});
            TryQueueRetirement();
        }

        /** @brief RST_STREAM 终止双向协议流；先清理应用队列，再等待 I/O 退栈。 */
        auto SetRemoteReset(const std::uint32_t ErrorCode) -> void
        {
            RemoteResetCode_ = ErrorCode;
            RemoteClosed_ = true;
            ResetByPeer_ = true;
            LocalTerminal_ = true;
            Closed_ = true;
            Rx_.clear();
            const auto BaseClosed = CloseBase();
            IncomingPending_ = false;
            Notify_.try_send(boost::system::error_code{});
            if (BaseClosed) TryQueueRetirement();
        }
        /** @brief 根连接结束使当前流双向终态；仍等待真实 I/O 与 END barrier。 */
        auto SetConnectionClosed() -> void
        {
            Closed_ = true;
            const auto BaseClosed = CloseBase();
            MarkConnectionClosed();
            if (BaseClosed) TryQueueRetirement();
        }

    private:
        auto MarkConnectionClosed() -> void
        {
            RemoteClosed_ = LocalTerminal_ = FinSent_ = true;
            LocalEndPending_ = ResetPending_ = false;
            Rx_.clear();
            Activity()->Seal();
            IncomingPending_ = false;
            Notify_.try_send(boost::system::error_code{});
        }
        [[nodiscard]] auto CloseBase() -> ControlResult
        {
            const auto Result = Prism::Transmission::Close();
            if (!Result) { Activity()->Seal(); MarkRetirementFailed(Result.error()); }
            return Result;
        }

    public:
        [[nodiscard]] auto CanRetire() const noexcept -> bool
        {
            return Retired_ || (CanAttemptRetirement() && !RetirementFailed_);
        }

        [[nodiscard]] auto CanAttemptRetirement() const noexcept -> bool
        {
            return LocalTerminal_ && RemoteClosed_ && !LocalEndPending_ && !ResetPending_ &&
                !IncomingPending_ && Rx_.empty();
        }

        [[nodiscard]] auto HasPendingControl() const noexcept -> bool
        {
            return LocalEndPending_ || ResetPending_;
        }

        auto MarkRetirementFailed(const Prism::Fault::Failure Failure) -> void
        {
            RetirementFailed_ = true;
            RetirementQueued_ = false;
            if (State_) State_->RecordFailure(Failure);
        }

        auto MarkRetirementRecovered() noexcept -> void { RetirementFailed_ = false; }

        /** @brief 真实读写与控制屏障排空后分离已退休句柄和共享连接 owner。 */
        auto MarkRetired() noexcept -> void
        {
            Retired_ = true;
            Closed_ = true;
            RemoteClosed_ = true;
            LocalTerminal_ = true;
            Rx_.clear();
            Activity()->Seal();
            State_.reset();
            Terminations_.reset();
        }

        /** @brief 等待本流所有 FIN/RESET/Flush 协程退栈并返回完整首个 typed failure。 */
        [[nodiscard]] auto DrainTerminations()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Terminations_) co_return std::expected<void, Prism::Fault::Failure>{};
            Terminations_->Seal();
            co_return co_await Terminations_->Drain();
        }

    private:
        enum class ControlKind : std::uint8_t { Fin, Reset };

        struct StreamRead final
        {
            std::shared_ptr<Http2Stream> Owner;
            std::span<std::byte> Buffer;
        };

        struct StreamWrite final
        {
            std::shared_ptr<Http2Stream> Owner;
            std::span<const std::byte> Buffer;
        };

        struct ControlRequest final
        {
            std::shared_ptr<Http2State> State;
            std::shared_ptr<Http2Stream> Stream;
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier;
            std::int32_t Id{0};
            ControlKind Kind{ControlKind::Fin};
            std::uint32_t ErrorCode{Prism::Http2::ErrorNoError};
        };

        struct ReadWork final
        {
            template<class StateValue>
            auto operator()(StateValue Operation, StreamRead Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner)
                    co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code ErrorCode;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer, ErrorCode), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(ErrorCode)}};
            }
        };

        struct WriteWork final
        {
            template<class StateValue>
            auto operator()(StateValue Operation, StreamWrite Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner)
                    co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code ErrorCode;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer, ErrorCode), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(ErrorCode)}};
            }
        };

        /** @brief 原协程体：部分读取，先排空已收 DATA，再交付远端 EOF。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            co_await Net::dispatch(Executor_, Net::use_awaitable);
            while (true)
            {
                if (!State_ || State_->Closed || Closed_)
                {
                    ErrorCode = Prism::Fault::Code::Eof;
                    co_return 0;
                }
                if (!Rx_.empty())
                {
                    auto &Front = Rx_.front();
                    const auto Count = (std::min)(Buffer.size(), Front.size());
                    std::copy_n(Front.begin(), Count, Buffer.begin());
                    if (Count == Front.size()) Rx_.pop_front();
                    else Front.erase(Front.begin(), Front.begin() + static_cast<std::ptrdiff_t>(Count));
                    ErrorCode.clear();
                    if (Rx_.empty()) TryQueueRetirement();
                    co_return Count;
                }
                if (RemoteClosed_)
                {
                    ErrorCode = Prism::Fault::Code::Eof;
                    TryQueueRetirement();
                    co_return 0;
                }
                Notify_.reset();
                boost::system::error_code Notified;
                co_await Notify_.async_receive(Net::redirect_error(Net::use_awaitable, Notified));
                if (Notified)
                {
                    ErrorCode = Prism::Fault::Code::Eof;
                    co_return 0;
                }
                co_await Net::dispatch(Executor_, Net::use_awaitable);
            }
        }

        /** @brief 原协程体：部分写入，保留 DATA 提交与 Flush 的完整写入语义。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
        {
            co_await Net::dispatch(Executor_, Net::use_awaitable);
            if (Closed_ || FinSent_ || !State_ || State_->Closed || !State_->Session)
            {
                ErrorCode = std::make_error_code(std::errc::broken_pipe);
                co_return 0;
            }
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                const auto Count = (std::min)(std::size_t{16U * 1024U}, Buffer.size() - Offset);
                const auto Chunk = Buffer.subspan(Offset, Count);
                auto Submitted = State_->Session->SubmitData(StreamId_, Chunk, false);
                while (Submitted == Prism::Http2::SubmitDataStatus::Blocked)
                {
                    const auto PendingFrames = co_await State_->Flush();
                    if (!PendingFrames)
                    {
                        ErrorCode = Prism::Fault::ToNative(PendingFrames.Error);
                        if (PendingFrames.CloseCanceled)
                            State_->RecordCloseCancellation(PendingFrames.Error);
                        else
                            State_->RecordFailure(PendingFrames.Error);
                        co_return Offset;
                    }
                    const auto Writable = co_await State_->Session->AwaitWritable(StreamId_, Count);
                    if (!Writable)
                    {
                        ErrorCode = Prism::Fault::ToNative(Writable.error());
                        co_return Offset;
                    }
                    Submitted = State_->Session->SubmitData(StreamId_, Chunk, false);
                }
                if (Submitted != Prism::Http2::SubmitDataStatus::Accepted)
                {
                    Prism::Fault::Failure Failure{Prism::Fault::Code::InvalidArgument};
                    if (Submitted == Prism::Http2::SubmitDataStatus::Closed)
                    {
                        Failure = {Prism::Fault::Code::ConnectionAborted};
                    }
                    ErrorCode = Prism::Fault::ToNative(Failure);
                    co_return Offset;
                }
                const auto Flushed = co_await State_->Flush();
                if (!Flushed)
                {
                    ErrorCode = Prism::Fault::ToNative(Flushed.Error);
                    if (Flushed.CloseCanceled)
                        State_->RecordCloseCancellation(Flushed.Error);
                    else
                        State_->RecordFailure(Flushed.Error);
                    co_return Offset;
                }
                Offset += Count;
            }
            ErrorCode.clear();
            co_return Offset;
        }

        [[nodiscard]] auto MakeControlRequest(
            const ControlKind Kind,
            const std::uint32_t ErrorCode) -> ControlRequest
        {
            return {State_,
                    std::static_pointer_cast<Http2Stream>(Transmission::shared_from_this()),
                    Terminations_, StreamId_, Kind, ErrorCode};
        }

        [[nodiscard]] static auto SubmitControl(ControlRequest Value) -> ControlResult;
        [[nodiscard]] static auto ProcessControl(ControlRequest Request) -> Net::awaitable<void>;
        auto OnControlFailed(Prism::Fault::Failure Failure) -> void;
        auto OnControlCompleted(
            ControlKind Kind,
            const std::expected<void, Prism::Fault::Failure> &Outcome) -> void;

        auto TryQueueRetirement() -> void
        {
            if (!CanAttemptRetirement() || RetirementQueued_) return;
            RetirementFailed_ = false;
            RetirementQueued_ = true;
            if (State_) State_->QueueRetirement();
        }

        /** @brief 在唯一 stream executor 上发起一次受跟踪的部分 I/O。 */
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<Http2State> State_;
        std::int32_t StreamId_{0};
        Net::experimental::channel<void(boost::system::error_code)> Notify_;
        std::deque<std::vector<std::byte>> Rx_;
        bool RemoteClosed_{false};
        bool Closed_{false};
        bool FinSent_{false};
        bool LocalEndPending_{false};
        bool ResetPending_{false};
        bool ResetByPeer_{false};
        std::uint32_t RemoteResetCode_{Prism::Http2::ErrorNoError};
        bool LocalTerminal_{false};
        bool IncomingPending_{true};
        bool RetirementQueued_{false};
        bool RetirementFailed_{false};
        bool Retired_{false};
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Terminations_;
    };
}
