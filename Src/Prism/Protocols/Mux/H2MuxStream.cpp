/** @file H2MuxStream.cpp @brief H2Mux 子流状态与 I/O 实现。 */
#include <Prism/Protocols/Mux/H2Mux/Http2Stream.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <cstddef>
#include <system_error>
#include <utility>

namespace Prism::Mux::H2Mux
{
    namespace
    {
        /** @brief 本地 reset/close 导致的后续写失败属于本端取消，不冒充连接级中止。 */
        [[nodiscard]] auto LocalWriteFailure(
            const Prism::Fault::Failure Failure,
            const bool LocalTermination) -> Prism::Fault::Failure
        {
            if (LocalTermination &&
                Failure.Code == Prism::Fault::Code::ConnectionAborted)
                return {Prism::Fault::Code::Canceled};
            return Failure;
        }
    }

    [[nodiscard]] auto Http2Stream::CanAttemptRetirement() const noexcept -> bool
    {
        return LocalTerminal_ && RemoteClosed_ && !LocalEndPending_ && !ResetPending_ &&
            !IncomingPending_ && Rx_.empty() &&
            (!StreamTerminalPending_ || TerminalCloseFinalized_);
    }

    Http2Stream::Http2Stream(
        std::shared_ptr<Http2State> StateValue,
        const std::int32_t StreamIdValue)
        : Prism::Transmission(StateValue ? StateValue->Strand : Net::any_io_executor{}),
          Executor_(StateValue ? StateValue->Strand : Net::any_io_executor{}),
          State_(std::move(StateValue)), StreamId_(StreamIdValue),
          Notify_(std::make_unique<Net::experimental::channel<void(
              boost::system::error_code)>>(State_->Strand)),
          Terminations_(std::make_shared<Prism::Lifecycle::DrainBarrier>(State_->Tasks->Reclaimer()))
    {
    }

    auto Http2Stream::OnClose() -> Prism::Transmission::ControlResult
    {
        CloseReceiptAvailable_ = true;
        if (!State_) return {};
        // Close 是 root/child 对当前流的最终接收决定；即使流此前已被本端
        // RST 标记为 Closed，也必须解除 accept 前遗留的 IncomingPending。
        MarkIncomingPending(false);
        if (ConnectionClosed_ || StreamTerminalPending_)
        {
            Rx_.clear();
            FinalizeTerminalClose();
            return {};
        }
        if (Closed_) return {};
        if (State_->CloseRequested.load(std::memory_order_acquire))
        {
            SetConnectionClosed(State_->ConnectionCloseFailure());
            FinalizeTerminalClose();
            return {};
        }
        Closed_ = true;
        LocalClose_ = true;
        Rx_.clear();
        Activity()->Seal();
        Notify_->try_send(boost::system::error_code{});
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

    auto Http2Stream::StartWriteShutdown(Prism::Transmission::Completion Handler) -> void
    {
        if (LocalEndFlushed_)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{});
            return;
        }
        if (LocalEndFailure_)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, *LocalEndFailure_});
            return;
        }
        if (!State_ || State_->Closed ||
            State_->CloseRequested.load(std::memory_order_acquire))
        {
            auto Failure = State_ ? State_->ConnectionTerminal.Load() :
                Prism::Fault::Failure{Prism::Fault::Code::Canceled};
            if (!Failure.Failed()) Failure = {Prism::Fault::Code::Canceled};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, Failure});
            return;
        }
        if (FinSent_ && LocalEndPending_)
        {
            PendingWriteShutdowns_.push_back(std::move(Handler));
            return;
        }
        if (Closed_ || FinSent_)
        {
            const auto Failure = ResetByPeer_
                ? PeerResetFailure()
                : Prism::Fault::Failure{Prism::Fault::Code::Canceled};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, Failure});
            return;
        }
        FinSent_ = true;
        LocalEndPending_ = true;
        PendingWriteShutdowns_.push_back(std::move(Handler));
        auto Request = MakeControlRequest(ControlKind::Fin, Prism::Http2::ErrorNoError);
        const auto Scheduled = SubmitControl(std::move(Request));
        if (!Scheduled)
        {
            LocalEndPending_ = false;
            if (!LocalEndFailure_) LocalEndFailure_ = Scheduled.error();
            CompletePendingWriteShutdowns(*LocalEndFailure_);
        }
    }

    auto Http2Stream::StartReset(const std::uint32_t ErrorCode)
        -> Prism::Transmission::ControlResult
    {
        if (!State_) return {};
        if (State_->CloseRequested.load(std::memory_order_acquire))
        {
            SetConnectionClosed(State_->ConnectionCloseFailure());
            FinalizeTerminalClose();
            return {};
        }
        if (State_->Closed) return {};
        if (ResetByPeer_)
        {
            Closed_ = true;
            LocalTerminal_ = true;
            const auto BaseClosed = CloseBase();
            if (BaseClosed) TryQueueRetirement();
            if (!BaseClosed) return BaseClosed;
            const Prism::Fault::Failure Failure{Prism::Fault::Code::ConnectionAborted};
            State_->RecordFailure(Failure);
            return std::unexpected(Failure);
        }
        if (LocalTerminal_ && RemoteClosed_)
        {
            const auto BaseClosed = CloseBase();
            if (BaseClosed) TryQueueRetirement();
            return BaseClosed;
        }
        if (ResetPending_) return {};
        Closed_ = true;
        LocalReset_ = ErrorCode == Prism::Http2::ErrorCancel;
        Rx_.clear();
        // 先预约本层最终 Close；Activity 的就绪依赖该命令的真实交付。
        const auto BaseClosed = CloseBase();
        Notify_->try_send(boost::system::error_code{});
        if (!BaseClosed)
        {
            // Close 失败仍需收敛虚拟流终态并保留首因；不能让目录项停在 Draining。
            RemoteClosed_ = true;
            LocalTerminal_ = true;
            MarkIncomingPending(false);
            TryQueueRetirement();
            return BaseClosed;
        }
        ResetPending_ = true;
        LocalEndPending_ = true;
        const auto Scheduled = SubmitControl(MakeControlRequest(ControlKind::Reset, ErrorCode));
        if (Scheduled)
        {
            // 只有 RESET 的真实提交/Flush 完成后才发布双向终态；若底层会话已
            // 先关闭该 stream，保留原 RemoteClosed_ 以正确暴露 ConnectionAborted。
        }
        else
        {
            // 控制预约已被封止时，本端仍必须发布虚拟流终态；
            // 失败原因由 ControlFailure 保留，不能让目录项永久停在 Draining。
            RemoteClosed_ = true;
            LocalTerminal_ = true;
            // Barrier::Enter 失败不会进入 OnControlFailed；这里必须自行
            // 清掉控制台账，否则 CanAttemptRetirement 会永久等待 RESET。
            ResetPending_ = false;
            LocalEndPending_ = false;
            MarkIncomingPending(false);
            TryQueueRetirement();
        }
        return Scheduled;
    }

    auto Http2Stream::Push(const std::span<const std::byte> Data) -> void
    {
        if (Closed_ || RemoteClosed_ || Data.empty()) return;
        Rx_.emplace_back(Data.begin(), Data.end());
        Notify_->try_send(boost::system::error_code{});
    }

    auto Http2Stream::MarkIncomingPending(const bool Pending) -> void
    {
        IncomingPending_ = Pending;
        if (!Pending) TryQueueRetirement();
    }

    auto Http2Stream::AcceptRequest()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (!State_)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (State_->Closed || ResetByPeer_ || ConnectionClosed_)
        {
            // 流/连接已在提交 200 前终止，没有可兑现的响应合同；这不是应用失败，
            // 不能让 root 把一个已终止流的竞争窗口记成终端故障。
            MarkIncomingPending(false);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (LocalTerminal_)
        {
            MarkIncomingPending(false);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        const auto Headers = State_->Session->SubmitHeaders(
            StreamId_, Prism::Http2::HeaderList{{":status", "200"}}, false);
        if (!Headers)
        {
            State_->RecordFailure(Headers.error());
            MarkIncomingPending(false);
            (void)StartReset(Prism::Http2::ErrorInternal);
            co_return std::unexpected(Headers.error());
        }
        const auto Flushed = co_await State_->Flush();
        if (!Flushed)
        {
            State_->RecordFailure(Flushed.Error);
            MarkIncomingPending(false);
            (void)StartReset(Prism::Http2::ErrorInternal);
            co_return std::unexpected(Flushed.Error);
        }
        MarkIncomingPending(false);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Http2Stream::SetRemoteClosed() -> void
    {
        RemoteClosed_ = true;
        Notify_->try_send(boost::system::error_code{});
        TryQueueRetirement();
    }

    auto Http2Stream::SetRemoteReset(const std::uint32_t ErrorCode) -> void
    {
        const auto Unaccepted = IncomingPending_;
        RemoteResetCode_ = ErrorCode;
        RemoteClosed_ = true;
        ResetByPeer_ = true;
        LocalTerminal_ = true;
        Closed_ = true;
        Rx_.clear();
        LocalEndPending_ = ResetPending_ = false;
        StreamTerminalPending_ = true;
        IncomingPending_ = false;
        Notify_->try_send(boost::system::error_code{});
        if (Unaccepted || CloseReceiptAvailable_)
        {
            FinalizeTerminalClose();
        }
        else
        {
            TryQueueRetirement();
            if (State_) State_->NotifyStreamDrain();
        }
    }

    auto Http2Stream::SetConnectionClosed(const Prism::Fault::Failure Terminal) -> void
    {
        if (ConnectionClosed_) return;
        const auto Unaccepted = IncomingPending_;
        ConnectionClosed_ = true;
        Closed_ = true;
        if (!RemoteClosed_)
        {
            RemoteClosed_ = true;
            ConnectionTerminal_ = Terminal.Failed()
                ? Terminal : Prism::Fault::Failure{Prism::Fault::Code::Eof};
        }
        LocalEndPending_ = ResetPending_ = false;
        FinSent_ = true;
        StreamTerminalPending_ = true;
        Notify_->try_send(boost::system::error_code{});
        if (Unaccepted || CloseReceiptAvailable_)
        {
            Rx_.clear();
            FinalizeTerminalClose();
        }
        else
        {
            TryQueueRetirement();
            if (State_) State_->NotifyStreamDrain();
        }
    }

    auto Http2Stream::FinalizeTerminalClose() -> void
    {
        if (TerminalCloseFinalized_) return;
        TerminalCloseFinalized_ = true;
        Closed_ = true;
        RemoteClosed_ = LocalTerminal_ = FinSent_ = true;
        LocalEndPending_ = ResetPending_ = false;
        IncomingPending_ = false;
        Notify_->try_send(boost::system::error_code{});
        if (!CloseReceiptAvailable_)
        {
            const auto CloseResult = CloseBase();
            if (!CloseResult && State_) State_->RecordFailure(CloseResult.error());
        }
        Activity()->Seal();
        TryQueueRetirement();
        if (State_) State_->NotifyStreamDrain();
    }

    auto Http2Stream::CloseBase() -> Prism::Transmission::ControlResult
    {
        const auto Result = Prism::Transmission::Close();
        if (!Result) { Activity()->Seal(); MarkRetirementFailed(Result.error()); }
        return Result;
    }

    auto Http2Stream::MarkRetirementFailed(const Prism::Fault::Failure Failure) -> void
    {
        RetirementFailed_ = true;
        RetirementQueued_ = false;
        if (State_) State_->RecordFailure(Failure);
    }

    auto Http2Stream::MarkRetired() noexcept -> void
    {
        Retired_ = true;
        Closed_ = true;
        RemoteClosed_ = true;
        LocalTerminal_ = true;
        Rx_.clear();
        Notify_->close();
        Notify_.reset();
        Activity()->Seal();
        State_.reset();
        Terminations_.reset();
    }

    auto Http2Stream::DrainTerminations()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        // 先回到流所属 strand，确保此前排队的 Cancel/Close 已进入正式控制队列。
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        // 引擎 pump 与 root child 可能并发提交同一条流的 Finish。第一个调用者
        // 已退休后，第二个调用只观察完成事实，绝不能重新封止已释放的控制屏障。
        if (Retired_)
            co_return std::expected<void, Prism::Fault::Failure>{};
        // root 已按 accepted child 完成协议终止；此处解除 accept-loop 待定事实，
        // 让 IncomingPending 不再成为长期 Draining 的原因。
        MarkIncomingPending(false);
        // 终止阶段不允许遗留读继续停在单槽 Notify 上；唤醒后 ReadPartial
        // 会按 LocalReset/LocalClose/RemoteClosed 交付真实终态并归还 Activity。
        Notify_->try_send(boost::system::error_code{});
        Prism::Fault::Failure FirstFailure;
        // 退休 pump 可能先于 root child 的最终 Close 观察到双向终态。此处必须
        // 主动发起本层 Close，确保随后等待的是真实 OnClose 交付，而不是把
        // Activity 封止后再让迟到的 Close 以 Canceled 失败。
        if (!CloseReceiptAvailable_)
        {
            // SetRemoteReset/SetConnectionClosed 会先置 Closed_；即使如此也必须
            // 提交一次真实 Close，才能产生 IoActivity 的 close 回执并使
            // Activity()->IsRetired() 成立。否则目录项会永久停在 Draining。
            const auto Closed = CloseBase();
            if (!Closed && Closed.error().Code != Prism::Fault::Code::Canceled)
                FirstFailure = Closed.error();
        }
        // Close 命令的 Delivery 才真正执行 OnClose 并登记 END_STREAM。这里只等
        // close dispatch 的真实回执，不提前封止 IoActivity，否则 OnCancel 在
        // CloseBase 阶段就会被拒绝，RESET_STREAM 无法发出。
        if (const auto Receipt = CloseReceipt())
        {
            const auto Dispatched = co_await Receipt->AwaitCloseDispatch();
            // CloseBase 已同步受理的关闭命令只有在真实交付结束后才会进入
            // Terminal；等待该回执是本流 Activity 可退休的必要条件。
            if (!Dispatched && !FirstFailure.Failed() &&
                Dispatched.error().Code != Prism::Fault::Code::Canceled)
                FirstFailure = Dispatched.error();
        }
        // IoActivity 同时覆盖 OnClose/OnCancel 控制预约和真实 I/O；在 Seal
        // Terminations 之前等待它可以避免后续 RESET/END_STREAM 被提前封止。
        const auto ActivityDrained = co_await Activity()->Drain();
        const bool ExpectedCancellation = LocalReset_ || LocalClose_ ||
            ResetByPeer_ || ConnectionClosed_;
        if (!ActivityDrained && !FirstFailure.Failed() &&
            !(ExpectedCancellation &&
              ActivityDrained.error().Code == Prism::Fault::Code::Canceled))
            FirstFailure = ActivityDrained.error();
        // close dispatch 已在原 executor 返回；回到当前 strand 后再 Seal，
        // 保证 OnClose/OnCancel 提交的终态控制已经登记到 Terminations。
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (!Terminations_)
        {
            if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        Terminations_->Seal();
        const auto Drained = co_await Terminations_->Drain();
        if (!Drained && !FirstFailure.Failed() &&
            !(ExpectedCancellation &&
              Drained.error().Code == Prism::Fault::Code::Canceled))
            FirstFailure = Drained.error();
        if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Http2Stream::ReadPartial(
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Buffer.empty())
        {
            ErrorCode.clear();
            co_return 0;
        }
        while (true)
        {
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
            // peer RST 是流级粘滞终态；之后的根 EOF/reset 不能覆盖它。
            if (ResetByPeer_)
            {
                ErrorCode = std::make_error_code(std::errc::connection_aborted);
                TryQueueRetirement();
                co_return 0;
            }
            if (ConnectionTerminal_)
            {
                ErrorCode = Prism::Fault::ToNative(*ConnectionTerminal_);
                co_return 0;
            }
            if (LocalReset_)
            {
                ErrorCode = Prism::Fault::ToNative(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                TryQueueRetirement();
                co_return 0;
            }
            if (LocalClose_)
            {
                ErrorCode = Prism::Fault::ToNative(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                TryQueueRetirement();
                co_return 0;
            }
            if (RemoteClosed_)
            {
                ErrorCode = Prism::Fault::Code::Eof;
                TryQueueRetirement();
                co_return 0;
            }
            if (!State_ || State_->Closed)
            {
                ErrorCode = Prism::Fault::Code::Eof;
                co_return 0;
            }
            Notify_->reset();
            boost::system::error_code Notified;
            co_await Notify_->async_receive(Net::redirect_error(Net::use_awaitable, Notified));
            if (Notified)
            {
                ErrorCode = LocalReset_
                    ? Prism::Fault::ToNative(
                        Prism::Fault::Failure{Prism::Fault::Code::Canceled})
                    : Prism::Fault::Code::Eof;
                co_return 0;
            }
            co_await Net::dispatch(Executor_, Net::use_awaitable);
        }
    }

    auto Http2Stream::WritePartial(
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Closed_ || FinSent_ || !State_ || State_->Closed || !State_->Session)
        {
            if (LocalReset_ || LocalClose_)
                ErrorCode = Prism::Fault::ToNative(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            else
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
                    ErrorCode = Prism::Fault::ToNative(
                        LocalWriteFailure(
                            PendingFrames.Error, LocalReset_ || LocalClose_));
                    if (PendingFrames.CloseCanceled)
                        State_->RecordCloseCancellation(PendingFrames.Error);
                    else
                        State_->RecordFailure(PendingFrames.Error);
                    co_return Offset;
                }
                const auto Writable = co_await State_->Session->AwaitWritable(StreamId_, Count);
                if (!Writable)
                {
                    ErrorCode = Prism::Fault::ToNative(
                        LocalWriteFailure(Writable.error(), LocalReset_ || LocalClose_));
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
                ErrorCode = Prism::Fault::ToNative(
                    LocalWriteFailure(Failure, LocalReset_ || LocalClose_));
                co_return Offset;
            }
            const auto Flushed = co_await State_->Flush();
            if (!Flushed)
            {
                ErrorCode = Prism::Fault::ToNative(
                    LocalWriteFailure(Flushed.Error, LocalReset_ || LocalClose_));
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

} // namespace Prism::Mux::H2Mux
