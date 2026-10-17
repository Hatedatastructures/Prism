/** @file Http2StreamControl.hpp @brief H2Mux 虚拟流终止帧提交与退休。 */
#pragma once

#include <Preview/Protocols/Mux/H2Mux/Http2Stream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <utility>

namespace Preview::Mux::H2Mux
{
    /** @brief 原 executor 上预约并追踪本流 END_STREAM 或 RST_STREAM。 */
    inline auto Http2Stream::SubmitControl(ControlRequest Value) -> ControlResult
    {
        if (!Value.State || !Value.Stream)
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        if (!Value.Barrier->Enter())
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        Preview::Lifecycle::TaskRequest Request;
        Request.Context = Preview::Lifecycle::FromParent(Value.State->Identity);
        Request.Context.StreamId = Preview::StreamId{static_cast<std::uint64_t>(Value.Id)};
        Request.StartOnSubmit = true;
        const auto WeakStream = std::weak_ptr<Http2Stream>(Value.Stream);
        Request.Cancel = [WeakStream]
        {
            if (const auto Stream = WeakStream.lock())
                Stream->OnControlFailed({Preview::Fault::Code::Canceled});
        };
        const auto Barrier = Value.Barrier;
        const auto Stream = Value.Stream;
        const auto Spawned = Value.State->Tasks->SpawnTracked(
            std::move(Request), ProcessControl(std::move(Value)));
        if (Spawned) return {};
        Barrier->Leave();
        Stream->OnControlFailed(Spawned.error());
        return std::unexpected(Spawned.error());
    }

    /** @brief 发送本流控制帧并完成唯一 writer Flush；失败不退还 admission slot。 */
    inline auto Http2Stream::ProcessControl(ControlRequest Request) -> Net::awaitable<void>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        struct Completion final
        {
            std::shared_ptr<Preview::Lifecycle::DrainBarrier> Barrier;
            ~Completion() { Barrier->Leave(); }
        } Done{Request.Barrier};
        const auto State = Request.State;
        const auto Stream = Request.Stream;
        auto Outcome = std::expected<void, Preview::Fault::Failure>{};
        bool CloseCanceled = false;
        // CloseRequested 先于 strand 上的 Closed 发布；关闭期间跳过尚未提交的流控制帧。
        if (State && !State->Closed && State->Session &&
            !State->CloseRequested.load(std::memory_order_acquire))
        {
            if (Request.Kind == ControlKind::Fin)
            {
                const auto Submitted = State->Session->SubmitData(
                    Request.Id, std::span<const std::byte>{}, true);
                if (Submitted == Preview::Http2::SubmitDataStatus::Accepted)
                {
                    const auto Flushed = co_await State->Flush();
                    CloseCanceled = Flushed.CloseCanceled;
                    if (!Flushed) Outcome = std::unexpected(Flushed.Error);
                }
                else if (Submitted == Preview::Http2::SubmitDataStatus::Blocked)
                    Outcome = std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::WouldBlock});
                else if (Submitted == Preview::Http2::SubmitDataStatus::Closed)
                {
                    Outcome = std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::ConnectionAborted});
                }
                else
                    Outcome = std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            else
            {
                const auto Submitted = State->Session->ResetStream(Request.Id, Request.ErrorCode);
                if (!Submitted)
                {
                    const auto AlreadyRemoteClosed =
                        Submitted.error().Code == Preview::Fault::Code::ConnectionAborted &&
                        Stream->RemoteClosed_;
                    if (!AlreadyRemoteClosed)
                    {
                        Outcome = std::unexpected(Submitted.error());
                    }
                }
                else
                {
                    const auto Flushed = co_await State->Flush();
                    CloseCanceled = Flushed.CloseCanceled;
                    if (!Flushed) Outcome = std::unexpected(Flushed.Error);
                }
            }
        }
        co_await Net::dispatch(State->Strand, Net::use_awaitable);
        if (!Outcome)
        {
            if (CloseCanceled) State->RecordCloseCancellation(Outcome.error());
            else State->RecordFailure(Outcome.error());
        }
        Stream->OnControlCompleted(Request.Kind, Outcome);
    }

    inline auto Http2Stream::OnControlFailed(const Preview::Fault::Failure Failure) -> void
    {
        LocalEndPending_ = false;
        ResetPending_ = false;
        if (State_) State_->RecordFailure(Failure);
    }

    inline auto Http2Stream::OnControlCompleted(
        const ControlKind Kind,
        const std::expected<void, Preview::Fault::Failure> &Outcome) -> void
    {
        LocalEndPending_ = false;
        if (!Outcome)
        {
            ResetPending_ = false;
            TryQueueRetirement();
            return;
        }
        if (Kind == ControlKind::Reset)
        {
            ResetPending_ = false;
            ResetByPeer_ = false;
            RemoteClosed_ = true;
            Closed_ = true;
            LocalTerminal_ = true;
            Rx_.clear();
        }
        else
        {
            LocalTerminal_ = true;
        }
        TryQueueRetirement();
    }
}
