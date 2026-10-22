/**
 * @file H2MuxStreamControl.cpp
 * @brief H2Mux 子流控制帧与关闭状态实现。
 */

#include <Prism/Protocols/Mux/H2Mux/Http2StreamControl.hpp>

#include <Prism/Protocols/Mux/H2Mux/Http2Stream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <cstdint>

namespace Prism::Mux::H2Mux
{
    auto Http2Stream::MakeControlRequest(
        const Http2Stream::ControlKind Kind,
        const std::uint32_t ErrorCode) -> Http2Stream::ControlRequest
    {
        return {State_,
                std::static_pointer_cast<Http2Stream>(Transmission::shared_from_this()),
                Terminations_, StreamId_, Kind, ErrorCode};
    }

    auto Http2Stream::TryQueueRetirement() -> void
    {
        if (!CanAttemptRetirement() || RetirementQueued_) return;
        RetirementFailed_ = false;
        RetirementQueued_ = true;
        if (State_) State_->QueueRetirement();
    }

    auto Http2Stream::CompletePendingWriteShutdowns(
        const Prism::Fault::Failure Failure) -> void
    {
        auto Pending = std::move(PendingWriteShutdowns_);
        PendingWriteShutdowns_.clear();
        for (auto &Handler : Pending)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{0, Failure});
        }
    }

    /** @brief 原 executor 上预约并追踪本流 END_STREAM 或 RST_STREAM。 */
    auto Http2Stream::SubmitControl(ControlRequest Value) -> ControlResult
    {
        if (!Value.State || !Value.Stream)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        if (!Value.Barrier->Enter())
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        const auto Kind = Value.Kind;
        Prism::Lifecycle::TaskRequest Request;
        Request.Context = Prism::Lifecycle::FromParent(Value.State->Identity);
        Request.Context.StreamId = Prism::StreamId{static_cast<std::uint64_t>(Value.Id)};
        Request.StartOnSubmit = true;
        const auto WeakStream = std::weak_ptr<Http2Stream>(Value.Stream);
        Request.Cancel = [WeakStream, Kind]
        {
            if (const auto Stream = WeakStream.lock())
                Stream->OnControlFailed(Kind, {Prism::Fault::Code::Canceled});
        };
        const auto Barrier = Value.Barrier;
        const auto Stream = Value.Stream;
        const auto Spawned = Value.State->Tasks->SpawnTracked(
            std::move(Request), ProcessControl(std::move(Value)));
        if (Spawned) return {};
        Barrier->Leave();
        Stream->OnControlFailed(Kind, Spawned.error());
        return std::unexpected(Spawned.error());
    }

    /** @brief 发送本流控制帧并完成唯一 writer Flush；失败不退还 admission slot。 */
    auto Http2Stream::ProcessControl(ControlRequest Request) -> Net::awaitable<void>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        struct Completion final
        {
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier;
            ~Completion() { Barrier->Leave(); }
        } Done{Request.Barrier};
        const auto State = Request.State;
        const auto Stream = Request.Stream;
        auto Outcome = std::expected<void, Prism::Fault::Failure>{};
        bool CloseCanceled = false;
        try
        {
            // CloseRequested 先于 strand 上的 Closed 发布；关闭期间跳过尚未提交的流控制帧。
            if (!State || !Stream)
            {
                Outcome = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            else if (State->Closed || State->CloseRequested.load(std::memory_order_acquire))
            {
                const auto Terminal = State->ConnectionTerminal.Load();
                const auto Failure = Terminal.Failed()
                    ? Terminal : Prism::Fault::Failure{Prism::Fault::Code::Canceled};
                Outcome = std::unexpected(Failure);
                CloseCanceled = Failure.Code == Prism::Fault::Code::Canceled;
            }
            else if (!State->Session)
            {
                Outcome = std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            else if (Request.Kind == ControlKind::Fin)
            {
                const auto Submitted = State->Session->SubmitData(
                    Request.Id, std::span<const std::byte>{}, true);
                if (Submitted == Prism::Http2::SubmitDataStatus::Accepted)
                {
                    const auto Flushed = co_await State->Flush();
                    CloseCanceled = Flushed.CloseCanceled;
                    if (!Flushed) Outcome = std::unexpected(Flushed.Error);
                }
                else if (Submitted == Prism::Http2::SubmitDataStatus::Blocked)
                    Outcome = std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                else if (Submitted == Prism::Http2::SubmitDataStatus::Closed)
                {
                    Outcome = std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ConnectionAborted});
                }
                else
                    Outcome = std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            else
            {
                const auto Submitted = State->Session->ResetStream(Request.Id, Request.ErrorCode);
                if (!Submitted)
                {
                    const auto AlreadyRemoteClosed =
                        Submitted.error().Code == Prism::Fault::Code::ConnectionAborted &&
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
        catch (const boost::system::system_error &Exception)
        {
            Outcome = std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Exception.code())));
        }
        catch (const std::system_error &Exception)
        {
            Outcome = std::unexpected(Prism::Fault::FromNative(Exception.code()));
        }
        catch (const std::bad_alloc &)
        {
            Outcome = std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
        }
        catch (...)
        {
            Outcome = std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        co_await Net::dispatch(State->Strand, Net::use_awaitable);
        if (!Outcome)
        {
            if (CloseCanceled || (State->CloseRequested.load(std::memory_order_acquire) &&
                                  Outcome.error().Code == Prism::Fault::Code::Eof))
                State->RecordCloseCancellation({Prism::Fault::Code::Canceled});
            else State->RecordFailure(Outcome.error());
        }
        Stream->OnControlCompleted(Request.Kind, Outcome);
    }

    auto Http2Stream::OnControlFailed(
        const ControlKind Kind,
        Prism::Fault::Failure Failure) -> void
    {
        LocalEndPending_ = false;
        ResetPending_ = false;
        const auto CloseCancellation = Failure.Code == Prism::Fault::Code::Canceled && State_ &&
            State_->CloseRequested.load(std::memory_order_acquire);
        if (Failure.Code == Prism::Fault::Code::Canceled && State_)
        {
            const auto Terminal = State_->ConnectionTerminal.Load();
            if (Terminal.Failed()) Failure = Terminal;
        }
        if (Kind == ControlKind::Reset)
        {
            // RST 控制未能交付时，本端虚拟流已被 CloseBase 封止；连接本身仍归共享根，
            // 因此把双向虚拟流收敛为终态，不能让远端 EOF 成为不可达的退休前提。
            RemoteClosed_ = true;
            LocalTerminal_ = true;
            Closed_ = true;
            Rx_.clear();
            MarkIncomingPending(false);
            TryQueueRetirement();
        }
        if (Kind == ControlKind::Fin)
        {
            if (!LocalEndFailure_) LocalEndFailure_ = Failure;
            CompletePendingWriteShutdowns(*LocalEndFailure_);
        }
        if (State_)
        {
            if (CloseCancellation)
                State_->RecordCloseCancellation({Prism::Fault::Code::Canceled});
            else if (Failure.Code == Prism::Fault::Code::Eof &&
                     State_->CloseRequested.load(std::memory_order_acquire))
                State_->RecordCloseCancellation({Prism::Fault::Code::Canceled});
            else
                State_->RecordFailure(Failure);
        }
    }

    auto Http2Stream::OnControlCompleted(
        const ControlKind Kind,
        const std::expected<void, Prism::Fault::Failure> &Outcome) -> void
    {
        LocalEndPending_ = false;
        if (!Outcome)
        {
            ResetPending_ = false;
            if (Kind == ControlKind::Reset)
            {
                // 控制帧失败仍须退休本虚拟流；失败已由 ControlFailure 保留给目录 owner。
                RemoteClosed_ = true;
                LocalTerminal_ = true;
                Closed_ = true;
                Rx_.clear();
                MarkIncomingPending(false);
            }
            else
            {
                if (!LocalEndFailure_) LocalEndFailure_ = Outcome.error();
                CompletePendingWriteShutdowns(*LocalEndFailure_);
            }
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
            LocalEndFlushed_ = true;
            LocalEndFailure_.reset();
            CompletePendingWriteShutdowns({});
        }
        TryQueueRetirement();
    }
}
