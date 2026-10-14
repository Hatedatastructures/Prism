/** @file Http2Dispatch.hpp @brief H2Mux HTTP/2 admission、stream retirement 与唯一 FlushGate writer。 */
#pragma once
#include <Preview/Protocols/Mux/H2Mux/Http2Stream.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <algorithm>
#include <utility>
namespace Preview::Mux::H2Mux
{
    inline auto Http2State::OnHeaders(
        const std::int32_t StreamId,
        const Preview::Http2::HeaderList & /*Headers*/,
        const bool /*EndStream*/) -> void
    {
        if (Closed || Streams.contains(StreamId)) return;
        if (Streams.size() >= MaxStreams)
        {
            if (std::find(DeferredRefusedStreams.begin(), DeferredRefusedStreams.end(), StreamId) ==
                DeferredRefusedStreams.end())
                DeferredRefusedStreams.push_back(StreamId);
            return;
        }
        auto Stream = std::make_shared<Http2Stream>(shared_from_this(), StreamId);
        Streams.emplace(StreamId, Stream);
        Incoming.push_back(Stream);
        const auto Headers = Session->SubmitHeaders(
            StreamId, Preview::Http2::HeaderList{{":status", "200"}}, false);
        if (!Headers)
        {
            RecordFailure(Headers.error());
            RemoveIncoming(StreamId);
            const auto Reset = Stream->StartReset(Preview::Http2::ErrorInternal);
            if (!Reset) RecordFailure(Reset.error());
            return;
        }
        Notify.try_send(boost::system::error_code{});
    }

    inline auto Http2State::OnData(
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) -> void
    {
        if (const auto Iterator = Streams.find(StreamId); Iterator != Streams.end())
            Iterator->second->Push(Data);
    }

    inline auto Http2State::OnRemoteClose(
        const Preview::Http2::StreamReceiveClosure &Closure) -> void
    {
        const auto Iterator = Streams.find(Closure.StreamId);
        if (Iterator == Streams.end()) return;
        if (Closure.Kind == Preview::Http2::StreamReceiveClosureKind::EndStream)
        {
            Iterator->second->SetRemoteClosed();
            return;
        }
        RemoveIncoming(Closure.StreamId);
        Iterator->second->SetRemoteReset(Closure.ErrorCode);
    }

    inline auto Http2State::ApplyRefusedStreams() -> void
    {
        while (!DeferredRefusedStreams.empty())
        {
            const auto StreamId = DeferredRefusedStreams.front();
            DeferredRefusedStreams.pop_front();
            if (!Session)
            {
                RecordFailure(Failure{Preview::Fault::Code::ProtocolError});
                continue;
            }
            const auto Reset = Session->ResetStream(
                StreamId, Preview::Http2::ErrorRefusedStream);
            if (!Reset) RecordFailure(Reset.error());
        }
    }

    inline auto Http2State::RemoveIncoming(const std::int32_t StreamId) -> void
    {
        for (auto Iterator = Incoming.begin(); Iterator != Incoming.end();)
        {
            if ((*Iterator)->StreamId() == StreamId)
            {
                (*Iterator)->MarkIncomingPending(false);
                Iterator = Incoming.erase(Iterator);
            }
            else
            {
                ++Iterator;
            }
        }
    }

    inline auto Http2State::IsIncoming(const std::int32_t StreamId) const -> bool
    {
        return std::any_of(Incoming.begin(), Incoming.end(), [StreamId](const auto &Stream)
        {
            return Stream->StreamId() == StreamId;
        });
    }

    inline auto Http2State::StartRetirementPump() -> std::expected<void, Failure>
    {
        if (RetirementPumpStarted) return {};
        if (Closed || !Tasks)
            return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
        RetirementPumpStarted = true;
        Preview::Lifecycle::TaskRequest Request;
        Request.Context = Preview::Lifecycle::FromParent(Identity);
        Request.StartOnSubmit = true;
        const auto WeakState = std::weak_ptr<Http2State>(shared_from_this());
        Request.Cancel = [WeakState]
        {
            if (const auto State = WeakState.lock()) State->Close();
        };
        const auto Started = Tasks->SpawnTracked(std::move(Request), RunRetirementPump());
        if (Started) return {};
        RetirementPumpStarted = false;
        RecordFailure(Started.error());
        return std::unexpected(Started.error());
    }

    inline auto Http2State::RunRetirementPump() -> Net::awaitable<void>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::dispatch(Strand, Net::use_awaitable);
        while (true)
        {
            boost::system::error_code NotificationError;
            co_await RetirementNotify.async_receive(
                Net::redirect_error(Net::use_awaitable, NotificationError));
            co_await Net::dispatch(Strand, Net::use_awaitable);
            if (NotificationError && !Closed)
                RecordFailure(Preview::Fault::FromNative(static_cast<std::error_code>(NotificationError)));
            while (true)
            {
                const auto Iterator = std::find_if(Streams.begin(), Streams.end(), [](const auto &Entry)
                {
                    return Entry.second->CanRetire();
                });
                if (Iterator == Streams.end()) break;
                const auto StreamId = Iterator->first;
                const auto Stream = Iterator->second;
                const auto Activity = co_await Stream->Activity()->Drain();
                co_await Net::dispatch(Strand, Net::use_awaitable);
                if (!Activity)
                {
                    Stream->MarkRetirementFailed(Activity.error());
                    continue;
                }
                const auto EndDrain = co_await Stream->DrainTerminations();
                co_await Net::dispatch(Strand, Net::use_awaitable);
                if (!EndDrain)
                {
                    Stream->MarkRetirementFailed(EndDrain.error());
                    continue;
                }
                Stream->MarkRetirementRecovered();
                if (Stream->CanRetire()) RetireStream(StreamId, Stream);
            }
            if (Closed)
            {
                const auto PendingControl = std::any_of(Streams.begin(), Streams.end(), [](const auto &Entry)
                {
                    return Entry.second->HasPendingControl();
                });
                if (!PendingControl) co_return;
            }
        }
    }

    inline auto Http2State::QueueRetirement() -> void
    {
        (void)RetirementNotify.try_send(boost::system::error_code{});
    }

    inline auto Http2State::RetireStream(
        const std::int32_t StreamId,
        const std::shared_ptr<Http2Stream> &Stream) -> void
    {
        const auto Iterator = Streams.find(StreamId);
        if (Iterator == Streams.end() || Iterator->second != Stream) return;
        RemoveIncoming(StreamId);
        Stream->MarkRetired();
        Streams.erase(Iterator);
        Notify.try_send(boost::system::error_code{});
    }

    inline auto Http2State::RecordFailure(const Failure Value) noexcept -> void
    {
        if (Value.Failed())
        {
            // TrySet 只报告并发首因是否由本次发布；失败控制流仍由当前调用者处理。
            (void)FirstFailure.TrySet(Value);
        }
    }

    /** @brief 同一个连接 owner 重试关闭命令、任务与所有实际 stream barrier。 */
    inline auto Http2State::Drain() -> Net::awaitable<std::expected<void, Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (Retired.load(std::memory_order_acquire))
        {
            const auto First = FirstFailure.Load();
            if (First.Failed()) co_return std::unexpected(First);
            co_return std::expected<void, Failure>{};
        }
        boost::system::error_code GateError;
        co_await DrainGate->async_receive(Net::redirect_error(Net::use_awaitable, GateError));
        if (GateError)
        {
            RecordFailure(Preview::Fault::FromNative(static_cast<std::error_code>(GateError)));
            co_return std::unexpected(FirstFailure.Load());
        }
        struct DrainRelease final
        {
            std::shared_ptr<DrainChannel> Gate;
            ~DrainRelease() noexcept
            {
                if (Gate) (void)Gate->try_send(boost::system::error_code{});
            }
        } Release{DrainGate};
        try
        {
            Close();
            TasksDrained = false;
            RawDrained = false;
            const auto TaskResult = co_await Tasks->Drain();
            co_await Net::dispatch(Strand, Net::use_awaitable);
            TasksDrained = static_cast<bool>(TaskResult);
            if (!TaskResult) RecordFailure(TaskResult.error());
            const auto StreamsComplete = co_await DrainStreams();
            const auto RawComplete = co_await DrainRaw();
            co_await Net::dispatch(Strand, Net::use_awaitable);
            RefreshRetirement();
            if (!TasksDrained || !StreamsComplete || !RawComplete)
                RecordFailure(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        catch (const boost::system::system_error &Exception)
        {
            RecordFailure(Preview::Fault::FromNative(
                static_cast<std::error_code>(Exception.code())));
        }
        catch (const std::system_error &Exception)
        {
            RecordFailure(Preview::Fault::FromNative(Exception.code()));
        }
        catch (const std::bad_alloc &)
        {
            RecordFailure(Preview::Fault::Failure{
                Preview::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
        }
        const auto First = FirstFailure.Load();
        if (First.Failed()) co_return std::unexpected(First);
        co_return std::expected<void, Failure>{};
    }

    /** @brief 按 stream id 顺序真实排空 I/O 与 tracked 控制后释放 stream owner。 */
    inline auto Http2State::DrainStreams() -> Net::awaitable<bool>
    {
        co_await Net::dispatch(Strand, Net::use_awaitable);
        bool Complete = true;
        std::optional<std::int32_t> LastStreamId;
        while (true)
        {
            const auto Iterator = LastStreamId ? Streams.upper_bound(*LastStreamId) : Streams.begin();
            if (Iterator == Streams.end()) break;
            const auto StreamId = Iterator->first;
            const auto Stream = Iterator->second;
            LastStreamId = StreamId;
            const auto Activity = co_await Stream->Activity()->Drain();
            co_await Net::dispatch(Strand, Net::use_awaitable);
            if (!Activity)
            {
                Stream->MarkRetirementFailed(Activity.error());
                Complete = false;
                continue;
            }
            const auto Terminations = co_await Stream->DrainTerminations();
            co_await Net::dispatch(Strand, Net::use_awaitable);
            if (!Terminations)
            {
                Stream->MarkRetirementFailed(Terminations.error());
                Complete = false;
                continue;
            }
            Stream->MarkRetirementRecovered();
            if (Stream->CanRetire()) RetireStream(StreamId, Stream);
            else Complete = false;
        }
        co_return Complete && Streams.empty();
    }

    /** @brief 重试底层关闭并以 raw activity 真实排空作为传输退休证据。 */
    inline auto Http2State::DrainRaw() -> Net::awaitable<bool>
    {
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (!Raw)
        {
            RecordFailure(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            RawDrained = false;
            co_return false;
        }
        const auto Canceled = Raw->Cancel();
        if (!Canceled) RecordFailure(Canceled.error());
        const auto ClosedRaw = Raw->Close();
        if (!ClosedRaw) RecordFailure(ClosedRaw.error());
        const auto Activity = Raw->Activity();
        if (!Activity)
        {
            RecordFailure(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            RawDrained = false;
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (!Drained) RecordFailure(Drained.error());
        RawDrained = !Raw->IsOpen() && static_cast<bool>(Drained);
        if (!RawDrained) RecordFailure(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        co_return RawDrained;
    }

    inline auto Http2State::RefreshRetirement() noexcept -> void
    {
        Retired.store(RunCompleted.load(std::memory_order_acquire) && TasksDrained &&
                          Streams.empty() && RawDrained,
            std::memory_order_release);
    }

    inline auto Http2State::WriteAll(const std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Failure>>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Remaining = Data.size() - Offset;
            const auto Part = co_await Raw->WriteSome(Data.subspan(Offset));
            if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
            if (Part.Bytes == 0)
                co_return std::unexpected(Failure{Preview::Fault::Code::WouldBlock});
            if (Part.Bytes > Remaining)
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            Offset += Part.Bytes;
        }
        co_return std::expected<void, Failure>{};
    }

    inline auto Http2State::Flush() -> Net::awaitable<std::expected<void, Failure>>
    {
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (!FlushGate)
            co_return std::unexpected(Failure{Preview::Fault::Code::Canceled});
        boost::system::error_code GateError;
        co_await FlushGate->async_receive(Net::redirect_error(Net::use_awaitable, GateError));
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (GateError)
            co_return std::unexpected(Preview::Fault::FromNative(static_cast<std::error_code>(GateError)));
        struct FlushRelease final
        {
            std::shared_ptr<FlushChannel> Gate;
            ~FlushRelease() noexcept
            {
                if (Gate) (void)Gate->try_send(boost::system::error_code{});
            }
        } Release{FlushGate};
        std::vector<std::byte> Wire;
        while (Session->Collect(Wire))
        {
            const auto Written = co_await WriteAll(Wire);
            if (!Written) co_return std::unexpected(Written.error());
            Wire.clear();
            co_await Net::dispatch(Strand, Net::use_awaitable);
        }
        co_return std::expected<void, Failure>{};
    }

    inline auto Http2State::Close() -> void
    {
        if (!Closed)
        {
            Closed = true;
            FlushGate->close();
            Notify.try_send(boost::system::error_code{});
            for (const auto &Stream : Incoming) Stream->MarkIncomingPending(false);
            Incoming.clear();
            for (auto &[StreamId, Stream] : Streams)
            {
                (void)StreamId;
                Stream->SetConnectionClosed();
            }
            QueueRetirement();
        }
        if (Raw)
        {
            const auto Canceled = Raw->Cancel();
            if (!Canceled) RecordFailure(Canceled.error());
            const auto ClosedRaw = Raw->Close();
            if (!ClosedRaw) RecordFailure(ClosedRaw.error());
        }
    }
}
