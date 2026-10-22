/** @file H2MuxState.cpp @brief H2Mux 连接分发、排空与关闭实现。 */
#include <Prism/Protocols/Mux/H2Mux/Http2Dispatch.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2State.hpp>

#include <Prism/Protocols/Mux/H2Mux/Http2Stream.hpp>
#include <Prism/Protocols/Mux/H2Mux/Http2StreamControl.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/error_code.hpp>
#include <algorithm>
#include <array>
#include <utility>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <system_error>
#include <vector>
namespace Prism::Mux::H2Mux
{
    namespace
    {
        /** @brief root 接管应用准入时，对超额 CONNECT 返回可观察的单字节拒绝体。 */
        auto RejectConnect(
            const std::shared_ptr<Prism::Http2::Session> &Session,
            const std::int32_t StreamId,
            Prism::Fault::FailureState &Failure) -> void
        {
            if (!Session)
            {
                (void)Failure.TrySet(
                    Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                return;
            }
            const auto Headers = Session->SubmitHeaders(
                StreamId, Prism::Http2::HeaderList{{":status", "200"}}, false);
            if (!Headers)
            {
                (void)Failure.TrySet(Headers.error());
                return;
            }
            const std::array<std::byte, 1> Status{std::byte{0x01}};
            const auto Submitted = Session->SubmitData(StreamId, Status, true);
            if (Submitted != Prism::Http2::SubmitDataStatus::Accepted)
            {
                (void)Failure.TrySet(Prism::Fault::Failure{
                    Submitted == Prism::Http2::SubmitDataStatus::Closed
                        ? Prism::Fault::Code::ConnectionAborted
                        : Prism::Fault::Code::ProtocolError});
            }
        }
    }

    Http2State::Http2State(
        Prism::SharedTransmission RawValue,
        const std::size_t MaxStreamsValue,
        const bool DeferAcceptValue)
        : Strand(RawValue->Executor()), Raw(std::move(RawValue)), MaxStreams(MaxStreamsValue),
          DeferAccept(DeferAcceptValue),
          Notify(Strand, 1), RetirementNotify(Strand, 1), StreamDrainNotify(Strand, 1),
          RunCompletionNotify(Strand, 1),
          DrainGate(std::make_shared<DrainChannel>(Strand, 1)),
          FlushGate(std::make_shared<FlushChannel>(Strand, 1)),
          Tasks(std::make_shared<Prism::Lifecycle::TaskRegistry>(Strand))
    {
        (void)DrainGate->try_send(boost::system::error_code{});
        (void)FlushGate->try_send(boost::system::error_code{});
    }

    auto Http2State::NotifyStreamDrain() -> void
    {
        StreamDrainPending.store(true, std::memory_order_release);
        (void)StreamDrainNotify.try_send(boost::system::error_code{});
    }

    auto Http2State::NotifyAccept() noexcept -> void
    {
        NotifyPending.store(true, std::memory_order_release);
        (void)Notify.try_send(boost::system::error_code{});
    }

    auto Http2State::RecordConnectionTerminal(const Http2State::Failure Value) noexcept -> void
    {
        if (Value.Failed()) (void)ConnectionTerminal.TrySet(Value);
    }

    auto Http2State::ConnectionCloseFailure() const noexcept -> Http2State::Failure
    {
        const auto Value = ConnectionTerminal.Load();
        if (Value.Failed()) return Value;
        return {Prism::Fault::Code::Eof};
    }

    auto Http2State::OnHeaders(
        const std::int32_t StreamId,
        const Prism::Http2::HeaderList &RequestHeaders,
        const bool EndStream) -> void
    {
        if (Closed || Streams.contains(StreamId)) return;
        const Prism::Http2::Header *Method = nullptr;
        const Prism::Http2::Header *Scheme = nullptr;
        const Prism::Http2::Header *Authority = nullptr;
        const Prism::Http2::Header *Path = nullptr;
        bool RegularHeaderSeen = false;
        bool Malformed = false;
        for (const auto &Header : RequestHeaders)
        {
            if (Header.Name.empty() || Header.Name.front() != ':')
            {
                RegularHeaderSeen = true;
                continue;
            }
            if (RegularHeaderSeen)
            {
                Malformed = true;
                break;
            }
            const Prism::Http2::Header **Field = nullptr;
            if (Header.Name == ":method") Field = &Method;
            else if (Header.Name == ":scheme") Field = &Scheme;
            else if (Header.Name == ":authority") Field = &Authority;
            else if (Header.Name == ":path") Field = &Path;
            else
            {
                Malformed = true;
                break;
            }
            if (!Field || *Field)
            {
                Malformed = true;
                break;
            }
            *Field = &Header;
        }

        const auto IsConnect = Method && Method->Value == "CONNECT";
        if (!Method || Method->Value.empty())
        {
            Malformed = true;
        }
        else if (IsConnect)
        {
            Malformed = Malformed || !Authority || Authority->Value.empty() || Scheme || Path;
        }
        else
        {
            Malformed = Malformed || !Scheme || Scheme->Value.empty() || !Path ||
                        ((Scheme->Value == "http" || Scheme->Value == "https") && Path->Value.empty());
        }
        if (Malformed)
        {
            const auto Rejected = Session->SubmitHeaders(
                StreamId, Prism::Http2::HeaderList{{":status", "400"}}, true);
            if (!Rejected)
            {
                RecordFailure(Rejected.error());
                return;
            }
            const auto Reset = Session->ResetStream(StreamId, Prism::Http2::ErrorProtocol);
            if (!Reset) RecordFailure(Reset.error());
            return;
        }
        if (!IsConnect)
        {
            const auto Rejected = Session->SubmitHeaders(
                StreamId,
                Prism::Http2::HeaderList{{":status", "405"}, {"allow", "CONNECT"}},
                true);
            if (!Rejected) RecordFailure(Rejected.error());
            return;
        }
        const auto QuotaUsed = static_cast<std::size_t>(std::count_if(
            Streams.begin(), Streams.end(), [](const auto &Entry)
            {
                return Entry.second->OccupiesQuota();
            }));
        if (QuotaUsed >= MaxStreams)
        {
            if (DeferAccept.load(std::memory_order_acquire))
            {
                // root 已接管应用层准入：超额 CONNECT 也必须让客户端观察到
                // 单字节 {1} + END_STREAM，而不是只有不可见正文的 RST。
                RejectConnect(Session, StreamId, FirstFailure);
            }
            else
            {
                // 纯帧引擎没有应用层拒绝合同，以 RFC 9113 的 REFUSED_STREAM 结束。
                const auto Reset = Session->ResetStream(
                    StreamId, Prism::Http2::ErrorRefusedStream);
                if (!Reset) RecordFailure(Reset.error());
            }
            return;
        }
        auto Stream = std::make_shared<Http2Stream>(shared_from_this(), StreamId);
        Streams.emplace(StreamId, Stream);
        Incoming.push_back(Stream);
        if (!DeferAccept.load(std::memory_order_acquire))
        {
            const auto Headers = Session->SubmitHeaders(
                StreamId, Prism::Http2::HeaderList{{":status", "200"}}, false);
            if (!Headers)
            {
                RecordFailure(Headers.error());
                RemoveIncoming(StreamId);
                const auto Reset = Stream->StartReset(Prism::Http2::ErrorInternal);
                if (!Reset) RecordFailure(Reset.error());
                return;
            }
        }
        // 远端已在本端 accept 前结束发送：记录该事实，避免 child 启动后把
        // 已收到的 END_STREAM 误当成仍在等待的远端半关闭。
        // 保持 IncomingPending_，仅登记远端半关闭事实。
        if (EndStream) Stream->SetRemoteClosed();
        NotifyAccept();
    }

    auto Http2State::OnData(
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) -> void
    {
        if (const auto Iterator = Streams.find(StreamId); Iterator != Streams.end())
            Iterator->second->Push(Data);
    }

    auto Http2State::OnRemoteClose(
        const Prism::Http2::StreamReceiveClosure &Closure) -> void
    {
        const auto Iterator = Streams.find(Closure.StreamId);
        if (Iterator == Streams.end()) return;
        if (Closure.Kind == Prism::Http2::StreamReceiveClosureKind::EndStream)
        {
            Iterator->second->SetRemoteClosed();
            return;
        }
        Iterator->second->SetRemoteReset(Closure.ErrorCode);
        RemoveIncoming(Closure.StreamId);
    }

    auto Http2State::ApplyRefusedStreams() -> void
    {
        while (!DeferredRefusedStreams.empty())
        {
            const auto StreamId = DeferredRefusedStreams.front();
            DeferredRefusedStreams.pop_front();
            if (!Session)
            {
                RecordFailure(Failure{Prism::Fault::Code::ProtocolError});
                continue;
            }
            const auto Reset = Session->ResetStream(
                StreamId, Prism::Http2::ErrorRefusedStream);
            if (!Reset) RecordFailure(Reset.error());
        }
    }

    auto Http2State::RemoveIncoming(const std::int32_t StreamId) -> void
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

    auto Http2State::IsIncoming(const std::int32_t StreamId) const -> bool
    {
        return std::any_of(Incoming.begin(), Incoming.end(), [StreamId](const auto &Stream)
        {
            return Stream->StreamId() == StreamId;
        });
    }

    auto Http2State::StartRetirementPump() -> std::expected<void, Failure>
    {
        if (RetirementPumpStarted) return {};
        if (Closed || !Tasks)
            return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        RetirementPumpStarted = true;
        Prism::Lifecycle::TaskRequest Request;
        Request.Context = Prism::Lifecycle::FromParent(Identity);
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

    auto Http2State::RunRetirementPump() -> Net::awaitable<void>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::dispatch(Strand, Net::use_awaitable);
        while (true)
        {
            boost::system::error_code NotificationError;
            if (!RetirementPending.exchange(false, std::memory_order_acq_rel))
            {
                co_await RetirementNotify.async_receive(
                    Net::redirect_error(Net::use_awaitable, NotificationError));
                co_await Net::dispatch(Strand, Net::use_awaitable);
                if (NotificationError && !Closed)
                    RecordFailure(Prism::Fault::FromNative(
                        static_cast<std::error_code>(NotificationError)));
            }
            while (true)
            {
                const auto Iterator = std::find_if(Streams.begin(), Streams.end(), [](const auto &Entry)
                {
                    return Entry.second->CanRetire();
                });
                if (Iterator == Streams.end()) break;
                const auto StreamId = Iterator->first;
                const auto Stream = Iterator->second;
                const auto EndDrain = co_await Stream->DrainTerminations();
                co_await Net::dispatch(Strand, Net::use_awaitable);
                if (!EndDrain)
                {
                    Stream->MarkRetirementFailed(EndDrain.error());
                    continue;
                }
                const auto StreamActivity = Stream->Activity();
                if (!StreamActivity->IsRetired())
                {
                    Stream->MarkRetirementFailed(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                    continue;
                }
                Stream->MarkRetirementRecovered();
                if (Stream->CanRetire()) RetireStream(StreamId, Stream);
            }
            if (Closed)
            {
                // DrainStreams 在 Tasks::Drain 之后承担最终流关闭；pump 不能等待
                // Streams.empty()，否则会与调用方形成互等死锁。
                const auto PendingControl = std::any_of(
                    Streams.begin(), Streams.end(), [](const auto &Entry)
                    {
                        return Entry.second->HasPendingControl();
                    });
                if (!PendingControl) co_return;
            }
        }
    }

    auto Http2State::QueueRetirement() -> void
    {
        RetirementPending.store(true, std::memory_order_release);
        (void)RetirementNotify.try_send(boost::system::error_code{});
    }

    auto Http2State::RetireStream(
        const std::int32_t StreamId,
        const std::shared_ptr<Http2Stream> &Stream) -> void
    {
        const auto Iterator = Streams.find(StreamId);
        if (Iterator == Streams.end() || Iterator->second != Stream) return;
        RemoveIncoming(StreamId);
        Stream->MarkRetired();
        Streams.erase(Iterator);
        NotifyAccept();
    }

    auto Http2State::RecordFailure(const Failure Value) noexcept -> void
    {
        if (Value.Failed()) (void)FirstFailure.TrySet(Value);
    }

    auto Http2State::RecordCloseCancellation(const Failure Value) noexcept -> void
    {
        // 连接拆除期间底层 channel/socket 关闭会同步报告 connection_reset；
        // 它不是应用失败，也不得覆盖已排空或首因结果。
        if (Value.Failed() && Value.Native ==
                std::make_error_code(std::errc::connection_reset) &&
            CloseRequested.load(std::memory_order_acquire))
            return;
        if (Value.Code != Prism::Fault::Code::Canceled ||
            !CloseRequested.load(std::memory_order_acquire))
        {
            RecordFailure(Value.Failed() ? Value : Failure{Prism::Fault::Code::InvalidArgument});
            return;
        }
        (void)CloseCancellation.TrySet(Value);
    }

    /** @brief 同一个连接 owner 重试关闭命令、任务与所有实际 stream barrier。 */
    auto Http2State::Drain() -> Net::awaitable<std::expected<void, Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
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
            RecordFailure(Prism::Fault::FromNative(static_cast<std::error_code>(GateError)));
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
                RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        catch (const boost::system::system_error &Exception)
        {
            RecordFailure(Prism::Fault::FromNative(
                static_cast<std::error_code>(Exception.code())));
        }
        catch (const std::system_error &Exception)
        {
            RecordFailure(Prism::Fault::FromNative(Exception.code()));
        }
        catch (const std::bad_alloc &)
        {
            RecordFailure(Prism::Fault::Failure{
                Prism::Fault::Code::ResourceUnavailable,
                std::make_error_code(std::errc::not_enough_memory)});
        }
        const auto First = FirstFailure.Load();
        if (First.Failed()) co_return std::unexpected(First);
        if (!Retired.load(std::memory_order_acquire))
        {
            const auto CloseFailure = CloseCancellation.Load();
            if (CloseFailure.Failed()) co_return std::unexpected(CloseFailure);
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return std::expected<void, Failure>{};
    }

    /** @brief 等 accepted child 确认连接终态，再排空 I/O 与 tracked 控制并释放 owner。 */
    auto Http2State::DrainStreams() -> Net::awaitable<bool>
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
            if (Stream->AwaitsTerminalClose())
            {
                // 根 Drain 是最终关闭者：accepted child 未自行 Close 时，必须由这里
                // 提交最终 Close，产生 terminal 回执后再等待，否则永远停在 Pending。
                const auto Closed = Stream->Close();
                if (!Closed)
                {
                    Stream->MarkRetirementFailed(Closed.error());
                    Complete = false;
                    continue;
                }
                boost::system::error_code NotificationError;
                if (!StreamDrainPending.exchange(
                        false, std::memory_order_acq_rel))
                {
                    co_await StreamDrainNotify.async_receive(
                        Net::redirect_error(Net::use_awaitable, NotificationError));
                    co_await Net::dispatch(Strand, Net::use_awaitable);
                    if (NotificationError)
                    {
                        RecordFailure(Prism::Fault::FromNative(
                            static_cast<std::error_code>(NotificationError)));
                        co_return false;
                    }
                }
                // terminal close 等待是被接受的清理状态；不能为了唤醒线程把它
                // 记成 `Blocked` 首因，否则会覆盖已经交付的 Stream/Connection 终态。
                continue;
            }
            LastStreamId = StreamId;
            const auto Terminations = co_await Stream->DrainTerminations();
            co_await Net::dispatch(Strand, Net::use_awaitable);
            if (!Terminations)
            {
                if (Stream->AwaitsTerminalClose()) continue;
                Stream->MarkRetirementFailed(Terminations.error());
                Complete = false;
                continue;
            }
            const auto StreamActivity = Stream->Activity();
            if (!StreamActivity->IsRetired())
            {
                if (Stream->AwaitsTerminalClose()) continue;
                Stream->MarkRetirementFailed(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
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
    auto Http2State::DrainRaw() -> Net::awaitable<bool>
    {
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (!Raw)
        {
            RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
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
            RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            RawDrained = false;
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (!Drained) RecordFailure(Drained.error());
        RawDrained = !Raw->IsOpen() && Activity->IsRetired();
        if (!RawDrained) RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return RawDrained;
    }

    auto Http2State::RefreshRetirement() noexcept -> void
    {
        Retired.store(RunCompleted.load(std::memory_order_acquire) && TasksDrained &&
                          Streams.empty() && RawDrained,
            std::memory_order_release);
    }

    auto Http2State::NotifyRunCompleted() noexcept -> void
    {
        RunCompleted.store(true, std::memory_order_release);
        RunCompletionNotify.close();
    }

    auto Http2State::WaitForRunCompletion() -> Net::awaitable<void>
    {
        if (RunCompleted.load(std::memory_order_acquire)) co_return;
        boost::system::error_code Error;
        co_await RunCompletionNotify.async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
    }

    auto Http2State::WriteAll(const std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Failure>>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Remaining = Data.size() - Offset;
            const auto Part = co_await Raw->WriteSome(Data.subspan(Offset));
            if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
            if (Part.Bytes == 0)
                co_return std::unexpected(Failure{Prism::Fault::Code::WouldBlock});
            if (Part.Bytes > Remaining)
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            Offset += Part.Bytes;
        }
        co_return std::expected<void, Failure>{};
    }

    auto Http2State::Flush() -> Net::awaitable<FlushResult>
    {
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (!FlushGate)
            co_return FlushResult{Failure{Prism::Fault::Code::Canceled}, false};
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        boost::system::error_code GateError;
        co_await FlushGate->async_receive(Net::redirect_error(Net::use_awaitable, GateError));
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (GateError)
        {
            if (Closed)
                co_return FlushResult{Failure{Prism::Fault::Code::Canceled}, true};
            co_return FlushResult{
                Prism::Fault::FromNative(static_cast<std::error_code>(GateError)), false};
        }
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
            if (!Written)
            {
                const auto Error = Written.error();
                // 只把根关闭后取消的 Raw 写入标为关闭回执。
                const bool CloseCanceled = Error.Code == Prism::Fault::Code::Canceled &&
                    CloseRequested.load(std::memory_order_acquire);
                co_return FlushResult{Error, CloseCanceled};
            }
            Wire.clear();
            co_await Net::dispatch(Strand, Net::use_awaitable);
        }
        co_return FlushResult{};
    }

    auto Http2State::Close() -> void
    {
        CloseRequested.store(true, std::memory_order_release);
        if (!Closed)
        {
            Closed = true;
            FlushGate->close();
            Notify.try_send(boost::system::error_code{});
            const auto Terminal = ConnectionCloseFailure();
            for (auto &[StreamId, Stream] : Streams)
            {
                (void)StreamId;
                Stream->SetConnectionClosed(Terminal);
            }
            // 终态前已解析的 CONNECT 仍属于已登记流；直接清空会丢弃其已缓冲
            // DATA 并让 accept owner 永远看不到数据。真正的移除由退休完成。
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
