/** @file Ring.cpp @brief 定长会话跟踪存储与写入器实现。 */
#include <Prism/Runtime/Session/Trace/Ring.hpp>

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

namespace Prism::Runtime
{
    WorkerSessionTraceOwner::WorkerSessionTraceOwner(
        const Prism::ProcessId Process,
        const Prism::WorkerId Worker)
        : Ring_(std::make_shared<SessionTraceRing>(Process, Worker))
    {
    }

    auto SessionTraceRing::Record(SessionTraceRecord Value) noexcept -> void
    {
        if (NextSequence_ == (std::numeric_limits<std::uint64_t>::max)())
        {
            SequenceExhausted_.store(true, std::memory_order_release);
            return;
        }
        const auto Sequence = ++NextSequence_;
        Value.Sequence = Sequence;
        auto& Slot = Slots_[static_cast<std::size_t>((Sequence - 1U) % Capacity)];
        Slot.Sequence.store(0U, std::memory_order_release);
        Store(Slot, Value);
        Slot.Sequence.store(Sequence, std::memory_order_release);
        PublishedSequence_.store(Sequence, std::memory_order_release);
    }

    auto SessionTraceRing::Query(const SessionTraceQuery& QueryValue) const
        -> SessionTraceSnapshot
    {
        SessionTraceSnapshot Result;
        Result.Process = Process_;
        if (QueryValue.Process && QueryValue.Process != Process_)
        {
            return Result;
        }
        if (QueryValue.Worker && QueryValue.Worker != Worker_)
        {
            return Result;
        }

        const auto Head = PublishedSequence_.load(std::memory_order_acquire);
        const auto CursorBefore = ReadCursor(QueryValue, Worker_);
        const auto Oldest = Head > Capacity ? Head - Capacity + 1U
                                            : (Head == 0U ? 0U : 1U);
        auto Cursor = (std::min)(CursorBefore, Head);
        const auto RequestedStart = Cursor == (std::numeric_limits<std::uint64_t>::max)()
                                        ? Cursor
                                        : Cursor + 1U;
        auto Start = RequestedStart;
        std::uint64_t LostSinceCursor = 0U;
        if (Oldest != 0U && Start < Oldest)
        {
            LostSinceCursor = Oldest - Start;
            Start = Oldest;
            Cursor = Oldest - 1U;
        }

        const auto Limit = (std::min)(QueryValue.LimitPerWorker, Capacity);
        std::uint64_t ConcurrentReadSkips = 0U;
        for (auto Sequence = Start; Sequence != 0U && Sequence <= Head; ++Sequence)
        {
            if (Result.Records.size() >= Limit)
            {
                break;
            }
            const auto& Slot = Slots_[static_cast<std::size_t>((Sequence - 1U) % Capacity)];
            const auto Before = Slot.Sequence.load(std::memory_order_acquire);
            if (Before != Sequence)
            {
                ++ConcurrentReadSkips;
                Cursor = Sequence;
                continue;
            }
            auto Value = Load(Slot);
            const auto After = Slot.Sequence.load(std::memory_order_acquire);
            if (After != Before)
            {
                ++ConcurrentReadSkips;
                Cursor = Sequence;
                continue;
            }
            Cursor = Sequence;
            if (Matches(QueryValue, Value.Identity))
            {
                Result.Records.push_back(std::move(Value));
            }
        }

        Result.Cursors.push_back(SessionTraceCursor{Worker_, Cursor});
        Result.Loss.push_back(SessionTraceLoss{
            Worker_, Head > Capacity ? Head - Capacity : 0U,
            LostSinceCursor, ConcurrentReadSkips});
        Result.HasMore = Cursor < Head;
        return Result;
    }

    auto SessionTraceRing::Store(Slot& SlotValue, const SessionTraceRecord& Value) noexcept -> void
    {
        SlotValue.Process.store(Value.Identity.Process.Value(), std::memory_order_relaxed);
        SlotValue.Generation.store(Value.Identity.Generation.Value(), std::memory_order_relaxed);
        SlotValue.Session.store(Value.Identity.Session.Value(), std::memory_order_relaxed);
        SlotValue.Worker.store(Value.Identity.Worker.Value(), std::memory_order_relaxed);
        SlotValue.Account.store(Value.Identity.Account.Value(), std::memory_order_relaxed);
        SlotValue.Task.store(Value.Identity.Task.Value(), std::memory_order_relaxed);
        SlotValue.ParentTask.store(Value.Identity.ParentTask.Value(), std::memory_order_relaxed);
        SlotValue.Stream.store(Value.Identity.Stream.Value(), std::memory_order_relaxed);
        SlotValue.UtcUnixNanoseconds.store(
            static_cast<std::uint64_t>(Value.UtcUnixNanoseconds), std::memory_order_relaxed);
        SlotValue.ElapsedNanoseconds.store(Value.ElapsedNanoseconds, std::memory_order_relaxed);
        SlotValue.Stage.store(static_cast<std::uint64_t>(Value.Stage), std::memory_order_relaxed);
        SlotValue.Outcome.store(static_cast<std::uint64_t>(Value.Outcome), std::memory_order_relaxed);
        SlotValue.Failure.store(static_cast<std::uint64_t>(
            static_cast<std::int32_t>(Value.Failure)), std::memory_order_relaxed);
    }

    auto SessionTraceRing::Load(const Slot& SlotValue) noexcept -> SessionTraceRecord
    {
        SessionTraceRecord Value;
        Value.Sequence = SlotValue.Sequence.load(std::memory_order_relaxed);
        Value.UtcUnixNanoseconds = static_cast<std::int64_t>(
            SlotValue.UtcUnixNanoseconds.load(std::memory_order_relaxed));
        Value.ElapsedNanoseconds = SlotValue.ElapsedNanoseconds.load(std::memory_order_relaxed);
        Value.Identity.Process = Prism::ProcessId{SlotValue.Process.load(std::memory_order_relaxed)};
        Value.Identity.Generation = Prism::GenerationId{
            SlotValue.Generation.load(std::memory_order_relaxed)};
        Value.Identity.Session = Prism::SessionId{SlotValue.Session.load(std::memory_order_relaxed)};
        Value.Identity.Worker = Prism::WorkerId{SlotValue.Worker.load(std::memory_order_relaxed)};
        Value.Identity.Account = Prism::AccountId{SlotValue.Account.load(std::memory_order_relaxed)};
        Value.Identity.Task = Prism::TaskId{SlotValue.Task.load(std::memory_order_relaxed)};
        Value.Identity.ParentTask = Prism::TaskId{
            SlotValue.ParentTask.load(std::memory_order_relaxed)};
        Value.Identity.Stream = Prism::StreamId{SlotValue.Stream.load(std::memory_order_relaxed)};
        Value.Stage = static_cast<SessionTraceStage>(
            SlotValue.Stage.load(std::memory_order_relaxed));
        Value.Outcome = static_cast<SessionTraceOutcome>(
            SlotValue.Outcome.load(std::memory_order_relaxed));
        Value.Failure = static_cast<Prism::Fault::Code>(static_cast<std::int32_t>(
            SlotValue.Failure.load(std::memory_order_relaxed)));
        return Value;
    }

    auto SessionTraceRing::ReadCursor(
        const SessionTraceQuery& QueryValue,
        const Prism::WorkerId Worker) noexcept -> std::uint64_t
    {
        for (const auto& Cursor : QueryValue.Cursors)
        {
            if (Cursor.Worker == Worker)
            {
                return Cursor.Sequence;
            }
        }
        return 0U;
    }

    auto SessionTraceRing::Matches(
        const SessionTraceQuery& QueryValue,
        const SessionTraceIdentity& Identity) noexcept -> bool
    {
        return (!QueryValue.Generation || QueryValue.Generation == Identity.Generation) &&
               (!QueryValue.Session || QueryValue.Session == Identity.Session) &&
               (!QueryValue.Account || QueryValue.Account == Identity.Account) &&
               (!QueryValue.Task || QueryValue.Task == Identity.Task) &&
               (!QueryValue.ParentTask || QueryValue.ParentTask == Identity.ParentTask) &&
               (!QueryValue.Stream || QueryValue.Stream == Identity.Stream);
    }

    auto SessionTraceWriter::RecordAt(SessionTraceRecordRequest Request) noexcept -> void
    {
        if (!Ring_)
        {
            return;
        }
        const auto Utc = std::chrono::duration_cast<std::chrono::nanoseconds>(
            Request.Wall.time_since_epoch()).count();
        const auto Elapsed = Request.Monotonic >= AcceptedMonotonic_
                                 ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       Request.Monotonic - AcceptedMonotonic_).count()
                                 : 0;
        Ring_->Record(SessionTraceRecord{
            0U, static_cast<std::int64_t>(Utc), static_cast<std::uint64_t>(Elapsed),
            Identity_, Request.Stage, Request.Outcome, Request.Failure});
    }

    auto SessionTraceWriter::SetTaskIdentity(
        const Prism::Lifecycle::TaskIdentity& Value) noexcept -> void
    {
        if (Value.Generation) Identity_.Generation = Value.Generation;
        if (Value.SessionId) Identity_.Session = Value.SessionId;
        if (Value.WorkerId) Identity_.Worker = Value.WorkerId;
        Identity_.Task = Value.TaskId;
        Identity_.ParentTask = Value.ParentTaskId;
        Identity_.Stream = Value.StreamId;
    }

    auto SessionTraceWriter::Record(
        const SessionTraceStage Stage,
        const SessionTraceOutcome Outcome,
        const Prism::Fault::Code Failure) noexcept -> void
    {
        const auto Wall = WallClock::now();
        const auto Monotonic = MonotonicClock::now();
        RecordAt(SessionTraceRecordRequest{Stage, Outcome, Failure, Wall, Monotonic});
    }

    auto SessionTraceWriter::OnFirstTransfer(const std::size_t Direction) noexcept -> void
    {
        if (Direction == 0U)
        {
            Record(SessionTraceStage::RelayFirstUploadByte);
        }
        else if (Direction == 1U)
        {
            Record(SessionTraceStage::RelayFirstDownloadByte);
        }
    }
}
