/** @file SessionTraceRing.hpp @brief Worker-local 固定容量会话轨迹及 writer。 */
#pragma once

#include <Preview/Net/Relay/FirstTransferObserver.hpp>
#include <Preview/Runtime/SessionTraceModel.hpp>
#include <Preview/Lifecycle/TaskState.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

namespace Preview::Runtime
{
    /** @brief 单 worker 固定容量事件环；写入只能发生在该 worker executor。 */
    class SessionTraceRing final
    {
    public:
        static inline constexpr std::size_t Capacity{512U};

        explicit SessionTraceRing(const Preview::ProcessId Process,
                                  const Preview::WorkerId Worker) noexcept
            : Process_(Process), Worker_(Worker)
        {
        }

        SessionTraceRing(const SessionTraceRing &) = delete;
        auto operator=(const SessionTraceRing &) -> SessionTraceRing & = delete;

        /** @brief 写入一条固定字段记录；不分配、不等待，覆盖最旧槽位。 */
        auto Record(SessionTraceRecord Value) noexcept -> void
        {
            if (NextSequence_ == (std::numeric_limits<std::uint64_t>::max)())
            {
                SequenceExhausted_.store(true, std::memory_order_release);
                return;
            }
            const auto Sequence = ++NextSequence_;
            Value.Sequence = Sequence;
            auto &Slot = Slots_[static_cast<std::size_t>((Sequence - 1U) % Capacity)];
            Slot.Sequence.store(0U, std::memory_order_release);
            Store(Slot, Value);
            Slot.Sequence.store(Sequence, std::memory_order_release);
            PublishedSequence_.store(Sequence, std::memory_order_release);
        }

        /** @brief 按值读取单 worker 事件页及覆盖、游标信息；读取只执行原子 load。 */
        [[nodiscard]] auto Query(const SessionTraceQuery &QueryValue) const
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
                const auto &Slot = Slots_[static_cast<std::size_t>((Sequence - 1U) % Capacity)];
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

        [[nodiscard]] auto Process() const noexcept -> Preview::ProcessId
        {
            return Process_;
        }

        [[nodiscard]] auto Worker() const noexcept -> Preview::WorkerId
        {
            return Worker_;
        }

        [[nodiscard]] auto SequenceExhausted() const noexcept -> bool
        {
            return SequenceExhausted_.load(std::memory_order_acquire);
        }

    private:
        struct Slot final
        {
            std::atomic<std::uint64_t> Sequence{0U};
            std::atomic<std::uint64_t> Process{0U};
            std::atomic<std::uint64_t> Generation{0U};
            std::atomic<std::uint64_t> Session{0U};
            std::atomic<std::uint64_t> Worker{0U};
            std::atomic<std::uint64_t> Account{0U};
            std::atomic<std::uint64_t> Task{0U};
            std::atomic<std::uint64_t> ParentTask{0U};
            std::atomic<std::uint64_t> Stream{0U};
            std::atomic<std::uint64_t> UtcUnixNanoseconds{0U};
            std::atomic<std::uint64_t> ElapsedNanoseconds{0U};
            std::atomic<std::uint64_t> Stage{0U};
            std::atomic<std::uint64_t> Outcome{0U};
            std::atomic<std::uint64_t> Failure{0U};
        };

        static auto Store(Slot &SlotValue, const SessionTraceRecord &Value) noexcept -> void
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

        [[nodiscard]] static auto Load(const Slot &SlotValue) noexcept -> SessionTraceRecord
        {
            SessionTraceRecord Value;
            Value.Sequence = SlotValue.Sequence.load(std::memory_order_relaxed);
            Value.UtcUnixNanoseconds = static_cast<std::int64_t>(
                SlotValue.UtcUnixNanoseconds.load(std::memory_order_relaxed));
            Value.ElapsedNanoseconds = SlotValue.ElapsedNanoseconds.load(std::memory_order_relaxed);
            Value.Identity.Process = Preview::ProcessId{
                SlotValue.Process.load(std::memory_order_relaxed)};
            Value.Identity.Generation = Preview::GenerationId{
                SlotValue.Generation.load(std::memory_order_relaxed)};
            Value.Identity.Session = Preview::SessionId{
                SlotValue.Session.load(std::memory_order_relaxed)};
            Value.Identity.Worker = Preview::WorkerId{
                SlotValue.Worker.load(std::memory_order_relaxed)};
            Value.Identity.Account = Preview::AccountId{
                SlotValue.Account.load(std::memory_order_relaxed)};
            Value.Identity.Task = Preview::TaskId{
                SlotValue.Task.load(std::memory_order_relaxed)};
            Value.Identity.ParentTask = Preview::TaskId{
                SlotValue.ParentTask.load(std::memory_order_relaxed)};
            Value.Identity.Stream = Preview::StreamId{
                SlotValue.Stream.load(std::memory_order_relaxed)};
            Value.Stage = static_cast<SessionTraceStage>(
                SlotValue.Stage.load(std::memory_order_relaxed));
            Value.Outcome = static_cast<SessionTraceOutcome>(
                SlotValue.Outcome.load(std::memory_order_relaxed));
            Value.Failure = static_cast<Preview::Fault::Code>(static_cast<std::int32_t>(
                SlotValue.Failure.load(std::memory_order_relaxed)));
            return Value;
        }

        [[nodiscard]] static auto ReadCursor(
            const SessionTraceQuery &QueryValue,
            const Preview::WorkerId Worker) noexcept -> std::uint64_t
        {
            for (const auto &Cursor : QueryValue.Cursors)
            {
                if (Cursor.Worker == Worker)
                {
                    return Cursor.Sequence;
                }
            }
            return 0U;
        }

        [[nodiscard]] static auto Matches(
            const SessionTraceQuery &QueryValue,
            const SessionTraceIdentity &Identity) noexcept -> bool
        {
            return (!QueryValue.Generation || QueryValue.Generation == Identity.Generation) &&
                   (!QueryValue.Session || QueryValue.Session == Identity.Session) &&
                   (!QueryValue.Account || QueryValue.Account == Identity.Account) &&
                   (!QueryValue.Task || QueryValue.Task == Identity.Task) &&
                   (!QueryValue.ParentTask || QueryValue.ParentTask == Identity.ParentTask) &&
                   (!QueryValue.Stream || QueryValue.Stream == Identity.Stream);
        }

        const Preview::ProcessId Process_{};
        const Preview::WorkerId Worker_{};
        std::array<Slot, Capacity> Slots_{};
        std::uint64_t NextSequence_{0U}; ///< 只由所属 worker executor 访问。
        std::atomic<std::uint64_t> PublishedSequence_{0U};
        std::atomic<bool> SequenceExhausted_{false};
    };

    /** @brief Worker 持有的轨迹环 owner；与网络资源和 SessionRegistry 分离。 */
    class WorkerSessionTraceOwner
    {
    public:
        WorkerSessionTraceOwner(const Preview::ProcessId Process,
                                const Preview::WorkerId Worker)
            : Ring_(std::make_shared<SessionTraceRing>(Process, Worker))
        {
        }

        /** @brief 借用 worker-local 固定容量轨迹环；写入限于该 worker executor。 */
        [[nodiscard]] auto TraceRing() const noexcept -> std::shared_ptr<SessionTraceRing>
        {
            return Ring_;
        }

    private:
        std::shared_ptr<SessionTraceRing> Ring_;
    };

    /** @brief 固定相关身份与接入时钟；调用者在所属 worker executor 写入。 */
    class SessionTraceWriter final : public Preview::Network::Relay::FirstTransferObserver
    {
    public:
        using WallClock = std::chrono::system_clock;
        using MonotonicClock = std::chrono::steady_clock;

        SessionTraceWriter(std::shared_ptr<SessionTraceRing> Ring,
                           SessionTraceIdentity Identity,
                           const MonotonicClock::time_point AcceptedMonotonic) noexcept
            : Ring_(std::move(Ring)), Identity_(Identity),
              AcceptedMonotonic_(AcceptedMonotonic)
        {
        }

        auto SetTaskIdentity(const Preview::Lifecycle::TaskIdentity &Value) noexcept -> void
        {
            if (Value.Generation) Identity_.Generation = Value.Generation;
            if (Value.SessionId) Identity_.Session = Value.SessionId;
            if (Value.WorkerId) Identity_.Worker = Value.WorkerId;
            Identity_.Task = Value.TaskId;
            Identity_.ParentTask = Value.ParentTaskId;
            Identity_.Stream = Value.StreamId;
        }

        auto SetAccount(const Preview::AccountId Value) noexcept -> void
        {
            Identity_.Account = Value;
        }

        auto Record(const SessionTraceStage Stage) noexcept -> void
        {
            Record(Stage, SessionTraceOutcome::None, Preview::Fault::Code::Success);
        }

        auto Record(const SessionTraceStage Stage,
                    const Preview::Fault::Code Failure) noexcept -> void
        {
            Record(Stage,
                Preview::Fault::Failed(Failure) ? SessionTraceOutcome::Failed
                                                : SessionTraceOutcome::Succeeded,
                Failure);
        }

        auto Record(const SessionTraceStage Stage,
                    const SessionTraceOutcome Outcome,
                    const Preview::Fault::Code Failure) noexcept -> void
        {
            const auto Wall = WallClock::now();
            const auto Monotonic = MonotonicClock::now();
            RecordAt(Stage, Outcome, Failure, Wall, Monotonic);
        }

        auto RecordAt(const SessionTraceStage Stage,
                      const SessionTraceOutcome Outcome,
                      const Preview::Fault::Code Failure,
                      const WallClock::time_point Wall,
                      const MonotonicClock::time_point Monotonic) noexcept -> void
        {
            if (!Ring_)
            {
                return;
            }
            const auto Utc = std::chrono::duration_cast<std::chrono::nanoseconds>(
                Wall.time_since_epoch()).count();
            const auto Elapsed = Monotonic >= AcceptedMonotonic_
                                     ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                                           Monotonic - AcceptedMonotonic_).count()
                                     : 0;
            Ring_->Record(SessionTraceRecord{
                0U, static_cast<std::int64_t>(Utc), static_cast<std::uint64_t>(Elapsed),
                Identity_, Stage, Outcome, Failure});
        }

        auto OnFirstTransfer(const std::size_t Direction) noexcept -> void override
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

    private:
        std::shared_ptr<SessionTraceRing> Ring_;
        SessionTraceIdentity Identity_;
        MonotonicClock::time_point AcceptedMonotonic_;
    };
}
