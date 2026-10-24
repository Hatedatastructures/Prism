/** @file SessionTraceRing.hpp @brief Worker-local 固定容量会话轨迹及 writer。 */
#pragma once

#include <Prism/Contract/Services/FirstTransferObserver.hpp>
#include <Prism/Runtime/SessionTraceModel.hpp>
#include <Prism/Lifecycle/TaskState.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Runtime
{
    /** @brief 单 worker 固定容量事件环；写入只能发生在该 worker executor。 */
    class SessionTraceRing final
    {
    public:
        static inline constexpr std::size_t Capacity{512U};

        explicit SessionTraceRing(const Prism::ProcessId Process,
                                  const Prism::WorkerId Worker) noexcept
            : Process_(Process), Worker_(Worker)
        {
        }

        SessionTraceRing(const SessionTraceRing &) = delete;
        auto operator=(const SessionTraceRing &) -> SessionTraceRing & = delete;

        /** @brief 写入一条固定字段记录；不分配、不等待，覆盖最旧槽位。 */
        auto Record(SessionTraceRecord Value) noexcept -> void;

        /** @brief 按值读取单 worker 事件页及覆盖、游标信息；读取只执行原子 load。 */
        [[nodiscard]] auto Query(const SessionTraceQuery &QueryValue) const
            -> SessionTraceSnapshot;

        [[nodiscard]] auto Process() const noexcept -> Prism::ProcessId
        {
            return Process_;
        }

        [[nodiscard]] auto Worker() const noexcept -> Prism::WorkerId
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

        static auto Store(Slot &SlotValue, const SessionTraceRecord &Value) noexcept -> void;

        [[nodiscard]] static auto Load(const Slot &SlotValue) noexcept -> SessionTraceRecord;

        [[nodiscard]] static auto ReadCursor(
            const SessionTraceQuery &QueryValue,
            const Prism::WorkerId Worker) noexcept -> std::uint64_t;

        [[nodiscard]] static auto Matches(
            const SessionTraceQuery &QueryValue,
            const SessionTraceIdentity &Identity) noexcept -> bool;

        const Prism::ProcessId Process_{};
        const Prism::WorkerId Worker_{};
        std::array<Slot, Capacity> Slots_{};
        std::uint64_t NextSequence_{0U}; ///< 只由所属 worker executor 访问。
        std::atomic<std::uint64_t> PublishedSequence_{0U};
        std::atomic<bool> SequenceExhausted_{false};
    };

    /** @brief Worker 持有的轨迹环 owner；与网络资源和 SessionRegistry 分离。 */
    class WorkerSessionTraceOwner
    {
    public:
        WorkerSessionTraceOwner(const Prism::ProcessId Process,
                                const Prism::WorkerId Worker);

        /** @brief 借用 worker-local 固定容量轨迹环；写入限于该 worker executor。 */
        [[nodiscard]] auto TraceRing() const noexcept -> std::shared_ptr<SessionTraceRing>
        {
            return Ring_;
        }

    private:
        std::shared_ptr<SessionTraceRing> Ring_;
    };

    /** @brief 固定相关身份与接入时钟；调用者在所属 worker executor 写入。 */
    class SessionTraceWriter final : public Prism::Contract::Services::FirstTransferObserver
    {
    public:
        using WallClock = std::chrono::system_clock;
        using MonotonicClock = std::chrono::steady_clock;

        /** @brief 写入一个阶段结果及其 wall/monotonic 观测时刻。 */
        struct SessionTraceRecordRequest final
        {
            SessionTraceStage Stage{SessionTraceStage::TcpAccepted};
            SessionTraceOutcome Outcome{SessionTraceOutcome::None};
            Prism::Fault::Code Failure{Prism::Fault::Code::Success};
            WallClock::time_point Wall{};
            MonotonicClock::time_point Monotonic{};
        };

        SessionTraceWriter(std::shared_ptr<SessionTraceRing> Ring,
                           SessionTraceIdentity Identity,
                           const MonotonicClock::time_point AcceptedMonotonic) noexcept
            : Ring_(std::move(Ring)), Identity_(Identity),
              AcceptedMonotonic_(AcceptedMonotonic)
        {
        }

        auto SetTaskIdentity(const Prism::Lifecycle::TaskIdentity &Value) noexcept -> void;

        auto SetAccount(const Prism::AccountId Value) noexcept -> void
        {
            Identity_.Account = Value;
        }

        auto Record(const SessionTraceStage Stage) noexcept -> void
        {
            Record(Stage, SessionTraceOutcome::None, Prism::Fault::Code::Success);
        }

        auto Record(const SessionTraceStage Stage,
                    const Prism::Fault::Code Failure) noexcept -> void
        {
            Record(Stage,
                Prism::Fault::Failed(Failure) ? SessionTraceOutcome::Failed
                                                : SessionTraceOutcome::Succeeded,
                Failure);
        }

        auto Record(const SessionTraceStage Stage,
                    const SessionTraceOutcome Outcome,
                    const Prism::Fault::Code Failure) noexcept -> void;

        auto RecordAt(SessionTraceRecordRequest Request) noexcept -> void;

        auto OnFirstTransfer(const std::size_t Direction) noexcept -> void override;

    private:
        std::shared_ptr<SessionTraceRing> Ring_;
        SessionTraceIdentity Identity_;
        MonotonicClock::time_point AcceptedMonotonic_;
    };
}
