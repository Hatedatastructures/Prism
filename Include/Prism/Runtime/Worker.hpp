/**
 * @file Worker.hpp
 * @brief Prism worker executor、mailbox 和本地资源边界
 * @details 外部线程只能通过 Dispatch 发布命令；命令消费、任务启动和
 *          worker-local 可变状态均在 Scheduler 上执行。Worker 不复制也不
 *          共享其 WorkerResources owner。
 */

#pragma once

#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Resource/WorkerResources.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/WorkerAdmissionReceipt.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>
#include <Prism/Runtime/Session/Trace/Ring.hpp>
#include <Prism/Runtime/WorkerTaskSnapshotGate.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <utility>

namespace Prism::Network::Services
{
    class WorkerDialService;
}

namespace Prism::Executor
{
    class ContextOwner;
}

namespace Prism::Runtime
{

    namespace Net = boost::asio;

    namespace Detail
    {
        class Mailbox;

        struct WorkerStatisticsSnapshot final
        {
            std::uint64_t DispatchAccepted{0};
            std::uint64_t DispatchFull{0};
            std::uint64_t DispatchClosed{0};
            std::uint64_t DispatchWorkerUnavailable{0};
            std::uint64_t DispatchGenerationRejected{0};
            std::uint64_t CommandsExecuted{0};
            std::uint64_t CommandsFailed{0};
        };

        class WorkerStatistics final
        {
        public:
            auto RecordAccepted() noexcept -> void { DispatchAccepted_.fetch_add(1, std::memory_order_relaxed); }
            auto RecordFull() noexcept -> void { DispatchFull_.fetch_add(1, std::memory_order_relaxed); }
            auto RecordClosed() noexcept -> void { DispatchClosed_.fetch_add(1, std::memory_order_relaxed); }
            auto RecordWorkerUnavailable() noexcept -> void
            { DispatchWorkerUnavailable_.fetch_add(1, std::memory_order_relaxed); }
            auto RecordGenerationRejected() noexcept -> void
            { DispatchGenerationRejected_.fetch_add(1, std::memory_order_relaxed); }
            auto RecordExecuted() noexcept -> void { CommandsExecuted_.fetch_add(1, std::memory_order_relaxed); }
            auto RecordFailed() noexcept -> void { CommandsFailed_.fetch_add(1, std::memory_order_relaxed); }

            [[nodiscard]] auto Snapshot() const noexcept -> WorkerStatisticsSnapshot;

        private:
            std::atomic<std::uint64_t> DispatchAccepted_{0};
            std::atomic<std::uint64_t> DispatchFull_{0};
            std::atomic<std::uint64_t> DispatchClosed_{0};
            std::atomic<std::uint64_t> DispatchWorkerUnavailable_{0};
            std::atomic<std::uint64_t> DispatchGenerationRejected_{0};
            std::atomic<std::uint64_t> CommandsExecuted_{0};
            std::atomic<std::uint64_t> CommandsFailed_{0};
        };
    }

    struct WorkerSnapshot final
    {
        Prism::ProcessId Process{};
        Prism::WorkerId Id{};
        Prism::GenerationId Generation{};
        bool Running{false};
        bool Accepting{false};
        std::size_t MailboxSize{0};
        std::size_t MailboxCapacity{0};
        std::size_t ActiveTasks{0};
        std::size_t StartedTasks{0};
        std::size_t CompletedTasks{0};
        std::size_t CancelledTasks{0};
        std::uint64_t DispatchAccepted{0};
        std::uint64_t DispatchFull{0};
        std::uint64_t DispatchClosed{0};
        std::uint64_t DispatchWorkerUnavailable{0};
        std::uint64_t DispatchGenerationRejected{0};
        std::uint64_t CommandsExecuted{0};
        std::uint64_t CommandsFailed{0};
    };

    enum class GenerationPrepareStatus : std::uint8_t
    {
        Prepared,
        WorkerUnavailable,
        BaseMismatch,
        CandidateMismatch,
    };

    struct GenerationPrepareAck final
    {
        Prism::WorkerId Worker{};
        Prism::GenerationId Base{};
        Prism::GenerationId Candidate{};
        GenerationPrepareStatus Status{GenerationPrepareStatus::WorkerUnavailable};
    };

    class Worker final : public WorkerSessionTraceOwner
    {
    public:
        using AdmissionReceipt = WorkerAdmissionReceipt;

        struct Options final
        {
            Prism::ProcessId Process{};
            Prism::WorkerId Id{};
            Prism::GenerationId Generation{};
            std::size_t MailboxCapacity{64};
            Prism::Network::Dns::Config Dns{};
            std::shared_ptr<GenerationPublication> Publication;
        };

        Worker();
        explicit Worker(Options Value);
        ~Worker() noexcept;
        Worker(const Worker &) = delete;
        auto operator=(const Worker &) -> Worker & = delete;
        Worker(Worker &&) = delete;
        auto operator=(Worker &&) -> Worker & = delete;

        [[nodiscard]] auto Id() const noexcept -> Prism::WorkerId;

        [[nodiscard]] auto Process() const noexcept -> Prism::ProcessId;

        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId;

        /** @brief 借用 root TaskRegistry；仅 Worker 存活且 Shutdown 未开始时有效。Cancel 仅登记请求，Drain/Shutdown 确认退栈；I/O 关闭归实际 Session/Carrier owner。 */
        [[nodiscard]] auto TaskRegistry() noexcept -> Prism::Lifecycle::TaskRegistry &;
        /** @brief 按值返回 scheduler executor；句柄不保活 Worker/ContextOwner，最终停止 io_context 归 Process::Stop。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor;

        [[nodiscard]] auto IsOnExecutor() const noexcept -> bool;

        [[nodiscard]] auto IsRunning() const noexcept -> bool;

        [[nodiscard]] auto IsAccepting() const noexcept -> bool;

        /** @brief 按 generation 预约 listener carrier；不匹配或 admission 已封止返回空。
         * @param Generation 当前 worker group generation。
         * @return 固定 WorkerId/Generation 的票据，由 Reservation 接管至真实 carrier 退役。 */
        [[nodiscard]] auto TryReserveAdmission(const Prism::GenerationId Generation)
            -> std::shared_ptr<AdmissionReceipt>;

        /** @brief 在 worker executor 确认候选代次可被共享发布，不修改任何活动状态。 */
        [[nodiscard]] auto PrepareGeneration(
            const Prism::GenerationId Base,
            Prism::Foundation::GenerationPin Candidate)
            -> Net::awaitable<GenerationPrepareAck>;

        /** @brief 将命令交给本 worker 的固定容量 executor 队列。
         * @details 按值接管闭包；Accepted 仅表示入队，worker executor 执行仍在队列中的命令，Stop 可释放未执行闭包。
         * 返回队列、worker 或 generation 的拒绝原因。提交不取消 I/O、不做半关闭；最终关闭归闭包捕获的真实 owner。
         * @param Generation 此次 dispatch 所属的已发布代次。
         * @param CommandValue 由 worker 接管的命令及其 owning captures。
         * @return 入队结果；命令执行期异常由 worker 隔离并计入失败统计。
         */
        [[nodiscard]] auto Dispatch(Prism::GenerationId Generation,
            WorkerDispatchCommand CommandValue) -> WorkerDispatchResult;

        auto Run() -> void;

        [[nodiscard]] auto Pump() -> std::size_t;

        /** @brief 同步封闭准入/mailbox、封止并请求取消；无 driver 线程时仅尝试退休确认为空的 root scope，
         *         不能代替完整 Drain。 */
        auto Stop() noexcept -> void;

        /** @brief 封闭 admission、receipt fence 与 mailbox；不取消任务、不 Drain，也不停止 executor。 */
        auto CloseAdmission() noexcept -> void;

        /** @brief 异步退休 root tasks、admission receipts 与 DNS owner。
         * @details 屏蔽调用方取消并在 worker scheduler 排空；首次失败后 gate 不复位，
         *          后续调用返回 WouldBlock，调用方须保留 Worker/ContextOwner；最终停止 io_context
         *          仍归 Process::Stop。
         * @return tasks、receipts、DNS owner、executor 与快照 fence 全部 drain 成功才成功，否则返回 Failure。 */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 读取 worker 快照；TaskStats 通过关闭读闸门与退休快照安全切换。 */
        [[nodiscard]] auto Snapshot() const noexcept -> WorkerSnapshot;
        /** @brief 借用 WorkerResources；引用不拥有 Worker/ContextOwner，Stop/Shutdown 会改变成员状态。 */
        [[nodiscard]] auto Resources() noexcept -> Prism::Resource::WorkerResources &;
        /** @brief 只读借用同一 WorkerResources；资源生命周期仍由 Worker 与 Process 所有。 */
        [[nodiscard]] auto Resources() const noexcept
            -> const Prism::Resource::WorkerResources &;
        /** @brief 返回初始会话快照使用的拨号 owner 句柄。
         * @details 句柄不保活 Worker executor；Worker::Shutdown 负责排空会话后关闭服务。
         */
        [[nodiscard]] auto DialService() const noexcept
            -> std::shared_ptr<Prism::Network::Services::WorkerDialService>;

    private:
        friend class WorkerTestAccess;

        struct EmptyTaskRetirement final
        {
            std::atomic<bool> Retired{false};
            std::atomic<bool> Failed{false};
        };

        [[nodiscard]] auto IsShutdownFenceClear(
            const std::shared_ptr<Prism::Executor::ExecutorReclaimer>& Reclaimer,
            const std::shared_ptr<Prism::Executor::ClosingStorage>& Storage) const noexcept -> bool;

        [[nodiscard]] auto IsRetirementFenceClear(
            const std::shared_ptr<Prism::Executor::ExecutorReclaimer>& Reclaimer,
            const std::shared_ptr<Prism::Executor::ClosingStorage>& Storage) const noexcept -> bool;

        [[nodiscard]] auto CanRetireEmptyTasks() const noexcept -> bool;
        [[nodiscard]] static auto RetireEmptyTasks(
            std::unique_ptr<Prism::Lifecycle::TaskRegistry> Registry,
            std::shared_ptr<Prism::Network::Services::WorkerDialService> DialService)
            -> Net::awaitable<bool>;
        [[nodiscard]] auto DrainAndRetireEmptyTasks() noexcept -> bool;

        auto Record(WorkerDispatchResult Result) noexcept -> void;
        auto Notify() noexcept -> void;
        auto DrainMailbox() noexcept -> void;

        /** @brief 让 context 在 Resource task registry 与 worker 拨号服务依次析构后再释放。 */
        std::shared_ptr<Prism::Executor::ContextOwner> ContextOwner_;
        std::shared_ptr<Prism::Network::Services::WorkerDialService> DialService_;
        Prism::Resource::WorkerResources Resources_;
        Net::strand<Net::any_io_executor> Scheduler_;
        Net::executor_work_guard<Net::any_io_executor> Work_;
        std::shared_ptr<GenerationPublication> Publication_;
        std::unique_ptr<Detail::Mailbox> Mailbox_;
        Detail::WorkerTaskSnapshotGate TaskSnapshots_;
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> AdmissionFence_;
        Detail::WorkerStatistics Stats_;
        /** @brief 已停止并 join driver 后使迟到通知失效；不保留 Worker/服务，独立 context 可安全退休。 */
        struct DispatchTarget;
        std::shared_ptr<DispatchTarget> DispatchTarget_;
        std::atomic<bool> Accepting_{true};
        std::atomic<bool> Running_{true};
        std::atomic<bool> DrainPosted_{false};
        std::atomic<bool> ShutdownDrained_{false};
        std::atomic<bool> ShutdownRunning_{false};
        std::atomic<bool> Stopping_{false};
        std::atomic<std::size_t> DriverCount_{0};
    };

} // namespace Prism::Runtime
