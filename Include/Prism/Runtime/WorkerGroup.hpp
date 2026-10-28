/**
 * @file WorkerGroup.hpp
 * @brief Prism worker 集合及其唯一 worker owner
 * @details WorkerGroup 只由 Process 持有；每个 Worker 由 unique_ptr 独占，
 *          创建后集合大小固定。Dispatch 是无阻塞发布入口，Snapshot 只读
 *          原子状态和 worker-local task 统计。
 */
#pragma once

#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/Worker.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>
#include <Prism/Runtime/Session/Trace/Model.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Net/Dns/Config.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <vector>

namespace Prism::Runtime
{
    namespace Net = boost::asio;

    class WorkerGroup final
    {
    public:
        struct Options final
        {
            Prism::ProcessId Process{};
            Prism::GenerationId Generation{};
            std::size_t WorkerCount{1};
            std::size_t MailboxCapacity{64};
            Prism::Network::Dns::Config Dns{};
            /** @brief 构造时共享给各 Worker 的进程级发布 owner。 */
            std::shared_ptr<GenerationPublication> Publication;
        };

        WorkerGroup();
        explicit WorkerGroup(Options Value);
        ~WorkerGroup() noexcept;

        WorkerGroup(const WorkerGroup &) = delete;
        auto operator=(const WorkerGroup &) -> WorkerGroup & = delete;
        WorkerGroup(WorkerGroup &&) = delete;
        auto operator=(WorkerGroup &&) -> WorkerGroup & = delete;

        /** @brief 按值返回固定进程身份；不借出 worker 或资源 owner。 */
        [[nodiscard]] auto Process() const noexcept -> Prism::ProcessId;
        /** @brief 按值返回当前发布代次身份；没有已发布快照时返回构造时的初始身份。 */
        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId;

        /**
         * @brief 在所有 worker 上依次准备同一 base/candidate 并收集 typed ack。
         * @details 候选 pin 由调用方共享持有，并在本协程和 worker 准备结果中借用；
         *          操作屏蔽协程取消，在各 worker executor 执行。失败保留首个 typed
         *          Failure，不发布候选，也不改变当前代次。
         * @param Base 预期的当前代次身份。
         * @param Candidate 调用方持有的候选代次 pin。
         * @return 每个 worker 的准备回执，或 Invalid/Unavailable/Blocked 失败。
         */
        [[nodiscard]] auto PrepareGeneration(
            Prism::GenerationId Base,
            Prism::Foundation::GenerationPin Candidate)
            -> Net::awaitable<std::expected<std::vector<GenerationPrepareAck>, Prism::Fault::Failure>>;

        /** @brief 按值返回固定 worker 数量。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t;
        /** @brief 按稳定 WorkerId 查找 worker；返回指针借用本组持有的 Worker。 */
        [[nodiscard]] auto Find(Prism::WorkerId Id) noexcept -> Worker *;
        [[nodiscard]] auto Find(Prism::WorkerId Id) const noexcept -> const Worker *;

        /**
         * @brief 向指定 worker 执行器提交拥有型命令。
         * @details 命令按值转移到目标 worker 的 mailbox；Accepted 仅表示入队，不表示
         *          handler 已执行。拒绝或 Stop 丢弃闭包时，由闭包捕获值的真实 owner
         *          释放其预约。此 API 不触发 socket I/O、取消或半关闭。
         * @param Id 已选定的 worker 身份。
         * @param Generation 命令所属的已发布代次。
         * @param CommandValue 按值转移给 worker 的命令闭包。
         * @return Accepted、Full、Closed、WorkerUnavailable 或 GenerationRejected。
         */
        [[nodiscard]] auto Dispatch(
            Prism::WorkerId Id,
            Prism::GenerationId Generation,
            WorkerDispatchCommand CommandValue) -> WorkerDispatchResult;
        /**
         * @brief 按轮转顺序选择 worker 并提交拥有型命令。
         * @details WorkerGroup 不接管 I/O 最终关闭权，调用者仍负责错误/拒绝路径的资源回收。
         *          Accepted 只说明命令已入选队列，目标 worker 实际执行可能受 Stop 影响。
         * @param Generation 命令所属的已发布代次。
         * @param CommandValue 按值转移给目标 worker 的命令闭包。
         * @return Accepted、Full、Closed、WorkerUnavailable 或 GenerationRejected。
         */
        [[nodiscard]] auto Dispatch(
            Prism::GenerationId Generation,
            WorkerDispatchCommand CommandValue) -> WorkerDispatchResult;

        /**
         * @brief 封止指定 generation 的单一 worker admission，并等待其本地 owner 真实退休。
         * @details 不改变 WorkerGroup 全局 Stopping，也不停止进程的其它 worker/context；
         *          Worker::Shutdown 排空该 worker root task、admission receipt、mailbox 与本地 dial service。
         * @return admission identity 不匹配或 drain fence 失败时保留 typed Failure。
         */
        [[nodiscard]] auto DrainWorker(
            Prism::WorkerId Id,
            Prism::GenerationId Generation)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /**
         * @brief 先封止全部 worker admission，再逐个执行真实任务 Drain 与 executor fence。
         * @details 调用方须保持 WorkerGroup/Worker owner，直到 await 完成。该协程不 stop
         *          worker context；每个 worker root scope 与其后代真实 Drain 后，Group 汇总
         *          Collect/检查进程 ClosingStorage。协程屏蔽调用方 cancellation，超时由应用
         *          外层 deadline 返回失败并把整个运行时留给进程终态 owner。
         * @return 任一 worker scope、reclaimer、storage fence 失败时返回原 Failure 或 Blocked。
         */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /**
         * @brief 同步停止各 worker 的 admission 和 executor。
         * @details 这是紧急停止请求，不等待任务退栈、传输关闭或 executor fence；
         *          正常生命周期必须先 await Shutdown。最终资源 owner 保留未排空实物。
         */
        auto Stop() noexcept -> void;

        /** @brief 按值读取停止请求事实，不代表 worker 已物理退休。 */
        [[nodiscard]] auto IsStopping() const noexcept -> bool;
        /** @brief 复制当前 worker 值快照；不转移任务、队列或传输所有权。 */
        [[nodiscard]] auto Snapshot() const -> std::vector<WorkerSnapshot>;
        /** @brief 合并 worker-local 轨迹页；每个 worker 保留独立游标和丢失计数。 */
        [[nodiscard]] auto QuerySessionTrace(const SessionTraceQuery &QueryValue) const
            -> SessionTraceSnapshot;

    private:
        [[nodiscard]] static auto SessionTraceRecordLess(
            const SessionTraceRecord &Left,
            const SessionTraceRecord &Right) -> bool;

        Prism::ProcessId Process_{};
        Prism::GenerationId Generation_{};
        std::shared_ptr<GenerationPublication> Publication_;
        std::vector<std::unique_ptr<Worker>> Workers_;
        std::atomic<std::size_t> NextWorker_{0};
        std::atomic<bool> Stopping_;
    };
} // namespace Prism::Runtime
