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
#include <Prism/Runtime/SessionTraceModel.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dns/Config.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <expected>
#include <iterator>
#include <memory>
#include <utility>
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

        WorkerGroup() : WorkerGroup(Options{}) {}

        explicit WorkerGroup(Options Value)
            : Process_(Value.Process),
              Generation_(Value.Generation),
              Publication_(std::move(Value.Publication)),
              Stopping_(false)
        {
            auto Count = Value.WorkerCount;
            if (Count == 0)
            {
                Count = 1;
            }
            Workers_.reserve(Count);
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                Workers_.push_back(std::make_unique<Worker>(Worker::Options{
                    Value.Process,
                    Prism::WorkerId{static_cast<std::uint64_t>(Index + 1)},
                    Value.Generation,
                    Value.MailboxCapacity,
                    Value.Dns,
                    Publication_}));
            }
        }

        ~WorkerGroup() noexcept
        {
            Stop();
        }

        WorkerGroup(const WorkerGroup &) = delete;
        auto operator=(const WorkerGroup &) -> WorkerGroup & = delete;
        WorkerGroup(WorkerGroup &&) = delete;
        auto operator=(WorkerGroup &&) -> WorkerGroup & = delete;

        /** @brief 按值返回固定进程身份；不借出 worker 或资源 owner。 */
        [[nodiscard]] auto Process() const noexcept -> Prism::ProcessId
        {
            return Process_;
        }

        /**
         * @brief 按值返回当前发布代次身份。
         * @details 只读一次发布 owner 并复制 GenerationId，不返回或延长代次 pin；
         *          没有已发布快照时返回构造时的初始身份。
         */
        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId
        {
            if (Publication_)
            {
                const auto Current = Publication_->Current();
                if (Current)
                {
                    return Current->Id();
                }
            }
            return Generation_;
        }

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
            const Prism::GenerationId Base,
            Prism::Foundation::GenerationPin Candidate)
            -> Net::awaitable<std::expected<std::vector<GenerationPrepareAck>, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (Workers_.empty() || !Candidate || Candidate->Id() <= Base ||
                Generation() != Base)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            std::vector<GenerationPrepareAck> Acknowledgements;
            Acknowledgements.reserve(Workers_.size());
            for (const auto &WorkerValue : Workers_)
            {
                if (!WorkerValue)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
                auto Ack = co_await WorkerValue->PrepareGeneration(Base, Candidate);
                if (Ack.Status != GenerationPrepareStatus::Prepared)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                }
                Acknowledgements.push_back(std::move(Ack));
            }
            co_return Acknowledgements;
        }

        /** @brief 按值返回固定 worker 数量，不等待或修改 worker 状态。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Workers_.size();
        }

        /**
         * @brief 按稳定 WorkerId 查找 worker。
         * @details 返回值借用本组独占的 worker；调用方不得在 WorkerGroup 销毁后保存。
         * @param Id 组内唯一 worker 身份。
         * @return 存在时为借用指针，否则为空。
         */
        [[nodiscard]] auto Find(Prism::WorkerId Id) noexcept -> Worker *
        {
            if (!Id || Id.Value() == 0 || Id.Value() > Workers_.size())
            {
                return nullptr;
            }
            return Workers_[static_cast<std::size_t>(Id.Value() - 1)].get();
        }

        /** @brief const 版本的 Find；返回指针借用本组持有的 Worker。 */
        [[nodiscard]] auto Find(Prism::WorkerId Id) const noexcept -> const Worker *
        {
            if (!Id || Id.Value() == 0 || Id.Value() > Workers_.size())
            {
                return nullptr;
            }
            return Workers_[static_cast<std::size_t>(Id.Value() - 1)].get();
        }

        /** @brief 向指定 worker 执行器提交拥有型命令。
         * @details 命令按值转移到目标 worker 的 mailbox；Accepted 仅表示入队，不表示
         *          handler 已执行。拒绝或 Stop 丢弃闭包时，由闭包捕获值的真实 owner
         *          释放其预约。此 API 不触发 socket I/O、取消或半关闭。
         * @param Id 已选定的 worker 身份。
         * @param Generation 命令所属的已发布代次。
         * @param CommandValue 按值转移给 worker 的命令闭包。
         * @return Accepted、Full、Closed、WorkerUnavailable 或 GenerationRejected。
         */
        [[nodiscard]] auto Dispatch(Prism::WorkerId Id,
                                    Prism::GenerationId Generation,
                                    WorkerDispatchCommand CommandValue) -> WorkerDispatchResult
        {
            auto *WorkerValue = Find(Id);
            if (!WorkerValue || Stopping_.load(std::memory_order_acquire))
            {
                return WorkerDispatchResult::WorkerUnavailable;
            }
            return WorkerValue->Dispatch(Generation, std::move(CommandValue));
        }

        /** @brief 按轮转顺序选择 worker 并提交拥有型命令；结果与目标 worker 队列一致。
         * @details WorkerGroup 不接管 I/O 最终关闭权，调用者仍负责错误/拒绝路径的资源回收。
         *          Accepted 只说明命令已入选队列，目标 worker 实际执行可能受 Stop 影响。
         * @param Generation 命令所属的已发布代次。
         * @param CommandValue 按值转移给目标 worker 的命令闭包。
         * @return Accepted、Full、Closed、WorkerUnavailable 或 GenerationRejected。
         */
        [[nodiscard]] auto Dispatch(Prism::GenerationId Generation,
                                    WorkerDispatchCommand CommandValue) -> WorkerDispatchResult
        {
            if (Stopping_.load(std::memory_order_acquire) || Workers_.empty())
            {
                return WorkerDispatchResult::WorkerUnavailable;
            }
            const auto Index = NextWorker_.fetch_add(1, std::memory_order_relaxed) % Workers_.size();
            return Workers_[Index]->Dispatch(Generation, std::move(CommandValue));
        }

        /** @brief 封止指定 generation 的单一 worker admission，并等待其本地 owner 真实退休。
         * @details 不改变 WorkerGroup 全局 Stopping，也不停止该进程的其它 worker/context；
         *          Worker::Shutdown 排空该 worker root task、admission receipt、mailbox 与本地 dial service。
         * @return admission identity 不匹配或 drain fence 失败时保留 typed Failure。
         */
        [[nodiscard]] auto DrainWorker(
            const Prism::WorkerId Id,
            const Prism::GenerationId Generation)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (Stopping_.load(std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            auto *WorkerValue = Find(Id);
            auto Retained = Generation == Generation_;
            if (Publication_)
            {
                Retained = Publication_->Contains(Generation);
            }
            if (!WorkerValue || !Retained)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            WorkerValue->CloseAdmission();
            co_return co_await WorkerValue->Shutdown();
        }

        /**
         * @brief 先封止全部 worker admission，再逐个执行真实任务 Drain 与 executor fence。
         * @details 调用方须保持 WorkerGroup/Worker owner，直到 await 完成。该协程不 stop
         *          worker context；每个 worker root scope 与其后代真实 Drain 后，Group 汇总
         *          Collect/检查进程 ClosingStorage。协程屏蔽调用方 cancellation，超时由应用
         *          外层 deadline 返回失败并把整个运行时留给进程终态 owner。
         * @return 任一 worker scope、reclaimer、storage fence 失败时返回原 Failure 或 Blocked。
         */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            Stopping_.store(true, std::memory_order_release);
            for (const auto &WorkerValue : Workers_)
            {
                if (WorkerValue) WorkerValue->CloseAdmission();
            }
            for (const auto &WorkerValue : Workers_)
            {
                if (!WorkerValue) continue;
                const auto Result = co_await WorkerValue->Shutdown();
                if (!Result) co_return std::unexpected(Result.error());
            }
            if (!Workers_.empty())
            {
                const auto Storage = Prism::Executor::ContextOwner::Storage(Workers_.front()->Executor());
                Storage->Collect();
                if (Storage->IsSealed() || Storage->Pending() != 0)
                {
                    co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /**
         * @brief 同步停止各 worker 的 admission 和 executor。
         * @details 这是紧急停止请求，不等待任务退栈、传输关闭或 executor fence；
         *          正常生命周期必须先 await Shutdown。最终资源 owner 保留未排空实物。
         */
        auto Stop() noexcept -> void
        {
            Stopping_.store(true, std::memory_order_release);
            for (const auto &WorkerValue : Workers_)
            {
                if (WorkerValue)
                {
                    WorkerValue->Stop();
                }
            }
        }

        /** @brief 按值读取停止请求事实，不代表 worker 已物理退休。 */
        [[nodiscard]] auto IsStopping() const noexcept -> bool
        {
            return Stopping_.load(std::memory_order_acquire);
        }

        /** @brief 复制当前 worker 值快照；不转移任务、队列或传输所有权。 */
        [[nodiscard]] auto Snapshot() const -> std::vector<WorkerSnapshot>
        {
            std::vector<WorkerSnapshot> Result;
            Result.reserve(Workers_.size());
            for (const auto &WorkerValue : Workers_)
            {
                if (WorkerValue)
                {
                    Result.push_back(WorkerValue->Snapshot());
                }
            }
            return Result;
        }

        /** @brief 合并 worker-local 轨迹页；每个 worker 保留独立游标和丢失计数。 */
        [[nodiscard]] auto QuerySessionTrace(const SessionTraceQuery &QueryValue) const
            -> SessionTraceSnapshot
        {
            SessionTraceSnapshot Result;
            Result.Process = Process_;
            if (QueryValue.Process && QueryValue.Process != Process_)
            {
                return Result;
            }
            for (const auto &WorkerValue : Workers_)
            {
                if (!WorkerValue)
                {
                    continue;
                }
                auto Local = WorkerValue->TraceRing()->Query(QueryValue);
                Result.HasMore = Result.HasMore || Local.HasMore;
                Result.Records.insert(Result.Records.end(),
                    std::make_move_iterator(Local.Records.begin()),
                    std::make_move_iterator(Local.Records.end()));
                Result.Cursors.insert(Result.Cursors.end(), Local.Cursors.begin(), Local.Cursors.end());
                Result.Loss.insert(Result.Loss.end(), Local.Loss.begin(), Local.Loss.end());
            }
            std::sort(Result.Records.begin(), Result.Records.end(),
                SessionTraceRecordLess);
            return Result;
        }

    private:
        [[nodiscard]] static auto SessionTraceRecordLess(
            const SessionTraceRecord &Left,
            const SessionTraceRecord &Right) -> bool
        {
            if (Left.UtcUnixNanoseconds != Right.UtcUnixNanoseconds)
            {
                return Left.UtcUnixNanoseconds < Right.UtcUnixNanoseconds;
            }
            if (Left.Identity.Worker != Right.Identity.Worker)
            {
                return Left.Identity.Worker < Right.Identity.Worker;
            }
            return Left.Sequence < Right.Sequence;
        }

        Prism::ProcessId Process_{};
        Prism::GenerationId Generation_{};
        std::shared_ptr<GenerationPublication> Publication_;
        std::vector<std::unique_ptr<Worker>> Workers_;
        std::atomic<std::size_t> NextWorker_{0};
        std::atomic<bool> Stopping_;
    };

} // namespace Prism::Runtime
