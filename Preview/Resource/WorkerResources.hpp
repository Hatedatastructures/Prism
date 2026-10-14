/**
 * @file WorkerResources.hpp
 * @brief Preview worker 本地资源所有者
 * @details 运行时服务、TaskRegistry 和统计由本 owner 独占；独立 ContextOwner
 *          持有 PMR/IoContext，使失败实物可保留实际 executor 依赖而不保留 worker 服务。
 *          跨线程入口只发布到 Scheduler，正常停机仍先排空任务再停止执行器。
 */

#pragma once

#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Net/Dns/Config.hpp>
#include <Preview/Net/Services/WorkerDialService.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <memory_resource>

namespace Preview::Resource
{

    namespace Net = boost::asio;

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
        void RecordAccepted() noexcept
        {
            DispatchAccepted_.fetch_add(1, std::memory_order_relaxed);
        }

        void RecordFull() noexcept
        {
            DispatchFull_.fetch_add(1, std::memory_order_relaxed);
        }

        void RecordClosed() noexcept
        {
            DispatchClosed_.fetch_add(1, std::memory_order_relaxed);
        }

        void RecordWorkerUnavailable() noexcept
        {
            DispatchWorkerUnavailable_.fetch_add(1, std::memory_order_relaxed);
        }

        void RecordGenerationRejected() noexcept
        {
            DispatchGenerationRejected_.fetch_add(1, std::memory_order_relaxed);
        }

        void RecordExecuted() noexcept
        {
            CommandsExecuted_.fetch_add(1, std::memory_order_relaxed);
        }

        void RecordFailed() noexcept
        {
            CommandsFailed_.fetch_add(1, std::memory_order_relaxed);
        }

        [[nodiscard]] auto Snapshot() const noexcept -> WorkerStatisticsSnapshot
        {
            return WorkerStatisticsSnapshot{DispatchAccepted_.load(std::memory_order_relaxed),
                DispatchFull_.load(std::memory_order_relaxed),
                DispatchClosed_.load(std::memory_order_relaxed),
                DispatchWorkerUnavailable_.load(std::memory_order_relaxed),
                DispatchGenerationRejected_.load(std::memory_order_relaxed),
                CommandsExecuted_.load(std::memory_order_relaxed),
                CommandsFailed_.load(std::memory_order_relaxed)};
        }

    private:
        std::atomic<std::uint64_t> DispatchAccepted_{0};
        std::atomic<std::uint64_t> DispatchFull_{0};
        std::atomic<std::uint64_t> DispatchClosed_{0};
        std::atomic<std::uint64_t> DispatchWorkerUnavailable_{0};
        std::atomic<std::uint64_t> DispatchGenerationRejected_{0};
        std::atomic<std::uint64_t> CommandsExecuted_{0};
        std::atomic<std::uint64_t> CommandsFailed_{0};
    };

    struct WorkerResources final
    {
        struct Options final
        {
            Preview::ProcessId Process{};
            Preview::WorkerId Id{};
            Preview::GenerationId Generation{};
            Preview::Network::Dns::Config Dns{};
            Preview::Memory::BytePoolOptions Bytes{}; ///< 冷路径创建的固定字节容量。
        };

        WorkerResources() : WorkerResources(Options{})
        {
        }

        explicit WorkerResources(Options Value)
            : Process(Value.Process), Id(Value.Id), Generation(Value.Generation),
              Execution(Preview::Executor::ContextOwner::Create()), MemoryResource(&Execution->Pool),
              Bytes(std::make_shared<Preview::Memory::BytePool>(Value.Bytes)),
              IoContext(Execution->Io), Scheduler(Net::any_io_executor(IoContext.get_executor())),
              DialService(std::make_shared<Preview::Network::Services::WorkerDialService>(
                  Preview::Network::Services::WorkerDialOptions{Net::any_io_executor(Scheduler), Value.Dns})),
              Tasks(std::make_unique<Preview::Lifecycle::TaskRegistry>(Net::any_io_executor(Scheduler))),
              Work(Net::any_io_executor(Scheduler))
        {
        }

        ~WorkerResources() noexcept
        {
            Stop();
        }

        WorkerResources(const WorkerResources&) = delete;
        auto operator=(const WorkerResources&) -> WorkerResources& = delete;
        WorkerResources(WorkerResources&&) = delete;
        auto operator=(WorkerResources&&) -> WorkerResources& = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Net::any_io_executor(Scheduler);
        }

        [[nodiscard]] auto IsStopping() const noexcept -> bool
        {
            return Stopping.load(std::memory_order_acquire);
        }

        /**
         * @brief 停止 worker 执行上下文；空态先关闭 DNS 维护 owner，再退休根注册表。
         * @param AllowEmptyTaskRetirement 上层快照所有者已封止读者后允许退休空注册表。
         */
        auto Stop(const bool AllowEmptyTaskRetirement = true) noexcept -> void
        {
            if (Stopping.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            if (!Tasks)
            {
                Work.reset();
                IoContext.stop();
                return;
            }

            Tasks->Seal();
            if (AllowEmptyTaskRetirement && CanRetireEmptyTasks())
            {
                if (DrainAndRetireEmptyTasks())
                {
                    IoContext.stop();
                    return;
                }
            }
            if (Tasks) (void)Tasks->Cancel();
            Work.reset();
            IoContext.stop();
        }

        Preview::ProcessId Process{};
        Preview::WorkerId Id{};
        Preview::GenerationId Generation{};
        std::shared_ptr<Preview::Executor::ContextOwner> Execution;
        Preview::Memory::ResourcePointer MemoryResource{nullptr};
        std::shared_ptr<Preview::Memory::BytePool> Bytes; ///< 唯一worker块池owner；服务和在途租约共享总容量。
        Net::io_context& IoContext;
        Net::strand<Net::any_io_executor> Scheduler;
        std::shared_ptr<Preview::Network::Services::WorkerDialService> DialService;
        /** @brief 可在 executor 仍运行时退休的 worker root registry facade。 */
        std::unique_ptr<Preview::Lifecycle::TaskRegistry> Tasks;
        Net::executor_work_guard<Net::any_io_executor> Work;
        WorkerStatistics Stats;

    private:
        /** @brief 跨执行器停止边界保留真实注册表退休结果。 */
        struct EmptyTaskRetirement final
        {
            std::atomic<bool> Retired{false};
            std::atomic<bool> Failed{false};
        };

        /** @brief 仅当封止后的 root 与全部后代真实空闲时允许在原 executor 退休。 */
        [[nodiscard]] auto CanRetireEmptyTasks() const noexcept -> bool
        {
            if (!Tasks || !Execution || Execution->Fatal->HasFailure() || IoContext.stopped() ||
                Scheduler.running_in_this_thread())
            {
                return false;
            }
            const auto Snapshot = Tasks->Stats();
            const auto Reclaimer = Tasks->Reclaimer();
            if (Snapshot.Active != 0 || Snapshot.DrainBlocked || Snapshot.Quarantined != 0 ||
                !Reclaimer->CanDispatch() || Reclaimer->IsQuarantined() ||
                Reclaimer->QuarantinedCount() != 0 || Reclaimer->ActionFailures() != 0)
            {
                return false;
            }
            try
            {
                return !Preview::Executor::ContextOwner::Storage(Executor())->IsSealed();
            }
            catch (...)
            {
                return false;
            }
        }

        /** @brief 排空任务与 DNS 维护 owner 后才销毁根注册表。 */
        [[nodiscard]] static auto RetireEmptyTasks(
            std::unique_ptr<Preview::Lifecycle::TaskRegistry> Registry,
            std::shared_ptr<Preview::Network::Services::WorkerDialService> DialService)
            -> Net::awaitable<bool>
        {
            if (!Registry || !DialService)
            {
                co_return false;
            }
            const auto Drained = co_await Registry->Drain();
            if (!Drained)
            {
                co_return false;
            }
            const auto DialServiceStopped = co_await DialService->Shutdown();
            if (!DialServiceStopped)
            {
                co_return false;
            }
            const auto Snapshot = Registry->Stats();
            if (Snapshot.Active != 0 || Snapshot.DrainBlocked || Snapshot.Quarantined != 0)
            {
                co_return false;
            }
            Registry.reset();
            co_return true;
        }

        /** @brief 在真实执行器上驱动取消、根注册表退休和回收处理函数退栈。 */
        auto DrainAndRetireEmptyTasks() noexcept -> bool
        {
            const auto Reclaimer = Tasks->Reclaimer();
            const auto Fatal = Execution->Fatal;
            std::shared_ptr<Preview::Executor::ClosingStorage> Storage;
            std::shared_ptr<EmptyTaskRetirement> Outcome;
            std::size_t StoragePendingBefore = 0;
            try
            {
                Storage = Preview::Executor::ContextOwner::Storage(Executor());
                StoragePendingBefore = Storage->Pending();
                Outcome = std::make_shared<EmptyTaskRetirement>();
                auto Registry = std::move(Tasks);
                (void)Registry->Cancel();
                Net::co_spawn(Scheduler, RetireEmptyTasks(std::move(Registry), DialService),
                    [Outcome, Fatal](std::exception_ptr Error, const bool Completed)
                    {
                        if (Error)
                        {
                            Fatal->Publish(std::move(Error));
                            Outcome->Failed.store(true, std::memory_order_release);
                            return;
                        }
                        Outcome->Retired.store(Completed, std::memory_order_release);
                    });
                Work.reset();
                IoContext.run();
            }
            catch (...)
            {
                Fatal->Publish(std::current_exception());
                Work.reset();
                IoContext.stop();
                return false;
            }
            Storage->Collect();
            return Outcome->Retired.load(std::memory_order_acquire) &&
                   !Outcome->Failed.load(std::memory_order_acquire) && !Fatal->HasFailure() &&
                   !Storage->IsSealed() && Storage->Pending() <= StoragePendingBefore &&
                   Reclaimer->Pending() == 0 && Reclaimer->QuarantinedCount() == 0 &&
                   Reclaimer->ActionFailures() == 0;
        }
        std::atomic<bool> Stopping{false};
    };

} // namespace Preview::Resource
