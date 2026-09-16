/**
 * @file WorkerResources.hpp
 * @brief Preview worker 本地资源所有者
 * @details WorkerResources 以值成员持有 worker 的 PMR、Asio executor、
 *          TaskRegistry 和统计槽。它不复制、不移动，也不把 worker 资源
 *          转换成全局共享 owner；跨线程入口只发布到 Scheduler。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Net/Dns/Config.hpp>
#include <Preview/Net/Services/WorkerDialService.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
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
            return WorkerStatisticsSnapshot{
                DispatchAccepted_.load(std::memory_order_relaxed),
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
        };

        WorkerResources() : WorkerResources(Options{}) {}

        explicit WorkerResources(Options Value)
            : Process(Value.Process),
              Id(Value.Id),
              Generation(Value.Generation),
              Pool(std::pmr::pool_options{}, std::pmr::new_delete_resource()),
              MemoryResource(&Pool),
              IoContext(1),
              Scheduler(Net::any_io_executor(IoContext.get_executor())),
              DialService(std::make_shared<Preview::Network::Services::WorkerDialService>(
                  Preview::Network::Services::WorkerDialOptions{
                      Net::any_io_executor(Scheduler), Value.Dns})),
              Tasks(Net::any_io_executor(Scheduler)),
              Work(Net::any_io_executor(Scheduler))
        {
        }

        ~WorkerResources() noexcept
        {
            Stop();
        }

        WorkerResources(const WorkerResources &) = delete;
        auto operator=(const WorkerResources &) -> WorkerResources & = delete;
        WorkerResources(WorkerResources &&) = delete;
        auto operator=(WorkerResources &&) -> WorkerResources & = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Net::any_io_executor(Scheduler);
        }

        [[nodiscard]] auto IsStopping() const noexcept -> bool
        {
            return Stopping.load(std::memory_order_acquire);
        }

        void Stop() noexcept
        {
            if (Stopping.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            (void)Tasks.Cancel();
            Work.reset();
            IoContext.stop();
        }

        Preview::ProcessId Process{};
        Preview::WorkerId Id{};
        Preview::GenerationId Generation{};
        std::pmr::unsynchronized_pool_resource Pool;
        Preview::Memory::ResourcePointer MemoryResource{nullptr};
        Net::io_context IoContext;
        Net::strand<Net::any_io_executor> Scheduler;
        std::shared_ptr<Preview::Network::Services::WorkerDialService> DialService;
        Preview::Lifecycle::TaskRegistry Tasks;
        Net::executor_work_guard<Net::any_io_executor> Work;
        WorkerStatistics Stats;

    private:
        std::atomic<bool> Stopping{false};
    };

} // namespace Preview::Resource
