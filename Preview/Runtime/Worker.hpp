/**
 * @file Worker.hpp
 * @brief Preview worker executor、mailbox 和本地资源边界
 * @details 外部线程只能通过 Dispatch 发布命令；命令消费、任务启动和
 *          worker-local 可变状态均在 Scheduler 上执行。Worker 不复制也不
 *          共享其 WorkerResources owner。
 */

#pragma once

#include <Preview/Resource/WorkerResources.hpp>
#include <Preview/Runtime/Mailbox.hpp>

#include <boost/asio/post.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

namespace Preview::Runtime
{

    namespace Net = boost::asio;

    struct WorkerSnapshot final
    {
        Preview::ProcessId Process{};
        Preview::WorkerId Id{};
        Preview::GenerationId Generation{};
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

    class Worker final
    {
    public:
        struct Options final
        {
            Preview::ProcessId Process{};
            Preview::WorkerId Id{};
            Preview::GenerationId Generation{};
            std::size_t MailboxCapacity{64};
            Preview::Network::Dns::Config Dns{};
        };

        Worker() : Worker(Options{}) {}

        explicit Worker(Options Value)
            : Resources_(Preview::Resource::WorkerResources::Options{
                  Value.Process, Value.Id, Value.Generation, Value.Dns}),
              Mailbox_(Mailbox::Options{Value.MailboxCapacity, Value.Generation})
        {
        }

        ~Worker() noexcept
        {
            Stop();
        }

        Worker(const Worker &) = delete;
        auto operator=(const Worker &) -> Worker & = delete;
        Worker(Worker &&) = delete;
        auto operator=(Worker &&) -> Worker & = delete;

        [[nodiscard]] auto Id() const noexcept -> Preview::WorkerId
        {
            return Resources_.Id;
        }

        [[nodiscard]] auto Process() const noexcept -> Preview::ProcessId
        {
            return Resources_.Process;
        }

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            return Resources_.Generation;
        }

        [[nodiscard]] auto TaskRegistry() noexcept -> Preview::Lifecycle::TaskRegistry &
        {
            return Resources_.Tasks;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Resources_.Executor();
        }

        [[nodiscard]] auto IsOnExecutor() const noexcept -> bool
        {
            return Resources_.Scheduler.running_in_this_thread();
        }

        [[nodiscard]] auto IsRunning() const noexcept -> bool
        {
            return Running_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsAccepting() const noexcept -> bool
        {
            return Accepting_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Dispatch(Preview::GenerationId Generation,
                                    Mailbox::Command CommandValue) -> Mailbox::Result
        {
            if (!IsAccepting())
            {
                Resources_.Stats.RecordWorkerUnavailable();
                return Mailbox::Result::WorkerUnavailable;
            }

            const auto Result = Mailbox_.Post(Generation, std::move(CommandValue));
            Record(Result);
            if (Result == Mailbox::Result::Accepted)
            {
                Notify();
            }
            return Result;
        }

        [[nodiscard]] auto Dispatch(Mailbox::Command CommandValue) -> Mailbox::Result
        {
            return Dispatch(Generation(), std::move(CommandValue));
        }

        auto Run() -> void
        {
            if (!IsRunning())
            {
                return;
            }
            Resources_.IoContext.run();
        }

        [[nodiscard]] auto Pump() -> std::size_t
        {
            if (!IsRunning())
            {
                return 0;
            }
            return Resources_.IoContext.poll();
        }

        auto Stop() noexcept -> void
        {
            if (!Accepting_.exchange(false, std::memory_order_acq_rel))
            {
                return;
            }
            Running_.store(false, std::memory_order_release);
            Mailbox_.Close();
            Resources_.Stop();
        }

        [[nodiscard]] auto Snapshot() const noexcept -> WorkerSnapshot
        {
            const auto Tasks = Resources_.Tasks.Stats();
            const auto Stats = Resources_.Stats.Snapshot();
            return WorkerSnapshot{
                Resources_.Process,
                Resources_.Id,
                Resources_.Generation,
                IsRunning(),
                IsAccepting(),
                Mailbox_.Size(),
                Mailbox_.Capacity(),
                Tasks.Active,
                Tasks.Started,
                Tasks.Completed,
                Tasks.Cancelled,
                Stats.DispatchAccepted,
                Stats.DispatchFull,
                Stats.DispatchClosed,
                Stats.DispatchWorkerUnavailable,
                Stats.DispatchGenerationRejected,
                Stats.CommandsExecuted,
                Stats.CommandsFailed};
        }

        [[nodiscard]] auto Resources() noexcept -> Preview::Resource::WorkerResources &
        {
            return Resources_;
        }

        [[nodiscard]] auto Resources() const noexcept
            -> const Preview::Resource::WorkerResources &
        {
            return Resources_;
        }

        [[nodiscard]] auto MailboxRef() noexcept -> Mailbox &
        {
            return Mailbox_;
        }

        [[nodiscard]] auto MailboxRef() const noexcept -> const Mailbox &
        {
            return Mailbox_;
        }

    private:
        auto Record(Mailbox::Result Result) noexcept -> void
        {
            switch (Result)
            {
            case Mailbox::Result::Accepted:
                Resources_.Stats.RecordAccepted();
                break;
            case Mailbox::Result::Full:
                Resources_.Stats.RecordFull();
                break;
            case Mailbox::Result::Closed:
                Resources_.Stats.RecordClosed();
                break;
            case Mailbox::Result::WorkerUnavailable:
                Resources_.Stats.RecordWorkerUnavailable();
                break;
            case Mailbox::Result::GenerationRejected:
                Resources_.Stats.RecordGenerationRejected();
                break;
            }
        }

        auto Notify() noexcept -> void
        {
            bool Expected = false;
            if (!DrainPosted_.compare_exchange_strong(Expected, true,
                                                      std::memory_order_acq_rel,
                                                      std::memory_order_acquire))
            {
                return;
            }
            try
            {
                Net::post(Resources_.Scheduler, [this] { DrainMailbox(); });
            }
            catch (...)
            {
                DrainPosted_.store(false, std::memory_order_release);
                Stop();
            }
        }

        auto DrainMailbox() noexcept -> void
        {
            Mailbox::Command CommandValue;
            while (Mailbox_.TryReceive(CommandValue))
            {
                if (!IsAccepting())
                {
                    CommandValue = {};
                    continue;
                }
                try
                {
                    if (CommandValue)
                    {
                        CommandValue();
                    }
                    Resources_.Stats.RecordExecuted();
                }
                catch (...)
                {
                    Resources_.Stats.RecordFailed();
                }
                CommandValue = {};
            }

            DrainPosted_.store(false, std::memory_order_release);
            if (Mailbox_.Size() != 0 && IsAccepting())
            {
                Notify();
            }
        }

        Preview::Resource::WorkerResources Resources_;
        Mailbox Mailbox_;
        std::atomic<bool> Accepting_{true};
        std::atomic<bool> Running_{true};
        std::atomic<bool> DrainPosted_{false};
    };

} // namespace Preview::Runtime
