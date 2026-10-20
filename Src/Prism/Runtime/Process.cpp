/** @file Process.cpp @brief 进程所有者构造与工作线程生命周期实现。 */
#include <Prism/Runtime/Process.hpp>

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>

#include <boost/asio/this_coro.hpp>

#include <memory>
#include <utility>

namespace Prism::Runtime
{
    Process::Process() : Process(Options{})
    {
    }

    Process::Process(Options Value)
        : Resources_(Prism::Resource::ProcessResources::Options{
              Value.Id, Value.Generation, Prism::Memory::CurrentResource()}),
          WorkerGroup_(std::make_unique<WorkerGroup>(WorkerGroup::Options{
              Value.Id, Value.Generation, Value.WorkerCount, Value.MailboxCapacity,
              Value.Dns, Value.Publication}))
    {
    }

    Process::~Process() noexcept
    {
        Stop();
    }

    auto Process::Generation() const noexcept -> Prism::GenerationId
    {
        if (WorkerGroup_)
        {
            return WorkerGroup_->Generation();
        }
        return Resources_.Generation;
    }

    auto Process::Workers() noexcept -> WorkerGroup&
    {
        return *WorkerGroup_;
    }

    auto Process::Workers() const noexcept -> const WorkerGroup&
    {
        return *WorkerGroup_;
    }

    auto Process::Stop() noexcept -> void
    {
        (void)Resources_.BeginStop();
        if (WorkerGroup_)
        {
            WorkerGroup_->Stop();
        }
    }

    auto Process::ShutdownWorkers()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        (void)Resources_.BeginStop();
        if (!WorkerGroup_)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return co_await WorkerGroup_->Shutdown();
    }

    auto Process::Snapshot() const -> std::vector<WorkerSnapshot>
    {
        return WorkerGroup_ ? WorkerGroup_->Snapshot() : std::vector<WorkerSnapshot>{};
    }

    auto Process::QuerySessionTrace(const SessionTraceQuery& QueryValue) const
        -> SessionTraceSnapshot
    {
        if (WorkerGroup_)
        {
            return WorkerGroup_->QuerySessionTrace(QueryValue);
        }
        SessionTraceSnapshot Result;
        Result.Process = Resources_.Id;
        return Result;
    }
}
