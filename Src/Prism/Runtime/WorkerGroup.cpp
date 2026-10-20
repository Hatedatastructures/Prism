/** @file WorkerGroup.cpp @brief worker 集合调度与统一排空实现。 */
#include <Prism/Runtime/WorkerGroup.hpp>

#include <Prism/Foundation/Executor/ContextOwner.hpp>

#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <iterator>
#include <memory>
#include <utility>

namespace Prism::Runtime
{
    WorkerGroup::WorkerGroup() : WorkerGroup(Options{})
    {
    }

    WorkerGroup::WorkerGroup(Options Value)
        : Process_(Value.Process), Generation_(Value.Generation),
          Publication_(std::move(Value.Publication)), Stopping_(false)
    {
        auto Count = Value.WorkerCount;
        if (Count == 0) Count = 1;
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

    WorkerGroup::~WorkerGroup() noexcept
    {
        Stop();
    }

    auto WorkerGroup::Process() const noexcept -> Prism::ProcessId
    {
        return Process_;
    }

    auto WorkerGroup::Generation() const noexcept -> Prism::GenerationId
    {
        if (Publication_)
        {
            const auto Current = Publication_->Current();
            if (Current) return Current->Id();
        }
        return Generation_;
    }

    auto WorkerGroup::PrepareGeneration(const Prism::GenerationId Base,
        Prism::Foundation::GenerationPin Candidate)
        -> Net::awaitable<std::expected<std::vector<GenerationPrepareAck>, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (Workers_.empty() || !Candidate || Candidate->Id() <= Base || Generation() != Base)
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});

        std::vector<GenerationPrepareAck> Acknowledgements;
        Acknowledgements.reserve(Workers_.size());
        for (const auto &WorkerValue : Workers_)
        {
            if (!WorkerValue)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            auto Ack = co_await WorkerValue->PrepareGeneration(Base, Candidate);
            if (Ack.Status != GenerationPrepareStatus::Prepared)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            Acknowledgements.push_back(std::move(Ack));
        }
        co_return Acknowledgements;
    }

    auto WorkerGroup::Size() const noexcept -> std::size_t
    {
        return Workers_.size();
    }

    auto WorkerGroup::Find(const Prism::WorkerId Id) noexcept -> Worker *
    {
        if (!Id || Id.Value() == 0 || Id.Value() > Workers_.size()) return nullptr;
        return Workers_[static_cast<std::size_t>(Id.Value() - 1)].get();
    }

    auto WorkerGroup::Find(const Prism::WorkerId Id) const noexcept -> const Worker *
    {
        if (!Id || Id.Value() == 0 || Id.Value() > Workers_.size()) return nullptr;
        return Workers_[static_cast<std::size_t>(Id.Value() - 1)].get();
    }

    auto WorkerGroup::Dispatch(const Prism::WorkerId Id,
        const Prism::GenerationId Generation, WorkerDispatchCommand CommandValue)
        -> WorkerDispatchResult
    {
        auto *WorkerValue = Find(Id);
        if (!WorkerValue || Stopping_.load(std::memory_order_acquire))
            return WorkerDispatchResult::WorkerUnavailable;
        return WorkerValue->Dispatch(Generation, std::move(CommandValue));
    }

    auto WorkerGroup::Dispatch(const Prism::GenerationId Generation,
        WorkerDispatchCommand CommandValue) -> WorkerDispatchResult
    {
        if (Stopping_.load(std::memory_order_acquire) || Workers_.empty())
            return WorkerDispatchResult::WorkerUnavailable;
        const auto Index = NextWorker_.fetch_add(1, std::memory_order_relaxed) % Workers_.size();
        return Workers_[Index]->Dispatch(Generation, std::move(CommandValue));
    }

    auto WorkerGroup::DrainWorker(const Prism::WorkerId Id,
        const Prism::GenerationId Generation)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (Stopping_.load(std::memory_order_acquire))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        auto *WorkerValue = Find(Id);
        auto Retained = Generation == Generation_;
        if (Publication_) Retained = Publication_->Contains(Generation);
        if (!WorkerValue || !Retained)
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        WorkerValue->CloseAdmission();
        co_return co_await WorkerValue->Shutdown();
    }

    auto WorkerGroup::Shutdown()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        Stopping_.store(true, std::memory_order_release);
        for (const auto &WorkerValue : Workers_)
            if (WorkerValue) WorkerValue->CloseAdmission();
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
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto WorkerGroup::Stop() noexcept -> void
    {
        Stopping_.store(true, std::memory_order_release);
        for (const auto &WorkerValue : Workers_)
            if (WorkerValue) WorkerValue->Stop();
    }

    auto WorkerGroup::IsStopping() const noexcept -> bool
    {
        return Stopping_.load(std::memory_order_acquire);
    }

    auto WorkerGroup::Snapshot() const -> std::vector<WorkerSnapshot>
    {
        std::vector<WorkerSnapshot> Result;
        Result.reserve(Workers_.size());
        for (const auto &WorkerValue : Workers_)
            if (WorkerValue) Result.push_back(WorkerValue->Snapshot());
        return Result;
    }

    auto WorkerGroup::QuerySessionTrace(const SessionTraceQuery &QueryValue) const
        -> SessionTraceSnapshot
    {
        SessionTraceSnapshot Result;
        Result.Process = Process_;
        if (QueryValue.Process && QueryValue.Process != Process_) return Result;
        for (const auto &WorkerValue : Workers_)
        {
            if (!WorkerValue) continue;
            auto Local = WorkerValue->TraceRing()->Query(QueryValue);
            Result.HasMore = Result.HasMore || Local.HasMore;
            Result.Records.insert(Result.Records.end(),
                std::make_move_iterator(Local.Records.begin()),
                std::make_move_iterator(Local.Records.end()));
            Result.Cursors.insert(Result.Cursors.end(), Local.Cursors.begin(), Local.Cursors.end());
            Result.Loss.insert(Result.Loss.end(), Local.Loss.begin(), Local.Loss.end());
        }
        std::sort(Result.Records.begin(), Result.Records.end(), SessionTraceRecordLess);
        return Result;
    }

    auto WorkerGroup::SessionTraceRecordLess(const SessionTraceRecord &Left,
        const SessionTraceRecord &Right) -> bool
    {
        if (Left.UtcUnixNanoseconds != Right.UtcUnixNanoseconds)
            return Left.UtcUnixNanoseconds < Right.UtcUnixNanoseconds;
        if (Left.Identity.Worker != Right.Identity.Worker)
            return Left.Identity.Worker < Right.Identity.Worker;
        return Left.Sequence < Right.Sequence;
    }
}
