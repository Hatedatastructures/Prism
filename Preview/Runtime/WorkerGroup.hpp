/**
 * @file WorkerGroup.hpp
 * @brief Preview worker 集合及其唯一 worker owner
 * @details WorkerGroup 只由 Process 持有；每个 Worker 由 unique_ptr 独占，
 *          创建后集合大小固定。Dispatch 是无阻塞发布入口，Snapshot 只读
 *          原子状态和 worker-local task 统计。
 */

#pragma once

#include <Preview/Runtime/Worker.hpp>
#include <Preview/Net/Dns/Config.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace Preview::Runtime
{

    class WorkerGroup final
    {
    public:
        struct Options final
        {
            Preview::ProcessId Process{};
            Preview::GenerationId Generation{};
            std::size_t WorkerCount{1};
            std::size_t MailboxCapacity{64};
            Preview::Network::Dns::Config Dns{};
        };

        WorkerGroup() : WorkerGroup(Options{}) {}

        explicit WorkerGroup(Options Value)
            : Process_(Value.Process),
              Generation_(Value.Generation),
              Stopping_(false)
        {
            const auto Count = Value.WorkerCount == 0 ? 1 : Value.WorkerCount;
            Workers_.reserve(Count);
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                Workers_.push_back(std::make_unique<Worker>(Worker::Options{
                    Value.Process,
                    Preview::WorkerId{static_cast<std::uint64_t>(Index + 1)},
                    Value.Generation,
                    Value.MailboxCapacity,
                    Value.Dns}));
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

        [[nodiscard]] auto Process() const noexcept -> Preview::ProcessId
        {
            return Process_;
        }

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            return Generation_;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Workers_.size();
        }

        [[nodiscard]] auto Find(Preview::WorkerId Id) noexcept -> Worker *
        {
            if (!Id || Id.Value() == 0 || Id.Value() > Workers_.size())
            {
                return nullptr;
            }
            return Workers_[static_cast<std::size_t>(Id.Value() - 1)].get();
        }

        [[nodiscard]] auto Find(Preview::WorkerId Id) const noexcept -> const Worker *
        {
            if (!Id || Id.Value() == 0 || Id.Value() > Workers_.size())
            {
                return nullptr;
            }
            return Workers_[static_cast<std::size_t>(Id.Value() - 1)].get();
        }

        [[nodiscard]] auto Dispatch(Preview::WorkerId Id,
                                    Preview::GenerationId Generation,
                                    Mailbox::Command CommandValue) -> Mailbox::Result
        {
            auto *WorkerValue = Find(Id);
            if (!WorkerValue || Stopping_.load(std::memory_order_acquire))
            {
                return Mailbox::Result::WorkerUnavailable;
            }
            return WorkerValue->Dispatch(Generation, std::move(CommandValue));
        }

        [[nodiscard]] auto Dispatch(Preview::GenerationId Generation,
                                    Mailbox::Command CommandValue) -> Mailbox::Result
        {
            if (Stopping_.load(std::memory_order_acquire) || Workers_.empty())
            {
                return Mailbox::Result::WorkerUnavailable;
            }
            const auto Index = NextWorker_.fetch_add(1, std::memory_order_relaxed) % Workers_.size();
            return Workers_[Index]->Dispatch(Generation, std::move(CommandValue));
        }

        auto Stop() noexcept -> void
        {
            if (Stopping_.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            for (const auto &WorkerValue : Workers_)
            {
                if (WorkerValue)
                {
                    WorkerValue->Stop();
                }
            }
        }

        [[nodiscard]] auto IsStopping() const noexcept -> bool
        {
            return Stopping_.load(std::memory_order_acquire);
        }

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

    private:
        Preview::ProcessId Process_{};
        Preview::GenerationId Generation_{};
        std::vector<std::unique_ptr<Worker>> Workers_;
        std::atomic<std::size_t> NextWorker_{0};
        std::atomic<bool> Stopping_;
    };

} // namespace Preview::Runtime
