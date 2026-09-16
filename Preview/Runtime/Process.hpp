/**
 * @file Process.hpp
 * @brief Preview 进程级唯一 owner
 * @details Process 以 unique_ptr 持有一个 WorkerGroup，WorkerGroup 再以
 *          unique_ptr 持有固定集合的 Worker。Process 析构先停止子级，资源
 *          释放顺序不依赖共享指针或 detached 协程。
 */

#pragma once

#include <Preview/Resource/ProcessResources.hpp>
#include <Preview/Runtime/WorkerGroup.hpp>
#include <Preview/Net/Dns/Config.hpp>

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

namespace Preview::Runtime
{

    class Process final
    {
    public:
        struct Options final
        {
            Preview::ProcessId Id{};
            Preview::GenerationId Generation{};
            std::size_t WorkerCount{1};
            std::size_t MailboxCapacity{64};
            Preview::Network::Dns::Config Dns{};
        };

        Process() : Process(Options{}) {}

        explicit Process(Options Value)
            : Resources_(Preview::Resource::ProcessResources::Options{
                  Value.Id, Value.Generation, Preview::Memory::CurrentResource()}),
              WorkerGroup_(std::make_unique<WorkerGroup>(WorkerGroup::Options{
                  Value.Id, Value.Generation, Value.WorkerCount, Value.MailboxCapacity,
                  Value.Dns}))
        {
        }

        ~Process() noexcept
        {
            Stop();
        }

        Process(const Process &) = delete;
        auto operator=(const Process &) -> Process & = delete;
        Process(Process &&) = delete;
        auto operator=(Process &&) -> Process & = delete;

        [[nodiscard]] auto Id() const noexcept -> Preview::ProcessId
        {
            return Resources_.Id;
        }

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            return Resources_.Generation;
        }

        [[nodiscard]] auto IsRunning() const noexcept -> bool
        {
            return !Resources_.IsStopping();
        }

        [[nodiscard]] auto Workers() noexcept -> WorkerGroup &
        {
            return *WorkerGroup_;
        }

        [[nodiscard]] auto Workers() const noexcept -> const WorkerGroup &
        {
            return *WorkerGroup_;
        }

        [[nodiscard]] auto Resources() noexcept -> Preview::Resource::ProcessResources &
        {
            return Resources_;
        }

        [[nodiscard]] auto Resources() const noexcept
            -> const Preview::Resource::ProcessResources &
        {
            return Resources_;
        }

        auto Stop() noexcept -> void
        {
            if (!Resources_.BeginStop())
            {
                return;
            }
            if (WorkerGroup_)
            {
                WorkerGroup_->Stop();
            }
        }

        [[nodiscard]] auto Snapshot() const -> std::vector<WorkerSnapshot>
        {
            return WorkerGroup_ ? WorkerGroup_->Snapshot() : std::vector<WorkerSnapshot>{};
        }

    private:
        Preview::Resource::ProcessResources Resources_;
        std::unique_ptr<WorkerGroup> WorkerGroup_;
    };

} // namespace Preview::Runtime
