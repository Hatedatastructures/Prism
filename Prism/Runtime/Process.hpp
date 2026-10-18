/**
 * @file Process.hpp
 * @brief Prism 进程级唯一 owner
 * @details Process 以 unique_ptr 持有一个 WorkerGroup，WorkerGroup 再以
 *          unique_ptr 持有固定集合的 Worker。Process 析构先停止子级，资源
 *          释放顺序不依赖共享指针或 detached 协程。
 */

#pragma once

#include <Prism/Resource/ProcessResources.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/SessionTraceModel.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dns/Config.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <utility>
#include <vector>

namespace Prism::Runtime
{

    namespace Net = boost::asio;

    class Process final
    {
    public:
        struct Options final
        {
            Prism::ProcessId Id{};
            Prism::GenerationId Generation{};
            std::size_t WorkerCount{1};
            std::size_t MailboxCapacity{64};
            Prism::Network::Dns::Config Dns{};
            std::shared_ptr<GenerationPublication> Publication;
        };

        Process() : Process(Options{}) {}

        explicit Process(Options Value)
            : Resources_(Prism::Resource::ProcessResources::Options{
                  Value.Id, Value.Generation, Prism::Memory::CurrentResource()}),
              WorkerGroup_(std::make_unique<WorkerGroup>(WorkerGroup::Options{
                  Value.Id, Value.Generation, Value.WorkerCount, Value.MailboxCapacity,
                  Value.Dns, Value.Publication}))
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

        [[nodiscard]] auto Id() const noexcept -> Prism::ProcessId
        {
            return Resources_.Id;
        }

        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId
        {
            if (WorkerGroup_)
            {
                return WorkerGroup_->Generation();
            }
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

        [[nodiscard]] auto Resources() noexcept -> Prism::Resource::ProcessResources &
        {
            return Resources_;
        }

        [[nodiscard]] auto Resources() const noexcept
            -> const Prism::Resource::ProcessResources &
        {
            return Resources_;
        }

        /** @brief 同步停止 worker context；不声称执行 Drain，保留既有 fatal/最终关闭责任。 */
        auto Stop() noexcept -> void
        {
            (void)Resources_.BeginStop();
            if (WorkerGroup_)
            {
                WorkerGroup_->Stop();
            }
        }

        /**
         * @brief 保留 worker executor 调度，执行 root scope 的实际取消、Drain 与退休 fence。
         * @details 调用方继续持有 Process，直到 await 完成；成功后仍须由 Stop 停止 context，
         *          RuntimeState 随后 join 对应 worker threads。此协程不关闭 socket 或协议 owner，
         *          调用方先完成 listener/session/transport 的关闭与 Drain。
         * @return worker owner 全部排空返回成功；失败保留 Process/Worker/ContextOwner。
         */
        [[nodiscard]] auto ShutdownWorkers()
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

        [[nodiscard]] auto Snapshot() const -> std::vector<WorkerSnapshot>
        {
            return WorkerGroup_ ? WorkerGroup_->Snapshot() : std::vector<WorkerSnapshot>{};
        }

        /** @brief 按值查询当前 Process 的有界 Session 生命周期轨迹。 */
        [[nodiscard]] auto QuerySessionTrace(const SessionTraceQuery &QueryValue) const
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

    private:
        Prism::Resource::ProcessResources Resources_;
        std::unique_ptr<WorkerGroup> WorkerGroup_;
    };

} // namespace Prism::Runtime
