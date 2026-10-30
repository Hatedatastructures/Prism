/**
 * @file WorkerResources.hpp
 * @brief Prism worker 的执行上下文与通用资源所有者。
 * @details Runtime Worker 负责执行器调度和网络服务；本 owner 只保活执行上下文、
 *          PMR/字节池与任务注册表等通用资源。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/TrackingResource.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Resource/ResourceMemorySnapshot.hpp>

#include <memory>
#include <memory_resource>

namespace Prism::Executor
{
    class ContextOwner;
}

namespace Prism::Resource
{
    class WorkerMemoryResourceService;

    struct WorkerResources final
    {
        struct Options final
        {
            Prism::ProcessId Process{};
            Prism::WorkerId Id{};
            Prism::GenerationId Generation{};
            Prism::Memory::BytePoolOptions Bytes{}; ///< 冷路径创建的有界可增长字节池。
        };

        WorkerResources();
        explicit WorkerResources(Options Value);
        ~WorkerResources() noexcept;

        WorkerResources(const WorkerResources&) = delete;
        auto operator=(const WorkerResources&) -> WorkerResources& = delete;
        WorkerResources(WorkerResources&&) = delete;
        auto operator=(WorkerResources&&) -> WorkerResources& = delete;

        /** @brief 在冷快照边界返回 worker owner 的 PMR 请求与字节池租约值快照。 */
        [[nodiscard]] auto MemorySnapshot() const noexcept -> ResourceMemorySnapshot;

        Prism::ProcessId Process{};
        Prism::WorkerId Id{};
        Prism::GenerationId Generation{};
        std::shared_ptr<Prism::Executor::ContextOwner> Execution;

    private:
        Prism::Resource::WorkerMemoryResourceService* AllocationMetrics{nullptr};

    public:
        Prism::Memory::ResourcePointer MemoryResource{nullptr};
        std::shared_ptr<Prism::Memory::BytePool> Bytes; ///< 唯一 worker 块池 owner；按请求增长并受上限约束。
        /** @brief 由 Runtime::Worker 在建立 scheduler 后转移的 root task registry。 */
        std::unique_ptr<Prism::Lifecycle::TaskRegistry> Tasks;

    private:
        /** @brief 将计数器服务注册到执行上下文，生命周期覆盖 PMR 资源指针。 */
        [[nodiscard]] static auto AttachMemoryMetrics(
            const std::shared_ptr<Prism::Executor::ContextOwner>& Owner)
            -> Prism::Resource::WorkerMemoryResourceService*;
    };

} // namespace Prism::Resource
