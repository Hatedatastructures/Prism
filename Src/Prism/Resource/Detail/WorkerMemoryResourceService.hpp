/**
 * @file WorkerMemoryResourceService.hpp
 * @brief 将 worker PMR 跟踪器绑定到其 execution_context 生命周期。
 */
#pragma once

#include <Prism/Foundation/Memory/TrackingResource.hpp>

#include <boost/asio/execution_context.hpp>

namespace Prism::Executor
{
    class ContextOwner;
}

namespace Prism::Resource
{
    namespace Net = boost::asio;

    /**
     * @brief 为 worker 的 PMR 跟踪器提供与 io_context 同步的生命周期。
     * @details ContextOwner 的内存池可由失败收尾中的异步 owner 继续保活；跟踪器因此也挂在同一个
     *          execution_context service registry 中，避免 WorkerResources 退休后悬空。
     */
    class WorkerMemoryResourceService final : public Net::execution_context::service
    {
    public:
        inline static Net::execution_context::id id;

        WorkerMemoryResourceService(Net::execution_context& Context,
            Prism::Memory::ResourcePointer Upstream);

        /** @brief 返回由本 execution_context 保活的 PMR 跟踪器。 */
        [[nodiscard]] auto Tracker() noexcept -> Prism::Memory::TrackingResource&
        {
            return Tracker_;
        }

        /** @brief 返回跟踪器的独立计数快照。 */
        [[nodiscard]] auto Snapshot() const noexcept -> Prism::Memory::MemoryAllocationSnapshot
        {
            return Tracker_.Snapshot();
        }

    private:
        friend struct WorkerResources;
        /** @brief 把 PMR 跟踪服务绑定到 ContextOwner 的执行上下文。 */
        [[nodiscard]] static auto Attach(Prism::Executor::ContextOwner& Owner)
            -> WorkerMemoryResourceService*;
        auto shutdown() -> void override;

        Prism::Memory::TrackingResource Tracker_;
    };
}
