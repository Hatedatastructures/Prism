/**
 * @file ProcessResources.hpp
 * @brief Prism 进程级资源句柄
 * @details Process 拥有稳定身份和控制数据面共用的有界块池。
 *          协议视图保活同一个池；不在每个连接中创建最大预算存储。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Memory/TrackingResource.hpp>
#include <Prism/Resource/ResourceMemorySnapshot.hpp>

#include <atomic>
#include <memory>

namespace Prism::Resource
{

    struct ProcessResources final
    {
        struct Options final
        {
            Prism::ProcessId Id{};
            Prism::GenerationId Generation{};
            Prism::Memory::ResourcePointer MemoryResource{
                Prism::Memory::CurrentResource()};
        };

        ProcessResources();
        explicit ProcessResources(Options Value);

        ProcessResources(const ProcessResources &) = delete;
        auto operator=(const ProcessResources &) -> ProcessResources & = delete;
        ProcessResources(ProcessResources &&) = delete;
        auto operator=(ProcessResources &&) -> ProcessResources & = delete;

        [[nodiscard]] auto BeginStop() noexcept -> bool;

        [[nodiscard]] auto IsStopping() const noexcept -> bool;

        /** @brief 在冷快照边界返回进程 owner 的 PMR 请求与字节池租约值快照。 */
        [[nodiscard]] auto MemorySnapshot() const noexcept -> ResourceMemorySnapshot;

        Prism::ProcessId Id{};
        Prism::GenerationId Generation{};
        Prism::Memory::TrackingResource AllocationMetrics;
        Prism::Memory::ResourcePointer MemoryResource{
            &AllocationMetrics};
        std::atomic<bool> Stopping{false};
        /** @brief 控制 executor 上的 carrier/DNS/relay 共享总容量；租约保活真实存储。 */
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

} // namespace Prism::Resource
