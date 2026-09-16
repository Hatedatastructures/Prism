/**
 * @file ProcessResources.hpp
 * @brief Preview 进程级资源句柄
 * @details 进程资源只保存稳定身份、代际和非拥有内存句柄。真正的
 *          Process owner 持有本类型，子级资源通过值复制身份，避免
 *          在资源层引入共享 owner 或隐式 psm 依赖。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Memory/Container.hpp>

#include <atomic>

namespace Preview::Resource
{

    struct ProcessResources final
    {
        struct Options final
        {
            Preview::ProcessId Id{};
            Preview::GenerationId Generation{};
            Preview::Memory::ResourcePointer MemoryResource{
                Preview::Memory::CurrentResource()};
        };

        ProcessResources() noexcept : ProcessResources(Options{}) {}

        explicit ProcessResources(Options Value) noexcept
            : Id(Value.Id),
              Generation(Value.Generation),
              MemoryResource(Value.MemoryResource ? Value.MemoryResource
                                                   : Preview::Memory::CurrentResource())
        {
        }

        ProcessResources(const ProcessResources &) = delete;
        auto operator=(const ProcessResources &) -> ProcessResources & = delete;
        ProcessResources(ProcessResources &&) = delete;
        auto operator=(ProcessResources &&) -> ProcessResources & = delete;

        [[nodiscard]] auto BeginStop() noexcept -> bool
        {
            return Stopping.exchange(true, std::memory_order_acq_rel) == false;
        }

        [[nodiscard]] auto IsStopping() const noexcept -> bool
        {
            return Stopping.load(std::memory_order_acquire);
        }

        Preview::ProcessId Id{};
        Preview::GenerationId Generation{};
        Preview::Memory::ResourcePointer MemoryResource{
            Preview::Memory::CurrentResource()};
        std::atomic<bool> Stopping{false};
    };

} // namespace Preview::Resource
