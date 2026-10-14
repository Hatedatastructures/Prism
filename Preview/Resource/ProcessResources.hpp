/**
 * @file ProcessResources.hpp
 * @brief Preview 进程级资源句柄
 * @details Process 拥有稳定身份和控制数据面共用的有界块池。
 *          协议视图保活同一个池；不在每个连接中创建最大预算存储。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>

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

        ProcessResources() : ProcessResources(Options{}) {}

        explicit ProcessResources(Options Value)
            : Id(Value.Id),
              Generation(Value.Generation),
              MemoryResource(Value.MemoryResource),
              Bytes(std::make_shared<Preview::Memory::BytePool>())
        {
            if (!MemoryResource) MemoryResource = Preview::Memory::CurrentResource();
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
        /** @brief 控制 executor 上的 carrier/DNS/relay 共享总容量；租约保活真实存储。 */
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };

} // namespace Preview::Resource
