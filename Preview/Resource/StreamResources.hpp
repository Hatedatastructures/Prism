/**
 * @file StreamResources.hpp
 * @brief Preview stream 资源句柄
 * @details StreamResources 以值语义保存 stream/session/worker 关联和
 *          executor/PMR 句柄，不拥有上级资源，也不创建独立 detached 机制。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Memory/Container.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <utility>

namespace Preview::Resource
{

    namespace Net = boost::asio;

    struct StreamResources final
    {
        struct Options final
        {
            Preview::ProcessId Process{};
            Preview::WorkerId Worker{};
            Preview::GenerationId Generation{};
            Preview::SessionId Session{};
            Preview::StreamId Id{};
            Preview::Memory::ResourcePointer MemoryResource{
                Preview::Memory::CurrentResource()};
            Net::any_io_executor Executor{};
        };

        StreamResources() noexcept : StreamResources(Options{}) {}

        explicit StreamResources(Options Value) noexcept
            : Process(Value.Process),
              Worker(Value.Worker),
              Generation(Value.Generation),
              Session(Value.Session),
              Id(Value.Id),
              MemoryResource(Value.MemoryResource ? Value.MemoryResource
                                                  : Preview::Memory::CurrentResource()),
              Executor(std::move(Value.Executor))
        {
        }

        Preview::ProcessId Process{};
        Preview::WorkerId Worker{};
        Preview::GenerationId Generation{};
        Preview::SessionId Session{};
        Preview::StreamId Id{};
        Preview::Memory::ResourcePointer MemoryResource{
            Preview::Memory::CurrentResource()};
        Net::any_io_executor Executor{};
    };

} // namespace Preview::Resource
