/**
 * @file StreamResources.hpp
 * @brief Prism stream 资源句柄
 * @details StreamResources 以值语义保存 stream/session/worker 关联和
 *          executor/PMR 句柄，不拥有上级资源，也不创建独立 detached 机制。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Memory/Container.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <utility>

namespace Prism::Resource
{

    namespace Net = boost::asio;

    struct StreamResources final
    {
        struct Options final
        {
            Prism::ProcessId Process{};
            Prism::WorkerId Worker{};
            Prism::GenerationId Generation{};
            Prism::SessionId Session{};
            Prism::StreamId Id{};
            Prism::Memory::ResourcePointer MemoryResource{
                Prism::Memory::CurrentResource()};
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
                                                  : Prism::Memory::CurrentResource()),
              Executor(std::move(Value.Executor))
        {
        }

        Prism::ProcessId Process{};
        Prism::WorkerId Worker{};
        Prism::GenerationId Generation{};
        Prism::SessionId Session{};
        Prism::StreamId Id{};
        Prism::Memory::ResourcePointer MemoryResource{
            Prism::Memory::CurrentResource()};
        Net::any_io_executor Executor{};
    };

} // namespace Prism::Resource
