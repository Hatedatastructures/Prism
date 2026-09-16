/**
 * @file SessionResources.hpp
 * @brief Preview session 资源句柄
 * @details SessionResources 不拥有 process/worker。它只携带稳定 typed ID、
 *          worker executor 和 PMR 非拥有句柄，供后续 Session owner 显式持有。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Memory/Container.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <utility>

namespace Preview::Resource
{

    namespace Net = boost::asio;

    struct SessionResources final
    {
        struct Options final
        {
            Preview::ProcessId Process{};
            Preview::WorkerId Worker{};
            Preview::GenerationId Generation{};
            Preview::SessionId Id{};
            Preview::Memory::ResourcePointer MemoryResource{
                Preview::Memory::CurrentResource()};
            Net::any_io_executor Executor{};
        };

        SessionResources() noexcept : SessionResources(Options{}) {}

        explicit SessionResources(Options Value) noexcept
            : Process(Value.Process),
              Worker(Value.Worker),
              Generation(Value.Generation),
              Id(Value.Id),
              MemoryResource(Value.MemoryResource ? Value.MemoryResource
                                                  : Preview::Memory::CurrentResource()),
              Executor(std::move(Value.Executor))
        {
        }

        Preview::ProcessId Process{};
        Preview::WorkerId Worker{};
        Preview::GenerationId Generation{};
        Preview::SessionId Id{};
        Preview::Memory::ResourcePointer MemoryResource{
            Preview::Memory::CurrentResource()};
        Net::any_io_executor Executor{};
    };

} // namespace Preview::Resource
