/**
 * @file SessionResources.hpp
 * @brief Prism session 资源句柄
 * @details SessionResources 不拥有 process/worker。它只携带稳定 typed ID、
 *          worker executor 和 PMR 非拥有句柄，供后续 Session owner 显式持有。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Memory/Container.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <utility>

namespace Prism::Resource
{

    namespace Net = boost::asio;

    struct SessionResources final
    {
        struct Options final
        {
            Prism::ProcessId Process{};
            Prism::WorkerId Worker{};
            Prism::GenerationId Generation{};
            Prism::SessionId Id{};
            Prism::Memory::ResourcePointer MemoryResource{Prism::Memory::CurrentResource()};
            Net::any_io_executor Executor{};
        };

        SessionResources() noexcept : SessionResources(Options{})
        {
        }

        explicit SessionResources(Options Value) noexcept
            : Process(Value.Process), Worker(Value.Worker), Generation(Value.Generation), Id(Value.Id),
              MemoryResource(
                  Value.MemoryResource ? Value.MemoryResource : Prism::Memory::CurrentResource()),
              Executor(std::move(Value.Executor))
        {
        }

        Prism::ProcessId Process{};
        Prism::WorkerId Worker{};
        Prism::GenerationId Generation{};
        Prism::SessionId Id{};
        Prism::Memory::ResourcePointer MemoryResource{Prism::Memory::CurrentResource()};
        Net::any_io_executor Executor{};
    };

} // namespace Prism::Resource
