/**
 * @file SessionAdmissionTestSupport.hpp
 * @brief Runtime listener admission 用的最小已发布 generation fixture。
 */
#pragma once

#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>

#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace Prism::Testing::Runtime
{

    [[nodiscard]] inline auto MakeListenerTestBytePool()
        -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
    }

    class ListenerTestGeneration final : public Prism::Foundation::GenerationLifetime
    {
    public:
        explicit ListenerTestGeneration(const Prism::GenerationId Value) noexcept
            : Value_(Value)
        {
        }

        [[nodiscard]] auto Id() const noexcept -> Prism::GenerationId override
        {
            return Value_;
        }

    private:
        Prism::GenerationId Value_{};
    };

    [[nodiscard]] inline auto MakeListenerTestPublication(const Prism::GenerationId Id)
        -> std::shared_ptr<Prism::Runtime::GenerationPublication>
    {
        auto Publication = std::make_shared<Prism::Runtime::GenerationPublication>();
        auto Generation = std::make_shared<const ListenerTestGeneration>(Id);
        auto Prepared = Publication->Prepare(
            std::shared_ptr<const Prism::Foundation::GenerationLifetime>{},
            std::move(Generation),
            std::vector<Prism::AccountId>{});
        if (!Prepared || !Publication->Publish(*Prepared))
        {
            throw std::logic_error("listener test generation publication failed");
        }
        return Publication;
    }

} // namespace Prism::Testing::Runtime
