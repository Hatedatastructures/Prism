/**
 * @file SessionAdmissionTestSupport.hpp
 * @brief Runtime listener admission 用的最小已发布 generation fixture。
 */
#pragma once

#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>

#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace Preview::Testing::Runtime
{

    class ListenerTestGeneration final : public Preview::Foundation::GenerationLifetime
    {
    public:
        explicit ListenerTestGeneration(const Preview::GenerationId Value) noexcept
            : Value_(Value)
        {
        }

        [[nodiscard]] auto Id() const noexcept -> Preview::GenerationId override
        {
            return Value_;
        }

    private:
        Preview::GenerationId Value_{};
    };

    [[nodiscard]] inline auto MakeListenerTestPublication(const Preview::GenerationId Id)
        -> std::shared_ptr<Preview::Runtime::GenerationPublication>
    {
        auto Publication = std::make_shared<Preview::Runtime::GenerationPublication>();
        auto Generation = std::make_shared<const ListenerTestGeneration>(Id);
        auto Prepared = Publication->Prepare(
            std::shared_ptr<const Preview::Foundation::GenerationLifetime>{},
            std::move(Generation),
            std::vector<Preview::AccountId>{});
        if (!Prepared || !Publication->Publish(*Prepared))
        {
            throw std::logic_error("listener test generation publication failed");
        }
        return Publication;
    }

} // namespace Preview::Testing::Runtime
