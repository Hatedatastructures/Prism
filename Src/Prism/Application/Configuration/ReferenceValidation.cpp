/** @file ReferenceValidation.cpp @brief Prism 配置引用索引构造与查询实现。 */
#include <Prism/Application/Configuration/ReferenceValidation.hpp>

namespace Prism::Application::Configuration
{

    auto ReferenceGraph::Build(const PrismConfiguration &Configuration)
        -> ReferenceGraph
    {
        ReferenceGraph Graph;
        Graph.ProtocolIndices_.reserve(Configuration.Protocols.size());
        for (std::size_t Index = 0; Index < Configuration.Protocols.size(); ++Index)
        {
            Graph.ProtocolIndices_.emplace(Configuration.Protocols[Index].Id, Index);
        }
        Graph.CarrierIndices_.reserve(Configuration.Carriers.size());
        for (std::size_t Index = 0; Index < Configuration.Carriers.size(); ++Index)
        {
            Graph.CarrierIndices_.emplace(Configuration.Carriers[Index].Id, Index);
        }
        return Graph;
    }

    auto ReferenceGraph::FindProtocolIndex(const std::string_view Id) const noexcept
        -> std::optional<std::size_t>
    {
        const auto Iterator = ProtocolIndices_.find(Id);
        return Iterator == ProtocolIndices_.end()
                   ? std::nullopt
                   : std::optional<std::size_t>{Iterator->second};
    }

    auto ReferenceGraph::FindCarrierIndex(const std::string_view Id) const noexcept
        -> std::optional<std::size_t>
    {
        const auto Iterator = CarrierIndices_.find(Id);
        return Iterator == CarrierIndices_.end()
                   ? std::nullopt
                   : std::optional<std::size_t>{Iterator->second};
    }

} // namespace Prism::Application::Configuration
