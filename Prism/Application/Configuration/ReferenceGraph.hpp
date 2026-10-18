/**
 * @file ReferenceGraph.hpp
 * @brief Prism 配置一次校验生命周期内的协议和承载引用索引。
 * @details 索引只借用配置数组中的 ID 字符串，保存稳定数组索引；不拥有配置、
 *          SecretRef、Composition snapshot 或运行时服务。
 */
#pragma once

#include <Prism/Application/Configuration/PrismConfiguration.hpp>

#include <cstddef>
#include <optional>
#include <string_view>
#include <unordered_map>

namespace Prism::Application::Configuration
{

    class ReferenceGraph final
    {
    public:
        [[nodiscard]] static inline auto Build(const PrismConfiguration &Configuration)
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

        [[nodiscard]] inline auto FindProtocolIndex(const std::string_view Id) const noexcept
            -> std::optional<std::size_t>
        {
            const auto Iterator = ProtocolIndices_.find(Id);
            return Iterator == ProtocolIndices_.end()
                       ? std::nullopt
                       : std::optional<std::size_t>{Iterator->second};
        }

        [[nodiscard]] inline auto FindCarrierIndex(const std::string_view Id) const noexcept
            -> std::optional<std::size_t>
        {
            const auto Iterator = CarrierIndices_.find(Id);
            return Iterator == CarrierIndices_.end()
                       ? std::nullopt
                       : std::optional<std::size_t>{Iterator->second};
        }

    private:
        ReferenceGraph() = default;

        std::unordered_map<std::string_view, std::size_t> ProtocolIndices_;
        std::unordered_map<std::string_view, std::size_t> CarrierIndices_;
    };

} // namespace Prism::Application::Configuration
