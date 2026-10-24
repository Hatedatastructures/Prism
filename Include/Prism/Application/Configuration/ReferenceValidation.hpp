/**
 * @file ReferenceValidation.hpp
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
        [[nodiscard]] static auto Build(const PrismConfiguration &Configuration) -> ReferenceGraph;

        [[nodiscard]] auto FindProtocolIndex(const std::string_view Id) const noexcept
            -> std::optional<std::size_t>;

        [[nodiscard]] auto FindCarrierIndex(const std::string_view Id) const noexcept
            -> std::optional<std::size_t>;

    private:
        ReferenceGraph() = default;

        std::unordered_map<std::string_view, std::size_t> ProtocolIndices_;
        std::unordered_map<std::string_view, std::size_t> CarrierIndices_;
    };

} // namespace Prism::Application::Configuration
