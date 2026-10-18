/**
 * @file ConfigurationAssembly.hpp
 * @brief 配置到运行时基础值的纯装配 helper。
 */
#pragma once

#include <Prism/Application/Assembly/DnsAssembly.hpp>
#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <Prism/Net/Dns/Config.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <string_view>

namespace Prism::Application::Assembly
{

    [[nodiscard]] inline auto ParseTargetPort(const std::string_view PortText)
        -> std::optional<std::uint16_t>
    {
        std::uint32_t Port = 0;
        const auto [End, Error] = std::from_chars(
            PortText.data(), PortText.data() + PortText.size(), Port);
        if (Error != std::errc{} || End != PortText.data() + PortText.size() ||
            Port == 0U || Port > 65535U)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

} // namespace Prism::Application::Assembly
