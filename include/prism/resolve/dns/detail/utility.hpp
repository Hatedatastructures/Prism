/**
 * @file utility.hpp
 * @brief DNS 解析器工具函数
 * @details 提供 DNS 解析器模块使用的零分配工具函数，
 * 避免 string_view 转整数时的中间堆分配。
 * 所有函数均为 inline header-only 实现。
 */
#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>

namespace psm::resolve::dns::detail
{
    /**
     * @brief 从 string_view 解析端口号
     * @details 使用 std::from_chars 零分配解析，支持 0-65535 范围。
     * 先检查长度是否在 1-5 之间，再进行数值转换和范围校验。
     * @param port_str 端口字符串视图
     * @return 解析成功的端口号，失败返回 nullopt
     */
    [[nodiscard]] inline auto parse_port(const std::string_view port_str) noexcept
        -> std::optional<std::uint16_t>
    {
        if (port_str.empty() || port_str.size() > 5)
        {
            return std::nullopt;
        }

        std::uint32_t value = 0;
        const auto result = std::from_chars(
            port_str.data(), port_str.data() + port_str.size(), value);

        if (result.ec != std::errc{} || value > 65535)
        {
            return std::nullopt;
        }

        return static_cast<std::uint16_t>(value);
    }
} // namespace psm::resolve::dns::detail
