/**
 * @file ParserSupport.hpp
 * @brief HTTP/1.1 请求转发使用的私有解析辅助声明。
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Http11::detail
{
    [[nodiscard]] auto Iequals(std::string_view Left, std::string_view Right) noexcept -> bool;
    [[nodiscard]] auto AbsoluteAuthority(std::string_view Target) noexcept
        -> std::optional<std::pair<std::string_view, std::uint16_t>>;
    [[nodiscard]] auto OriginForm(std::string_view Target) -> std::optional<std::string>;
} // namespace Prism::Http11::detail
