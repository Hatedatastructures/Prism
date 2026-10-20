/**
 * @file Encoder.hpp
 * @brief QPACK 头块编码接口。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace Prism::Http3::Qpack
{
    /** @brief 写入静态 QPACK 头块前缀；缓冲不足时返回零。 */
    [[nodiscard]] auto EncodePrefix(std::span<std::uint8_t> Output) -> std::size_t;

    /** @brief 编码一个头字段；缓冲不足或字段无法表示时返回零。 */
    [[nodiscard]] auto EncodeLiteral(
        std::string_view Name,
        std::string_view Value,
        std::span<std::uint8_t> Output) -> std::size_t;
}
