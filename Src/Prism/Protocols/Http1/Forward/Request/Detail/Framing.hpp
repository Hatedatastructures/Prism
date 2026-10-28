/**
 * @file Framing.hpp
 * @brief HTTP/1.1 首请求 framing 的无状态校验工具。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>

namespace Prism::Http11::Detail
{
    [[nodiscard]] auto IsTokenChar(char Character) noexcept -> bool;

    [[nodiscard]] auto IsFieldValueChar(char Character) noexcept -> bool;

    [[nodiscard]] auto IsChunkExtension(std::string_view Value) noexcept -> bool;

    [[nodiscard]] auto IsValidTrailer(std::string_view Line) noexcept -> bool;

    /** @brief 解析完整 chunk-size 行并验证其扩展字段。 */
    [[nodiscard]] auto ParseChunkSize(
        std::span<const std::byte> Line,
        std::uint64_t &Size) noexcept -> bool;

    [[nodiscard]] auto ToBodyEndFailure(Prism::Fault::Failure Failure)
        -> Prism::Fault::Failure;

    [[nodiscard]] auto ParseUpgradeStatus(std::string_view Header) noexcept
        -> std::optional<int>;

    enum class ChunkState : std::uint8_t
    {
        SizeLine,
        Data,
        DataCrlf,
        Trailer,
        Done,
    };
} // namespace Prism::Http11::Detail
