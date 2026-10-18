/** @file QuicConnectionId.hpp @brief 中立 QUIC CID 值、哈希与相等规则。 */
#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
namespace Prism::Boundary
{
    using QuicConnectionId = std::vector<std::byte>;

    /** @brief 以二进制字节计算透明 QUIC CID 哈希。 */
    struct QuicConnectionIdHash final
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(const QuicConnectionId& Id) const noexcept -> std::size_t
        {
            return (*this)(std::span<const std::byte>(Id.data(), Id.size()));
        }

        [[nodiscard]] auto operator()(const std::span<const std::byte> Id) const noexcept
            -> std::size_t
        {
            std::size_t Hash = 2166136261U;
            for (const auto Byte : Id)
            {
                Hash = (Hash ^ std::to_integer<std::uint8_t>(Byte)) * 16777619U;
            }
            return Hash;
        }
    };

    /** @brief 对 vector CID 与借用 span 执行透明二进制相等比较。 */
    struct QuicConnectionIdEqual final
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(
            const QuicConnectionId& Left, const QuicConnectionId& Right) const noexcept -> bool
        {
            return Left.size() == Right.size() && std::equal(Left.begin(), Left.end(), Right.begin());
        }

        [[nodiscard]] auto operator()(
            const QuicConnectionId& Left, const std::span<const std::byte> Right) const noexcept -> bool
        {
            return Left.size() == Right.size() && std::equal(Left.begin(), Left.end(), Right.begin());
        }

        [[nodiscard]] auto operator()(
            const std::span<const std::byte> Left, const QuicConnectionId& Right) const noexcept -> bool
        {
            return Left.size() == Right.size() && std::equal(Left.begin(), Left.end(), Right.begin());
        }
    };
}
