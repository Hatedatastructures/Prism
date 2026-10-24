/**
 * @file ChunkMask.hpp
 * @brief VMess 分块协议的 Nonce、选项与 SHAKE 掩码原语。
 */

#pragma once

#include <Prism/Protocols/Vmess/Types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace Prism::Vmess
{
    namespace detail
    {
        [[nodiscard]] auto HasOption(std::uint8_t Options, Option Value) noexcept -> bool;
    } // namespace detail

    /** @brief 与 Go sha3.Shake128 兼容的增量 XOF。 */
    class ShakeStream
    {
    public:
        explicit ShakeStream(std::span<const std::uint8_t> Seed);

        auto Take(std::span<std::uint8_t> Output) -> void;

    private:
        static constexpr std::size_t Rate = 168;
        static constexpr std::array<std::uint64_t, 24> RoundConstants{0x0000000000000001ULL,
            0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL,
            0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL,
            0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL, 0x8000000000008002ULL,
            0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

        [[nodiscard]] static constexpr auto Rotate(std::uint64_t Value, int Count) noexcept -> std::uint64_t
        {
            if (Count == 0)
            {
                return Value;
            }
            return (Value << Count) | (Value >> (64 - Count));
        }

        static auto Permute(std::array<std::uint64_t, 25>& State) noexcept -> void;

        std::array<std::uint64_t, 25> State_{};
        std::array<std::uint8_t, Rate> Buffer_{};
        std::size_t Cursor_{Rate};
    };
} // namespace Prism::Vmess
