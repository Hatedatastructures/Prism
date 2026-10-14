/**
 * @file ChunkMask.hpp
 * @brief VMess 分块协议的 Nonce、选项与 SHAKE 掩码原语。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include <Preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{
    namespace detail
    {
        inline auto IncNonce(std::span<std::uint8_t, 12> Nonce) -> void
        {
            for (std::size_t I = Nonce.size(); I > 0; --I)
            {
                if (++Nonce[I - 1] != 0)
                {
                    break;
                }
            }
        }

        [[nodiscard]] inline auto HasOption(std::uint8_t Options, Option Value) noexcept -> bool
        {
            return (Options & static_cast<std::uint8_t>(Value)) != 0;
        }

        [[nodiscard]] inline auto MakeNonce(std::uint16_t Count,
                                            std::span<const std::uint8_t, 16> Seed)
            -> std::array<std::uint8_t, 12>
        {
            std::array<std::uint8_t, 12> Nonce{};
            Nonce[0] = static_cast<std::uint8_t>(Count >> 8);
            Nonce[1] = static_cast<std::uint8_t>(Count & 0xFF);
            std::memcpy(Nonce.data() + 2, Seed.data() + 2, 10);
            return Nonce;
        }
    } // namespace detail

    /** @brief 与 Go sha3.Shake128 兼容的增量 XOF。 */
    class ShakeStream
    {
    public:
        explicit ShakeStream(std::span<const std::uint8_t> Seed)
        {
            std::size_t Offset = 0;
            auto *Block = reinterpret_cast<std::uint8_t *>(State_.data());
            while (Seed.size() - Offset >= Rate)
            {
                for (std::size_t Index = 0; Index < Rate; ++Index)
                {
                    Block[Index] ^= Seed[Offset + Index];
                }
                Permute(State_);
                Offset += Rate;
            }
            const auto Remaining = Seed.size() - Offset;
            for (std::size_t Index = 0; Index < Remaining; ++Index)
            {
                Block[Index] ^= Seed[Offset + Index];
            }
            Block[Remaining] ^= 0x1F;
            Block[Rate - 1] ^= 0x80;
            Permute(State_);
        }

        auto Take(std::span<std::uint8_t> Output) -> void
        {
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                if (Cursor_ == Rate)
                {
                    std::memcpy(Buffer_.data(), State_.data(), Rate);
                    Permute(State_);
                    Cursor_ = 0;
                }
                const auto Count = (std::min)(Rate - Cursor_, Output.size() - Offset);
                std::memcpy(Output.data() + Offset, Buffer_.data() + Cursor_, Count);
                Cursor_ += Count;
                Offset += Count;
            }
        }

    private:
        static constexpr std::size_t Rate = 168;
        static constexpr std::array<std::uint64_t, 24> RoundConstants{
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x0000000080008008ULL};

        [[nodiscard]] static constexpr auto Rotate(std::uint64_t Value, int Count) noexcept
            -> std::uint64_t
        {
            if (Count == 0)
            {
                return Value;
            }
            return (Value << Count) | (Value >> (64 - Count));
        }

        static auto Permute(std::array<std::uint64_t, 25> &State) noexcept -> void
        {
            static constexpr std::array<int, 24> Piln{
                10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
            static constexpr std::array<int, 24> Rotc{
                1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
            for (const auto RoundConstant : RoundConstants)
            {
                std::array<std::uint64_t, 5> Column{};
                for (std::size_t Index = 0; Index < 5; ++Index)
                {
                    Column[Index] = State[Index] ^ State[Index + 5] ^ State[Index + 10] ^
                                    State[Index + 15] ^ State[Index + 20];
                }
                for (std::size_t Index = 0; Index < 5; ++Index)
                {
                    const auto Delta = Column[(Index + 4) % 5] ^ Rotate(Column[(Index + 1) % 5], 1);
                    for (std::size_t Row = 0; Row < 25; Row += 5)
                    {
                        State[Row + Index] ^= Delta;
                    }
                }
                auto Temporary = State[1];
                for (std::size_t Index = 0; Index < Piln.size(); ++Index)
                {
                    const auto Position = static_cast<std::size_t>(Piln[Index]);
                    const auto Saved = State[Position];
                    State[Position] = Rotate(Temporary, Rotc[Index]);
                    Temporary = Saved;
                }
                for (std::size_t Row = 0; Row < 25; Row += 5)
                {
                    std::array<std::uint64_t, 5> Saved{};
                    for (std::size_t Index = 0; Index < 5; ++Index)
                    {
                        Saved[Index] = State[Row + Index];
                    }
                    for (std::size_t Index = 0; Index < 5; ++Index)
                    {
                        State[Row + Index] = Saved[Index] ^
                                             ((~Saved[(Index + 1) % 5]) & Saved[(Index + 2) % 5]);
                    }
                }
                State[0] ^= RoundConstant;
            }
        }

        std::array<std::uint64_t, 25> State_{};
        std::array<std::uint8_t, Rate> Buffer_{};
        std::size_t Cursor_{Rate};
    };
} // namespace Preview::Vmess
