/**
 * @file challenge.cpp
 * @brief 挑战-响应令牌实现
 */

#include <prism/stealth/challenge.hpp>

#include <prism/crypto/blake3.hpp>

#include <cstring>

namespace psm::stealth
{

    auto generate_challenge(const challenge_input &input) noexcept -> challenge_token
    {
        auto hasher = crypto::keyed_hasher(
            std::span<const std::uint8_t, 32>(input.server_secret));

        blake3_hasher_update(&hasher, input.src.bytes.data(), input.src.bytes.size());

        std::array<std::uint8_t, 2> sni_len{};
        sni_len[0] = static_cast<std::uint8_t>((input.sni.size() >> 8) & 0xFF);
        sni_len[1] = static_cast<std::uint8_t>(input.sni.size() & 0xFF);
        blake3_hasher_update(&hasher, sni_len.data(), 2);
        if (!input.sni.empty())
            blake3_hasher_update(&hasher, input.sni.data(), input.sni.size());

        std::array<std::uint8_t, 8> counter_bytes{};
        for (std::size_t i = 0; i < 8; ++i)
            counter_bytes[i] = static_cast<std::uint8_t>((input.counter >> (56 - 8 * i)) & 0xFF);
        blake3_hasher_update(&hasher, counter_bytes.data(), 8);

        challenge_token token{};
        blake3_hasher_finalize(&hasher,
            reinterpret_cast<std::uint8_t *>(token.bytes.data()), 16);
        return token;
    }


    auto verify_challenge(
        const challenge_token &expected,
        std::span<const std::byte> response) noexcept -> bool
    {
        if (response.size() < 16)
            return false;
        return std::memcmp(expected.bytes.data(), response.data(), 16) == 0;
    }

} // namespace psm::stealth
