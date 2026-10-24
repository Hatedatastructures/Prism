/**
 * @file KeyDerivation.cpp
 * @brief Shadowsocks 2022 会话密钥派生实现。
 */

#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>

#include <blake3.h>

namespace Prism::Shadowsocks2022
{
    auto SessionKey(std::span<const std::uint8_t> Psk, std::span<const std::uint8_t> Salt,
        std::span<std::uint8_t> Output) -> void
    {
        if (Output.empty())
        {
            return;
        }
        blake3_hasher Hasher;
        blake3_hasher_init_derive_key(&Hasher, KdfContext.data());
        if (!Psk.empty())
        {
            blake3_hasher_update(&Hasher, Psk.data(), Psk.size());
        }
        if (!Salt.empty())
        {
            blake3_hasher_update(&Hasher, Salt.data(), Salt.size());
        }
        blake3_hasher_finalize(&Hasher, Output.data(), Output.size());
    }

    [[nodiscard]] auto SessionKey(std::span<const std::uint8_t> Psk, std::span<const std::uint8_t> Salt,
        std::size_t OutputLength) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output(OutputLength);
        SessionKey(Psk, Salt, std::span<std::uint8_t>(Output));
        return Output;
    }

} // namespace Prism::Shadowsocks2022
