/**
 * @file KeyDerivation.hpp
 * @brief Shadowsocks 2022 BLAKE3 会话密钥派生
 * @details 只负责由预共享密钥和会话盐派生子密钥；AEAD 分块状态机位于
 *          ChunkCodec.hpp，握手和数据报编解码位于 Codec.hpp。
 */

#pragma once

#include <blake3.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    /**
     * @brief 派生会话子密钥
     * @param Psk 预共享密钥
     * @param Salt 会话随机盐
     * @param OutLen 输出长度
     * @return 会话子密钥
     */
    [[nodiscard]] inline auto SessionKey(std::span<const std::uint8_t> Psk,
                                          std::span<const std::uint8_t> Salt,
                                          std::size_t OutLen = 16) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Material;
        Material.reserve(Psk.size() + Salt.size());
        Material.insert(Material.end(), Psk.begin(), Psk.end());
        Material.insert(Material.end(), Salt.begin(), Salt.end());
        std::vector<std::uint8_t> Out(OutLen);
        blake3_hasher Hasher;
        blake3_hasher_init_derive_key(&Hasher, KdfContext.data());
        blake3_hasher_update(&Hasher, Material.data(), Material.size());
        blake3_hasher_finalize(&Hasher, Out.data(), OutLen);
        return Out;
    }

} // namespace Preview::Shadowsocks2022
