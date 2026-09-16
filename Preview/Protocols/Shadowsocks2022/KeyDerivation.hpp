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

#include <Preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    /**
     * @brief 将会话子密钥派生到调用方缓冲区
     * @param Psk 预共享密钥
     * @param Salt 会话随机盐
     * @param Output 输出缓冲区
     * @details 分段更新 BLAKE3，避免为 Psk+Salt 构造临时 material。
     */
    inline auto SessionKey(std::span<const std::uint8_t> Psk,
                           std::span<const std::uint8_t> Salt,
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

    /**
     * @brief 派生会话子密钥
     * @param Psk 预共享密钥
     * @param Salt 会话随机盐
     * @param OutputLength 输出长度
     * @return 会话子密钥
     */
    [[nodiscard]] inline auto SessionKey(std::span<const std::uint8_t> Psk,
                                          std::span<const std::uint8_t> Salt,
                                          std::size_t OutputLength = 16)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output(OutputLength);
        SessionKey(Psk, Salt, std::span<std::uint8_t>(Output));
        return Output;
    }

} // namespace Preview::Shadowsocks2022
