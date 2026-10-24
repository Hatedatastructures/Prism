/**
 * @file KeyDerivation.hpp
 * @brief Shadowsocks 2022 BLAKE3 会话密钥派生
 * @details 只负责由预共享密钥和会话盐派生子密钥；AEAD 分块状态机位于
 *          ChunkCodec.hpp；握手与数据报 wire 状态分别位于 RequestState.hpp、
 *          RequestWire.hpp 和 ResponseCodec.hpp。
 */

#pragma once

#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace Prism::Shadowsocks2022
{

    /**
     * @brief 将会话子密钥派生到调用方缓冲区
     * @param Psk 预共享密钥
     * @param Salt 会话随机盐
     * @param Output 输出缓冲区
     * @details 分段更新 BLAKE3，避免为 Psk+Salt 构造临时 material。
     */
    auto SessionKey(std::span<const std::uint8_t> Psk, std::span<const std::uint8_t> Salt,
        std::span<std::uint8_t> Output) -> void;

    /**
     * @brief 派生会话子密钥
     * @param Psk 预共享密钥
     * @param Salt 会话随机盐
     * @param OutputLength 输出长度
     * @return 会话子密钥
     */
    [[nodiscard]] auto SessionKey(std::span<const std::uint8_t> Psk, std::span<const std::uint8_t> Salt,
        std::size_t OutputLength = 16) -> std::vector<std::uint8_t>;

} // namespace Prism::Shadowsocks2022
