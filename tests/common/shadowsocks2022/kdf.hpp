/**
 * @file kdf.hpp
 * @brief SS2022 密钥派生（BLAKE3 DeriveKey）
 * @details 会话子密钥 = BLAKE3-DeriveKey(context, psk + salt)，
 *          直接调用 BLAKE3 C API（blake3_derive_key），
 *          链接 blake3_c 库（CMake 目标），保持协议逻辑 header-only。
 * @note 参考 SIP022 规范。
 */

#pragma once

#include <common/shadowsocks2022/types.hpp>

#include <blake3.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace psmtest::ss2022
{

    /// @brief 派生会话密钥
    /// @param psk 预共享密钥（16/32 字节）
    /// @param salt 随机盐（与 psk 等长）
    /// @param out_len 输出长度
    /// @return 会话子密钥
    [[nodiscard]] inline auto session_key(std::span<const std::uint8_t> psk,
                                          std::span<const std::uint8_t> salt,
                                          std::size_t out_len = 16) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> material;
        material.reserve(psk.size() + salt.size());
        material.insert(material.end(), psk.begin(), psk.end());
        material.insert(material.end(), salt.begin(), salt.end());
        std::vector<std::uint8_t> out(out_len);
        blake3_hasher hasher;
        blake3_hasher_init_derive_key(&hasher, kdf_context.data());
        blake3_hasher_update(&hasher, material.data(), material.size());
        blake3_hasher_finalize(&hasher, out.data(), out_len);
        return out;
    }

} // namespace psmtest::ss2022
