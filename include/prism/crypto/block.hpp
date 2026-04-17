/**
 * @file block.hpp
 * @brief AES-ECB 单块加解密
 * @details 提供 AES-ECB 单块（16 字节）加密和解密功能。
 * 用于 SS2022 (SIP022) UDP 的 SeparateHeader 加密。
 * 不应直接用于大量数据加密（ECB 模式不安全）。
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psm::crypto
{
    /**
     * @brief AES-ECB 单块加密（16 字节 → 16 字节）
     * @details 对单个 16 字节块执行 AES-ECB 加密。支持 AES-128
     *（16 字节密钥）和 AES-256（32 字节密钥）。
     * @param input 明文（16 字节）
     * @param key AES 密钥（16 或 32 字节）
     * @return 密文（16 字节）
     */
    [[nodiscard]] auto aes_ecb_encrypt(std::span<const std::uint8_t, 16> input, std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>;

    /**
     * @brief AES-ECB 单块解密（16 字节 → 16 字节）
     * @details 对单个 16 字节块执行 AES-ECB 解密。支持 AES-128
     *（16 字节密钥）和 AES-256（32 字节密钥）。
     * @param input 密文（16 字节）
     * @param key AES 密钥（16 或 32 字节）
     * @return 明文（16 字节）
     */
    [[nodiscard]] auto aes_ecb_decrypt(std::span<const std::uint8_t, 16> input, std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>;
} // namespace psm::crypto
