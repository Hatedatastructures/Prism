/**
 * @file block.hpp
 * @brief AES-ECB 单块加解密
 * @details 提供 AES-ECB 单块（16 字节）加密和解密功能。
 * 用于 SS2022 (SIP022) UDP 的 SeparateHeader 加密。
 * 不应直接用于大量数据加密（ECB 模式不安全）。
 * @note 已分叉，各自演进（与主库 foundation 无镜像同步约束）
 */
#pragma once

#include <cstring>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace preview::crypto
{

    /**
     * @brief AES-ECB 单块加密（16 字节 → 16 字节）
     * @details 对单个 16 字节块执行 AES-ECB 加密。支持 AES-128
     *（16 字节密钥）和 AES-256（32 字节密钥）。
     * @param input 明文（16 字节）
     * @param key AES 密钥（16 或 32 字节）
     * @return 密文（16 字节）
     */
    [[nodiscard]] auto ecb_encrypt(std::span<const std::uint8_t, 16> input, std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>;

    /**
     * @brief AES-ECB 单块解密（16 字节 → 16 字节）
     * @details 对单个 16 字节块执行 AES-ECB 解密。支持 AES-128
     *（16 字节密钥）和 AES-256（32 字节密钥）。
     * @param input 密文（16 字节）
     * @param key AES 密钥（16 或 32 字节）
     * @return 明文（16 字节）
     */
    [[nodiscard]] auto ecb_decrypt(std::span<const std::uint8_t, 16> input, std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>;



    inline auto ecb_encrypt(std::span<const std::uint8_t, 16> input, std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> out{};

        const EVP_CIPHER *cipher = nullptr;
        if (key.size() == 16)
        {
            cipher = EVP_aes_128_ecb();
        }
        else
        {
            cipher = EVP_aes_256_ecb();
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return out;
        }

        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        // 禁用填充（输入已是完整块）
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        int out_len = 0; // EVP API 要求 int*
        if (EVP_EncryptUpdate(ctx, out.data(), &out_len, input.data(), 16) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }
        int final_len = 0; // EVP API 要求 int*
        if (EVP_EncryptFinal_ex(ctx, out.data() + out_len, &final_len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    inline auto ecb_decrypt(std::span<const std::uint8_t, 16> input, std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> out{};

        const EVP_CIPHER *cipher = nullptr;
        if (key.size() == 16)
        {
            cipher = EVP_aes_128_ecb();
        }
        else
        {
            cipher = EVP_aes_256_ecb();
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return out;
        }

        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        // 禁用填充
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        int out_len = 0; // EVP API 要求 int*
        if (EVP_DecryptUpdate(ctx, out.data(), &out_len, input.data(), 16) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }
        int final_len = 0; // EVP API 要求 int*
        if (EVP_DecryptFinal_ex(ctx, out.data() + out_len, &final_len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }


} // namespace preview::crypto
