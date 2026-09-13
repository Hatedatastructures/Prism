/**
 * @file Block.hpp
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
#include <expected>
#include <span>

#include <preview/Foundation/Error.hpp>

namespace Preview::Crypto
{

    /**
     * @brief AES-ECB 单块加密（16 字节 → 16 字节）
     * @details 对单个 16 字节块执行 AES-ECB 加密。支持 AES-128/192/256
     *（16/24/32 字节密钥）。
     * @param input 明文（16 字节）
     * @param key AES 密钥（16、24 或 32 字节）
     * @return 密文（16 字节）
     */
    [[nodiscard]] auto EcbEncrypt(std::span<const std::uint8_t, 16> Input,
                                   std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Preview::Error>;

    /**
     * @brief AES-ECB 单块解密（16 字节 → 16 字节）
     * @details 对单个 16 字节块执行 AES-ECB 解密。支持 AES-128/192/256
     *（16/24/32 字节密钥）。
     * @param input 密文（16 字节）
     * @param key AES 密钥（16、24 或 32 字节）
     * @return 明文（16 字节）
     */
    [[nodiscard]] auto EcbDecrypt(std::span<const std::uint8_t, 16> Input,
                                   std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Preview::Error>;



    inline auto EcbEncrypt(std::span<const std::uint8_t, 16> Input,
                           std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Preview::Error>
    {
        std::array<std::uint8_t, 16> Output{};

        const EVP_CIPHER *Cipher = nullptr;
        switch (Key.size())
        {
        case 16: Cipher = EVP_aes_128_ecb(); break;
        case 24: Cipher = EVP_aes_192_ecb(); break;
        case 32: Cipher = EVP_aes_256_ecb(); break;
        default: return std::unexpected(Preview::Error::BadLength);
        }

        EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
        if (!Context)
        {
            return std::unexpected(Preview::Error::CryptoError);
        }

        if (EVP_EncryptInit_ex(Context, Cipher, nullptr, Key.data(), nullptr) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }

        // 禁用填充（输入已是完整块）
        if (EVP_CIPHER_CTX_set_padding(Context, 0) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }

        int OutLen = 0; // EVP API 要求 int*
        if (EVP_EncryptUpdate(Context, Output.data(), &OutLen, Input.data(), 16) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }
        int FinalLen = 0; // EVP API 要求 int*
        if (EVP_EncryptFinal_ex(Context, Output.data() + OutLen, &FinalLen) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }

        EVP_CIPHER_CTX_free(Context);
        return Output;
    }

    inline auto EcbDecrypt(std::span<const std::uint8_t, 16> Input,
                           std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Preview::Error>
    {
        std::array<std::uint8_t, 16> Output{};

        const EVP_CIPHER *Cipher = nullptr;
        switch (Key.size())
        {
        case 16: Cipher = EVP_aes_128_ecb(); break;
        case 24: Cipher = EVP_aes_192_ecb(); break;
        case 32: Cipher = EVP_aes_256_ecb(); break;
        default: return std::unexpected(Preview::Error::BadLength);
        }

        EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
        if (!Context)
        {
            return std::unexpected(Preview::Error::CryptoError);
        }

        if (EVP_DecryptInit_ex(Context, Cipher, nullptr, Key.data(), nullptr) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }

        // 禁用填充
        if (EVP_CIPHER_CTX_set_padding(Context, 0) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }

        int OutLen = 0; // EVP API 要求 int*
        if (EVP_DecryptUpdate(Context, Output.data(), &OutLen, Input.data(), 16) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }
        int FinalLen = 0; // EVP API 要求 int*
        if (EVP_DecryptFinal_ex(Context, Output.data() + OutLen, &FinalLen) != 1)
        {
            EVP_CIPHER_CTX_free(Context);
            return std::unexpected(Preview::Error::CryptoError);
        }

        EVP_CIPHER_CTX_free(Context);
        return Output;
    }


} // namespace Preview::Crypto
