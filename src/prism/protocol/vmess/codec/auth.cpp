/**
 * @file auth.cpp
 * @brief VMess AEAD 认证头编解码实现
 */

#include <prism/protocol/vmess/codec/auth.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>

namespace psm::protocol::vmess::codec
{

    namespace
    {
        /**
         * @brief CRC32-IEEE 查表
         * @return 256 项 CRC32 查找表
         */
        constexpr auto make_crc32_table() noexcept
        {
            std::array<std::uint32_t, 256> table{};
            for (std::uint32_t i = 0; i < table.size(); ++i)
            {
                std::uint32_t c = i;
                for (int k = 0; k < 8; ++k)
                {
                    c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
                }
                table[i] = c;
            }
            return table;
        }

        constexpr auto crc32_table = make_crc32_table();

        /**
         * @brief 单块 AES-128-ECB 加密（无填充）
         * @param key 16 字节 AES 密钥
         * @param in 待加密的明文块
         * @param out 密文输出块
         * @return 是否加密成功
         */
        [[nodiscard]] auto aes_ecb_encrypt(std::span<const std::uint8_t, 16> key,
                                           std::span<const std::uint8_t, 16> in,
                                           std::span<std::uint8_t, 16> out) -> bool
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return false;
            }
            int len = 0;
            int total = 0;
            const bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) &&
                            EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
                            EVP_EncryptUpdate(ctx, out.data(), &len, in.data(), 16) && (total = len, true) &&
                            EVP_EncryptFinal_ex(ctx, out.data() + total, &len) && (total += len, true) &&
                            total == 16;
            EVP_CIPHER_CTX_free(ctx);
            return ok;
        }

        /**
         * @brief 单块 AES-128-ECB 解密（无填充）
         * @param key 16 字节 AES 密钥
         * @param in 待解密的密文块
         * @param out 明文输出块
         * @return 是否解密成功
         */
        [[nodiscard]] auto aes_ecb_decrypt(std::span<const std::uint8_t, 16> key,
                                           std::span<const std::uint8_t, 16> in,
                                           std::span<std::uint8_t, 16> out) -> bool
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return false;
            }
            int len = 0;
            int total = 0;
            const bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) &&
                            EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
                            EVP_DecryptUpdate(ctx, out.data(), &len, in.data(), 16) && (total = len, true) &&
                            EVP_DecryptFinal_ex(ctx, out.data() + total, &len) && (total += len, true) &&
                            total == 16;
            EVP_CIPHER_CTX_free(ctx);
            return ok;
        }
    } // namespace

    auto crc32_ieee(const std::span<const std::uint8_t> data) -> std::uint32_t
    {
        std::uint32_t crc = 0xFFFFFFFFU;
        for (const auto byte : data)
        {
            crc = crc32_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFFU;
    }

    auto fnv1a_32(const std::span<const std::uint8_t> data) -> std::uint32_t
    {
        std::uint32_t hash = 0x811C9DC5U;
        for (const auto byte : data)
        {
            hash ^= static_cast<std::uint32_t>(byte);
            hash *= 0x01000193U;
        }
        return hash;
    }

    auto seal_auth_header(const std::span<const std::uint8_t, 16> cmd_key, const std::int64_t timestamp,
                          const std::span<std::uint8_t, auth_header_len> out) -> fault::code
    {
        std::array<std::uint8_t, 16> plain{};
        const std::uint64_t ts = static_cast<std::uint64_t>(timestamp);
        for (std::size_t i = 0; i < 8; ++i)
        {
            plain[i] = static_cast<std::uint8_t>(ts >> (8 * (7 - i)));
        }

        // random 4B：密码学随机数，防止认证头重放关联
        if (RAND_bytes(plain.data() + 8, 4) != 1)
        {
            return fault::code::crypto_error;
        }

        const auto crc = crc32_ieee(std::span<const std::uint8_t>(plain.data(), 12));
        for (std::size_t i = 0; i < 4; ++i)
        {
            plain[12 + i] = static_cast<std::uint8_t>(crc >> (8 * (3 - i)));
        }

        const auto key = kdf(cmd_key, kdf_auth_id);
        return aes_ecb_encrypt(std::span<const std::uint8_t, 16>(key.data(), 16), plain, out)
                   ? fault::code::success
                   : fault::code::crypto_error;
    }

    auto open_auth_header(const std::span<const std::uint8_t, 16> cmd_key,
                          const std::span<const std::uint8_t, auth_header_len> auth_id) -> auth_result
    {
        auth_result result{};

        const auto key = kdf(cmd_key, kdf_auth_id);
        std::array<std::uint8_t, 16> plain{};
        if (!aes_ecb_decrypt(std::span<const std::uint8_t, 16>(key.data(), 16), auth_id, plain))
        {
            return result;
        }

        std::uint64_t ts = 0;
        for (std::size_t i = 0; i < 8; ++i)
        {
            ts = (ts << 8) | plain[i];
        }
        result.timestamp = static_cast<std::int64_t>(ts);

        const auto expected = crc32_ieee(std::span<const std::uint8_t>(plain.data(), 12));
        std::uint32_t actual = 0;
        for (std::size_t i = 0; i < 4; ++i)
        {
            actual = (actual << 8) | plain[12 + i];
        }
        result.valid = (actual == expected);
        return result;
    }

} // namespace psm::protocol::vmess::codec
