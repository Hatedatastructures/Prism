/**
 * @file kdf.hpp
 * @brief VMess 密钥派生与校验原语
 * @details 纯逻辑（无锁）：MD5/HMAC-SHA256 链式 KDF、CmdKey、AuthID 生成、
 *          CRC32-IEEE、FNV1a。命名空间 psm_test::vmess，参考 mihomo transport/vmess。
 */

#pragma once

#include <common/common.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace psm_test::vmess
{

    inline constexpr std::string_view kdf_salt_auth_id_enc = "AES Auth ID Encryption";
    inline constexpr std::string_view kdf_salt_aead_kdf = "VMess AEAD KDF";
    inline constexpr std::string_view kdf_salt_header_key = "VMess Header AEAD Key";
    inline constexpr std::string_view kdf_salt_header_iv = "VMess Header AEAD Nonce";
    inline constexpr std::string_view kdf_salt_header_len_key = "VMess Header AEAD Key_Length";
    inline constexpr std::string_view kdf_salt_header_len_iv = "VMess Header AEAD Nonce_Length";
    inline constexpr std::string_view cmd_key_const = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

    namespace detail
    {

        /// HMAC-SHA256 单次
        inline auto hmac_sha256(const view key, const view data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
                 out.data(), &len);
            return out;
        }

        /// MD5 摘要（16 字节）
        inline auto md5(const view data) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_md5(), nullptr);
            return out;
        }

        /// SHA-256 摘要（32 字节）
        inline auto sha256(const view data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr);
            return out;
        }

        /// CRC32-IEEE（与 Go hash/crc32 一致）
        inline auto crc32_ieee(const view data) -> std::uint32_t
        {
            std::uint32_t crc = 0xFFFFFFFF;
            for (const auto b : data)
            {
                crc ^= b;
                for (int i = 0; i < 8; ++i)
                    crc = (crc >> 1) ^ (0xEDB88320U & -(crc & 1));
            }
            return ~crc;
        }

        /// FNV1a 32 位（与 Go hash/fnv 一致）
        inline auto fnv1a32(const view data) -> std::uint32_t
        {
            std::uint32_t hash = 0x811C9DC5;
            for (const auto b : data)
            {
                hash ^= b;
                hash *= 0x01000193;
            }
            return hash;
        }

    } // namespace detail

    /**
     * @brief VMess AEAD 链式 KDF（HMAC-SHA256 嵌套）
     * @param key 基础密钥
     * @param paths 路径段（从内到外）
     * @return 32 字节派生密钥
     * @details kdf(key, p1, p2) = HMAC(p2, HMAC(p1, HMAC("VMess AEAD KDF", key)))
     */
    [[nodiscard]] inline auto kdf(const view key, const std::vector<std::string_view> &paths)
        -> std::array<std::uint8_t, 32>
    {
        auto out = detail::hmac_sha256(view(
            reinterpret_cast<const std::uint8_t *>(kdf_salt_aead_kdf.data()),
            kdf_salt_aead_kdf.size()), key);
        for (const auto &p : paths)
        {
            out = detail::hmac_sha256(
                view(reinterpret_cast<const std::uint8_t *>(p.data()), p.size()), out);
        }
        return out;
    }

    /// 单段 KDF 便捷重载
    [[nodiscard]] inline auto kdf(const view key, const std::string_view path)
        -> std::array<std::uint8_t, 32>
    {
        return kdf(key, std::vector<std::string_view>{path});
    }

    /// 计算 CmdKey = MD5(UUID 16B + 常量)
    [[nodiscard]] inline auto cmd_key(const std::span<const std::uint8_t> uuid)
        -> std::array<std::uint8_t, 16>
    {
        byte_writer w;
        w.write_bytes(uuid);
        w.write_bytes(cmd_key_const);
        return detail::md5(w.data());
    }

    /// 生成 AuthID：AES-128-ECB 加密(time 8B BE + random 4B + crc32 4B BE)
    [[nodiscard]] inline auto create_auth_id(const view cmd_key, const std::uint64_t time_sec,
                                             const view random4) -> std::array<std::uint8_t, 16>
    {
        byte_writer w;
        for (int i = 7; i >= 0; --i)
            w.write_u8(static_cast<std::uint8_t>(time_sec >> (i * 8)));
        w.write_bytes(random4);
        const auto crc = detail::crc32_ieee(w.data());
        w.write_u32(crc);

        const auto aes_key = kdf(cmd_key, kdf_salt_auth_id_enc);
        std::array<std::uint8_t, 16> out{};
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return out;
        int len = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, aes_key.data(), nullptr);
        EVP_CIPHER_CTX_set_padding(ctx, 0); // AES-ECB 单块，禁用 PKCS7 padding
        EVP_EncryptUpdate(ctx, out.data(), &len, w.data().data(), 16);
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

} // namespace psm_test::vmess
