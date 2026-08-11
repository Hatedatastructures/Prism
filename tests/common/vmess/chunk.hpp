/**
 * @file chunk.hpp
 * @brief VMess AEAD 分块编解码（流式，含状态机）
 * @details VMess 分块流格式：
 *          [2B 长度 BE][16B tag][payload][16B tag]
 *          - 长度密文：nonce 递增 AES-128-GCM
 *          - 载荷密文：nonce 递增 AES-128-GCM
 *          - 空块（长度 0）表示流结束
 *          - 客户端与服务端 nonce 独立（seal/open 双向）
 *          提供 chunk_encryptor / chunk_decryptor 两个状态机类。
 * @note 参考 mihomo transport/vmess/conn.go ChunkedWriter/Reader。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/vmess/kdf.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <vector>

namespace psmtest::vmess
{

    namespace detail
    {

        /// 单次 AES-128-GCM 加密（nonce 由调用方控制）
        inline auto chunk_seal(std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t, 12> nonce,
                               std::span<const std::uint8_t> plain,
                               std::span<std::uint8_t> out) -> void
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce.data());
            EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()));
            EVP_EncryptFinal_ex(ctx, out.data() + len, &len);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + plain.size());
            EVP_CIPHER_CTX_free(ctx);
        }

        /// 单次 AES-128-GCM 解密（失败返回 false）
        inline auto chunk_open(std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t, 12> nonce,
                               std::span<const std::uint8_t> cipher,
                               std::span<std::uint8_t> out) -> bool
        {
            if (cipher.size() < 16)
                return false;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce.data());
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), static_cast<int>(cipher.size() - 16));
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - 16);
            const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
            EVP_CIPHER_CTX_free(ctx);
            return ok == 1;
        }

        /// nonce 递增（大端 +1）
        inline auto inc_nonce(std::span<std::uint8_t, 12> nonce) -> void
        {
            for (std::size_t i = nonce.size(); i > 0; --i)
            {
                if (++nonce[i - 1] != 0)
                    break;
            }
        }

    } // namespace detail

    /// @brief VMess 分块加密器（状态机）
    class chunk_encryptor
    {
    public:
        /// 分块开销：2 长度 + 16 长度 tag + 16 载荷 tag
        static constexpr std::size_t overhead = 2 + 16 + 16;

        /// @brief 构造
        /// @param key 16 字节分块密钥
        /// @param nonce 12 字节起始 nonce
        explicit chunk_encryptor(std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 12> nonce)
            : key_()
        {
            std::memcpy(key_.data(), key.data(), 16);
            std::memcpy(nonce_.data(), nonce.data(), 12);
        }

        /// @brief 加密一块数据
        /// @param plain 明文
        /// @param out 输出（容量 ≥ plain.size() + overhead）
        /// @return 写入字节数（含块头）
        auto seal(std::span<const std::uint8_t> plain, std::span<std::uint8_t> out) -> std::size_t
        {
            const auto n = plain.size();
            if (out.size() < n + overhead)
                return 0;

            // 长度字段（大端 2 字节）加密
            std::array<std::uint8_t, 2> len_plain{};
            len_plain[0] = static_cast<std::uint8_t>((n >> 8) & 0xFF);
            len_plain[1] = static_cast<std::uint8_t>(n & 0xFF);
            std::array<std::uint8_t, 2 + 16> len_enc{};
            detail::chunk_seal(key_, nonce_, len_plain, len_enc);
            detail::inc_nonce(nonce_);

            std::memcpy(out.data(), len_enc.data(), len_enc.size());

            // 载荷加密
            detail::chunk_seal(key_, nonce_, plain, out.subspan(len_enc.size()));
            detail::inc_nonce(nonce_);
            return len_enc.size() + n + 16;
        }

        /// @brief 结束块（长度 0）
        /// @param out 输出（容量 ≥ 18）
        /// @return 写入字节数
        auto finish(std::span<std::uint8_t> out) -> std::size_t
        {
            return seal({}, out);
        }

    private:
        std::array<std::uint8_t, 16> key_;
        std::array<std::uint8_t, 12> nonce_;
    };

    /// @brief VMess 分块解密器（状态机，支持增量两步解析）
    class chunk_decryptor
    {
    public:
        /// @brief 构造
        /// @param key 16 字节分块密钥
        /// @param nonce 12 字节起始 nonce
        explicit chunk_decryptor(std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 12> nonce)
            : key_()
        {
            std::memcpy(key_.data(), key.data(), 16);
            std::memcpy(nonce_.data(), nonce.data(), 12);
        }

        /// @brief 解密长度字段（2 字节密文 + 16 tag）
        /// @param head 18 字节块头
        /// @return 载荷长度（0 = 流结束）；错误码
        auto open_len(std::span<const std::uint8_t> head) -> std::expected<std::size_t, error>
        {
            if (head.size() < 18)
                return std::unexpected(error::need_more);
            std::array<std::uint8_t, 2> len_plain{};
            if (!detail::chunk_open(key_, nonce_, head.first(18), len_plain))
                return std::unexpected(error::bad_auth);
            detail::inc_nonce(nonce_);
            const auto n = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];
            if (n > max_chunk_len)
                return std::unexpected(error::bad_length);
            return n;
        }

        /// @brief 解密载荷字段（n 字节密文 + 16 tag）
        /// @param data 载荷密文块（长度 + 16）
        /// @param out 输出明文（长度 ≥ data.size() - 16）
        /// @return 错误码
        auto open_payload(std::span<const std::uint8_t> data, std::span<std::uint8_t> out) -> error
        {
            if (data.size() < 16 || out.size() < data.size() - 16)
                return error::need_more;
            if (!detail::chunk_open(key_, nonce_, data, out.first(data.size() - 16)))
                return error::bad_auth;
            detail::inc_nonce(nonce_);
            return error::none;
        }

        /// @brief 解密一块数据（必须提供完整块：长度+tag+载荷+tag）
        /// @param data 完整密文块
        /// @param out 输出明文
        /// @param consumed 输出消耗字节数
        /// @return 错误码；need_more = 数据不足
        auto open(std::span<const std::uint8_t> data, std::span<std::uint8_t> out,
                  std::size_t &consumed) -> error
        {
            if (data.size() < 18)
                return error::need_more;
            auto len = open_len(data);
            if (!len)
                return len.error();
            if (*len == 0)
            {
                consumed = 18;
                return error::none; // 流结束
            }
            if (data.size() < 18 + *len + 16)
                return error::need_more;
            const auto ec = open_payload(data.subspan(18, *len + 16), out);
            if (ec != error::none)
                return ec;
            consumed = 18 + *len + 16;
            return error::none;
        }

    private:
        std::array<std::uint8_t, 16> key_;
        std::array<std::uint8_t, 12> nonce_;
    };

} // namespace psmtest::vmess
