/**
 * @file chunk.hpp
 * @brief SS2022 AEAD 分块编解码（流式，含状态机）
 * @details SS2022 数据格式：
 *          [2B 载荷长度密文 + 16B tag][载荷密文 + 16B tag]
 *          长度与载荷共享递增 nonce（长度 +2，载荷 +1）。
 *          空块（长度 0）表示流结束。
 *          提供 chunk_codec（状态机，含 AEAD 上下文）。
 * @note 参考 SIP022 规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/shadowsocks2022/types.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace psmtest::ss2022
{

    namespace detail
    {

        /// nonce 小端 +1（对齐 Go increaseNonce）
        inline auto inc_nonce(std::span<std::uint8_t> nonce) -> void
        {
            for (auto &b : nonce)
            {
                ++b;
                if (b != 0)
                    break;
            }
        }

        /// AEAD 加密（AES-128-GCM，AAD 为空）
        [[nodiscard]] inline auto aead_seal(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> plain)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out(plain.size() + aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return {};
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()));
            int out_len = len;
            EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + out_len);
            out.resize(static_cast<std::size_t>(out_len) + aead_tag_len);
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        /// AEAD 解密（失败返回空）
        [[nodiscard]] inline auto aead_open(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> cipher)
            -> std::vector<std::uint8_t>
        {
            if (cipher.size() < aead_tag_len)
                return {};
            std::vector<std::uint8_t> out(cipher.size() - aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return {};
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), static_cast<int>(cipher.size() - aead_tag_len));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(aead_tag_len),
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - aead_tag_len);
            const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            if (ok != 1)
                return {};
            out.resize(static_cast<std::size_t>(out_len));
            return out;
        }

    } // namespace detail

    /// @brief SS2022 AEAD 分块编解码器（状态机）
    class chunk_codec
    {
    public:
        /// @brief 构造
        /// @param key 会话密钥（16 字节 aes-128-gcm）
        explicit chunk_codec(std::span<const std::uint8_t> key)
            : key_(key.begin(), key.end())
        {
        }

        /// @brief 加密单块（长度 nonce 递增）
        /// @param plain 明文
        /// @return [len 密文 18B][载荷密文 len+16B]
        [[nodiscard]] auto seal(std::span<const std::uint8_t> plain) -> std::vector<std::uint8_t>
        {
            std::array<std::uint8_t, 2> len_plain{
                static_cast<std::uint8_t>((plain.size() >> 8) & 0xFF),
                static_cast<std::uint8_t>(plain.size() & 0xFF)};
            const auto len_enc = detail::aead_seal(key_, nonce_, len_plain);
            detail::inc_nonce(nonce_);
            const auto body_enc = detail::aead_seal(key_, nonce_, plain);
            detail::inc_nonce(nonce_);
            std::vector<std::uint8_t> out;
            out.reserve(len_enc.size() + body_enc.size());
            out.insert(out.end(), len_enc.begin(), len_enc.end());
            out.insert(out.end(), body_enc.begin(), body_enc.end());
            return out;
        }

        /// @brief 解密长度块（2 字节密文 + 16 tag）
        /// @param head 18 字节长度块
        /// @return 载荷长度（0 = 结束块）；nullopt = 校验失败
        [[nodiscard]] auto open_len(std::span<const std::uint8_t> head)
            -> std::optional<std::size_t>
        {
            if (head.size() < len_block_size)
                return std::nullopt;
            const auto len_plain = detail::aead_open(key_, nonce_, head.first(len_block_size));
            if (len_plain.size() != 2)
                return std::nullopt;
            detail::inc_nonce(nonce_);
            const auto n = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];
            if (n > max_chunk_size)
                return std::nullopt;
            return n;
        }

        /// @brief 解密载荷块（n 字节密文 + 16 tag）
        /// @param data 载荷密文块
        /// @return 明文（空 = 校验失败）
        [[nodiscard]] auto open_payload(std::span<const std::uint8_t> data)
            -> std::vector<std::uint8_t>
        {
            if (data.size() < aead_tag_len)
                return {};
            const auto body = detail::aead_open(key_, nonce_, data);
            if (body.empty() && data.size() > aead_tag_len)
                return {};
            detail::inc_nonce(nonce_);
            return body;
        }

        /// @brief 解密单块（完整块：长度 + 载荷）
        /// @param data 完整块
        /// @param consumed 输出消耗字节数
        /// @return 明文；空 = 失败或空块（len=0）
        [[nodiscard]] auto open(std::span<const std::uint8_t> data, std::size_t &consumed)
            -> std::vector<std::uint8_t>
        {
            auto len = open_len(data);
            if (!len)
                return {};
            if (*len == 0)
            {
                consumed = len_block_size;
                return {};
            }
            if (data.size() < len_block_size + *len + aead_tag_len)
                return {};
            const auto body = open_payload(data.subspan(len_block_size, *len + aead_tag_len));
            if (body.empty())
                return {};
            consumed = len_block_size + *len + aead_tag_len;
            return body;
        }

        /// 结束块（长度 0）
        [[nodiscard]] auto finish() -> std::vector<std::uint8_t>
        {
            return seal({});
        }

    private:
        std::vector<std::uint8_t> key_;
        std::array<std::uint8_t, 12> nonce_{};
    };

} // namespace psmtest::ss2022
