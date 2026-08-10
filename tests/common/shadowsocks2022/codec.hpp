/**
 * @file codec.hpp
 * @brief Shadowsocks 2022（SIP022）基础编解码
 * @details 纯逻辑（无锁）：会话密钥派生、AEAD chunk（nonce 递增）、
 *          固定头/变长头构造。命名空间 psm_test::shadow2022，
 *          参考 mihomo sing-shadowsocks/shadowaead_2022。
 */

#pragma once

#include <common/common.hpp>

#include <prism/crypto/blake3.hpp>

#include <openssl/evp.h>

namespace psm_test::shadow2022
{

    inline constexpr std::string_view kdf_context = "shadowsocks 2022 session subkey";
    inline constexpr std::uint8_t header_type_client = 0x00;
    inline constexpr std::uint8_t header_type_server = 0x01;
    inline constexpr std::size_t fixed_header_len = 1 + 8 + 2; ///< type + ts + varLen
    inline constexpr std::size_t aead_tag_len = 16;
    inline constexpr std::size_t key_len = 16; ///< aes-128-gcm

    namespace detail
    {

        /// nonce 小端 +1（Go increaseNonce）
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
        inline auto aead_seal(const view key, const view nonce12, const view plain) -> buffer
        {
            buffer out(plain.size() + aead_tag_len);
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

        /// AEAD 解密（失败返回 false，明文可能为空——空块合法）
        inline auto aead_open(const view key, const view nonce12, const view cipher,
                              buffer &out) -> bool
        {
            if (cipher.size() < aead_tag_len)
                return false;
            out.resize(cipher.size() - aead_tag_len);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return false;
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(),
                              static_cast<int>(cipher.size() - aead_tag_len));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(cipher.data() + cipher.size() - aead_tag_len));
            if (EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len) <= 0)
            {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            out.resize(static_cast<std::size_t>(out_len) + static_cast<std::size_t>(len));
            EVP_CIPHER_CTX_free(ctx);
            return true;
        }

    } // namespace detail

    /// 会话密钥 = BLAKE3-DeriveKey(context, psk + salt)
    [[nodiscard]] inline auto session_key(const view psk, const view salt)
        -> std::array<std::uint8_t, key_len>
    {
        buffer material(psk.size() + salt.size());
        std::copy(psk.begin(), psk.end(), material.begin());
        std::copy(salt.begin(), salt.end(), material.begin() + static_cast<std::ptrdiff_t>(psk.size()));
        const auto out = psm::crypto::derive_key(kdf_context, material, key_len);
        std::array<std::uint8_t, key_len> key{};
        std::copy(out.begin(), out.end(), key.begin());
        return key;
    }

    /// 固定头构造（type + 8B 大端时间戳 + varLen 2B 大端）
    [[nodiscard]] inline auto build_fixed_header(const std::uint8_t type,
                                                 const std::uint64_t time_sec,
                                                 const std::uint16_t var_len) -> std::array<std::uint8_t, fixed_header_len>
    {
        std::array<std::uint8_t, fixed_header_len> h{};
        h[0] = type;
        for (std::size_t i = 0; i < 8; ++i)
            h[1 + i] = static_cast<std::uint8_t>(time_sec >> (56 - 8 * i));
        h[9] = static_cast<std::uint8_t>(var_len >> 8);
        h[10] = static_cast<std::uint8_t>(var_len & 0xFF);
        return h;
    }

    /**
     * @class chunk_codec
     * @brief SIP022 会话编解码（nonce 递增）
     * @details 握手头直接 AEAD 加密（无长度前缀）；
     *          数据分块 = [len 2B 加密+tag][payload 加密+tag]。
     */
    class chunk_codec
    {
    public:
        /// @param key 会话密钥
        /// @param skip_nonce 跳过 nonce 数（握手消耗 0,1 后，数据从 2 起）
        explicit chunk_codec(const view key, const std::uint32_t skip_nonce = 0)
        {
            std::copy(key.begin(), key.end(), key_.begin());
            for (std::uint32_t i = 0; i < skip_nonce; ++i)
                detail::inc_nonce(nonce_);
        }

        /// 直接加密（握手头：固定头/变长头）
        [[nodiscard]] auto seal_raw(const view plain) -> buffer
        {
            const auto nonce = current_nonce();
            buffer out = detail::aead_seal(key_, nonce, plain);
            detail::inc_nonce(nonce_);
            return out;
        }

        /// 直接解密（握手头），失败返回 false
        [[nodiscard]] auto open_raw(const view data, buffer &out) -> bool
        {
            if (data.size() < aead_tag_len)
                return false;
            const auto nonce = current_nonce();
            if (!detail::aead_open(key_, nonce, data, out))
                return false;
            detail::inc_nonce(nonce_);
            return true;
        }

        /// 加密长度块（数据分块第一步）：返回 18B 长度块密文
        [[nodiscard]] auto seal_len(const std::uint16_t plain_len) -> buffer
        {
            std::array<std::uint8_t, 2> len_plain{
                static_cast<std::uint8_t>(plain_len >> 8),
                static_cast<std::uint8_t>(plain_len & 0xFF)};
            const auto nonce1 = current_nonce();
            buffer out = detail::aead_seal(key_, nonce1, len_plain);
            detail::inc_nonce(nonce_);
            return out;
        }

        /// 加密一块（数据分块：长度块 + 载荷块，各用一个 nonce）
        [[nodiscard]] auto seal(const view plain) -> buffer
        {
            buffer out = seal_len(static_cast<std::uint16_t>(plain.size()));
            const auto nonce2 = current_nonce();
            const auto body = detail::aead_seal(key_, nonce2, plain);
            detail::inc_nonce(nonce_);
            out.insert(out.end(), body.begin(), body.end());
            return out;
        }

        /// 解长度块（数据分块第一步）：从 18B 长度块解出载荷长度
        [[nodiscard]] auto open_len(const view data, std::size_t &body_len) -> bool
        {
            if (data.size() < 2 + aead_tag_len)
                return false;
            const auto nonce1 = current_nonce();
            buffer len_plain;
            if (!detail::aead_open(key_, nonce1, view(data.data(), 2 + aead_tag_len), len_plain))
                return false;
            if (len_plain.size() != 2)
                return false;
            detail::inc_nonce(nonce_);
            body_len = static_cast<std::size_t>((len_plain[0] << 8) | len_plain[1]);
            return true;
        }

        /// 解载荷块（数据分块第二步）：解密载荷
        [[nodiscard]] auto open_body(const view data, buffer &out) -> bool
        {
            if (data.size() < aead_tag_len)
                return false;
            const auto nonce2 = current_nonce();
            if (!detail::aead_open(key_, nonce2, data, out))
                return false;
            detail::inc_nonce(nonce_);
            return true;
        }

        /// 解密一块（数据分块：长度块 + 载荷块），失败返回 false
        [[nodiscard]] auto open(const view data, buffer &out) -> bool
        {
            if (data.size() < 2 + aead_tag_len)
                return false;
            const auto nonce1 = current_nonce();
            buffer len_plain;
            if (!detail::aead_open(key_, nonce1, view(data.data(), 2 + aead_tag_len), len_plain))
                return false;
            if (len_plain.size() != 2)
                return false;
            detail::inc_nonce(nonce_);
            const auto body_len = static_cast<std::size_t>((len_plain[0] << 8) | len_plain[1]);
            if (data.size() < 2 + aead_tag_len + body_len)
                return false;
            return open_body(view(data.data() + 2 + aead_tag_len, body_len), out);
        }

    private:
        [[nodiscard]] auto current_nonce() const -> std::array<std::uint8_t, 12>
        {
            std::array<std::uint8_t, 12> nonce{};
            std::copy(nonce_.begin(), nonce_.end(), nonce.begin());
            return nonce;
        }

        std::array<std::uint8_t, key_len> key_{};
        std::array<std::uint8_t, 12> nonce_{}; ///< 全 0 起始，小端递增
    };

} // namespace psm_test::shadow2022
