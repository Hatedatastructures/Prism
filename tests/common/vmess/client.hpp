/**
 * @file client.hpp
 * @brief VMess AEAD 客户端（握手编码 + 分块加密 + 响应解析）
 * @details 纯逻辑（无锁）：请求头构造、sealVMessAEADHeader、AEAD 分块。
 *          命名空间 psm_test::vmess，参考 mihomo transport/vmess/conn.go。
 */

#pragma once

#include <common/common.hpp>
#include <common/socks5/socks5.hpp>
#include <common/vmess/kdf.hpp>

#include <openssl/evp.h>

namespace psm_test::vmess
{

    inline constexpr std::uint8_t version = 0x04;
    inline constexpr std::uint8_t cmd_tcp = 0x01;
    inline constexpr std::uint8_t cmd_udp = 0x02;
    inline constexpr std::uint8_t opt_chunk_stream = 0x01;
    inline constexpr std::uint8_t security_aes128gcm = 0x03;
    inline constexpr std::uint8_t security_chacha20 = 0x04;
    inline constexpr std::uint8_t security_none = 0x05;

    using address = socks5::address;

    namespace detail
    {

        /// AES-128-GCM 加密（带 AAD）
        inline auto aes_gcm_seal(const view key16, const view nonce12, const view plain,
                                 const view aad) -> buffer
        {
            buffer out(plain.size() + 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return {};
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key16.data(), nonce12.data());
            if (!aad.empty())
                EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
            EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()));
            int out_len = len;
            EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + out_len);
            out.resize(static_cast<std::size_t>(out_len) + 16);
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        /// AES-128-GCM 解密（带 AAD），失败返回空
        inline auto aes_gcm_open(const view key16, const view nonce12, const view cipher,
                                 const view aad) -> buffer
        {
            if (cipher.size() < 16)
                return {};
            buffer out(cipher.size() - 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return {};
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key16.data(), nonce12.data());
            if (!aad.empty())
                EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), static_cast<int>(cipher.size() - 16));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(cipher.data() + cipher.size() - 16));
            if (EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len) <= 0)
            {
                EVP_CIPHER_CTX_free(ctx);
                return {};
            }
            out.resize(static_cast<std::size_t>(out_len) + static_cast<std::size_t>(len));
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

    } // namespace detail

    /**
     * @class client
     * @brief VMess AEAD 客户端
     */
    class client
    {
    public:
        explicit client(const std::span<const std::uint8_t> uuid)
            : cmd_key_(cmd_key(uuid))
        {
            std::copy(uuid.begin(), uuid.end(), uuid_.begin());
            std::srand(0);
        }

        /**
         * @brief 构造完整握手字节流（authID + 长度 + nonce + 加密请求头）
         * @param dst 目标地址
         * @param cmd TCP/UDP
         * @param time_sec UTC 秒
         * @return 握手字节（58 + header 长度）
         */
        [[nodiscard]] auto handshake(const address &dst, const std::uint8_t cmd,
                                     const std::uint64_t time_sec) -> buffer
        {
            // 请求头明文
            req_body_iv_ = rand16();
            req_body_key_ = rand16();
            const auto body_key_hash = detail::sha256(req_body_key_);
            const auto body_iv_hash = detail::sha256(req_body_iv_);
            std::copy(body_key_hash.begin(), body_key_hash.begin() + 16, resp_body_key_.begin());
            std::copy(body_iv_hash.begin(), body_iv_hash.begin() + 16, resp_body_iv_.begin());

            byte_writer w;
            w.write_u8(version);
            w.write_bytes(req_body_iv_);
            w.write_bytes(req_body_key_);
            resp_v_ = static_cast<std::uint8_t>(std::rand() & 0xFF);
            w.write_u8(resp_v_);
            w.write_u8(opt_chunk_stream);
            const std::uint8_t p = static_cast<std::uint8_t>(std::rand() % 16);
            w.write_u8(static_cast<std::uint8_t>((p << 4) | security_aes128gcm));
            w.write_u8(0); // RESV
            w.write_u8(cmd);
            w.write_u16(dst.port);
            encode_host(w, dst.type, dst.host);
            for (std::uint8_t i = 0; i < p; ++i)
                w.write_u8(static_cast<std::uint8_t>(std::rand() & 0xFF));
            w.write_u32(detail::fnv1a32(w.data()));

            return seal_header(w.data(), time_sec);
        }

        /// 解析服务端响应（[V 1][OPT 1] + AEAD 响应头长度 + AEAD 响应头）
        [[nodiscard]] auto parse_response(const view resp) -> bool
        {
            if (resp.size() < 4)
                return false;
            if (resp[0] != version)
                return false;
            // 响应头长度：KDF(respBodyKey, "AEAD Resp Header Len Key") 派生
            const auto len_key = kdf(resp_body_key_, "AEAD Resp Header Len Key");
            const auto len_iv = kdf(resp_body_key_, "AEAD Resp Header Len IV");
            const auto len_plain = detail::aes_gcm_open(
                view(len_key.data(), 16), view(len_iv.data(), 12),
                view(resp.data() + 2, 18), {});
            if (len_plain.size() != 2)
                return false;
            const auto header_len = static_cast<std::uint16_t>(
                (len_plain[0] << 8) | len_plain[1]);
            if (resp.size() < 20 + header_len)
                return false;
            const auto hdr_key = kdf(resp_body_key_, "AEAD Resp Header Key");
            const auto hdr_iv = kdf(resp_body_key_, "AEAD Resp Header IV");
            const auto hdr_plain = detail::aes_gcm_open(
                view(hdr_key.data(), 16), view(hdr_iv.data(), 12),
                view(resp.data() + 20, header_len), {});
            return !hdr_plain.empty();
        }

        /**
         * @brief 分块加密（VMess AEAD chunk）
         * @param plain 明文载荷
         * @param count 块计数（从 0 递增）
         * @return [len 2B 加密+tag][payload 加密+tag]
         */
        [[nodiscard]] auto encrypt_chunk(const view plain, const std::uint16_t count) const -> buffer
        {
            std::array<std::uint8_t, 2> len_plain{
                static_cast<std::uint8_t>((plain.size() + 16) >> 8),
                static_cast<std::uint8_t>((plain.size() + 16) & 0xFF)};
            const auto nonce = chunk_nonce(count);
            buffer out;
            const auto len_enc = detail::aes_gcm_seal(req_body_key_, nonce, len_plain, {});
            out.insert(out.end(), len_enc.begin(), len_enc.end());
            const auto body_enc = detail::aes_gcm_seal(req_body_key_, nonce, plain, {});
            out.insert(out.end(), body_enc.begin(), body_enc.end());
            return out;
        }

    private:
        [[nodiscard]] auto chunk_nonce(const std::uint16_t count) const -> std::array<std::uint8_t, 12>
        {
            std::array<std::uint8_t, 12> nonce{};
            nonce[0] = static_cast<std::uint8_t>(count >> 8);
            nonce[1] = static_cast<std::uint8_t>(count & 0xFF);
            for (std::size_t i = 0; i < 10; ++i)
                nonce[2 + i] = req_body_iv_[2 + i];
            return nonce;
        }

        [[nodiscard]] auto rand16() const -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            for (auto &b : out)
                b = static_cast<std::uint8_t>(std::rand() & 0xFF);
            return out;
        }

        /// sealVMessAEADHeader（header.go）
        [[nodiscard]] auto seal_header(const view plain, const std::uint64_t time_sec) -> buffer
        {
            std::array<std::uint8_t, 4> random4{};
            for (auto &b : random4)
                b = static_cast<std::uint8_t>(std::rand() & 0xFF);
            const auto auth_id = create_auth_id(cmd_key_, time_sec, random4);
            std::array<std::uint8_t, 8> nonce{};
            for (auto &b : nonce)
                b = static_cast<std::uint8_t>(std::rand() & 0xFF);

            const auto len_key = kdf(cmd_key_, {kdf_salt_header_len_key,
                                                std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                                std::string_view(reinterpret_cast<const char *>(nonce.data()), 8)});
            const auto len_iv = kdf(cmd_key_, {kdf_salt_header_len_iv,
                                               std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                               std::string_view(reinterpret_cast<const char *>(nonce.data()), 8)});
            std::array<std::uint8_t, 2> len_plain{
                static_cast<std::uint8_t>(plain.size() >> 8),
                static_cast<std::uint8_t>(plain.size() & 0xFF)};
            const auto len_enc = detail::aes_gcm_seal(
                view(len_key.data(), 16), view(len_iv.data(), 12), len_plain, auth_id);

            const auto hdr_key = kdf(cmd_key_, {kdf_salt_header_key,
                                                std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                                std::string_view(reinterpret_cast<const char *>(nonce.data()), 8)});
            const auto hdr_iv = kdf(cmd_key_, {kdf_salt_header_iv,
                                               std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                               std::string_view(reinterpret_cast<const char *>(nonce.data()), 8)});
            const auto hdr_enc = detail::aes_gcm_seal(
                view(hdr_key.data(), 16), view(hdr_iv.data(), 12), plain, auth_id);

            byte_writer w;
            w.write_bytes(auth_id);
            w.write_bytes(len_enc);
            w.write_bytes(nonce);
            w.write_bytes(hdr_enc);
            return w.data();
        }

        std::array<std::uint8_t, 16> uuid_{};
        std::array<std::uint8_t, 16> cmd_key_{};
        std::array<std::uint8_t, 16> req_body_iv_{};
        std::array<std::uint8_t, 16> req_body_key_{};
        std::array<std::uint8_t, 16> resp_body_key_{};
        std::array<std::uint8_t, 16> resp_body_iv_{};
        std::uint8_t resp_v_{0};
    };

} // namespace psm_test::vmess
