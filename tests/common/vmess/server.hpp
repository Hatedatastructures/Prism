/**
 * @file server.hpp
 * @brief VMess AEAD 服务端（握手解析 + 分块解密）
 * @details 纯逻辑（无锁）：AuthID 时间窗口校验、AEAD 头解密、请求头解析。
 *          命名空间 psm_test::vmess，参考 mihomo transport/vmess/conn.go。
 */

#pragma once

#include <common/common.hpp>
#include <common/vmess/kdf.hpp>
#include <common/vmess/client.hpp>

namespace psm_test::vmess
{

    /**
     * @class server
     * @brief VMess AEAD 服务端
     */
    class server
    {
    public:
        explicit server(const std::span<const std::uint8_t> uuid)
            : cmd_key_(cmd_key(uuid))
        {
            std::copy(uuid.begin(), uuid.end(), uuid_.begin());
        }

        /// 解析结果
        struct request
        {
            std::uint8_t cmd{cmd_tcp};
            address dst;
            bool valid{false};
        };

        /**
         * @brief 解析握手字节（58 + header 长度）
         * @param data 完整握手字节
         * @param time_sec 当前 UTC 秒（时间窗口校验）
         * @param window 时间窗口（秒）
         */
        [[nodiscard]] auto parse(const view data, const std::uint64_t time_sec,
                                 const std::uint64_t window = 90) -> request
        {
            request req;
            if (data.size() < 58)
                return req;
            const view auth_id(data.data(), 16);
            const view len_enc(data.data() + 16, 18);
            const view conn_nonce(data.data() + 34, 8);
            const view hdr_enc(data.data() + 42, data.size() - 42);

            // 时间窗口校验：解密 authID 前先重建明文（time + random + crc）
            std::array<std::uint8_t, 16> auth_plain{};
            const auto aes_key = kdf(cmd_key_, kdf_salt_auth_id_enc);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return req;
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, aes_key.data(), nullptr);
            EVP_CIPHER_CTX_set_padding(ctx, 0); // AES-ECB 单块，禁用 PKCS7 padding
            EVP_DecryptUpdate(ctx, auth_plain.data(), &len, auth_id.data(), 16);
            EVP_CIPHER_CTX_free(ctx);

            std::uint64_t ts = 0;
            for (std::size_t i = 0; i < 8; ++i)
                ts = (ts << 8) | auth_plain[i];
            const auto diff = time_sec > ts ? time_sec - ts : ts - time_sec;
            if (diff > window)
                return req;
            // CRC32 校验
            const auto crc_calc = detail::crc32_ieee(view(auth_plain.data(), 12));
            const auto crc_stored = static_cast<std::uint32_t>(
                static_cast<std::uint32_t>(auth_plain[12]) << 24
                | static_cast<std::uint32_t>(auth_plain[13]) << 16
                | static_cast<std::uint32_t>(auth_plain[14]) << 8 | auth_plain[15]);
            if (crc_calc != crc_stored)
                return req;

            // 解密头长度
            const auto len_key = kdf(cmd_key_, {kdf_salt_header_len_key,
                                                std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                                std::string_view(reinterpret_cast<const char *>(conn_nonce.data()), 8)});
            const auto len_iv = kdf(cmd_key_, {kdf_salt_header_len_iv,
                                               std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                               std::string_view(reinterpret_cast<const char *>(conn_nonce.data()), 8)});
            const auto len_plain = detail::aes_gcm_open(
                view(len_key.data(), 16), view(len_iv.data(), 12), len_enc, auth_id);
            if (len_plain.size() != 2)
                return req;
            const auto hdr_len = static_cast<std::size_t>((len_plain[0] << 8) | len_plain[1]);
            if (hdr_enc.size() < hdr_len + 16)
                return req;

            // 解密请求头
            const auto hdr_key = kdf(cmd_key_, {kdf_salt_header_key,
                                                std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                                std::string_view(reinterpret_cast<const char *>(conn_nonce.data()), 8)});
            const auto hdr_iv = kdf(cmd_key_, {kdf_salt_header_iv,
                                               std::string_view(reinterpret_cast<const char *>(auth_id.data()), 16),
                                               std::string_view(reinterpret_cast<const char *>(conn_nonce.data()), 8)});
            const auto plain = detail::aes_gcm_open(
                view(hdr_key.data(), 16), view(hdr_iv.data(), 12),
                view(hdr_enc.data(), hdr_len + 16), auth_id);
            if (plain.empty())
                return req;

            // 解析请求头明文
            byte_reader r(plain);
            std::uint8_t ver = 0, opt = 0, ps = 0, resv = 0;
            std::array<std::uint8_t, 16> iv{}, key{};
            if (!r.read_u8(ver) || ver != version)
                return req;
            const auto iv_v = r.read(16);
            const auto key_v = r.read(16);
            if (iv_v.size() != 16 || key_v.size() != 16)
                return req;
            std::copy(iv_v.begin(), iv_v.end(), iv.begin());
            std::copy(key_v.begin(), key_v.end(), key.begin());
            std::uint8_t resp_v = 0;
            if (!r.read_u8(resp_v) || !r.read_u8(opt) || !r.read_u8(ps) || !r.read_u8(resv))
                return req;
            if (!r.read_u8(req.cmd))
                return req;
            const auto pad_len = static_cast<std::size_t>(ps >> 4);
            const auto security = ps & 0x0F;
            if (security != security_aes128gcm && security != security_none)
                return req;
            if (!r.read_u16(req.dst.port))
                return req;
            if (!parse_host(r, req.dst.type, req.dst.host))
                return req;
            // 跳过 padding
            if (!r.skip(pad_len))
                return req;
            // FNV1a 校验
            const auto hash_v = r.read(4);
            if (hash_v.size() != 4)
                return req;
            const auto hash_calc = detail::fnv1a32(view(plain.data(), plain.size() - 4));
            const auto hash_stored = static_cast<std::uint32_t>(
                static_cast<std::uint32_t>(hash_v[0]) << 24
                | static_cast<std::uint32_t>(hash_v[1]) << 16
                | static_cast<std::uint32_t>(hash_v[2]) << 8 | hash_v[3]);
            if (hash_calc != hash_stored)
                return req;

            // 保存分块密钥
            req_body_key_ = key;
            req_body_iv_ = iv;
            req.valid = true;
            return req;
        }

        /**
         * @brief 分块解密（AEAD chunk）
         * @param data [len 2B 加密+tag][payload 加密+tag]
         * @param count 块计数（从 0 递增）
         * @param out 明文输出（失败返回 false）
         */
        [[nodiscard]] auto decrypt_chunk(const view data, const std::uint16_t count,
                                         buffer &out) -> bool
        {
            if (data.size() < 18)
                return false;
            const auto nonce = chunk_nonce(count);
            const auto len_plain = detail::aes_gcm_open(
                req_body_key_, nonce, view(data.data(), 18), {});
            if (len_plain.size() != 2)
                return false;
            const auto body_len = static_cast<std::size_t>((len_plain[0] << 8) | len_plain[1]);
            if (body_len < 16 || data.size() < 18 + body_len)
                return false;
            out = detail::aes_gcm_open(
                req_body_key_, nonce, view(data.data() + 18, body_len), {});
            return !out.empty();
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

        std::array<std::uint8_t, 16> uuid_{};
        std::array<std::uint8_t, 16> cmd_key_{};
        std::array<std::uint8_t, 16> req_body_key_{};
        std::array<std::uint8_t, 16> req_body_iv_{};
    };

} // namespace psm_test::vmess
