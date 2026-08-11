/**
 * @file codec.hpp
 * @brief VMess 请求/响应头编解码（纯函数，零状态）
 * @details 实现对齐 mihomo/sing-vmess 的 VMess AEAD 头格式：
 *          sealVMessAEADHeader：
 *          [AuthID 16B][LenEnc 18B][Nonce 8B][HdrEnc（含 16B tag）]
 *          - AuthID = fnv1a(time_sec 8B BE || random 4B) 后 16 字节
 *          - LenEnc/HdrEnc 密钥 = KDF(cmdKey, salt, authID, nonce8)
 *          - AAD = authID
 *          请求头明文格式：
 *          [Version 1][IV 16][Key 16][V 1][OPT 1][P|Sec 1][RESV 1][CMD 1]
 *          [Port 2 BE][ATYP 1][Addr][Padding][FNV1a 4]
 * @note 参考 mihomo transport/vmess/conn.go 与 header.go。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/vmess/kdf.hpp>

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <vector>

namespace psmtest::vmess
{

    namespace detail
    {

        /// AES-128-GCM 加密（带 AAD）
        [[nodiscard]] inline auto aes_gcm_seal(std::span<const std::uint8_t> key,
                                               std::span<const std::uint8_t> nonce,
                                               std::span<const std::uint8_t> plain,
                                               std::span<const std::uint8_t> aad)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out(plain.size() + 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return {};
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce.data());
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
        [[nodiscard]] inline auto aes_gcm_open(std::span<const std::uint8_t> key,
                                               std::span<const std::uint8_t> nonce,
                                               std::span<const std::uint8_t> cipher,
                                               std::span<const std::uint8_t> aad)
            -> std::vector<std::uint8_t>
        {
            if (cipher.size() < 16)
                return {};
            std::vector<std::uint8_t> out(cipher.size() - 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return {};
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce.data());
            if (!aad.empty())
                EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), static_cast<int>(cipher.size() - 16));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - 16);
            const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            if (ok != 1)
                return {};
            out.resize(static_cast<std::size_t>(out_len));
            return out;
        }

        /// FNV-1a 32 位（与 Go hash/fnv 一致）
        [[nodiscard]] inline auto fnv1a32(std::span<const std::uint8_t> data) -> std::uint32_t
        {
            std::uint32_t h = 0x811C9DC5;
            for (const auto b : data)
            {
                h ^= b;
                h *= 0x01000193;
            }
            return h;
        }

        /// 时间戳编码（大端 8 字节）
        [[nodiscard]] inline auto encode_timestamp(std::int64_t ts) -> std::array<std::uint8_t, 8>
        {
            std::array<std::uint8_t, 8> out{};
            const auto u = static_cast<std::uint64_t>(ts);
            for (std::size_t i = 0; i < 8; ++i)
                out[7 - i] = static_cast<std::uint8_t>((u >> (i * 8)) & 0xFF);
            return out;
        }

    } // namespace detail

    /// @brief 构造 AuthID：fnv1a(time_sec 8B BE || random 4B) 后 16 字节
    /// @param time_sec UTC 秒
    /// @param random 4 字节随机数
    /// @return 16 字节 AuthID
    [[nodiscard]] inline auto create_auth_id(std::int64_t time_sec,
                                             std::span<const std::uint8_t, 4> random)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 12> input{};
        const auto ts = detail::encode_timestamp(time_sec);
        std::memcpy(input.data(), ts.data(), 8);
        std::memcpy(input.data() + 8, random.data(), 4);
        const auto h = detail::fnv1a32(input);
        std::array<std::uint8_t, 16> out{};
        // 后 16 字节：fnv1a 结果填充（对齐 Go authID 派生）
        out[0] = static_cast<std::uint8_t>((h >> 24) & 0xFF);
        out[1] = static_cast<std::uint8_t>((h >> 16) & 0xFF);
        out[2] = static_cast<std::uint8_t>((h >> 8) & 0xFF);
        out[3] = static_cast<std::uint8_t>(h & 0xFF);
        // 扩展：md5(authID 前 4 字节) 填充其余
        const auto ext = detail::md5(std::span<const std::uint8_t>(out.data(), 4));
        std::memcpy(out.data() + 4, ext.data(), 12);
        return out;
    }

    /// @brief 密封 AEAD 认证头（sealVMessAEADHeader）
    /// @param cmd_key 16 字节 cmdKey
    /// @param body 明文载荷（请求头）
    /// @param time_sec UTC 秒
    /// @param random 4 字节随机数（AuthID 用）
    /// @return 认证头字节（16 authID + 18 len + 8 nonce + hdr_enc）
    [[nodiscard]] inline auto seal_auth_header(std::span<const std::uint8_t, 16> cmd_key,
                                               std::span<const std::uint8_t> body,
                                               std::int64_t time_sec,
                                               std::span<const std::uint8_t, 4> random)
        -> std::vector<std::uint8_t>
    {
        const auto auth_id = create_auth_id(time_sec, random);
        // 8 字节随机 nonce
        std::array<std::uint8_t, 8> nonce8{};
        {
            std::random_device rd;
            const auto r = rd();
            std::memcpy(nonce8.data(), &r, 4);
            const auto r2 = rd();
            std::memcpy(nonce8.data() + 4, &r2, 4);
        }

        // 长度密文
        std::array<std::uint8_t, 2> len_plain{
            static_cast<std::uint8_t>(body.size() >> 8),
            static_cast<std::uint8_t>(body.size() & 0xFF)};
        const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, nonce8);
        const auto len_iv = kdf(cmd_key, kdf_header_len_iv, auth_id, nonce8);
        const auto len_enc = detail::aes_gcm_seal(
            std::span<const std::uint8_t>(len_key.data(), 16),
            std::span<const std::uint8_t>(len_iv.data(), 12), len_plain, auth_id);

        // 载荷密文
        const auto hdr_key = kdf(cmd_key, kdf_header_key, auth_id, nonce8);
        const auto hdr_iv = kdf(cmd_key, kdf_header_iv, auth_id, nonce8);
        const auto hdr_enc = detail::aes_gcm_seal(
            std::span<const std::uint8_t>(hdr_key.data(), 16),
            std::span<const std::uint8_t>(hdr_iv.data(), 12), body, auth_id);

        std::vector<std::uint8_t> out;
        out.reserve(16 + len_enc.size() + 8 + hdr_enc.size());
        out.insert(out.end(), auth_id.begin(), auth_id.end());
        out.insert(out.end(), len_enc.begin(), len_enc.end());
        out.insert(out.end(), nonce8.begin(), nonce8.end());
        out.insert(out.end(), hdr_enc.begin(), hdr_enc.end());
        return out;
    }

    /// @brief 打开 AEAD 认证头
    /// @param cmd_key 16 字节 cmdKey
    /// @param header 认证头（≥ 16+18+8+18）
    /// @param out 输出明文载荷
    /// @return 错误码（bad_auth = 解密失败，need_more = 数据不足）
    [[nodiscard]] inline auto open_auth_header(std::span<const std::uint8_t, 16> cmd_key,
                                               std::span<const std::uint8_t> header,
                                               std::vector<std::uint8_t> &out) -> error
    {
        if (header.size() < 16 + 18 + 8 + 18)
            return error::need_more;
        const auto auth_id = header.first(16); // span 参数已含 first
        const auto len_enc = header.subspan(16, 18);
        const auto nonce8 = header.subspan(16 + 18, 8);

        const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, nonce8);
        const auto len_iv = kdf(cmd_key, kdf_header_len_iv, auth_id, nonce8);
        const auto len_plain = detail::aes_gcm_open(
            std::span<const std::uint8_t>(len_key.data(), 16),
            std::span<const std::uint8_t>(len_iv.data(), 12), len_enc, auth_id);
        if (len_plain.size() != 2)
            return error::bad_auth;
        const auto length = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

        const auto hdr_key = kdf(cmd_key, kdf_header_key, auth_id, nonce8);
        const auto hdr_iv = kdf(cmd_key, kdf_header_iv, auth_id, nonce8);
        const auto body = detail::aes_gcm_open(
            std::span<const std::uint8_t>(hdr_key.data(), 16),
            std::span<const std::uint8_t>(hdr_iv.data(), 12),
            header.subspan(16 + 18 + 8, length + 16), auth_id);
        if (body.empty())
            return error::bad_auth;
        out = body;
        return error::none;
    }

    /// @brief 编码请求头明文（Xray/sing 请求头格式）
    /// @param hdr 请求头
    /// @param iv 16 字节请求 IV（随机）
    /// @param key 16 字节请求 Key（随机）
    /// @param v 响应验证字节（随机）
    /// @param p 填充长度（0-15，P 高 4 位）
    /// @return 明文字节序列（含 FNV1a 校验）
    [[nodiscard]] inline auto build_request_header(const request_header &hdr,
                                                   std::span<const std::uint8_t, 16> iv,
                                                   std::span<const std::uint8_t, 16> key,
                                                   std::uint8_t v, std::uint8_t p)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(64 + hdr.target.host.size());
        out.push_back(hdr.version);
        out.insert(out.end(), iv.begin(), iv.end());
        out.insert(out.end(), key.begin(), key.end());
        out.push_back(v);
        out.push_back(static_cast<std::uint8_t>(hdr.opt)); // OPT
        out.push_back(static_cast<std::uint8_t>(((p & 0x0F) << 4) | static_cast<std::uint8_t>(hdr.sec)));
        out.push_back(hdr.reserved);
        out.push_back(static_cast<std::uint8_t>(hdr.cmd));
        out.push_back(static_cast<std::uint8_t>((hdr.target.port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.target.port & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.target.type));
        switch (hdr.target.type)
        {
            case address_type::ipv4:
            {
                // 点分十进制 → 4 字节二进制（wire 格式为裸 4 字节）
                std::array<std::uint8_t, 4> ip{};
                std::size_t part = 0;
                std::uint32_t octet = 0;
                for (const auto b : hdr.target.host)
                {
                    if (b == '.')
                    {
                        if (part >= 4 || octet > 255)
                            return {};
                        ip[part++] = static_cast<std::uint8_t>(octet);
                        octet = 0;
                    }
                    else if (b >= '0' && b <= '9')
                    {
                        octet = octet * 10 + static_cast<std::uint32_t>(b - '0');
                        if (octet > 255)
                            return {};
                    }
                }
                if (part != 3 || octet > 255)
                    return {};
                ip[part] = static_cast<std::uint8_t>(octet);
                out.insert(out.end(), ip.begin(), ip.end());
                break;
            }
            case address_type::ipv6:
            {
                out.insert(out.end(), hdr.target.host.begin(), hdr.target.host.end());
                break;
            }
            case address_type::domain:
            default:
            {
                out.push_back(static_cast<std::uint8_t>(hdr.target.host.size()));
                out.insert(out.end(), hdr.target.host.begin(), hdr.target.host.end());
                break;
            }
        }
        for (std::uint8_t i = 0; i < p; ++i)
            out.push_back(0);
        // FNV1a 校验（明文数据 + 填充）
        const auto hash = detail::fnv1a32(out);
        out.push_back(static_cast<std::uint8_t>((hash >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hash >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hash >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hash & 0xFF));
        return out;
    }

    /// @brief 解析请求头明文（校验 FNV1a）
    /// @param data 明文
    /// @param out 输出请求头
    /// @param iv 输出请求 IV
    /// @param key 输出请求 Key
    /// @param v 输出响应验证字节
    /// @return 错误码
    [[nodiscard]] inline auto parse_request_header(std::span<const std::uint8_t> data,
                                                   request_header &out,
                                                   std::array<std::uint8_t, 16> &iv,
                                                   std::array<std::uint8_t, 16> &key,
                                                   std::uint8_t &v) -> error
    {
        if (data.size() < 40) // 1+16+16+1+1+1+1+1+2+1 = 41
            return error::need_more;
        out.version = data[0];
        if (out.version != protocol_version)
            return error::bad_magic;
        std::memcpy(iv.data(), data.data() + 1, 16);
        std::memcpy(key.data(), data.data() + 17, 16);
        v = data[33];
        out.opt = data[34];
        out.sec = static_cast<security>(data[35] & 0x0F);
        out.reserved = data[36];
        out.cmd = static_cast<command>(data[37]);
        out.target.port = static_cast<std::uint16_t>(data[38]) << 8 | data[39];
        out.target.type = static_cast<address_type>(data[40]);
        std::size_t off = 41;
        switch (out.target.type)
        {
            case address_type::ipv4:
            {
                if (data.size() < off + 4)
                    return error::need_more;
                std::array<char, 16> buf{};
                std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u",
                              data[off], data[off + 1], data[off + 2], data[off + 3]);
                out.target.host = buf.data();
                off += 4;
                break;
            }
            case address_type::ipv6:
            {
                if (data.size() < off + 16)
                    return error::need_more;
                out.target.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
                off += 16;
                break;
            }
            case address_type::domain:
            default:
            {
                if (off >= data.size())
                    return error::need_more;
                const auto len = data[off++];
                if (data.size() < off + len)
                    return error::need_more;
                out.target.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
                off += len;
                break;
            }
        }
        if (data.size() < off + 4)
            return error::need_more;
        // FNV1a 校验（覆盖整个明文头部 + padding）
        const auto hash = detail::fnv1a32(data.first(data.size() - 4));
        const auto expected = static_cast<std::uint32_t>(data[data.size() - 4]) << 24 |
                              static_cast<std::uint32_t>(data[data.size() - 3]) << 16 |
                              static_cast<std::uint32_t>(data[data.size() - 2]) << 8 |
                              static_cast<std::uint32_t>(data[data.size() - 1]);
        if (hash != expected)
            return error::bad_auth;
        return error::none;
    }

    /// @brief 密封响应头（AEAD Resp Header，AAD = authID）
    /// @param resp_key 16 字节响应密钥（KDF(respBodyKey, "AEAD Resp Header Key")）
    /// @param resp_iv 12 字节响应 IV（KDF(respBodyKey, "AEAD Resp Header IV")）
    /// @param v 4 字节载荷（V + 随机 3 字节）
    /// @param auth_id 16 字节认证 ID（AAD）
    /// @return 响应头密文（4 + 16 tag）
    [[nodiscard]] inline auto seal_response_header(std::span<const std::uint8_t, 16> resp_key,
                                                   std::span<const std::uint8_t, 12> resp_iv,
                                                   std::span<const std::uint8_t, 4> v,
                                                   std::span<const std::uint8_t, 16> auth_id)
        -> std::vector<std::uint8_t>
    {
        return detail::aes_gcm_seal(resp_key, resp_iv, v, auth_id);
    }

    /// @brief 打开响应头
    /// @param resp_key 16 字节响应密钥
    /// @param resp_iv 12 字节响应 IV
    /// @param data 响应头密文
    /// @param auth_id 16 字节认证 ID（AAD）
    /// @param out 输出响应头
    /// @return 错误码
    [[nodiscard]] inline auto open_response_header(std::span<const std::uint8_t, 16> resp_key,
                                                   std::span<const std::uint8_t, 12> resp_iv,
                                                   std::span<const std::uint8_t> data,
                                                   std::span<const std::uint8_t, 16> auth_id,
                                                   response_header &out) -> error
    {
        const auto plain = detail::aes_gcm_open(resp_key, resp_iv, data, auth_id);
        if (plain.size() < 4)
            return error::bad_auth;
        out.version = plain[0];
        std::memcpy(out.v.data(), plain.data(), 4);
        return error::none;
    }

} // namespace psmtest::vmess
