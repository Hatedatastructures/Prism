/**
 * @file codec.hpp
 * @brief VMess 编解码（合并：认证头/请求头/响应头 + KDF + 分块 AEAD + 握手）
 * @details 对齐 mihomo/sing-vmess 的 VMess AEAD 头格式：
 *          sealVMessAEADHeader：
 *          [AuthID 16B][LenEnc 18B][Nonce 8B][HdrEnc（含 16B tag）]
 *          - AuthID = fnv1a(time_sec 8B BE || random 4B) 后 16 字节
 *          - LenEnc/HdrEnc 密钥 = KDF(cmdKey, salt, authID, nonce8)
 *          - AAD = authID
 *          请求头明文格式：
 *          [Version 1][IV 16][Key 16][V 1][OPT 1][P|Sec 1][RESV 1][CMD 1]
 *          [Port 2 BE][ATYP 1][Addr][Padding][FNV1a 4]
 *          另含：KDF 密钥派生（嵌套 HMAC-SHA256 链 + UUID→cmdKey）、
 *          AEAD 分块编解码（chunk_encryptor / chunk_decryptor 状态机）、
 *          握手 serializer/parser/chunk_stream/make_response。
 * @note 参考 mihomo transport/vmess/conn.go 与 header.go。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <expected>
#include <functional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

#include <common/core/error.hpp>
#include <common/protocols/vmess/types.hpp>

namespace preview::vmess
{

    namespace detail
    {

        /**
         * @brief HMAC-SHA256 单次
         * @param key 输入密钥
         * @param data 输入数据
         * @return 32 字节摘要
         */
        [[nodiscard]] inline auto hmac_sha256(std::span<const std::uint8_t> key,
                                              std::span<const std::uint8_t> data)
            -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(),
                 &len);
            return out;
        }

        /**
         * @brief MD5 摘要（16 字节）
         * @param data 输入数据
         * @return 16 字节摘要
         */
        [[nodiscard]] inline auto md5(std::span<const std::uint8_t> data) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_md5(), nullptr);
            return out;
        }

        /**
         * @brief SHA-256 摘要（32 字节）
         * @param data 输入数据
         * @return 32 字节摘要
         */
        [[nodiscard]] inline auto sha256(std::span<const std::uint8_t> data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr);
            return out;
        }

        /**
         * @brief 路径转字节视图（支持 string_view / span / array）
         * @tparam Path 路径类型
         * @param path 路径对象
         * @return 只读字节视图
         */
        template <typename Path>
        [[nodiscard]] inline auto as_bytes(const Path &path) -> std::span<const std::uint8_t>
        {
            if constexpr (std::is_convertible_v<Path, std::string_view>)
            {
                const std::string_view sv(path);
                return {reinterpret_cast<const std::uint8_t *>(sv.data()), sv.size()};
            }
            else
            {
                return std::span<const std::uint8_t>(path);
            }
        }

        /**
         * @brief 路径填充到 64 字节块（对齐 Go hmac copyPad）
         * @param path 路径字节
         * @param mask 异或掩码（0x36 / 0x5C）
         * @return 64 字节填充块
         */
        [[nodiscard]] inline auto xor_pad(std::span<const std::uint8_t> path, std::uint8_t mask)
            -> std::array<std::uint8_t, 64>
        {
            std::array<std::uint8_t, 64> out{};
            const auto n = std::min(path.size(), out.size());
            std::copy(path.begin(), path.begin() + static_cast<std::ptrdiff_t>(n), out.begin());
            for (auto &b : out)
            {
                b ^= mask;
            }
            return out;
        }

    } // namespace detail

    /**
     * @brief 执行 VMess AEAD KDF 链式哈希（对齐 Go 嵌套 HMAC 结构）
     * @tparam Path 路径类型（string_view / span / array）
     * @param key 初始密钥
     * @param paths KDF 路径列表
     * @return 32 字节派生密钥
     */
    template <typename... Path>
    [[nodiscard]] auto kdf(std::span<const std::uint8_t> key, const Path &...paths)
        -> std::array<std::uint8_t, 32>
    {
        std::function<std::array<std::uint8_t, 32>(std::span<const std::uint8_t>)> h =
            [](std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
        { return detail::hmac_sha256(detail::as_bytes(kdf_inner_marker), msg); };

        auto wrap = [&h](std::span<const std::uint8_t> path)
        {
            const auto prev = h;
            const auto ipad = detail::xor_pad(path, 0x36);
            const auto opad = detail::xor_pad(path, 0x5C);
            h = [prev, ipad, opad](std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
            {
                std::vector<std::uint8_t> inner_in(64 + msg.size());
                std::copy(ipad.begin(), ipad.end(), inner_in.begin());
                std::copy(msg.begin(), msg.end(), inner_in.begin() + 64);
                const auto inner = prev(inner_in);

                std::array<std::uint8_t, 64 + 32> outer_in{};
                std::copy(opad.begin(), opad.end(), outer_in.begin());
                std::copy(inner.begin(), inner.end(), outer_in.begin() + 64);
                return prev(outer_in);
            };
        };

        (wrap(detail::as_bytes(paths)), ...);
        return h(key);
    }

    /**
     * @brief 由 UUID 16 字节派生 cmdKey
     * @param uuid 16 字节 UUID 原始字节
     * @return 16 字节 cmdKey = MD5(uuid || uuid_salt)
     */
    [[nodiscard]] inline auto cmd_key_from_uuid(std::span<const std::uint8_t, 16> uuid)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16 + 36> input{};
        std::copy(uuid.begin(), uuid.end(), input.begin());
        const auto salt = detail::as_bytes(uuid_salt);
        std::copy(salt.begin(), salt.end(), input.begin() + 16);
        return detail::md5(input);
    }

    /**
     * @brief 解析 36 字符 UUID 字符串为 16 字节
     * @param uuid UUID 字符串
     * @param out 输出 16 字节
     * @return 成功返回 true
     */
    [[nodiscard]] inline auto parse_uuid(std::string_view uuid, std::span<std::uint8_t, 16> out) -> bool
    {
        if (uuid.size() != 36)
        {
            return false;
        }
        auto nibble = [](char c) -> int
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }
            return -1;
        };
        std::size_t pos = 0;
        for (std::size_t i = 0; i < uuid.size();)
        {
            if (uuid[i] == '-')
            {
                ++i;
                continue;
            }
            if (i + 1 >= uuid.size())
            {
                return false;
            }
            const int hi = nibble(uuid[i]);
            const int lo = nibble(uuid[i + 1]);
            if (hi < 0 || lo < 0)
            {
                return false;
            }
            out[pos++] = static_cast<std::uint8_t>((hi << 4) | lo);
            i += 2;
        }
        return pos == 16;
    }

    // ==================== codec.hpp（认证/请求/响应头）合并 ====================

    namespace detail
    {

        /**
         * @brief AES-GCM 加密输入（key + nonce + plain + aad）
         */
        struct seal_input
        {
            std::span<const std::uint8_t> key;   ///< 密钥
            std::span<const std::uint8_t> nonce; ///< nonce
            std::span<const std::uint8_t> plain; ///< 明文
            std::span<const std::uint8_t> aad;   ///< 附加认证数据
        };

        /**
         * @brief AES-GCM 解密输入（key + nonce + cipher + aad）
         */
        struct open_input
        {
            std::span<const std::uint8_t> key;    ///< 密钥
            std::span<const std::uint8_t> nonce;  ///< nonce
            std::span<const std::uint8_t> cipher; ///< 密文 + tag
            std::span<const std::uint8_t> aad;    ///< 附加认证数据
        };

        /**
         * @brief AES-128-GCM 加密（带 AAD）
         * @param in 加密输入
         * @return 密文 + 16 字节 tag；失败返回空
         */
        [[nodiscard]] inline auto aes_gcm_seal(const seal_input &in) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out(in.plain.size() + 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.nonce.data());
            if (!in.aad.empty())
            {
                EVP_EncryptUpdate(ctx, nullptr, &len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_EncryptUpdate(ctx, out.data(), &len, in.plain.data(), static_cast<int>(in.plain.size()));
            int out_len = len;
            EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + out_len);
            out.resize(static_cast<std::size_t>(out_len) + 16);
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        /**
         * @brief AES-128-GCM 解密（带 AAD），失败返回空
         * @param in 解密输入
         * @return 明文；失败返回空
         */
        [[nodiscard]] inline auto aes_gcm_open(const open_input &in) -> std::vector<std::uint8_t>
        {
            if (in.cipher.size() < 16)
            {
                return {};
            }
            std::vector<std::uint8_t> out(in.cipher.size() - 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.nonce.data());
            if (!in.aad.empty())
            {
                EVP_DecryptUpdate(ctx, nullptr, &len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_DecryptUpdate(ctx, out.data(), &len, in.cipher.data(),
                              static_cast<int>(in.cipher.size() - 16));
            int out_len = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(in.cipher.data()) + in.cipher.size() - 16);
            const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
            out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            if (ok != 1)
            {
                return {};
            }
            out.resize(static_cast<std::size_t>(out_len));
            return out;
        }

        /**
         * @brief FNV-1a 32 位（与 Go hash/fnv 一致）
         * @param data 输入数据
         * @return 32 位哈希
         */
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

        /**
         * @brief 时间戳编码（大端 8 字节）
         * @param ts 时间戳（秒）
         * @return 大端 8 字节
         */
        [[nodiscard]] inline auto encode_timestamp(std::int64_t ts) -> std::array<std::uint8_t, 8>
        {
            std::array<std::uint8_t, 8> out{};
            const auto u = static_cast<std::uint64_t>(ts);
            for (std::size_t i = 0; i < 8; ++i)
            {
                out[7 - i] = static_cast<std::uint8_t>((u >> (i * 8)) & 0xFF);
            }
            return out;
        }

    } // namespace detail

    /**
     * @brief 构造 AuthID：fnv1a(time_sec 8B BE || random 4B) 后 16 字节
     * @param time_sec UTC 秒
     * @param random 4 字节随机数
     * @return 16 字节 AuthID
     */
    [[nodiscard]] inline auto create_auth_id(std::int64_t time_sec, std::span<const std::uint8_t, 4> random)
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

    /**
     * @brief 认证头密封输入（body + 时间戳 + 随机数）
     */
    struct auth_header_input
    {
        std::span<const std::uint8_t> body;      ///< 明文载荷（请求头）
        std::int64_t time_sec{0};                ///< UTC 秒（AuthID 用）
        std::span<const std::uint8_t, 4> random; ///< 4 字节随机数
    };

    /**
     * @brief 密封 AEAD 认证头（sealVMessAEADHeader）
     * @param cmd_key 16 字节 cmdKey
     * @param in 输入（body + time_sec + random）
     * @return 认证头字节（16 authID + 18 len + 8 nonce + hdr_enc）
     */
    [[nodiscard]] inline auto seal_auth_header(std::span<const std::uint8_t, 16> cmd_key,
                                               const auth_header_input &in) -> std::vector<std::uint8_t>
    {
        const auto auth_id = create_auth_id(in.time_sec, in.random);
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
        std::array<std::uint8_t, 2> len_plain{static_cast<std::uint8_t>(in.body.size() >> 8),
                                              static_cast<std::uint8_t>(in.body.size() & 0xFF)};
        const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, nonce8);
        const auto len_iv = kdf(cmd_key, kdf_header_len_iv, auth_id, nonce8);
        const auto len_enc = detail::aes_gcm_seal(
            detail::seal_input{std::span<const std::uint8_t>(len_key.data(), 16),
                               std::span<const std::uint8_t>(len_iv.data(), 12), len_plain, auth_id});

        // 载荷密文
        const auto hdr_key = kdf(cmd_key, kdf_header_key, auth_id, nonce8);
        const auto hdr_iv = kdf(cmd_key, kdf_header_iv, auth_id, nonce8);
        const auto hdr_enc = detail::aes_gcm_seal(
            detail::seal_input{std::span<const std::uint8_t>(hdr_key.data(), 16),
                               std::span<const std::uint8_t>(hdr_iv.data(), 12), in.body, auth_id});

        std::vector<std::uint8_t> out;
        out.reserve(16 + len_enc.size() + 8 + hdr_enc.size());
        out.insert(out.end(), auth_id.begin(), auth_id.end());
        out.insert(out.end(), len_enc.begin(), len_enc.end());
        out.insert(out.end(), nonce8.begin(), nonce8.end());
        out.insert(out.end(), hdr_enc.begin(), hdr_enc.end());
        return out;
    }

    /**
     * @brief 打开 AEAD 认证头
     * @param cmd_key 16 字节 cmdKey
     * @param header 认证头（≥ 16+18+8+18）
     * @param out 输出明文载荷
     * @return 错误码（bad_auth = 解密失败，need_more = 数据不足）
     */
    [[nodiscard]] inline auto open_auth_header(std::span<const std::uint8_t, 16> cmd_key,
                                               std::span<const std::uint8_t> header,
                                               std::vector<std::uint8_t> &out) -> error
    {
        if (header.size() < 16 + 18 + 8 + 18)
        {
            return error::need_more;
        }
        const auto auth_id = header.first(16); // span 参数已含 first
        const auto len_enc = header.subspan(16, 18);
        const auto nonce8 = header.subspan(16 + 18, 8);

        const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, nonce8);
        const auto len_iv = kdf(cmd_key, kdf_header_len_iv, auth_id, nonce8);
        const auto len_plain = detail::aes_gcm_open(
            detail::open_input{std::span<const std::uint8_t>(len_key.data(), 16),
                               std::span<const std::uint8_t>(len_iv.data(), 12), len_enc, auth_id});
        if (len_plain.size() != 2)
        {
            return error::bad_auth;
        }
        const auto length = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

        const auto hdr_key = kdf(cmd_key, kdf_header_key, auth_id, nonce8);
        const auto hdr_iv = kdf(cmd_key, kdf_header_iv, auth_id, nonce8);
        const auto body =
            detail::aes_gcm_open(detail::open_input{std::span<const std::uint8_t>(hdr_key.data(), 16),
                                                    std::span<const std::uint8_t>(hdr_iv.data(), 12),
                                                    header.subspan(16 + 18 + 8, length + 16), auth_id});
        if (body.empty())
        {
            return error::bad_auth;
        }
        out = body;
        return error::none;
    }

    /**
     * @brief 请求头附加元数据（IV + Key + V + Padding）
     */
    struct request_meta
    {
        std::span<const std::uint8_t, 16> iv;  ///< 16 字节请求 IV（随机）
        std::span<const std::uint8_t, 16> key; ///< 16 字节请求 Key（随机）
        std::uint8_t v{0};                     ///< 响应验证字节（随机）
        std::uint8_t p{0};                     ///< 填充长度（0-15，P 高 4 位）
    };

    /**
     * @brief 编码请求头明文（Xray/sing 请求头格式）
     * @param hdr 请求头
     * @param meta 附加元数据（iv/key/v/p）
     * @return 明文字节序列（含 FNV1a 校验）
     */
    [[nodiscard]] inline auto build_request_header(const request_header &hdr, const request_meta &meta)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(64 + hdr.target.host.size());
        out.push_back(hdr.version);
        out.insert(out.end(), meta.iv.begin(), meta.iv.end());
        out.insert(out.end(), meta.key.begin(), meta.key.end());
        out.push_back(meta.v);
        out.push_back(static_cast<std::uint8_t>(hdr.opt)); // OPT
        out.push_back(static_cast<std::uint8_t>(((meta.p & 0x0F) << 4) | static_cast<std::uint8_t>(hdr.sec)));
        out.push_back(hdr.reserved);
        out.push_back(static_cast<std::uint8_t>(hdr.cmd));
        out.push_back(static_cast<std::uint8_t>((hdr.target.port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.target.port & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.target.type));
        switch (hdr.target.type)
        {
        case address_type::ipv4: {
            // 点分十进制 → 4 字节二进制（wire 格式为裸 4 字节）
            std::array<std::uint8_t, 4> ip{};
            std::size_t part = 0;
            std::uint32_t octet = 0;
            for (const auto b : hdr.target.host)
            {
                if (b == '.')
                {
                    if (part >= 4 || octet > 255)
                    {
                        return {};
                    }
                    ip[part++] = static_cast<std::uint8_t>(octet);
                    octet = 0;
                }
                else if (b >= '0' && b <= '9')
                {
                    octet = octet * 10 + static_cast<std::uint32_t>(b - '0');
                    if (octet > 255)
                    {
                        return {};
                    }
                }
            }
            if (part != 3 || octet > 255)
            {
                return {};
            }
            ip[part] = static_cast<std::uint8_t>(octet);
            out.insert(out.end(), ip.begin(), ip.end());
            break;
        }
        case address_type::ipv6: {
            // 文本形式（如 "::1"）解析为 16 字节二进制（线缆约定）；
            // 非法文本或已为 16 字节二进制的输入解析失败，原样拷贝
            boost::system::error_code ec;
            const auto v6 = boost::asio::ip::make_address_v6(hdr.target.host, ec);
            if (!ec)
            {
                const auto bytes = v6.to_bytes();
                out.insert(out.end(), bytes.begin(), bytes.end());
            }
            else
            {
                out.insert(out.end(), hdr.target.host.begin(), hdr.target.host.end());
            }
            break;
        }
        case address_type::domain:
        default: {
            out.push_back(static_cast<std::uint8_t>(hdr.target.host.size()));
            out.insert(out.end(), hdr.target.host.begin(), hdr.target.host.end());
            break;
        }
        }
        for (std::uint8_t i = 0; i < meta.p; ++i)
        {
            out.push_back(0);
        }
        // FNV1a 校验（明文数据 + 填充）
        const auto hash = detail::fnv1a32(out);
        out.push_back(static_cast<std::uint8_t>((hash >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hash >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((hash >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hash & 0xFF));
        return out;
    }

    /**
     * @brief 解析出的请求头元数据（IV + Key + V）
     */
    struct request_meta_out
    {
        std::array<std::uint8_t, 16> iv{};  ///< 请求 IV
        std::array<std::uint8_t, 16> key{}; ///< 请求 Key
        std::uint8_t v{0};                  ///< 响应验证字节
    };

    /**
     * @brief 解析请求头明文（校验 FNV1a）
     * @param data 明文
     * @param out 输出请求头
     * @param meta 输出元数据（iv/key/v）
     * @return 错误码
     */
    [[nodiscard]] inline auto parse_request_header(std::span<const std::uint8_t> data, request_header &out,
                                                   request_meta_out &meta) -> error
    {
        if (data.size() < 40) // 1+16+16+1+1+1+1+1+2+1 = 41
        {
            return error::need_more;
        }
        out.version = data[0];
        if (out.version != protocol_version)
        {
            return error::bad_magic;
        }
        std::memcpy(meta.iv.data(), data.data() + 1, 16);
        std::memcpy(meta.key.data(), data.data() + 17, 16);
        meta.v = data[33];
        out.opt = data[34];
        out.sec = static_cast<security>(data[35] & 0x0F);
        out.reserved = data[36];
        out.cmd = static_cast<command>(data[37]);
        out.target.port = static_cast<std::uint16_t>(data[38]) << 8 | data[39];
        out.target.type = static_cast<address_type>(data[40]);
        std::size_t off = 41;
        switch (out.target.type)
        {
        case address_type::ipv4: {
            if (data.size() < off + 4)
            {
                return error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", data[off], data[off + 1], data[off + 2],
                          data[off + 3]);
            out.target.host = buf.data();
            off += 4;
            break;
        }
        case address_type::ipv6: {
            if (data.size() < off + 16)
            {
                return error::need_more;
            }
            out.target.host.assign(reinterpret_cast<const char *>(data.data() + off), 16);
            off += 16;
            break;
        }
        case address_type::domain:
        default: {
            if (off >= data.size())
            {
                return error::need_more;
            }
            const auto len = data[off++];
            if (data.size() < off + len)
            {
                return error::need_more;
            }
            out.target.host.assign(reinterpret_cast<const char *>(data.data() + off), len);
            off += len;
            break;
        }
        }
        if (data.size() < off + 4)
        {
            return error::need_more;
        }
        // FNV1a 校验（覆盖整个明文头部 + padding）
        const auto hash = detail::fnv1a32(data.first(data.size() - 4));
        const auto expected = static_cast<std::uint32_t>(data[data.size() - 4]) << 24 |
                              static_cast<std::uint32_t>(data[data.size() - 3]) << 16 |
                              static_cast<std::uint32_t>(data[data.size() - 2]) << 8 |
                              static_cast<std::uint32_t>(data[data.size() - 1]);
        if (hash != expected)
        {
            return error::bad_auth;
        }
        return error::none;
    }

    /**
     * @brief 响应头密封输入（IV + V + AuthID）
     */
    struct resp_header_input
    {
        std::span<const std::uint8_t, 12> iv;      ///< 12 字节响应 IV
        std::span<const std::uint8_t, 4> v;        ///< 4 字节载荷（V + 随机 3 字节）
        std::span<const std::uint8_t, 16> auth_id; ///< 16 字节认证 ID（AAD）
    };

    /**
     * @brief 响应头解析输入（IV + 密文 + AuthID）
     */
    struct resp_header_parse_input
    {
        std::span<const std::uint8_t, 12> iv;      ///< 12 字节响应 IV
        std::span<const std::uint8_t> data;        ///< 响应头密文
        std::span<const std::uint8_t, 16> auth_id; ///< 16 字节认证 ID（AAD）
    };

    /**
     * @brief 密封响应头（AEAD Resp Header，AAD = authID）
     * @param resp_key 16 字节响应密钥
     * @param in 输入（iv + v + auth_id）
     * @return 响应头密文（4 + 16 tag）
     */
    [[nodiscard]] inline auto seal_response_header(std::span<const std::uint8_t, 16> resp_key,
                                                   const resp_header_input &in) -> std::vector<std::uint8_t>
    {
        return detail::aes_gcm_seal(detail::seal_input{resp_key, in.iv, in.v, in.auth_id});
    }

    /**
     * @brief 打开响应头
     * @param resp_key 16 字节响应密钥
     * @param in 输入（iv + data + auth_id）
     * @param out 输出响应头
     * @return 错误码
     */
    [[nodiscard]] inline auto open_response_header(std::span<const std::uint8_t, 16> resp_key,
                                                   const resp_header_parse_input &in, response_header &out)
        -> error
    {
        const auto plain = detail::aes_gcm_open(detail::open_input{resp_key, in.iv, in.data, in.auth_id});
        if (plain.size() < 4)
        {
            return error::bad_auth;
        }
        out.version = plain[0];
        std::memcpy(out.v.data(), plain.data(), 4);
        return error::none;
    }

    namespace detail
    {

        /**
         * @brief 单次 AES-128-GCM 加密（nonce 由调用方控制）
         * @param key 密钥
         * @param nonce 12 字节 nonce
         * @param plain 明文
         * @param out 输出密文（含 tag）
         */
        inline auto chunk_seal(std::span<const std::uint8_t> key, std::span<const std::uint8_t, 12> nonce,
                               std::span<const std::uint8_t> plain, std::span<std::uint8_t> out) -> void
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce.data());
            EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()));
            EVP_EncryptFinal_ex(ctx, out.data() + len, &len);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + plain.size());
            EVP_CIPHER_CTX_free(ctx);
        }

        /**
         * @brief 单次 AES-128-GCM 解密（失败返回 false）
         * @param key 密钥
         * @param nonce 12 字节 nonce
         * @param cipher 密文（含 tag）
         * @param out 输出明文
         * @return 校验成功返回 true
         */
        inline auto chunk_open(std::span<const std::uint8_t> key, std::span<const std::uint8_t, 12> nonce,
                               std::span<const std::uint8_t> cipher, std::span<std::uint8_t> out) -> bool
        {
            if (cipher.size() < 16)
            {
                return false;
            }
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

        /**
         * @brief nonce 递增（大端 +1）
         * @param nonce 12 字节 nonce（原地递增）
         */
        inline auto inc_nonce(std::span<std::uint8_t, 12> nonce) -> void
        {
            for (std::size_t i = nonce.size(); i > 0; --i)
            {
                if (++nonce[i - 1] != 0)
                {
                    break;
                }
            }
        }

    } // namespace detail

    /**
     * @brief VMess 分块加密器（状态机）
     */
    class chunk_encryptor
    {
    public:
        /// 分块开销：2 长度 + 16 长度 tag + 16 载荷 tag
        static constexpr std::size_t overhead = 2 + 16 + 16;

        /**
         * @brief 构造
         * @param key 16 字节分块密钥
         * @param nonce 12 字节起始 nonce
         */
        explicit chunk_encryptor(std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 12> nonce)
            : key_()
        {
            std::memcpy(key_.data(), key.data(), 16);
            std::memcpy(nonce_.data(), nonce.data(), 12);
        }

        /**
         * @brief 加密一块数据
         * @param plain 明文
         * @param out 输出（容量 ≥ plain.size() + overhead）
         * @return 写入字节数（含块头）
         */
        auto seal(std::span<const std::uint8_t> plain, std::span<std::uint8_t> out) -> std::size_t
        {
            const auto n = plain.size();
            if (out.size() < n + overhead)
            {
                return 0;
            }

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

        /**
         * @brief 结束块（长度 0）
         * @param out 输出（容量 ≥ 18）
         * @return 写入字节数
         */
        auto finish(std::span<std::uint8_t> out) -> std::size_t
        {
            return seal({}, out);
        }

    private:
        std::array<std::uint8_t, 16> key_;
        std::array<std::uint8_t, 12> nonce_;
    };

    /**
     * @brief VMess 分块解密器（状态机，支持增量两步解析）
     */
    class chunk_decryptor
    {
    public:
        /**
         * @brief 构造
         * @param key 16 字节分块密钥
         * @param nonce 12 字节起始 nonce
         */
        explicit chunk_decryptor(std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 12> nonce)
            : key_()
        {
            std::memcpy(key_.data(), key.data(), 16);
            std::memcpy(nonce_.data(), nonce.data(), 12);
        }

        /**
         * @brief 解密长度字段（2 字节密文 + 16 tag）
         * @param head 18 字节块头
         * @return 载荷长度（0 = 流结束）；错误码
         */
        auto open_len(std::span<const std::uint8_t> head) -> std::expected<std::size_t, error>
        {
            if (head.size() < 18)
            {
                return std::unexpected(error::need_more);
            }
            std::array<std::uint8_t, 2> len_plain{};
            if (!detail::chunk_open(key_, nonce_, head.first(18), len_plain))
            {
                return std::unexpected(error::bad_auth);
            }
            detail::inc_nonce(nonce_);
            const auto n = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];
            if (n > max_chunk_len)
            {
                return std::unexpected(error::bad_length);
            }
            return n;
        }

        /**
         * @brief 解密载荷字段（n 字节密文 + 16 tag）
         * @param data 载荷密文块（长度 + 16）
         * @param out 输出明文（长度 ≥ data.size() - 16）
         * @return 错误码
         */
        auto open_payload(std::span<const std::uint8_t> data, std::span<std::uint8_t> out) -> error
        {
            if (data.size() < 16 || out.size() < data.size() - 16)
            {
                return error::need_more;
            }
            if (!detail::chunk_open(key_, nonce_, data, out.first(data.size() - 16)))
            {
                return error::bad_auth;
            }
            detail::inc_nonce(nonce_);
            return error::none;
        }

        /**
         * @brief 解密一块数据（必须提供完整块：长度+tag+载荷+tag）
         * @param data 完整密文块
         * @param out 输出明文
         * @param consumed 输出消耗字节数
         * @return 错误码；need_more = 数据不足
         */
        auto open(std::span<const std::uint8_t> data, std::span<std::uint8_t> out, std::size_t &consumed)
            -> error
        {
            if (data.size() < 18)
            {
                return error::need_more;
            }
            auto len = open_len(data);
            if (!len)
            {
                return len.error();
            }
            if (*len == 0)
            {
                consumed = 18;
                return error::none; // 流结束
            }
            if (data.size() < 18 + *len + 16)
            {
                return error::need_more;
            }
            const auto ec = open_payload(data.subspan(18, *len + 16), out);
            if (ec != error::none)
            {
                return ec;
            }
            consumed = 18 + *len + 16;
            return error::none;
        }

    private:
        std::array<std::uint8_t, 16> key_;
        std::array<std::uint8_t, 12> nonce_;
    };

    // ==================== chunk.hpp（分块 AEAD）合并 ====================

    /**
     * @brief VMess 握手消息（Beast 风格，供 serializer/parser 使用）
     */
    struct message
    {
        /// 客户端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// 请求 nonce（作为请求头 IV）
        std::array<std::uint8_t, 16> request_nonce{};
        /// 请求密钥（作为请求头 Key）
        std::array<std::uint8_t, 16> request_key{};
        /// 命令字节（cmd_tcp / cmd_udp / cmd_mux）
        std::uint8_t cmd{cmd_tcp};
        /// 目标地址
        address dst;
        /// 响应验证字节（请求头 V，响应头回显）
        std::uint8_t resp_header{0};
    };

    /**
     * @brief VMess 握手序列化器（对象 → wire，Beast 风格）
     */
    class serializer
    {
    public:
        /**
         * @brief 构造
         * @param uuid 客户端 UUID（16 字节）
         */
        explicit serializer(const std::array<std::uint8_t, 16> &uuid) : uuid_(uuid)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         * @param time_sec UTC 秒（AuthID 用）
         */
        auto reset(const message &msg, std::uint64_t time_sec) -> void
        {
            const auto cmd_key = cmd_key_from_uuid(uuid_);
            request_header hdr;
            hdr.version = protocol_version;
            hdr.cmd = static_cast<command>(msg.cmd);
            hdr.opt = 0;
            hdr.sec = security::aes_128_gcm;
            hdr.reserved = 0;
            hdr.target = msg.dst;
            const auto body = build_request_header(
                hdr, request_meta{msg.request_nonce, msg.request_key, msg.resp_header, 0});

            std::random_device rd;
            std::array<std::uint8_t, 4> random{};
            for (auto &b : random)
            {
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            }
            wire_ = seal_auth_header(cmd_key,
                                     auth_header_input{body, static_cast<std::int64_t>(time_sec), random});
            offset_ = 0;
        }

        /**
         * @brief 增量输出
         * @param buffer 输出缓冲区
         * @param ec 错误码（成功 = 空）
         * @return 实际写入字节数
         */
        auto get(boost::asio::mutable_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(buffer.size(), wire_.size() - offset_);
            std::memcpy(buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto is_done() const -> bool
        {
            return offset_ >= wire_.size();
        }

    private:
        std::array<std::uint8_t, 16> uuid_;
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /**
     * @brief VMess 握手解析器（wire → 对象，Beast 风格）
     */
    class parser
    {
    public:
        /**
         * @brief 构造
         * @param uuid 客户端 UUID（16 字节，不匹配则 auth_failed）
         */
        explicit parser(const std::array<std::uint8_t, 16> &uuid) : uuid_(uuid)
        {
        }

        /**
         * @brief 增量喂入
         * @param buffer 输入缓冲区
         * @param ec 错误码（auth_failed = UUID 不匹配，need_more = 数据不足）
         * @return 已累积缓冲字节数
         */
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            if (done_)
            {
                return buf_.size();
            }
            const auto data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(buffer.data()),
                                                            buffer.size());
            buf_.insert(buf_.end(), data.begin(), data.end());
            if (buf_.size() < 16 + 18 + 8 + 18)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }

            const auto cmd_key = cmd_key_from_uuid(uuid_);
            const auto auth_id = std::span<const std::uint8_t>(buf_).first(16);
            const auto len_enc = std::span<const std::uint8_t>(buf_).subspan(16, 18);
            const auto nonce8 = std::span<const std::uint8_t>(buf_).subspan(34, 8);

            // 先解长度块，确定请求头密文总长
            const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, nonce8);
            const auto len_iv = kdf(cmd_key, kdf_header_len_iv, auth_id, nonce8);
            std::array<std::uint8_t, 16> lk{};
            std::memcpy(lk.data(), len_key.data(), 16);
            std::array<std::uint8_t, 12> liv{};
            std::memcpy(liv.data(), len_iv.data(), 12);
            const auto len_plain = detail::aes_gcm_open(detail::open_input{lk, liv, len_enc, auth_id});
            if (len_plain.size() != 2)
            {
                ec = make_error_code(error::auth_failed);
                return 0;
            }
            const auto length = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];
            const auto total = 16 + 18 + 8 + length + 16;
            if (buf_.size() < total)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }

            // 解请求头并校验 FNV1a
            std::vector<std::uint8_t> body;
            const auto err =
                open_auth_header(cmd_key, std::span<const std::uint8_t>(buf_).first(total), body);
            if (err != error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            request_header hdr{};
            request_meta_out meta{};
            const auto perr = parse_request_header(body, hdr, meta);
            if (perr != error::none)
            {
                ec = make_error_code(perr);
                return 0;
            }

            msg_.uuid = uuid_;
            msg_.request_nonce = meta.iv;
            msg_.request_key = meta.key;
            msg_.cmd = static_cast<std::uint8_t>(hdr.cmd);
            msg_.dst = hdr.target;
            msg_.resp_header = meta.v;
            done_ = true;
            return buf_.size();
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto is_done() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto get() const -> const message &
        {
            return msg_;
        }

        /**
         * @brief 重置
         */
        auto reset() -> void
        {
            buf_.clear();
            msg_ = message{};
            done_ = false;
        }

    private:
        std::array<std::uint8_t, 16> uuid_;
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

    /**
     * @brief VMess 会话级分块流（Beast 风格封装）
     * @details 内部持有独立 nonce 的加密器 / 解密器各一：
     *          encrypt 与 decrypt 各自推进 nonce，方向相反时密钥互逆。
     */
    class chunk_stream
    {
    public:
        /**
         * @brief 解密结果
         */
        struct result
        {
            /// 错误码（error::none 成功）
            std::error_code ec;
            /// 已消耗 wire 字节数
            std::size_t consumed{0};
        };

        /**
         * @brief 初始化
         * @param key 16 字节分块密钥
         * @param iv 16 字节分块 IV（chunk nonce 取前 12 字节）
         */
        auto init(std::span<const std::uint8_t, 16> key, std::span<const std::uint8_t, 16> iv) -> void
        {
            std::array<std::uint8_t, 12> nonce{};
            std::memcpy(nonce.data(), iv.data(), 12);
            enc_ = chunk_encryptor(key, nonce);
            dec_ = chunk_decryptor(key, nonce);
        }

        /**
         * @brief 加密一块载荷
         * @param payload 明文
         * @param wire 输出密文（含块头与 tag）
         * @return false = 成功
         */
        auto encrypt(std::span<const std::uint8_t> payload, std::string &wire) -> bool
        {
            std::vector<std::uint8_t> out(payload.size() + chunk_encryptor::overhead);
            const auto n = enc_.seal(payload, out);
            wire.assign(reinterpret_cast<const char *>(out.data()), n);
            return false;
        }

        /**
         * @brief 解密一块密文
         * @param wire 密文（完整块：长度 + tag + 载荷 + tag）
         * @param plain 输出明文
         * @return 解密结果
         * @note 结束块（长度 0）时 consumed = 18，明文为空串；
         *       计算明文长度前先校验，避免无符号下溢越界读。
         */
        auto decrypt(std::span<const std::uint8_t> wire, std::string &plain) -> result
        {
            result r;
            if (wire.size() < 18)
            {
                r.ec = make_error_code(error::need_more);
                return r;
            }
            std::vector<std::uint8_t> out(wire.size());
            std::size_t consumed = 0;
            const auto ec = dec_.open(wire, out, consumed);
            if (ec != error::none)
            {
                r.ec = make_error_code(ec);
                return r;
            }
            std::size_t plain_len;
            if (consumed >= 18 + 16)
            {
                plain_len = consumed - 18 - 16;
            }
            else
            {
                plain_len = 0;
            }
            plain.assign(reinterpret_cast<const char *>(out.data()), plain_len);
            r.consumed = consumed;
            return r;
        }

    private:
        chunk_encryptor enc_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
        chunk_decryptor dec_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
    };

    /**
     * @brief 构造 VMess AEAD 响应头（Beast 风格）
     * @details 响应 = [18B 长度块] + [20B 响应头块] = 38 字节：
     *          respBodyKey = sha256(request_key)[:16]
     *          respBodyIV  = sha256(request_nonce)[:16]
     *          AAD = 随机 AuthID（内部生成）
     * @param msg 请求消息（request_key / request_nonce / resp_header）
     * @param resp 输出响应字节
     * @return false = 成功
     */
    [[nodiscard]] inline auto make_response(const message &msg, std::string &resp) -> bool
    {
        const auto resp_body_key = detail::sha256(msg.request_key);
        const auto resp_body_iv = detail::sha256(msg.request_nonce);
        std::array<std::uint8_t, 16> resp_key16{};
        std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
        std::array<std::uint8_t, 16> resp_iv16{};
        std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);

        std::random_device rd;
        std::array<std::uint8_t, 4> random{};
        for (auto &b : random)
        {
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        }
        const auto auth_id = create_auth_id(static_cast<std::int64_t>(std::time(nullptr)), random);

        const std::array<std::uint8_t, 4> v_plain{msg.resp_header, 0, 0, 0};
        const auto resp_key = kdf(resp_key16, kdf_resp_key);
        const auto resp_iv = kdf(resp_iv16, kdf_resp_iv);
        std::array<std::uint8_t, 16> rk{};
        std::memcpy(rk.data(), resp_key.data(), 16);
        std::array<std::uint8_t, 12> riv{};
        std::memcpy(riv.data(), resp_iv.data(), 12);
        const auto resp_enc = seal_response_header(rk, resp_header_input{riv, v_plain, auth_id});

        const auto resp_len_key = kdf(resp_key16, kdf_resp_len_key);
        const auto resp_len_iv = kdf(resp_iv16, kdf_resp_len_iv);
        std::array<std::uint8_t, 16> rlk{};
        std::memcpy(rlk.data(), resp_len_key.data(), 16);
        std::array<std::uint8_t, 12> rliv{};
        std::memcpy(rliv.data(), resp_len_iv.data(), 12);
        const std::array<std::uint8_t, 2> resp_len_plain{static_cast<std::uint8_t>(resp_enc.size() >> 8),
                                                         static_cast<std::uint8_t>(resp_enc.size() & 0xFF)};
        const auto len_enc = detail::aes_gcm_seal(detail::seal_input{rlk, rliv, resp_len_plain, auth_id});

        resp.clear();
        resp.reserve(len_enc.size() + resp_enc.size());
        resp.insert(resp.end(), len_enc.begin(), len_enc.end());
        resp.insert(resp.end(), resp_enc.begin(), resp_enc.end());
        return false;
    }

} // namespace preview::vmess
