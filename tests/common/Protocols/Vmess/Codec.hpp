/**
 * @file Codec.hpp
 * @brief VMess 编解码（合并：认证头/请求头/响应头 + KDF + 分块 AEAD + 握手）
 * @details 对齐 mihomo/sing-vmess 的 VMess AEAD 头格式：
 *          sealVMessAEADHeader：
 *          [AuthID 16B][LenEnc 18B][Nonce 8B][HdrEnc（含 16B tag）]
 *          - AuthID = fnv1a(TimeSec 8B BE || random 4B) 后 16 字节
 *          - LenEnc/HdrEnc 密钥 = KDF(cmdKey, salt, authID, nonce8)
 *          - AAD = authID
 *          请求头明文格式：
 *          [Version 1][IV 16][Key 16][V 1][OPT 1][P|Sec 1][RESV 1][CMD 1]
 *          [Port 2 BE][ATYP 1][Addr][Padding][FNV1a 4]
 *          另含：KDF 密钥派生（嵌套 HMAC-SHA256 链 + UUID→cmdKey）、
 *          AEAD 分块编解码（ChunkEncryptor / ChunkDecryptor 状态机）、
 *          握手 Serializer/Parser/ChunkStream/MakeResponse。
 * @note 参考 mihomo transport/vmess/Conn.go 与 Header.go。
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

#include <common/Core/Error.hpp>
#include <common/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    namespace detail
    {

        /**
         * @brief HMAC-SHA256 单次
         * @param key 输入密钥
         * @param Data 输入数据
         * @return 32 字节摘要
         */
        [[nodiscard]] inline auto HmacSha256(std::span<const std::uint8_t> key,
                                              std::span<const std::uint8_t> Data)
            -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), Data.data(), Data.size(), out.data(),
                 &len);
            return out;
        }

        /**
         * @brief MD5 摘要（16 字节）
         * @param Data 输入数据
         * @return 16 字节摘要
         */
        [[nodiscard]] inline auto Md5(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            unsigned int len = 0;
            EVP_Digest(Data.data(), Data.size(), out.data(), &len, EVP_md5(), nullptr);
            return out;
        }

        /**
         * @brief SHA-256 摘要（32 字节）
         * @param Data 输入数据
         * @return 32 字节摘要
         */
        [[nodiscard]] inline auto Sha256(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            EVP_Digest(Data.data(), Data.size(), out.data(), &len, EVP_sha256(), nullptr);
            return out;
        }

        /**
         * @brief 路径转字节视图（支持 string_view / span / array）
         * @tparam Path 路径类型
         * @param Path 路径对象
         * @return 只读字节视图
         */
        template <typename Path>
        [[nodiscard]] inline auto AsBytes(const Path &obj) -> std::span<const std::uint8_t>
        {
            if constexpr (std::is_convertible_v<Path, std::string_view>)
            {
                const std::string_view sv(obj);
                return {reinterpret_cast<const std::uint8_t *>(sv.data()), sv.size()};
            }
            else
            {
                return std::span<const std::uint8_t>(obj);
            }
        }

        /**
         * @brief 路径填充到 64 字节块（对齐 Go hmac copyPad）
         * @param Path 路径字节
         * @param mask 异或掩码（0x36 / 0x5C）
         * @return 64 字节填充块
         */
        [[nodiscard]] inline auto XorPad(std::span<const std::uint8_t> Path, std::uint8_t mask)
            -> std::array<std::uint8_t, 64>
        {
            std::array<std::uint8_t, 64> out{};
            const auto n = std::min(Path.size(), out.size());
            std::copy(Path.begin(), Path.begin() + static_cast<std::ptrdiff_t>(n), out.begin());
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
    [[nodiscard]] auto Kdf(std::span<const std::uint8_t> key, const Path &...paths)
        -> std::array<std::uint8_t, 32>
    {
        std::function<std::array<std::uint8_t, 32>(std::span<const std::uint8_t>)> h =
            [](std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
        { return detail::HmacSha256(detail::AsBytes(KdfInnerMarker), msg); };

        auto wrap = [&h](std::span<const std::uint8_t> PathSpan)
        {
            const auto prev = h;
            const auto ipad = detail::XorPad(PathSpan, 0x36);
            const auto opad = detail::XorPad(PathSpan, 0x5C);
            h = [prev, ipad, opad](std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
            {
                std::vector<std::uint8_t> inner_in(64 + msg.size());
                std::copy(ipad.begin(), ipad.end(), inner_in.begin());
                std::copy(msg.begin(), msg.end(), inner_in.begin() + 64);
                const auto Inner = prev(inner_in);

                std::array<std::uint8_t, 64 + 32> outer_in{};
                std::copy(opad.begin(), opad.end(), outer_in.begin());
                std::copy(Inner.begin(), Inner.end(), outer_in.begin() + 64);
                return prev(outer_in);
            };
        };

        (wrap(detail::AsBytes(paths)), ...);
        return h(key);
    }

    /**
     * @brief 由 UUID 16 字节派生 cmdKey
     * @param uuid 16 字节 UUID 原始字节
     * @return 16 字节 cmdKey = MD5(uuid || UuidSalt)
     */
    [[nodiscard]] inline auto CmdKeyFromUuid(std::span<const std::uint8_t, 16> uuid)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16 + 36> input{};
        std::copy(uuid.begin(), uuid.end(), input.begin());
        const auto salt = detail::AsBytes(UuidSalt);
        std::copy(salt.begin(), salt.end(), input.begin() + 16);
        return detail::Md5(input);
    }

    /**
     * @brief 解析 36 字符 UUID 字符串为 16 字节
     * @param uuid UUID 字符串
     * @param out 输出 16 字节
     * @return 成功返回 true
     */
    [[nodiscard]] inline auto ParseUuid(std::string_view uuid, std::span<std::uint8_t, 16> out) -> bool
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

    // ==================== Codec.hpp（认证/请求/响应头）合并 ====================

    namespace detail
    {

        /**
         * @brief AES-GCM 加密输入（key + Nonce + plain + aad）
         */
        struct SealInput
        {
            std::span<const std::uint8_t> key;   ///< 密钥
            std::span<const std::uint8_t> Nonce; ///< Nonce
            std::span<const std::uint8_t> plain; ///< 明文
            std::span<const std::uint8_t> aad;   ///< 附加认证数据
        };

        /**
         * @brief AES-GCM 解密输入（key + Nonce + cipher + aad）
         */
        struct OpenInput
        {
            std::span<const std::uint8_t> key;    ///< 密钥
            std::span<const std::uint8_t> Nonce;  ///< Nonce
            std::span<const std::uint8_t> cipher; ///< 密文 + tag
            std::span<const std::uint8_t> aad;    ///< 附加认证数据
        };

        /**
         * @brief AES-128-GCM 加密（带 AAD）
         * @param in 加密输入
         * @return 密文 + 16 字节 tag；失败返回空
         */
        [[nodiscard]] inline auto AesGcmSeal(const SealInput &in) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out(in.plain.size() + 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.Nonce.data());
            if (!in.aad.empty())
            {
                EVP_EncryptUpdate(ctx, nullptr, &len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_EncryptUpdate(ctx, out.data(), &len, in.plain.data(), static_cast<int>(in.plain.size()));
            int OutLen = len;
            EVP_EncryptFinal_ex(ctx, out.data() + OutLen, &len);
            OutLen += len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + OutLen);
            out.resize(static_cast<std::size_t>(OutLen) + 16);
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        /**
         * @brief AES-128-GCM 解密（带 AAD），失败返回空
         * @param in 解密输入
         * @return 明文；失败返回空
         */
        [[nodiscard]] inline auto AesGcmOpen(const OpenInput &in) -> std::vector<std::uint8_t>
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
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.Nonce.data());
            if (!in.aad.empty())
            {
                EVP_DecryptUpdate(ctx, nullptr, &len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_DecryptUpdate(ctx, out.data(), &len, in.cipher.data(),
                              static_cast<int>(in.cipher.size() - 16));
            int OutLen = len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(in.cipher.data()) + in.cipher.size() - 16);
            const auto Ok = EVP_DecryptFinal_ex(ctx, out.data() + OutLen, &len);
            OutLen += len;
            EVP_CIPHER_CTX_free(ctx);
            if (Ok != 1)
            {
                return {};
            }
            out.resize(static_cast<std::size_t>(OutLen));
            return out;
        }

        /**
         * @brief FNV-1a 32 位（与 Go Hash/fnv 一致）
         * @param Data 输入数据
         * @return 32 位哈希
         */
        [[nodiscard]] inline auto Fnv1a32(std::span<const std::uint8_t> Data) -> std::uint32_t
        {
            std::uint32_t h = 0x811C9DC5;
            for (const auto b : Data)
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
        [[nodiscard]] inline auto EncodeTimestamp(std::int64_t ts) -> std::array<std::uint8_t, 8>
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
     * @brief 构造 AuthID：fnv1a(TimeSec 8B BE || random 4B) 后 16 字节
     * @param TimeSec UTC 秒
     * @param random 4 字节随机数
     * @return 16 字节 AuthID
     */
    [[nodiscard]] inline auto CreateAuthId(std::int64_t TimeSec, std::span<const std::uint8_t, 4> random)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 12> input{};
        const auto ts = detail::EncodeTimestamp(TimeSec);
        std::memcpy(input.data(), ts.data(), 8);
        std::memcpy(input.data() + 8, random.data(), 4);
        const auto h = detail::Fnv1a32(input);
        std::array<std::uint8_t, 16> out{};
        // 后 16 字节：fnv1a 结果填充（对齐 Go authID 派生）
        out[0] = static_cast<std::uint8_t>((h >> 24) & 0xFF);
        out[1] = static_cast<std::uint8_t>((h >> 16) & 0xFF);
        out[2] = static_cast<std::uint8_t>((h >> 8) & 0xFF);
        out[3] = static_cast<std::uint8_t>(h & 0xFF);
        // 扩展：Md5(authID 前 4 字节) 填充其余
        const auto ext = detail::Md5(std::span<const std::uint8_t>(out.data(), 4));
        std::memcpy(out.data() + 4, ext.data(), 12);
        return out;
    }

    /**
     * @brief 认证头密封输入（body + 时间戳 + 随机数）
     */
    struct AuthHeaderInput
    {
        std::span<const std::uint8_t> body;      ///< 明文载荷（请求头）
        std::int64_t TimeSec{0};                ///< UTC 秒（AuthID 用）
        std::span<const std::uint8_t, 4> random; ///< 4 字节随机数
    };

    /**
     * @brief 密封 AEAD 认证头（sealVMessAEADHeader）
     * @param CmdKey 16 字节 cmdKey
     * @param in 输入（body + TimeSec + random）
     * @return 认证头字节（16 authID + 18 len + 8 Nonce + HdrEnc）
     */
    [[nodiscard]] inline auto SealAuthHeader(std::span<const std::uint8_t, 16> CmdKey,
                                               const AuthHeaderInput &in) -> std::vector<std::uint8_t>
    {
        const auto AuthId = CreateAuthId(in.TimeSec, in.random);
        // 8 字节随机 Nonce
        std::array<std::uint8_t, 8> nonce8{};
        {
            std::random_device rd;
            const auto r = rd();
            std::memcpy(nonce8.data(), &r, 4);
            const auto r2 = rd();
            std::memcpy(nonce8.data() + 4, &r2, 4);
        }

        // 长度密文
        std::array<std::uint8_t, 2> LenPlain{static_cast<std::uint8_t>(in.body.size() >> 8),
                                              static_cast<std::uint8_t>(in.body.size() & 0xFF)};
        const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, nonce8);
        const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, nonce8);
        const auto LenEnc = detail::AesGcmSeal(
            detail::SealInput{std::span<const std::uint8_t>(LenKey.data(), 16),
                               std::span<const std::uint8_t>(LenIv.data(), 12), LenPlain, AuthId});

        // 载荷密文
        const auto HdrKey = Kdf(CmdKey, KdfHeaderKey, AuthId, nonce8);
        const auto HdrIv = Kdf(CmdKey, KdfHeaderIv, AuthId, nonce8);
        const auto HdrEnc = detail::AesGcmSeal(
            detail::SealInput{std::span<const std::uint8_t>(HdrKey.data(), 16),
                               std::span<const std::uint8_t>(HdrIv.data(), 12), in.body, AuthId});

        std::vector<std::uint8_t> out;
        out.reserve(16 + LenEnc.size() + 8 + HdrEnc.size());
        out.insert(out.end(), AuthId.begin(), AuthId.end());
        out.insert(out.end(), LenEnc.begin(), LenEnc.end());
        out.insert(out.end(), nonce8.begin(), nonce8.end());
        out.insert(out.end(), HdrEnc.begin(), HdrEnc.end());
        return out;
    }

    /**
     * @brief 打开 AEAD 认证头
     * @param CmdKey 16 字节 cmdKey
     * @param Header 认证头（≥ 16+18+8+18）
     * @param out 输出明文载荷
     * @return 错误码（bad_auth = 解密失败，need_more = 数据不足）
     */
    [[nodiscard]] inline auto OpenAuthHeader(std::span<const std::uint8_t, 16> CmdKey,
                                               std::span<const std::uint8_t> Header,
                                               std::vector<std::uint8_t> &out) -> Error
    {
        if (Header.size() < 16 + 18 + 8 + 18)
        {
            return Error::need_more;
        }
        const auto AuthId = Header.first(16); // span 参数已含 first
        const auto LenEnc = Header.subspan(16, 18);
        const auto nonce8 = Header.subspan(16 + 18, 8);

        const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, nonce8);
        const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, nonce8);
        const auto LenPlain = detail::AesGcmOpen(
            detail::OpenInput{std::span<const std::uint8_t>(LenKey.data(), 16),
                               std::span<const std::uint8_t>(LenIv.data(), 12), LenEnc, AuthId});
        if (LenPlain.size() != 2)
        {
            return Error::bad_auth;
        }
        const auto length = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];

        const auto HdrKey = Kdf(CmdKey, KdfHeaderKey, AuthId, nonce8);
        const auto HdrIv = Kdf(CmdKey, KdfHeaderIv, AuthId, nonce8);
        const auto body =
            detail::AesGcmOpen(detail::OpenInput{std::span<const std::uint8_t>(HdrKey.data(), 16),
                                                    std::span<const std::uint8_t>(HdrIv.data(), 12),
                                                    Header.subspan(16 + 18 + 8, length + 16), AuthId});
        if (body.empty())
        {
            return Error::bad_auth;
        }
        out = body;
        return Error::none;
    }

    /**
     * @brief 请求头附加元数据（IV + Key + V + Padding）
     */
    struct RequestMeta
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
    [[nodiscard]] inline auto BuildRequestHeader(const RequestHeader &hdr, const RequestMeta &meta)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        out.reserve(64 + hdr.Target.Host.size());
        out.push_back(hdr.Version);
        out.insert(out.end(), meta.iv.begin(), meta.iv.end());
        out.insert(out.end(), meta.key.begin(), meta.key.end());
        out.push_back(meta.v);
        out.push_back(static_cast<std::uint8_t>(hdr.opt)); // OPT
        out.push_back(static_cast<std::uint8_t>(((meta.p & 0x0F) << 4) | static_cast<std::uint8_t>(hdr.sec)));
        out.push_back(hdr.reserved);
        out.push_back(static_cast<std::uint8_t>(hdr.Cmd));
        out.push_back(static_cast<std::uint8_t>((hdr.Target.Port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.Target.Port & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.Target.Type));
        switch (hdr.Target.Type)
        {
        case AddressType::Ipv4: {
            // 点分十进制 → 4 字节二进制（wire 格式为裸 4 字节）
            std::array<std::uint8_t, 4> ip{};
            std::size_t part = 0;
            std::uint32_t octet = 0;
            for (const auto b : hdr.Target.Host)
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
        case AddressType::Ipv6: {
            // 文本形式（如 "::1"）解析为 16 字节二进制（线缆约定）；
            // 非法文本或已为 16 字节二进制的输入解析失败，原样拷贝
            boost::system::error_code ec;
            const auto v6 = boost::asio::ip::make_address_v6(hdr.Target.Host, ec);
            if (!ec)
            {
                const auto Bytes = v6.to_bytes();
                out.insert(out.end(), Bytes.begin(), Bytes.end());
            }
            else
            {
                out.insert(out.end(), hdr.Target.Host.begin(), hdr.Target.Host.end());
            }
            break;
        }
        case AddressType::Domain:
        default: {
            out.push_back(static_cast<std::uint8_t>(hdr.Target.Host.size()));
            out.insert(out.end(), hdr.Target.Host.begin(), hdr.Target.Host.end());
            break;
        }
        }
        for (std::uint8_t i = 0; i < meta.p; ++i)
        {
            out.push_back(0);
        }
        // FNV1a 校验（明文数据 + 填充）
        const auto Hash = detail::Fnv1a32(out);
        out.push_back(static_cast<std::uint8_t>((Hash >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Hash >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((Hash >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(Hash & 0xFF));
        return out;
    }

    /**
     * @brief 解析出的请求头元数据（IV + Key + V）
     */
    struct RequestMetaOut
    {
        std::array<std::uint8_t, 16> iv{};  ///< 请求 IV
        std::array<std::uint8_t, 16> key{}; ///< 请求 Key
        std::uint8_t v{0};                  ///< 响应验证字节
    };

    /**
     * @brief 解析请求头明文（校验 FNV1a）
     * @param Data 明文
     * @param out 输出请求头
     * @param meta 输出元数据（iv/key/v）
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseRequestHeader(std::span<const std::uint8_t> Data, RequestHeader &out,
                                                   RequestMetaOut &meta) -> Error
    {
        if (Data.size() < 40) // 1+16+16+1+1+1+1+1+2+1 = 41
        {
            return Error::need_more;
        }
        out.Version = Data[0];
        if (out.Version != ProtocolVersion)
        {
            return Error::bad_magic;
        }
        std::memcpy(meta.iv.data(), Data.data() + 1, 16);
        std::memcpy(meta.key.data(), Data.data() + 17, 16);
        meta.v = Data[33];
        out.opt = Data[34];
        out.sec = static_cast<Security>(Data[35] & 0x0F);
        out.reserved = Data[36];
        out.Cmd = Data[37];
        out.Target.Port = static_cast<std::uint16_t>(Data[38]) << 8 | Data[39];
        out.Target.Type = static_cast<AddressType>(Data[40]);
        std::size_t off = 41;
        switch (out.Target.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < off + 4)
            {
                return Error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[off], Data[off + 1], Data[off + 2],
                          Data[off + 3]);
            out.Target.Host = buf.data();
            off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < off + 16)
            {
                return Error::need_more;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + off), 16);
            off += 16;
            break;
        }
        case AddressType::Domain:
        default: {
            if (off >= Data.size())
            {
                return Error::need_more;
            }
            const auto len = Data[off++];
            if (Data.size() < off + len)
            {
                return Error::need_more;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + off), len);
            off += len;
            break;
        }
        }
        if (Data.size() < off + 4)
        {
            return Error::need_more;
        }
        // FNV1a 校验（覆盖整个明文头部 + padding）
        const auto Hash = detail::Fnv1a32(Data.first(Data.size() - 4));
        const auto expected = static_cast<std::uint32_t>(Data[Data.size() - 4]) << 24 |
                              static_cast<std::uint32_t>(Data[Data.size() - 3]) << 16 |
                              static_cast<std::uint32_t>(Data[Data.size() - 2]) << 8 |
                              static_cast<std::uint32_t>(Data[Data.size() - 1]);
        if (Hash != expected)
        {
            return Error::bad_auth;
        }
        return Error::none;
    }

    /**
     * @brief 响应头密封输入（IV + V + AuthID）
     */
    struct RespHeaderInput
    {
        std::span<const std::uint8_t, 12> iv;      ///< 12 字节响应 IV
        std::span<const std::uint8_t, 4> v;        ///< 4 字节载荷（V + 随机 3 字节）
        std::span<const std::uint8_t, 16> AuthId; ///< 16 字节认证 ID（AAD）
    };

    /**
     * @brief 响应头解析输入（IV + 密文 + AuthID）
     */
    struct RespHeaderParseInput
    {
        std::span<const std::uint8_t, 12> iv;      ///< 12 字节响应 IV
        std::span<const std::uint8_t> Data;        ///< 响应头密文
        std::span<const std::uint8_t, 16> AuthId; ///< 16 字节认证 ID（AAD）
    };

    /**
     * @brief 密封响应头（AEAD Resp Header，AAD = authID）
     * @param RespKey 16 字节响应密钥
     * @param in 输入（iv + v + AuthId）
     * @return 响应头密文（4 + 16 tag）
     */
    [[nodiscard]] inline auto SealResponseHeader(std::span<const std::uint8_t, 16> RespKey,
                                                   const RespHeaderInput &in) -> std::vector<std::uint8_t>
    {
        return detail::AesGcmSeal(detail::SealInput{RespKey, in.iv, in.v, in.AuthId});
    }

    /**
     * @brief 打开响应头
     * @param RespKey 16 字节响应密钥
     * @param in 输入（iv + Data + AuthId）
     * @param out 输出响应头
     * @return 错误码
     */
    [[nodiscard]] inline auto OpenResponseHeader(std::span<const std::uint8_t, 16> RespKey,
                                                   const RespHeaderParseInput &in, ResponseHeader &out)
        -> Error
    {
        const auto plain = detail::AesGcmOpen(detail::OpenInput{RespKey, in.iv, in.Data, in.AuthId});
        if (plain.size() < 4)
        {
            return Error::bad_auth;
        }
        out.Version = plain[0];
        std::memcpy(out.v.data(), plain.data(), 4);
        return Error::none;
    }

    namespace detail
    {

        /**
         * @brief 单次 AES-128-GCM 加密（Nonce 由调用方控制）
         * @param key 密钥
         * @param Nonce 12 字节 Nonce
         * @param plain 明文
         * @param out 输出密文（含 tag）
         */
        inline auto ChunkSeal(std::span<const std::uint8_t> key, std::span<const std::uint8_t, 12> Nonce,
                               std::span<const std::uint8_t> plain, std::span<std::uint8_t> out) -> void
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), Nonce.data());
            EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()));
            EVP_EncryptFinal_ex(ctx, out.data() + len, &len);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + plain.size());
            EVP_CIPHER_CTX_free(ctx);
        }

        /**
         * @brief 单次 AES-128-GCM 解密（失败返回 false）
         * @param key 密钥
         * @param Nonce 12 字节 Nonce
         * @param cipher 密文（含 tag）
         * @param out 输出明文
         * @return 校验成功返回 true
         */
        inline auto ChunkOpen(std::span<const std::uint8_t> key, std::span<const std::uint8_t, 12> Nonce,
                               std::span<const std::uint8_t> cipher, std::span<std::uint8_t> out) -> bool
        {
            if (cipher.size() < 16)
            {
                return false;
            }
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), Nonce.data());
            EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), static_cast<int>(cipher.size() - 16));
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - 16);
            const auto Ok = EVP_DecryptFinal_ex(ctx, out.data() + len, &len);
            EVP_CIPHER_CTX_free(ctx);
            return Ok == 1;
        }

        /**
         * @brief Nonce 递增（大端 +1）
         * @param Nonce 12 字节 Nonce（原地递增）
         */
        inline auto IncNonce(std::span<std::uint8_t, 12> Nonce) -> void
        {
            for (std::size_t i = Nonce.size(); i > 0; --i)
            {
                if (++Nonce[i - 1] != 0)
                {
                    break;
                }
            }
        }

    } // namespace detail

    /**
     * @brief VMess 分块加密器（状态机）
     */
    class ChunkEncryptor
    {
    public:
        /// 分块开销：2 长度 + 16 长度 tag + 16 载荷 tag
        static constexpr std::size_t overhead = 2 + 16 + 16;

        /**
         * @brief 构造
         * @param key 16 字节分块密钥
         * @param Nonce 12 字节起始 Nonce
         */
        explicit ChunkEncryptor(std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 12> Nonce)
            : key_()
        {
            std::memcpy(key_.data(), key.data(), 16);
            std::memcpy(nonce_.data(), Nonce.data(), 12);
        }

        /**
         * @brief 加密一块数据
         * @param plain 明文
         * @param out 输出（容量 ≥ plain.size() + overhead）
         * @return 写入字节数（含块头）
         */
        auto Seal(std::span<const std::uint8_t> plain, std::span<std::uint8_t> out) -> std::size_t
        {
            const auto n = plain.size();
            if (out.size() < n + overhead)
            {
                return 0;
            }

            // 长度字段（大端 2 字节）加密
            std::array<std::uint8_t, 2> LenPlain{};
            LenPlain[0] = static_cast<std::uint8_t>((n >> 8) & 0xFF);
            LenPlain[1] = static_cast<std::uint8_t>(n & 0xFF);
            std::array<std::uint8_t, 2 + 16> LenEnc{};
            detail::ChunkSeal(key_, nonce_, LenPlain, LenEnc);
            detail::IncNonce(nonce_);

            std::memcpy(out.data(), LenEnc.data(), LenEnc.size());

            // 载荷加密
            detail::ChunkSeal(key_, nonce_, plain, out.subspan(LenEnc.size()));
            detail::IncNonce(nonce_);
            return LenEnc.size() + n + 16;
        }

        /**
         * @brief 结束块（长度 0）
         * @param out 输出（容量 ≥ 18）
         * @return 写入字节数
         */
        auto Finish(std::span<std::uint8_t> out) -> std::size_t
        {
            return Seal({}, out);
        }

    private:
        std::array<std::uint8_t, 16> key_;
        std::array<std::uint8_t, 12> nonce_;
    };

    /**
     * @brief VMess 分块解密器（状态机，支持增量两步解析）
     */
    class ChunkDecryptor
    {
    public:
        /**
         * @brief 构造
         * @param key 16 字节分块密钥
         * @param Nonce 12 字节起始 Nonce
         */
        explicit ChunkDecryptor(std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 12> Nonce)
            : key_()
        {
            std::memcpy(key_.data(), key.data(), 16);
            std::memcpy(nonce_.data(), Nonce.data(), 12);
        }

        /**
         * @brief 解密长度字段（2 字节密文 + 16 tag）
         * @param head 18 字节块头
         * @return 载荷长度（0 = 流结束）；错误码
         */
        auto OpenLen(std::span<const std::uint8_t> head) -> std::expected<std::size_t, Error>
        {
            if (head.size() < 18)
            {
                return std::unexpected(Error::need_more);
            }
            std::array<std::uint8_t, 2> LenPlain{};
            if (!detail::ChunkOpen(key_, nonce_, head.first(18), LenPlain))
            {
                return std::unexpected(Error::bad_auth);
            }
            detail::IncNonce(nonce_);
            const auto n = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
            if (n > MaxChunkLen)
            {
                return std::unexpected(Error::bad_length);
            }
            return n;
        }

        /**
         * @brief 解密载荷字段（n 字节密文 + 16 tag）
         * @param Data 载荷密文块（长度 + 16）
         * @param out 输出明文（长度 ≥ Data.size() - 16）
         * @return 错误码
         */
        auto OpenPayload(std::span<const std::uint8_t> Data, std::span<std::uint8_t> out) -> Error
        {
            if (Data.size() < 16 || out.size() < Data.size() - 16)
            {
                return Error::need_more;
            }
            if (!detail::ChunkOpen(key_, nonce_, Data, out.first(Data.size() - 16)))
            {
                return Error::bad_auth;
            }
            detail::IncNonce(nonce_);
            return Error::none;
        }

        /**
         * @brief 解密一块数据（必须提供完整块：长度+tag+载荷+tag）
         * @param Data 完整密文块
         * @param out 输出明文
         * @param consumed 输出消耗字节数
         * @return 错误码；need_more = 数据不足
         */
        auto Open(std::span<const std::uint8_t> Data, std::span<std::uint8_t> out, std::size_t &consumed)
            -> Error
        {
            if (Data.size() < 18)
            {
                return Error::need_more;
            }
            auto len = OpenLen(Data);
            if (!len)
            {
                return len.error();
            }
            if (*len == 0)
            {
                consumed = 18;
                return Error::none; // 流结束
            }
            if (Data.size() < 18 + *len + 16)
            {
                return Error::need_more;
            }
            const auto ec = OpenPayload(Data.subspan(18, *len + 16), out);
            if (ec != Error::none)
            {
                return ec;
            }
            consumed = 18 + *len + 16;
            return Error::none;
        }

    private:
        std::array<std::uint8_t, 16> key_;
        std::array<std::uint8_t, 12> nonce_;
    };

    // ==================== chunk.hpp（分块 AEAD）合并 ====================

    /**
     * @brief VMess 握手消息（Beast 风格，供 Serializer/Parser 使用）
     */
    struct Message
    {
        /// 客户端 UUID（16 字节）
        std::array<std::uint8_t, 16> uuid{};
        /// 请求 Nonce（作为请求头 IV）
        std::array<std::uint8_t, 16> request_nonce{};
        /// 请求密钥（作为请求头 Key）
        std::array<std::uint8_t, 16> request_key{};
        /// 命令字节（cmd_tcp / cmd_udp / cmd_mux）
        std::uint8_t Cmd{static_cast<std::uint8_t>(Command::Tcp)};
        /// 目标地址
        Address dst;
        /// 响应验证字节（请求头 V，响应头回显）
        std::uint8_t RespHeader{0};
    };

    /**
     * @brief VMess 握手序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 构造
         * @param uuid 客户端 UUID（16 字节）
         */
        explicit Serializer(const std::array<std::uint8_t, 16> &uuid) : uuid_(uuid)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         * @param TimeSec UTC 秒（AuthID 用）
         */
        auto Reset(const Message &msg, std::uint64_t TimeSec) -> void
        {
            const auto CmdKey = CmdKeyFromUuid(uuid_);
            RequestHeader hdr;
            hdr.Version = ProtocolVersion;
            hdr.Cmd = msg.Cmd;
            hdr.opt = 0;
            hdr.sec = Security::aes_128_gcm;
            hdr.reserved = 0;
            hdr.Target = msg.dst;
            const auto body = BuildRequestHeader(
                hdr, RequestMeta{msg.request_nonce, msg.request_key, msg.RespHeader, 0});

            std::random_device rd;
            std::array<std::uint8_t, 4> random{};
            for (auto &b : random)
            {
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            }
            wire_ = SealAuthHeader(CmdKey,
                                     AuthHeaderInput{body, static_cast<std::int64_t>(TimeSec), random});
            offset_ = 0;
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ec 错误码（成功 = 空）
         * @return 实际写入字节数
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(Buffer.size(), wire_.size() - offset_);
            std::memcpy(Buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
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
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param uuid 客户端 UUID（16 字节，不匹配则 auth_failed）
         */
        explicit Parser(const std::array<std::uint8_t, 16> &uuid) : uuid_(uuid)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param ec 错误码（auth_failed = UUID 不匹配，need_more = 数据不足）
         * @return 已累积缓冲字节数
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            if (done_)
            {
                return buf_.size();
            }
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            buf_.insert(buf_.end(), Data.begin(), Data.end());
            if (buf_.size() < 16 + 18 + 8 + 18)
            {
                ec = make_error_code(Error::need_more);
                return 0;
            }

            const auto CmdKey = CmdKeyFromUuid(uuid_);
            const auto AuthId = std::span<const std::uint8_t>(buf_).first(16);
            const auto LenEnc = std::span<const std::uint8_t>(buf_).subspan(16, 18);
            const auto nonce8 = std::span<const std::uint8_t>(buf_).subspan(34, 8);

            // 先解长度块，确定请求头密文总长
            const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, nonce8);
            const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, nonce8);
            std::array<std::uint8_t, 16> lk{};
            std::memcpy(lk.data(), LenKey.data(), 16);
            std::array<std::uint8_t, 12> liv{};
            std::memcpy(liv.data(), LenIv.data(), 12);
            const auto LenPlain = detail::AesGcmOpen(detail::OpenInput{lk, liv, LenEnc, AuthId});
            if (LenPlain.size() != 2)
            {
                ec = make_error_code(Error::auth_failed);
                return 0;
            }
            const auto length = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
            const auto Total = 16 + 18 + 8 + length + 16;
            if (buf_.size() < Total)
            {
                ec = make_error_code(Error::need_more);
                return 0;
            }

            // 解请求头并校验 FNV1a
            std::vector<std::uint8_t> body;
            const auto err =
                OpenAuthHeader(CmdKey, std::span<const std::uint8_t>(buf_).first(Total), body);
            if (err != Error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            RequestHeader hdr{};
            RequestMetaOut meta{};
            const auto perr = ParseRequestHeader(body, hdr, meta);
            if (perr != Error::none)
            {
                ec = make_error_code(perr);
                return 0;
            }

            msg_.uuid = uuid_;
            msg_.request_nonce = meta.iv;
            msg_.request_key = meta.key;
            msg_.Cmd = static_cast<std::uint8_t>(hdr.Cmd);
            msg_.dst = hdr.Target;
            msg_.RespHeader = meta.v;
            done_ = true;
            return buf_.size();
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return msg_;
        }

        /**
         * @brief 重置
         */
        auto Reset() -> void
        {
            buf_.clear();
            msg_ = Message{};
            done_ = false;
        }

    private:
        std::array<std::uint8_t, 16> uuid_;
        std::vector<std::uint8_t> buf_;
        Message msg_{};
        bool done_{false};
    };

    /**
     * @brief VMess 会话级分块流（Beast 风格封装）
     * @details 内部持有独立 Nonce 的加密器 / 解密器各一：
     *          Encrypt 与 Decrypt 各自推进 Nonce，方向相反时密钥互逆。
     */
    class ChunkStream
    {
    public:
        /**
         * @brief 解密结果
         */
        struct Result
        {
            /// 错误码（Error::none 成功）
            std::error_code ec;
            /// 已消耗 wire 字节数
            std::size_t consumed{0};
        };

        /**
         * @brief 初始化
         * @param key 16 字节分块密钥
         * @param iv 16 字节分块 IV（chunk Nonce 取前 12 字节）
         */
        auto Init(std::span<const std::uint8_t, 16> key, std::span<const std::uint8_t, 16> iv) -> void
        {
            std::array<std::uint8_t, 12> Nonce{};
            std::memcpy(Nonce.data(), iv.data(), 12);
            enc_ = ChunkEncryptor(key, Nonce);
            dec_ = ChunkDecryptor(key, Nonce);
        }

        /**
         * @brief 加密一块载荷
         * @param payload 明文
         * @param wire 输出密文（含块头与 tag）
         * @return false = 成功
         */
        auto Encrypt(std::span<const std::uint8_t> payload, std::string &wire) -> bool
        {
            std::vector<std::uint8_t> out(payload.size() + ChunkEncryptor::overhead);
            const auto n = enc_.Seal(payload, out);
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
        auto Decrypt(std::span<const std::uint8_t> wire, std::string &plain) -> Result
        {
            Result r;
            if (wire.size() < 18)
            {
                r.ec = make_error_code(Error::need_more);
                return r;
            }
            std::vector<std::uint8_t> out(wire.size());
            std::size_t consumed = 0;
            const auto ec = dec_.Open(wire, out, consumed);
            if (ec != Error::none)
            {
                r.ec = make_error_code(ec);
                return r;
            }
            std::size_t PlainLen;
            if (consumed >= 18 + 16)
            {
                PlainLen = consumed - 18 - 16;
            }
            else
            {
                PlainLen = 0;
            }
            plain.assign(reinterpret_cast<const char *>(out.data()), PlainLen);
            r.consumed = consumed;
            return r;
        }

    private:
        ChunkEncryptor enc_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
        ChunkDecryptor dec_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
    };

    /**
     * @brief 构造 VMess AEAD 响应头（Beast 风格）
     * @details 响应 = [18B 长度块] + [20B 响应头块] = 38 字节：
     *          respBodyKey = Sha256(request_key)[:16]
     *          respBodyIV  = Sha256(request_nonce)[:16]
     *          AAD = 随机 AuthID（内部生成）
     * @param msg 请求消息（request_key / request_nonce / RespHeader）
     * @param resp 输出响应字节
     * @return false = 成功
     */
    [[nodiscard]] inline auto MakeResponse(const Message &msg, std::string &resp) -> bool
    {
        const auto RespBodyKey = detail::Sha256(msg.request_key);
        const auto RespBodyIv = detail::Sha256(msg.request_nonce);
        std::array<std::uint8_t, 16> RespKey16{};
        std::memcpy(RespKey16.data(), RespBodyKey.data(), 16);
        std::array<std::uint8_t, 16> RespIv16{};
        std::memcpy(RespIv16.data(), RespBodyIv.data(), 16);

        std::random_device rd;
        std::array<std::uint8_t, 4> random{};
        for (auto &b : random)
        {
            b = static_cast<std::uint8_t>(rd() & 0xFF);
        }
        const auto AuthId = CreateAuthId(static_cast<std::int64_t>(std::time(nullptr)), random);

        const std::array<std::uint8_t, 4> v_plain{msg.RespHeader, 0, 0, 0};
        const auto RespKey = Kdf(RespKey16, KdfRespKey);
        const auto RespIv = Kdf(RespIv16, KdfRespIv);
        std::array<std::uint8_t, 16> rk{};
        std::memcpy(rk.data(), RespKey.data(), 16);
        std::array<std::uint8_t, 12> riv{};
        std::memcpy(riv.data(), RespIv.data(), 12);
        const auto RespEnc = SealResponseHeader(rk, RespHeaderInput{riv, v_plain, AuthId});

        const auto RespLenKey = Kdf(RespKey16, KdfRespLenKey);
        const auto RespLenIv = Kdf(RespIv16, KdfRespLenIv);
        std::array<std::uint8_t, 16> rlk{};
        std::memcpy(rlk.data(), RespLenKey.data(), 16);
        std::array<std::uint8_t, 12> rliv{};
        std::memcpy(rliv.data(), RespLenIv.data(), 12);
        const std::array<std::uint8_t, 2> resp_LenPlain{static_cast<std::uint8_t>(RespEnc.size() >> 8),
                                                         static_cast<std::uint8_t>(RespEnc.size() & 0xFF)};
        const auto LenEnc = detail::AesGcmSeal(detail::SealInput{rlk, rliv, resp_LenPlain, AuthId});

        resp.clear();
        resp.reserve(LenEnc.size() + RespEnc.size());
        resp.insert(resp.end(), LenEnc.begin(), LenEnc.end());
        resp.insert(resp.end(), RespEnc.begin(), RespEnc.end());
        return false;
    }

} // namespace Preview::Vmess
