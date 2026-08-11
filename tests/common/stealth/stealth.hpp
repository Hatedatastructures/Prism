/**
 * @file stealth.hpp
 * @brief TLS 伪装方案基础工具（ShadowTLS / Restls / AnyTLS / TrustTunnel）
 * @details 提供各伪装方案的核心纯逻辑函数：
 *          - shadowtls：首包打包/解析 + SHA256 哈希
 *          - restls：认证密钥派生 + 认证载荷
 *          - anytls：会话密钥派生 + 认证帧
 *          - trusttunnel：Basic Auth + HTTP/2 CONNECT 头
 * @note 参考各方案协议规范（ShadowTLS v3 / Restls / AnyTLS / TrustTunnel）。
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psmtest::stealth
{

    /// ShadowTLS 相关
    namespace shadowtls
    {
        /// SHA256 摘要长度
        inline constexpr std::size_t hash_len = 32;

        /// 首包固定前缀长度
        inline constexpr std::size_t prefix_len = 5;

        /// @brief 计算认证哈希：HMAC-SHA256(password, handshake)
        /// @param password 密码
        /// @param handshake TLS 握手前缀
        /// @param out 输出 32 字节
        auto compute_hash(std::string_view password,
                          std::span<const std::uint8_t> handshake,
                          std::span<std::uint8_t, hash_len> out) -> void
        {
            unsigned int len = 0;
            HMAC(EVP_sha256(), password.data(), static_cast<int>(password.size()),
                 handshake.data(), handshake.size(), out.data(), &len);
        }

        /// @brief 构造首包：[前缀 5B][哈希 32B][原始握手]
        /// @param password 密码
        /// @param handshake TLS 握手前缀
        /// @param payload 附加载荷
        /// @param out 输出首包
        /// @return 成功返回 false
        auto build_first_packet(std::string_view password,
                                std::span<const std::uint8_t> handshake,
                                std::span<const std::uint8_t> payload,
                                std::string &out) -> bool
        {
            out.clear();
            out.reserve(prefix_len + hash_len + handshake.size() + payload.size());
            out.append("\x16\x03\x01\x00\x00", prefix_len); // 简化 TLS 记录头
            std::array<std::uint8_t, hash_len> hash{};
            compute_hash(password, handshake, hash);
            out.append(reinterpret_cast<const char *>(hash.data()), hash_len);
            out.append(reinterpret_cast<const char *>(handshake.data()), handshake.size());
            out.append(reinterpret_cast<const char *>(payload.data()), payload.size());
            return false;
        }

        /// @brief 解析首包
        /// @param pkt 首包
        /// @param hash 输出哈希（32 字节）
        /// @param offset 输出数据偏移
        /// @return 成功返回 false
        auto parse_first_packet(std::span<const std::uint8_t> pkt,
                                std::array<std::uint8_t, hash_len> &hash,
                                std::size_t &offset) -> bool
        {
            if (pkt.size() < prefix_len + hash_len)
                return true;
            std::memcpy(hash.data(), pkt.data() + prefix_len, hash_len);
            offset = prefix_len + hash_len;
            return false;
        }
    } // namespace shadowtls

    /// Restls 相关
    namespace restls
    {
        /// 认证载荷长度
        inline constexpr std::size_t auth_payload_len = 33;

        /// @brief 派生认证密钥（简化：SHA256(password || handshake || ctx)）
        /// @param password 密码
        /// @param handshake TLS 握手前缀
        /// @param key 输出 32 字节
        /// @return 成功返回 false
        auto derive_auth_key(std::string_view password,
                             std::span<const std::uint8_t> handshake,
                             std::span<std::uint8_t, 32> key) -> bool
        {
            std::vector<std::uint8_t> material;
            material.insert(material.end(), password.begin(), password.end());
            material.insert(material.end(), handshake.begin(), handshake.end());
            unsigned int len = 0;
            EVP_Digest(material.data(), material.size(), key.data(), &len, EVP_sha256(), nullptr);
            return false;
        }

        /// @brief 构造认证载荷：[版本 1B][密钥 32B]
        /// @param version 版本号
        /// @param key 认证密钥（32 字节）
        /// @param out 输出载荷（33 字节）
        /// @return 成功返回 false
        auto build_auth_payload(std::uint8_t version,
                                std::span<const std::uint8_t, 32> key,
                                std::span<std::uint8_t, auth_payload_len> out) -> bool
        {
            out[0] = version;
            std::memcpy(out.data() + 1, key.data(), 32);
            return false;
        }
    } // namespace restls

    /// AnyTLS 相关
    namespace anytls
    {
        /// @brief 派生会话密钥（简化：HMAC-SHA256(secret, context)）
        /// @param secret 会话密钥
        /// @param salt 盐（可空）
        /// @param context 上下文
        /// @param key 输出 32 字节
        /// @return 成功返回 false
        auto derive_session_key(std::span<const std::uint8_t> secret,
                                std::span<const std::uint8_t> salt,
                                std::string_view context,
                                std::span<std::uint8_t, 32> key) -> bool
        {
            unsigned int len = 0;
            HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
                 reinterpret_cast<const std::uint8_t *>(context.data()), context.size(),
                 key.data(), &len);
            (void)salt;
            return false;
        }

        /// @brief 构造认证帧：[类型 1B][长度 1B][载荷]
        /// @param payload 载荷
        /// @param out 输出帧
        /// @return 成功返回 false
        auto build_auth_frame(std::span<const std::uint8_t> payload, std::string &out) -> bool
        {
            out.clear();
            out.reserve(2 + payload.size());
            out.push_back(0);
            out.push_back(static_cast<char>(payload.size()));
            out.append(reinterpret_cast<const char *>(payload.data()), payload.size());
            return false;
        }
    } // namespace anytls

    /// TrustTunnel 相关
    namespace trusttunnel
    {
        /// @brief 构造 Basic Auth 头值
        /// @param user 用户名
        /// @param pass 密码
        /// @param out 输出 "Basic base64(user:pass)"
        /// @return 成功返回 false
        auto basic_auth(std::string_view user, std::string_view pass, std::string &out) -> bool
        {
            static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            const std::string raw = std::string(user) + ":" + std::string(pass);
            std::string enc;
            std::size_t i = 0;
            for (; i + 2 < raw.size(); i += 3)
            {
                const auto n = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i])) << 16 |
                               static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i + 1])) << 8 |
                               static_cast<std::uint8_t>(raw[i + 2]);
                enc.push_back(table[(n >> 18) & 0x3F]);
                enc.push_back(table[(n >> 12) & 0x3F]);
                enc.push_back(table[(n >> 6) & 0x3F]);
                enc.push_back(table[n & 0x3F]);
            }
            if (i + 1 == raw.size())
            {
                const auto n = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i])) << 16;
                enc.push_back(table[(n >> 18) & 0x3F]);
                enc.push_back(table[(n >> 12) & 0x3F]);
                enc.push_back('=');
            }
            else if (i + 2 == raw.size())
            {
                const auto n = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i])) << 16 |
                               static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i + 1])) << 8;
                enc.push_back(table[(n >> 18) & 0x3F]);
                enc.push_back(table[(n >> 12) & 0x3F]);
                enc.push_back(table[(n >> 6) & 0x3F]);
                enc.push_back('=');
            }
            out = "Basic " + enc;
            return false;
        }

        /// @brief 构造 HTTP/2 CONNECT 头块（HPACK 简化，:method CONNECT）
        /// @param host 目标主机
        /// @param port 目标端口
        /// @param auth Basic Auth 值
        /// @param out 输出头块
        /// @return 成功返回 false
        auto h2_connect_headers(std::string_view host, std::uint16_t port,
                                std::string_view auth, std::string &out) -> bool
        {
            // 简化 HPACK：静态表索引编码 + 字面量头
            out.clear();
            // :method CONNECT（静态表索引 7 → 0x87 或 0x80|7）
            out.push_back(static_cast<char>(0x80 | 7));
            // :authority = host:port（字面量，无索引）
            const std::string authority = std::string(host) + ":" + std::to_string(port);
            out.push_back(0x40);
            const std::string_view name = ":authority";
            out.push_back(static_cast<char>(name.size()));
            out.append(name);
            out.push_back(static_cast<char>(authority.size()));
            out.append(authority);
            return false;
        }
    } // namespace trusttunnel

} // namespace psmtest::stealth

// 顶层命名空间别名（测试引用 shadowtls::/restls::/anytls::/trusttunnel::）
namespace shadowtls = psmtest::stealth::shadowtls;
namespace restls = psmtest::stealth::restls;
namespace anytls = psmtest::stealth::anytls;
namespace trusttunnel = psmtest::stealth::trusttunnel;
