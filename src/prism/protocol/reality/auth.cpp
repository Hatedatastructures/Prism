/**
 * @file auth.cpp
 * @brief Reality 认证逻辑实现
 * @details 实现 Reality 协议的客户端认证流程，包括 SNI 匹配、
 * X25519 密钥交换和 short_id 验证。
 */

#include <prism/protocol/reality/auth.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/trace.hpp>
#include <algorithm>
#include <cstring>

namespace psm::protocol::reality
{
    constexpr std::string_view AuthTag = "[Reality.Auth]";

    auto match_server_name(const std::string_view sni, const memory::vector<memory::string> &server_names)
        -> bool
    {
        if (sni.empty())
        {
            return false;
        }

        for (const auto &name : server_names)
        {
            if (name == sni)
            {
                return true;
            }
        }
        return false;
    }

    auto extract_short_id(const std::span<const std::uint8_t> session_id)
        -> memory::vector<std::uint8_t>
    {
        // Reality 的 short_id 从 session_id 开头提取
        // Xray Reality: session_id 前 min(len, 16) 字节为 short_id
        if (session_id.empty())
        {
            return {};
        }

        // short_id 长度取 min(session_id.size(), SHORT_ID_MAX_LEN)
        const auto sid_len = std::min(session_id.size(), tls::SHORT_ID_MAX_LEN);
        memory::vector<std::uint8_t> short_id(session_id.begin(), session_id.begin() + static_cast<std::ptrdiff_t>(sid_len));
        return short_id;
    }

    auto match_short_id(const std::span<const std::uint8_t> short_id, const memory::vector<memory::string> &allowed_short_ids)
        -> bool
    {
        for (const auto &allowed : allowed_short_ids)
        {
            // 空字符串表示接受任意 short_id
            if (allowed.empty())
            {
                return true;
            }

            // 将 hex 编码的 allowed 转为字节进行比较
            if (allowed.size() % 2 != 0)
            {
                continue;
            }

            const auto allowed_bytes = hex_to_bytes(allowed);
            if (allowed_bytes.empty())
            {
                continue;
            }

            if (std::equal(short_id.begin(), short_id.end(),
                           allowed_bytes.begin(), allowed_bytes.end()))
            {
                return true;
            }
        }
        return false;
    }

    auto authenticate(const config &cfg, const client_hello_info &client_hello,
                      const std::span<const std::uint8_t> decoded_private_key)
        -> std::pair<fault::code, auth_result>
    {
        auth_result result{};

        // Step 1: 检查 SNI
        if (!match_server_name(client_hello.server_name, cfg.server_names))
        {
            trace::debug("{} SNI mismatch: {}", AuthTag, client_hello.server_name);
            return {fault::code::reality_sni_mismatch, result};
        }

        // Step 2: 检查 X25519 公钥
        if (!client_hello.has_client_public_key)
        {
            trace::debug("{} no X25519 public key in key_share", AuthTag);
            return {fault::code::reality_auth_failed, result};
        }

        // Step 3: 检查 TLS 1.3 支持
        bool supports_tls13 = false;
        for (const auto version : client_hello.supported_versions)
        {
            if (version == tls::VERSION_TLS13)
            {
                supports_tls13 = true;
                break;
            }
        }
        if (!supports_tls13)
        {
            trace::debug("{} client does not support TLS 1.3", AuthTag);
            return {fault::code::reality_auth_failed, result};
        }

        // Step 4: 检查 short_id
        const auto client_short_id = extract_short_id(client_hello.session_id);
        if (!match_short_id(client_short_id, cfg.short_ids))
        {
            trace::debug("{} short_id mismatch", AuthTag);
            return {fault::code::reality_auth_failed, result};
        }

        // Step 5: X25519 密钥交换
        auto [ec, shared_secret] = crypto::x25519(decoded_private_key, client_hello.client_public_key);
        if (fault::failed(ec))
        {
            trace::warn("{} X25519 key exchange failed", AuthTag);
            return {fault::code::reality_key_exchange_failed, result};
        }

        // Step 6: 检查共享密钥是否为全零（低阶点攻击）
        bool all_zero = true;
        for (const auto byte : shared_secret)
        {
            if (byte != 0)
            {
                all_zero = false;
                break;
            }
        }
        if (all_zero)
        {
            trace::warn("{} shared secret is all zeros (low-order point)", AuthTag);
            return {fault::code::reality_key_exchange_failed, result};
        }

        // Step 7: 生成服务端临时密钥对
        result.server_ephemeral_key = crypto::generate_x25519_keypair();
        result.shared_secret = shared_secret;
        result.authenticated = true;

        trace::debug("{} authentication successful", AuthTag);
        return {fault::code::success, result};
    }

    // ========================================================================
    // 辅助函数
    // ========================================================================

    auto hex_to_bytes(const std::string_view hex) -> memory::vector<std::uint8_t>
    {
        if (hex.empty())
        {
            return {};
        }

        memory::vector<std::uint8_t> bytes;
        bytes.reserve(hex.size() / 2);

        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            const auto hi = hex_digit(hex[i]);
            const auto lo = hex_digit(hex[i + 1]);
            if (hi < 0 || lo < 0)
            {
                return {};
            }
            bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }
        return bytes;
    }

    auto hex_digit(const char c) -> int
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
    }
} // namespace psm::protocol::reality
