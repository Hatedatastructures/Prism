#include <prism/protocol/reality/auth.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/crypto/aead.hpp>
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

            // short_id 长度以 allowed_bytes 为准进行前缀比较
            if (short_id.size() >= allowed_bytes.size() &&
                std::equal(allowed_bytes.begin(), allowed_bytes.end(), short_id.begin()))
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
        // SNI 非空但不匹配 → 确定不是 Reality 客户端
        // SNI 为空 → 无法判断（IP 地址连接不发 SNI），继续后续认证来确认
        if (!client_hello.server_name.empty() &&
            !match_server_name(client_hello.server_name, cfg.server_names))
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

        // Step 4: 检查 session_id 长度
        if (client_hello.session_id.size() < tls::SESSION_ID_MAX_LEN)
        {
            trace::debug("{} session_id too short: {}", AuthTag, client_hello.session_id.size());
            return {fault::code::reality_auth_failed, result};
        }

        // Step 5: X25519 密钥交换（服务端私钥 × 客户端 key_share 公钥）
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

        // Step 7: HKDF 派生认证密钥
        // PRK = HMAC-SHA256(salt=Random[:20], IKM=shared_secret)
        const auto prk = crypto::hkdf_extract(
            std::span<const std::uint8_t>(client_hello.random.data(), 20),
            std::span<const std::uint8_t>(shared_secret.data(), shared_secret.size()));

        // auth_key = HKDF-Expand(PRK, info="REALITY", length=32)
        constexpr std::array<std::uint8_t, 7> reality_info{'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
        const auto [expand_ec, auth_key_vec] = crypto::hkdf_expand(
            std::span<const std::uint8_t>(prk.data(), prk.size()),
            std::span<const std::uint8_t>(reality_info.data(), reality_info.size()),
            32);

        if (fault::failed(expand_ec))
        {
            trace::warn("{} HKDF-Expand failed", AuthTag);
            return {fault::code::reality_auth_failed, result};
        }

        trace::debug("{} HKDF derived auth_key ({} bytes)", AuthTag, auth_key_vec.size());

        // Step 8: 构造 AAD = raw_message，session_id 区域清零
        // handshake 消息格式：type(1)+len(3)+version(2)+random(32)+sid_len(1)+session_id(32)
        // session_id 起始偏移 = 1+3+2+32+1 = 39
        constexpr std::size_t sid_offset = 39;
        memory::vector<std::uint8_t> aad(client_hello.raw_message.begin(), client_hello.raw_message.end());
        if (aad.size() >= sid_offset + tls::SESSION_ID_MAX_LEN)
        {
            std::memset(aad.data() + sid_offset, 0, tls::SESSION_ID_MAX_LEN);
        }

        // Step 9: AES-256-GCM 解密 session_id
        // ciphertext = session_id[0:32]（16 字节密文 + 16 字节 GCM tag）
        // nonce = Random[20:32]（12 字节）
        // plaintext output = 16 字节
        crypto::aead_context aead(crypto::aead_cipher::aes_256_gcm,
                                  std::span<const std::uint8_t>(auth_key_vec.data(), auth_key_vec.size()));

        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> nonce;
        std::memcpy(nonce.data(), client_hello.random.data() + 20, tls::AEAD_NONCE_LEN);

        std::array<std::uint8_t, 16> decrypted_sid{};
        const auto decrypt_ec = aead.open(
            std::span<std::uint8_t>(decrypted_sid.data(), decrypted_sid.size()),
            std::span<const std::uint8_t>(client_hello.session_id.data(), tls::SESSION_ID_MAX_LEN),
            std::span<const std::uint8_t>(nonce.data(), nonce.size()),
            std::span<const std::uint8_t>(aad.data(), aad.size()));

        if (fault::failed(decrypt_ec))
        {
            trace::debug("{} session_id decryption failed", AuthTag);
            return {fault::code::reality_auth_failed, result};
        }

        trace::debug("{} session_id decrypted: [{:02x} {:02x} {:02x} ...]",
                     AuthTag, decrypted_sid[0], decrypted_sid[1], decrypted_sid[2]);

        // Step 10: 验证解密后的格式标记
        // mihomo 客户端写入: [0]=0x01, [1]=0x08, [2]=0x02
        if (decrypted_sid[0] != 0x01)
        {
            trace::debug("{} invalid version marker: 0x{:02x}", AuthTag, decrypted_sid[0]);
            return {fault::code::reality_auth_failed, result};
        }

        // Step 11: 从解密后的 session_id[8:16] 提取 short_id 并验证
        const std::span<const std::uint8_t> client_short_id(decrypted_sid.data() + 8, 8);
        if (!match_short_id(client_short_id, cfg.short_ids))
        {
            trace::debug("{} short_id mismatch", AuthTag);
            return {fault::code::reality_auth_failed, result};
        }

        // Step 12: 生成服务端临时密钥对
        result.server_ephemeral_key = crypto::generate_x25519_keypair();
        result.shared_secret = shared_secret;
        std::copy(auth_key_vec.begin(), auth_key_vec.end(), result.auth_key.begin());
        result.authenticated = true;

        trace::debug("{} authentication successful", AuthTag);
        return {fault::code::success, result};
    }

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
