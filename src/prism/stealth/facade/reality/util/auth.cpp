#include <prism/stealth/facade/reality/util/auth.hpp>

#include <prism/crypto/aead.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/trace/trace.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>

using namespace psm::trace;

namespace psm::stealth::reality
{

    namespace tls = psm::protocol::tls;


    auto match_sni(const std::string_view sni, const memory::vector<memory::string> &server_names)
        -> bool
    {
        if (sni.empty())
            return false;

        for (const auto &name : server_names)
        {
            if (name == sni)
                return true;
        }
        return false;
    }


    auto match_shortid(const std::span<const std::uint8_t> short_id, const memory::vector<memory::string> &allowed_short_ids)
        -> bool
    {
        for (const auto &allowed : allowed_short_ids)
        {
            if (allowed.empty())
                return true;

            if (allowed.size() % 2 != 0)
                continue;

            const auto allowed_bytes = hex_decode(allowed);
            if (allowed_bytes.empty())
                continue;

            if (short_id.size() >= allowed_bytes.size() &&
                CRYPTO_memcmp(short_id.data(), allowed_bytes.data(), allowed_bytes.size()) == 0)
            {
                return true;
            }
        }
        return false;
    }


    auto verify_client_hello(const config &cfg, const tls::hello_features &client_hello)
        -> fault::code
    {
        if (!client_hello.server_name.empty() &&
            !match_sni(client_hello.server_name, cfg.server_names))
        {
            return fault::code::badsni;
        }

        if (!client_hello.has_x25519)
        {
            return fault::code::unauth;
        }

        bool supports_tls13 = false;
        for (const auto version : client_hello.versions)
        {
            if (version == tls::VERSION_TLS13)
            {
                supports_tls13 = true;
                break;
            }
        }
        if (!supports_tls13)
        {
            return fault::code::unauth;
        }

        if (client_hello.session_id.size() < tls::SESSION_ID_MAX_LEN)
        {
            return fault::code::unauth;
        }

        return fault::code::success;
    }


    auto authenticate(const config &cfg, const tls::hello_features &client_hello, const std::span<const std::uint8_t> decoded_privkey)
        -> std::pair<fault::code, auth_result>
    {
        auth_result result{};

        const auto verify_ec = verify_client_hello(cfg, client_hello);
        if (fault::failed(verify_ec))
        {
            return {verify_ec, result};
        }

        auto [ec, shared_secret] = crypto::x25519(decoded_privkey, client_hello.x25519_key);
        if (fault::failed(ec))
        {
            return {fault::code::kexfail, result};
        }

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
            return {fault::code::kexfail, result};
        }

        // HKDF-Extract: 以 ClientHello.random 前 20 字节为 salt，X25519 共享密钥为 IKM
        // 派生出伪随机密钥 PRK，用于后续的认证密钥扩展
        const auto prk = crypto::hkdf_extract(
            std::span<const std::uint8_t>(client_hello.random.data(), 20),
            std::span<const std::uint8_t>(shared_secret.data(), shared_secret.size()));

        // HKDF-Expand: 以 PRK 为输入，info 为 "REALITY"，扩展出 32 字节认证密钥
        // 用于后续 AEAD 解密 ClientHello.session_id 中嵌入的认证数据
        constexpr std::array<std::uint8_t, 7> reality_info{'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
        const auto [expand_ec, auth_key_vec] = crypto::hkdf_expand(
            std::span<const std::uint8_t>(prk.data(), prk.size()),
            std::span<const std::uint8_t>(reality_info.data(), reality_info.size()),
            32);

        if (fault::failed(expand_ec))
        {
            return {fault::code::unauth, result};
        }

        // session_id 偏移：hs_type(1)+hs_len(3)+version(2)+random(32)+sid_len(1)=39
        constexpr std::size_t sid_offset = 39;
        // AAD 构造：复制 ClientHello 原始消息，将 session_id 区域清零
        // 因为 session_id 是被 Reality 加密封装的，清零后作为 AEAD 的附加认证数据
        memory::vector<std::uint8_t> aad(client_hello.raw_msg.begin(), client_hello.raw_msg.end());
        if (aad.size() >= sid_offset + tls::SESSION_ID_MAX_LEN)
        {
            std::memset(aad.data() + sid_offset, 0, tls::SESSION_ID_MAX_LEN);
        }

        // AEAD 解密：用认证密钥解密 ClientHello.session_id
        // nonce 取 ClientHello.random 的第 20~32 字节（跳过 HKDF 用掉的前 20 字节）
        crypto::aead_context aead(crypto::aead_cipher::aes_256_gcm,
                                  std::span<const std::uint8_t>(auth_key_vec.data(), auth_key_vec.size()));

        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> nonce;
        std::memcpy(nonce.data(), client_hello.random.data() + 20, tls::AEAD_NONCE_LEN);

        std::array<std::uint8_t, 16> decrypted_sid{};
        const auto decrypt_ec = aead.open(crypto::open_input{
            std::span<std::uint8_t>(decrypted_sid.data(), decrypted_sid.size()),
            std::span<const std::uint8_t>(client_hello.session_id.data(), tls::SESSION_ID_MAX_LEN),
            std::span<const std::uint8_t>(nonce.data(), nonce.size()),
            std::span<const std::uint8_t>(aad.data(), aad.size())});

        if (fault::failed(decrypt_ec))
        {
            return {fault::code::unauth, result};
        }

        if (decrypted_sid[0] != 0x01)
        {
            return {fault::code::unauth, result};
        }

        const std::span<const std::uint8_t> cli_sid(decrypted_sid.data() + 8, 8);
        if (!match_shortid(cli_sid, cfg.short_ids))
        {
            return {fault::code::unauth, result};
        }

        result.server_ephkey = crypto::generate_keypair();
        result.shared_secret = shared_secret;
        std::copy(auth_key_vec.begin(), auth_key_vec.end(), result.auth_key.begin());
        result.authenticated = true;

        return {fault::code::success, result};
    }


    auto hex_decode(const std::string_view hex)
        -> memory::vector<std::uint8_t>
    {
        if (hex.empty())
            return {};

        memory::vector<std::uint8_t> bytes;
        bytes.reserve(hex.size() / 2);

        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            const auto hi = hex_digit(hex[i]);
            const auto lo = hex_digit(hex[i + 1]);
            if (hi < 0 || lo < 0)
                return {};
            bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }
        return bytes;
    }


    auto hex_digit(const char c)
        -> std::int32_t
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    }
} // namespace psm::stealth::reality
