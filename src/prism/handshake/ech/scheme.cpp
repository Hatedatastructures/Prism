/**
 * @file scheme.cpp
 * @brief ECH 伪装方案实现
 */

#include <prism/handshake/ech/scheme.hpp>
#include <prism/handshake/ech/util/keygen.hpp>

#include <prism/settings/settings.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/resource/session.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/preview.hpp>

#include <boost/asio.hpp>
#include <openssl/ssl.h>

using namespace psm::diagnose;

namespace psm::handshake::ech
{

    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /// ECH 扩展类型（draft-ietf-tls-esni-18）
    inline constexpr std::uint16_t ech_extension_type = 0xfe0d;

    namespace
    {
        /// 在原始 ClientHello 中遍历扩展查找 ECH 类型
        [[nodiscard]] auto contains_ech_extension(const std::span<const std::byte> raw)
            -> bool
        {
            // ClientHello：type(1) legacy_version(2) random(32) session_id_len(1)+sid
            // cipher_suites_len(2)+suites compression_len(1)+methods extensions_len(2)+...
            const auto *bytes = reinterpret_cast<const std::uint8_t *>(raw.data());
            const std::size_t size = raw.size();
            if (size < 4 + 32 + 1 + 1 + 2 + 1 + 2)
                return false;

            std::size_t offset = 0;
            // 跳过 handshake 头（4 字节：type + len）
            offset = 4;
            offset += 2; // legacy_version
            offset += 32; // random
            if (offset >= size)
                return false;
            const std::size_t sid_len = bytes[offset];
            offset += 1 + sid_len;
            if (offset + 2 > size)
                return false;
            const std::size_t cipher_len = (static_cast<std::size_t>(bytes[offset]) << 8) | bytes[offset + 1];
            offset += 2 + cipher_len;
            if (offset >= size)
                return false;
            const std::size_t comp_len = bytes[offset];
            offset += 1 + comp_len;
            if (offset + 2 > size)
                return false;
            const std::size_t ext_len = (static_cast<std::size_t>(bytes[offset]) << 8) | bytes[offset + 1];
            offset += 2;
            if (offset + ext_len > size)
                return false;

            const std::size_t end = offset + ext_len;
            while (offset + 4 <= end)
            {
                const std::uint16_t type = static_cast<std::uint16_t>(
                    (bytes[offset] << 8) | bytes[offset + 1]);
                const std::uint16_t len = static_cast<std::uint16_t>(
                    (bytes[offset + 2] << 8) | bytes[offset + 3]);
                if (type == ech_extension_type)
                    return true;
                offset += 4 + len;
            }
            return false;
        }
    } // namespace

    auto scheme::name() const noexcept -> std::string_view
    {
        return "ech";
    }

    auto scheme::active(const psm::settings &cfg) const noexcept -> bool
    {
        return cfg.stealth.ech.enabled();
    }

    auto scheme::verify(const hello_features &, const std::span<const std::byte> raw,
                        const psm::settings &cfg) const -> verify_result
    {
        if (!active(cfg))
            return {.score = 0, .solo_flag = 0, .note = "ech disabled"};

        if (contains_ech_extension(raw))
        {
            return {.score = 1000, .solo_flag = 1, .note = "ech: ClientHello contains ECH extension"};
        }
        return {.score = 0, .solo_flag = 0, .note = "ech: no ECH extension"};
    }

    auto scheme::handshake(handshake::handshake_context ctx)
        -> net::awaitable<handshake::handshake_result>
    {
        handshake::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.session->worker->process->ssl)
        {
            diagnose::warn(prefix_, "No SSL context configured");
            result.error = fault::code::not_supported;
            co_return result;
        }

        const auto &cfg = ctx.session->worker->process->cfg->stealth.ech;

        // 解码 X25519 私钥
        memory::vector<std::uint8_t> private_key_bytes;
        if (!base64_decode(std::string_view(cfg.key.data(), cfg.key.size()), private_key_bytes) ||
            private_key_bytes.size() != private_key_len)
        {
            diagnose::warn(prefix_, "ech: invalid private key");
            result.error = fault::code::keyfail;
            co_return result;
        }
        std::array<std::uint8_t, private_key_len> private_key{};
        std::copy(private_key_bytes.begin(), private_key_bytes.end(), private_key.begin());

        // 恢复 ECHConfig 并构造 SSL_ECH_KEYS
        ech_keypair keypair;
        if (fault::failed(keypair_from_private(
                std::span<const std::uint8_t, private_key_len>(private_key.data(), private_key.size()),
                std::string_view(cfg.public_name.data(), cfg.public_name.size()),
                cfg.max_name_len, keypair)))
        {
            diagnose::warn(prefix_, "ech: failed to restore keypair");
            result.error = fault::code::keyfail;
            co_return result;
        }

        SSL_ECH_KEYS *ech_keys = make_ech_keys(
            std::span<const std::uint8_t, private_key_len>(private_key.data(), private_key.size()),
            keypair.ech_config);
        if (!ech_keys)
        {
            diagnose::warn(prefix_, "ech: failed to build ECH keys");
            result.error = fault::code::keyfail;
            co_return result;
        }

        auto raw = connect::peel(std::move(ctx.transport));
        if (!raw)
        {
            SSL_ECH_KEYS_free(ech_keys);
            diagnose::debug(prefix_, "Cannot unwrap transport layers");
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 独立 SSL_CTX：复制证书 + 挂载 ECH keys
        auto ech_ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv13);
        {
            auto &src_ctx = *ctx.session->worker->process->ssl;
            auto *src_native = src_ctx.native_handle();
            auto *dst_native = ech_ssl_ctx->native_handle();

            SSL_CTX_use_certificate(dst_native, SSL_CTX_get0_certificate(src_native));
            SSL_CTX_use_PrivateKey(dst_native, SSL_CTX_get0_privatekey(src_native));
            SSL_CTX_set_min_proto_version(dst_native, SSL_CTX_get_min_proto_version(src_native));
            SSL_CTX_set_max_proto_version(dst_native, SSL_CTX_get_max_proto_version(src_native));
            SSL_CTX_set_session_cache_mode(dst_native, SSL_CTX_get_session_cache_mode(src_native));

            if (SSL_CTX_set1_ech_keys(dst_native, ech_keys) != 1)
            {
                SSL_ECH_KEYS_free(ech_keys);
                diagnose::warn(prefix_, "ech: SSL_CTX_set1_ech_keys failed");
                result.error = fault::code::keyfail;
                co_return result;
            }
        }
        SSL_ECH_KEYS_free(ech_keys);

        auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
        auto clean_inbound = psm::transport::wrap_with_preview(std::move(raw), preread_span);

        auto [ssl_ec, ssl_stream, recovered] = co_await psm::transport::encrypted::ssl_handshake(
            std::move(clean_inbound), *ech_ssl_ctx);

        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.transport = std::move(recovered);
            result.error = ssl_ec;
            diagnose::debug(prefix_, "TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        // ECH 解密成功：检查握手是否真的使用了 ECH
        if (SSL_ech_accepted(ssl_stream->native_handle()) != 1)
        {
            // 客户端未使用 ECH（如仅探测）：回落为普通 TLS
            diagnose::debug(prefix_, "ech: no ECH in handshake, fallback to plain TLS");
            result.detected = psm::connect::protocol_type::tls;
            result.transport = std::make_shared<psm::transport::encrypted>(ssl_stream);
            result.error = fault::code::success;
            co_return result;
        }

        diagnose::debug(prefix_, "ech: handshake accepted (inner SNI hidden)");

        result.transport = std::make_shared<psm::transport::encrypted>(ssl_stream);
        result.detected = psm::connect::protocol_type::unknown;
        result.error = fault::code::success;
        co_return result;
    }

} // namespace psm::handshake::ech
