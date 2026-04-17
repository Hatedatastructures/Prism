#include <prism/stealth/reality/handshake.hpp>
#include <prism/stealth/reality/constants.hpp>
#include <prism/stealth/reality/request.hpp>
#include <prism/stealth/reality/auth.hpp>
#include <prism/stealth/reality/keygen.hpp>
#include <prism/stealth/reality/response.hpp>
#include <prism/stealth/reality/seal.hpp>
#include <prism/stealth/reality/config.hpp>
#include <prism/resolve/router.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/trace.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <cstring>
#include <memory>
#include <string>
#include <charconv>

namespace psm::stealth
{
    constexpr std::string_view HsTag = "[Stealth.Handshake]";

    // ============================================================
    // 诊断工具
    // ============================================================

    static auto format_hex_short(const std::span<const std::uint8_t> data, const std::size_t max_bytes = 16) -> std::string
    {
        std::string result;
        result.reserve(max_bytes * 2);
        const auto n = std::min(data.size(), max_bytes);
        for (std::size_t i = 0; i < n; ++i)
        {
            constexpr char hex[] = "0123456789abcdef";
            result.push_back(hex[data[i] >> 4]);
            result.push_back(hex[data[i] & 0x0F]);
        }
        return result;
    }

    // ============================================================
    // 工具函数
    // ============================================================

    static auto read_exact(channel::transport::transmission &transport, std::span<std::byte> buf)
        -> net::awaitable<bool>
    {
        std::size_t done = 0;
        while (done < buf.size())
        {
            std::error_code ec;
            const auto n = co_await transport.async_read_some(
                std::span<std::byte>(buf.data() + done, buf.size() - done), ec);
            if (ec || n == 0)
                co_return false;
            done += n;
        }
        co_return true;
    }

    // ============================================================
    // parse_dest
    // ============================================================

    auto parse_dest(const std::string_view dest, std::string &host, std::uint16_t &port) -> bool
    {
        if (dest.empty())
            return false;

        const auto colon_pos = dest.rfind(':');
        if (colon_pos == std::string_view::npos)
        {
            host = dest;
            port = 443;
            return true;
        }

        // IPv6: [address]:port
        if (dest.find(']') != std::string_view::npos)
        {
            const auto bracket_end = dest.find(']');
            if (bracket_end == std::string_view::npos)
                return false;
            host = dest.substr(1, bracket_end - 1);
            if (bracket_end + 2 < dest.size() && dest[bracket_end + 1] == ':')
            {
                const auto port_sv = dest.substr(bracket_end + 2);
                std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
            }
            else
            {
                port = 443;
            }
            return true;
        }

        host = dest.substr(0, colon_pos);
        try
        {
            const auto port_sv = dest.substr(colon_pos + 1);
            std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
        }
        catch (...)
        {
            return false;
        }
        return true;
    }

    // ============================================================
    // fallback_to_dest
    // ============================================================

    auto fallback_to_dest(psm::agent::session_context &ctx, const std::span<const std::uint8_t> raw_record)
        -> net::awaitable<fault::code>
    {
        const auto &reality_cfg = ctx.server.cfg.reality;

        std::string dest_host;
        std::uint16_t dest_port = 443;
        if (!parse_dest(std::string_view(reality_cfg.dest.data(), reality_cfg.dest.size()), dest_host, dest_port))
        {
            trace::error("{} invalid dest config: {}", HsTag, reality_cfg.dest);
            co_return fault::code::reality_dest_unreachable;
        }

        trace::info("{} falling back to {}:{}", HsTag, dest_host, dest_port);

        char dest_port_buf[8];
        const auto [dest_port_end, dest_port_ec] = std::to_chars(dest_port_buf, dest_port_buf + sizeof(dest_port_buf), dest_port);
        auto [connect_ec, dest_conn] = co_await ctx.worker.router.async_forward(dest_host, std::string_view(dest_port_buf, std::distance(dest_port_buf, dest_port_end)));
        if (fault::failed(connect_ec) || !dest_conn.valid())
        {
            trace::warn("{} connect to dest failed: {}", HsTag, fault::describe(connect_ec));
            co_return fault::code::reality_dest_unreachable;
        }

        auto *dest_socket_raw = dest_conn.release();

        boost::system::error_code write_ec;
        co_await net::async_write(*dest_socket_raw, net::buffer(raw_record.data(), raw_record.size()),
                                  net::redirect_error(net::use_awaitable, write_ec));
        if (write_ec)
        {
            trace::warn("{} write to dest failed: {}", HsTag, write_ec.message());
            co_return fault::code::reality_dest_unreachable;
        }

        auto dest_trans = channel::transport::make_reliable(std::move(*dest_socket_raw));
        co_await pipeline::primitives::tunnel(ctx.inbound, std::move(dest_trans), ctx);

        trace::debug("{} fallback tunnel completed", HsTag);
        co_return fault::code::success;
    }

    // ============================================================
    // fetch_dest_certificate
    // ============================================================

    auto fetch_dest_certificate(const std::string_view host, const std::uint16_t port, resolve::router &router)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        memory::vector<std::uint8_t> empty_cert;

        try
        {
            char cert_port_buf[8];
            const auto [cert_port_end, cert_port_ec2] = std::to_chars(cert_port_buf, cert_port_buf + sizeof(cert_port_buf), port);
            auto [connect_ec, conn] = co_await router.async_forward(host, std::string_view(cert_port_buf, std::distance(cert_port_buf, cert_port_end)));
            if (fault::failed(connect_ec) || !conn.valid())
            {
                trace::warn("{} connect to dest for cert failed: {}", HsTag, fault::describe(connect_ec));
                co_return std::pair{fault::code::reality_certificate_error, empty_cert};
            }

            auto *socket_raw = conn.release();

            namespace ssl_local = net::ssl;
            ssl_local::context ssl_ctx(ssl_local::context::tls_client);
            ssl_ctx.set_verify_mode(ssl_local::verify_none);

            ssl_local::stream<net::ip::tcp::socket> ssl_stream(std::move(*socket_raw), ssl_ctx);
            SSL_set_tlsext_host_name(ssl_stream.native_handle(), std::string(host).c_str());

            boost::system::error_code ec;
            co_await ssl_stream.async_handshake(ssl_local::stream_base::client,
                                                net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                trace::warn("{} TLS handshake to dest failed: {}", HsTag, ec.message());
                co_return std::pair{fault::code::reality_certificate_error, empty_cert};
            }

            auto *ssl_native = ssl_stream.native_handle();
            memory::vector<std::uint8_t> cert_der;

            auto *peer_cert = SSL_get_peer_certificate(ssl_native);
            if (peer_cert)
            {
                auto *bio = BIO_new(BIO_s_mem());
                i2d_X509_bio(bio, peer_cert);
                char *data = nullptr;
                const auto len = BIO_get_mem_data(bio, &data);
                cert_der.insert(cert_der.end(),
                                reinterpret_cast<std::uint8_t *>(data),
                                reinterpret_cast<std::uint8_t *>(data + len));
                BIO_free(bio);
                X509_free(peer_cert);
            }

            boost::system::error_code shutdown_ec;
            ssl_stream.shutdown(shutdown_ec);

            if (cert_der.empty())
            {
                trace::warn("{} failed to extract certificate from dest", HsTag);
                co_return std::pair{fault::code::reality_certificate_error, empty_cert};
            }

            trace::debug("{} fetched dest certificate ({} bytes)", HsTag, cert_der.size());
            co_return std::pair{fault::code::success, std::move(cert_der)};
        }
        catch (const std::exception &e)
        {
            trace::warn("{} exception fetching cert: {}", HsTag, e.what());
            co_return std::pair{fault::code::reality_certificate_error, empty_cert};
        }
    }

    // ============================================================
    // 握手子流程
    // ============================================================

    /// 用正确的 finished_key 重算 Finished 并加密握手记录
    static auto derive_and_encrypt_finished(
        const key_material &keys,
        server_hello_result &sh_result,
        std::span<const std::uint8_t> client_hello_raw_msg)
        -> fault::code
    {
        constexpr std::size_t FINISHED_MSG_SIZE = 36; // Type(1) + Length(3) + verify_data(32)
        const auto &old_plaintext = sh_result.encrypted_handshake_plaintext;

        if (old_plaintext.size() < FINISHED_MSG_SIZE)
        {
            trace::warn("{} plaintext too short for Finished: {}", HsTag, old_plaintext.size());
            return fault::code::reality_key_schedule_error;
        }

        const auto ee_cert_cv = std::span<const std::uint8_t>(
            old_plaintext.data(), old_plaintext.size() - FINISHED_MSG_SIZE);

        const auto transcript_for_finished = crypto::sha256(
            client_hello_raw_msg,
            sh_result.server_hello_msg,
            ee_cert_cv);

        const auto verify_data = compute_finished_verify_data(
            keys.server_finished_key, transcript_for_finished);

        // 诊断日志：Finished 计算
        trace::debug("{} server Finished transcript: {}", HsTag,
                     format_hex_short({transcript_for_finished.data(), transcript_for_finished.size()}));
        trace::debug("{} server Finished verify_data: {}", HsTag,
                     format_hex_short({verify_data.data(), verify_data.size()}));

        memory::vector<std::uint8_t> correct_plaintext(ee_cert_cv.begin(), ee_cert_cv.end());
        correct_plaintext.push_back(tls::HANDSHAKE_TYPE_FINISHED);
        correct_plaintext.push_back(0x00);
        correct_plaintext.push_back(0x00);
        correct_plaintext.push_back(static_cast<std::uint8_t>(verify_data.size()));
        correct_plaintext.insert(correct_plaintext.end(), verify_data.begin(), verify_data.end());

        auto [enc_ec, encrypted_record] = encrypt_tls_record(
            keys.server_handshake_key,
            keys.server_handshake_iv,
            0,
            tls::CONTENT_TYPE_HANDSHAKE,
            correct_plaintext);

        if (fault::failed(enc_ec))
        {
            trace::warn("{} failed to encrypt handshake record", HsTag);
            return enc_ec;
        }

        sh_result.encrypted_handshake_plaintext = std::move(correct_plaintext);
        sh_result.encrypted_handshake_record = std::move(encrypted_record);
        return fault::code::success;
    }

    /// 读取并消费客户端 CCS + Finished
    static auto consume_client_finished(
        channel::transport::transmission &inbound,
        const key_material &keys)
        -> net::awaitable<fault::code>
    {
        bool consumed = false;
        while (!consumed)
        {
            std::array<std::byte, tls::RECORD_HEADER_LEN> rec_hdr{};
            if (!co_await read_exact(inbound, rec_hdr))
            {
                trace::warn("{} failed to read client record header", HsTag);
                co_return fault::code::io_error;
            }

            const auto *hdr_raw = reinterpret_cast<const std::uint8_t *>(rec_hdr.data());
            const auto rec_content_type = hdr_raw[0];
            const auto rec_len = (static_cast<std::size_t>(hdr_raw[3]) << 8) |
                                 static_cast<std::size_t>(hdr_raw[4]);

            trace::debug("{} client rec: type=0x{:02x} len={}", HsTag,
                         static_cast<unsigned>(rec_content_type), rec_len);

            memory::vector<std::byte> rec_body(rec_len);
            if (rec_len > 0 && !co_await read_exact(inbound, rec_body))
            {
                trace::warn("{} failed to read client record body", HsTag);
                co_return fault::code::io_error;
            }

            if (rec_content_type == tls::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            {
                trace::debug("{} skipping client CCS record", HsTag);
                continue;
            }

            // 非 CCS 记录：尝试解密以判断是 Finished 还是 Alert
            {
                std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_nonce{};
                std::memcpy(client_nonce.data(), keys.client_handshake_iv.data(), tls::AEAD_NONCE_LEN);

                const auto ad_span = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(rec_hdr.data()), rec_hdr.size());
                const auto ct_span = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(rec_body.data()), rec_body.size());

                crypto::aead_context client_aead(
                    crypto::aead_cipher::aes_128_gcm,
                    std::span<const std::uint8_t>(keys.client_handshake_key.data(), keys.client_handshake_key.size()));

                const auto pt_size = crypto::aead_context::open_output_size(rec_body.size());
                memory::vector<std::uint8_t> decrypted(pt_size);
                const auto nonce_span = std::span<const std::uint8_t>(client_nonce.data(), client_nonce.size());

                const auto open_ec = client_aead.open(decrypted, ct_span, nonce_span, ad_span);

                if (!fault::failed(open_ec) && decrypted.size() >= 2)
                {
                    const auto inner_content_type = decrypted.back();
                    if (inner_content_type == tls::CONTENT_TYPE_ALERT && decrypted.size() >= 3)
                    {
                        trace::error("{} client sent TLS ALERT: level={}, desc=0x{:02x} — server Finished was rejected",
                                     HsTag,
                                     static_cast<unsigned>(decrypted[0]),
                                     static_cast<unsigned>(decrypted[1]));
                        co_return fault::code::reality_handshake_failed;
                    }
                    else
                    {
                        trace::debug("{} consumed client Finished record ({} bytes, inner_type=0x{:02x})",
                                     HsTag, rec_len, static_cast<unsigned>(inner_content_type));
                        // 诊断日志：客户端 Finished verify_data
                        if (inner_content_type == tls::CONTENT_TYPE_HANDSHAKE && decrypted.size() >= 36)
                        {
                            trace::info("{} client Finished verify_data: {}", HsTag,
                                        format_hex_short({decrypted.data() + 4, 32}));
                        }
                    }
                }
                else
                {
                    trace::warn("{} failed to decrypt client record (ec={}), raw {} bytes",
                                HsTag, static_cast<int>(open_ec), rec_len);
                    co_return fault::code::reality_handshake_failed;
                }
            }
            consumed = true;
        }

        co_return fault::code::success;
    }

    // ============================================================
    // handshake 主入口
    // ============================================================

    auto handshake(psm::agent::session_context &ctx, const std::span<const std::byte> preread)
        -> net::awaitable<handshake_result>
    {
        handshake_result result;

        if (!ctx.inbound)
        {
            result.error = fault::code::io_error;
            co_return result;
        }

        const auto &reality_cfg = ctx.server.cfg.reality;

        // 1. 读取 ClientHello
        auto [read_ec, raw_record] = co_await read_tls_record(*ctx.inbound, preread);
        if (fault::failed(read_ec))
        {
            trace::warn("{} failed to read TLS record: {}", HsTag, fault::describe(read_ec));
            result.error = read_ec;
            co_return result;
        }

        auto [parse_ec, client_hello] = parse_client_hello(raw_record);
        if (fault::failed(parse_ec))
        {
            trace::warn("{} failed to parse ClientHello: {}", HsTag, fault::describe(parse_ec));
            const auto fb_ec = co_await fallback_to_dest(ctx, raw_record);
            result.type = (fault::succeeded(fb_ec)) ? handshake_result_type::fallback : handshake_result_type::failed;
            result.error = fb_ec;
            co_return result;
        }

        trace::debug("{} ClientHello parsed, SNI: {}", HsTag, client_hello.server_name);

        // 2. 解码私钥
        const auto private_key_str = std::string(reality_cfg.private_key.data(), reality_cfg.private_key.size());
        auto decoded_key_str = crypto::base64_decode(private_key_str);
        if (decoded_key_str.size() != tls::REALITY_KEY_LEN)
        {
            trace::warn("{} invalid private key length: {}", HsTag, decoded_key_str.size());
            const auto fb_ec = co_await fallback_to_dest(ctx, raw_record);
            result.type = (fault::succeeded(fb_ec)) ? handshake_result_type::fallback : handshake_result_type::failed;
            result.error = fb_ec;
            co_return result;
        }

        const auto decoded_private_key = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(decoded_key_str.data()), decoded_key_str.size());

        // 3. Reality 认证
        auto [auth_ec, auth_res] = authenticate(reality_cfg, client_hello, decoded_private_key);
        if (!auth_res.authenticated)
        {
            // SNI 不匹配 → 标准 TLS
            if (auth_ec == fault::code::reality_sni_mismatch)
            {
                trace::debug("{} SNI mismatch, falling back to standard TLS", HsTag);
                result.type = handshake_result_type::not_reality;
                result.raw_tls_record.assign(
                    reinterpret_cast<const std::byte *>(raw_record.data()),
                    reinterpret_cast<const std::byte *>(raw_record.data() + raw_record.size()));
                co_return result;
            }
            // SNI 为空 + auth 失败 → 非 Reality 客户端
            if (client_hello.server_name.empty())
            {
                trace::debug("{} auth failed with empty SNI, falling back to standard TLS", HsTag);
                result.type = handshake_result_type::not_reality;
                result.raw_tls_record.assign(
                    reinterpret_cast<const std::byte *>(raw_record.data()),
                    reinterpret_cast<const std::byte *>(raw_record.data() + raw_record.size()));
                co_return result;
            }
            // SNI 匹配但 auth 失败 → 透传到 dest
            trace::debug("{} auth failed: {}, falling back to dest", HsTag, fault::describe(auth_ec));
            const auto fb_ec = co_await fallback_to_dest(ctx, raw_record);
            result.type = (fault::succeeded(fb_ec)) ? handshake_result_type::fallback : handshake_result_type::failed;
            result.error = fb_ec;
            co_return result;
        }

        trace::info("{} authentication successful", HsTag);

        // 4. TLS ECDH 密钥交换
        // 注意：不为认证客户端获取 dest 证书 — generate_reality_certificate() 会生成合成 ed25519 证书
        auto [ephemeral_ec, tls_shared_secret] = crypto::x25519(
            std::span<const std::uint8_t>(auth_res.server_ephemeral_key.private_key.data(),
                                          auth_res.server_ephemeral_key.private_key.size()),
            std::span<const std::uint8_t>(client_hello.client_public_key.data(),
                                          client_hello.client_public_key.size()));
        if (fault::failed(ephemeral_ec))
        {
            trace::warn("{} ephemeral X25519 key exchange failed", HsTag);
            result.error = ephemeral_ec;
            co_return result;
        }

        // 诊断日志：TLS ECDH 共享密钥
        trace::debug("{} TLS ECDH shared_secret: {}", HsTag,
                     format_hex_short({tls_shared_secret.data(), tls_shared_secret.size()}));

        // 5. 生成 ServerHello + 派生握手密钥
        key_material dummy_keys{};
        auto [sh_ec, sh_result] = generate_server_hello(
            client_hello,
            auth_res.server_ephemeral_key.public_key,
            dummy_keys,
            {}, // 不需要 dest 证书 — Reality 认证客户端使用合成证书
            client_hello.raw_message,
            std::span<const std::uint8_t>(auth_res.auth_key.data(), auth_res.auth_key.size()));

        if (fault::failed(sh_ec))
        {
            trace::warn("{} failed to generate ServerHello: {}", HsTag, fault::describe(sh_ec));
            result.error = sh_ec;
            co_return result;
        }

        auto [ks_ec, keys] = derive_handshake_keys(
            tls_shared_secret,
            client_hello.raw_message,
            sh_result.server_hello_msg);

        if (fault::failed(ks_ec))
        {
            trace::warn("{} failed to derive keys: {}", HsTag, fault::describe(ks_ec));
            result.error = ks_ec;
            co_return result;
        }

        // 6. 用正确密钥重算 Finished
        const auto finished_ec = derive_and_encrypt_finished(keys, sh_result, client_hello.raw_message);
        if (fault::failed(finished_ec))
        {
            result.error = finished_ec;
            co_return result;
        }

        // 7. 发送握手记录（scatter-gather）
        {
            std::error_code write_ec;
            const std::span<const std::byte> handshake_parts[] = {
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(sh_result.server_hello_record.data()),
                    sh_result.server_hello_record.size()),
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(sh_result.change_cipher_spec_record.data()),
                    sh_result.change_cipher_spec_record.size()),
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(sh_result.encrypted_handshake_record.data()),
                    sh_result.encrypted_handshake_record.size()),
            };
            co_await ctx.inbound->async_write_scatter(handshake_parts, 3, write_ec);
            if (write_ec)
            {
                trace::warn("{} failed to send handshake records: {}", HsTag, write_ec.message());
                result.error = fault::to_code(write_ec);
                co_return result;
            }
        }

        // 8. 消费客户端 CCS + Finished
        const auto consumed_ec = co_await consume_client_finished(*ctx.inbound, keys);
        if (fault::failed(consumed_ec))
        {
            result.error = consumed_ec;
            co_return result;
        }

        // 9. 派生应用数据密钥
        const auto full_transcript_hash = crypto::sha256(
            {client_hello.raw_message.data(), client_hello.raw_message.size()},
            {sh_result.server_hello_msg.data(), sh_result.server_hello_msg.size()},
            {sh_result.encrypted_handshake_plaintext.data(), sh_result.encrypted_handshake_plaintext.size()});

        const auto app_ec = derive_application_keys(keys.master_secret,
                                                    {full_transcript_hash.data(), full_transcript_hash.size()}, keys);
        if (fault::failed(app_ec))
        {
            trace::warn("{} failed to derive application keys", HsTag);
            result.error = app_ec;
            co_return result;
        }

        // 诊断日志：应用密钥
        trace::debug("{} app transcript hash: {}", HsTag,
                     format_hex_short({full_transcript_hash.data(), full_transcript_hash.size()}));
        trace::debug("{} server_app_key: {}", HsTag,
                     format_hex_short({keys.server_app_key.data(), keys.server_app_key.size()}));
        trace::debug("{} server_app_iv: {}", HsTag,
                     format_hex_short({keys.server_app_iv.data(), keys.server_app_iv.size()}));
        trace::debug("{} client_app_key: {}", HsTag,
                     format_hex_short({keys.client_app_key.data(), keys.client_app_key.size()}));
        trace::debug("{} client_app_iv: {}", HsTag,
                     format_hex_short({keys.client_app_iv.data(), keys.client_app_iv.size()}));

        // 10. 创建加密传输层 + 预读内层数据
        auto reality_session = std::make_shared<seal>(
            std::move(ctx.inbound), std::move(keys));

        constexpr std::size_t preread_size = 64;
        memory::vector<std::byte> inner_buf(preread_size);
        std::error_code read_inner_ec;
        const auto inner_n = co_await reality_session->async_read_some(
            std::span<std::byte>(inner_buf.data(), preread_size), read_inner_ec);

        if (read_inner_ec || inner_n == 0)
        {
            trace::warn("{} failed to read inner data: {}", HsTag, read_inner_ec.message());
            result.error = fault::to_code(read_inner_ec);
            co_return result;
        }

        result.type = handshake_result_type::authenticated;
        result.encrypted_transport = std::move(reality_session);
        result.inner_preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));
        result.error = fault::code::success;

        trace::info("{} handshake completed successfully", HsTag);
        co_return result;
    }
} // namespace psm::stealth
