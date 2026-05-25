#include <prism/stealth/reality/handshake.hpp>
#include <prism/stealth/reality/util/auth.hpp>
#include <prism/recognition/tls/signal.hpp>
#include <prism/stealth/reality/util/keygen.hpp>
#include <prism/stealth/reality/util/response.hpp>
#include <prism/stealth/reality/seal.hpp>
#include <prism/stealth/reality/config.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/connect.hpp>
#include <prism/config.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/memory/container.hpp>
#include <prism/trace.hpp>

namespace tls = psm::protocol::tls;
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <cstring>
#include <memory>
#include <string>
#include <charconv>
#include <chrono>
#include <boost/asio/steady_timer.hpp>

namespace psm::stealth::reality
{
    constexpr std::string_view HsTag = "[Stealth.Handshake]";

    // ============================================================
    // 工具函数
    // ============================================================

    static auto read_exact(transport::transmission &transport, std::span<std::byte> buf)
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

    auto parse_dest(const std::string_view dest, std::string &host, std::uint16_t &port)
        -> bool
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
        {
            const auto port_sv = dest.substr(colon_pos + 1);
            const auto [ptr, fc_ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
            if (fc_ec != std::errc())
                return false;
        }
        return true;
    }

    // ============================================================
    // fallback_dest
    // ============================================================

    auto fallback_dest(psm::context::session &session, transport::shared_transmission inbound, const std::span<const std::uint8_t> raw_record)
        -> net::awaitable<fault::code>
    {
        const auto &reality_cfg = session.server_ctx.config().stealth.reality;

        std::string dest_host;
        std::uint16_t dest_port = 443;
        if (!parse_dest(std::string_view(reality_cfg.dest.data(), reality_cfg.dest.size()), dest_host, dest_port))
        {
            trace::error("{} invalid dest config: {}", HsTag, reality_cfg.dest);
            co_return fault::code::reality_unreach;
        }

        trace::info("{} falling back to {}:{}", HsTag, dest_host, dest_port);

        char dest_port_buf[8];
        const auto [dest_port_end, dest_port_ec] = std::to_chars(dest_port_buf, dest_port_buf + sizeof(dest_port_buf), dest_port);
        auto [connect_ec, dest_conn] = co_await connect::async_forward(session.worker_ctx.router, dest_host, std::string_view(dest_port_buf, std::distance(dest_port_buf, dest_port_end)));
        if (fault::failed(connect_ec) || !dest_conn.valid())
        {
            trace::warn("{} connect to dest failed: {}", HsTag, fault::describe(connect_ec));
            co_return fault::code::reality_unreach;
        }

        auto *dest_socket_raw = dest_conn.release();

        boost::system::error_code write_ec;
        co_await net::async_write(*dest_socket_raw, net::buffer(raw_record.data(), raw_record.size()),
                                  net::redirect_error(net::use_awaitable, write_ec));
        if (write_ec)
        {
            trace::warn("{} write to dest failed: {}", HsTag, write_ec.message());
            co_return fault::code::reality_unreach;
        }

        auto dest_trans = transport::make_reliable(std::move(*dest_socket_raw));
        co_await connect::tunnel({inbound, std::move(dest_trans), session});

        trace::debug("{} fallback tunnel completed", HsTag);
        co_return fault::code::success;
    }

    // ============================================================
    // fetch_dest_cert
    // ============================================================

    auto fetch_dest_cert(const std::string_view host, const std::uint16_t port, connect::router &router)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        memory::vector<std::uint8_t> empty_cert;

        try
        {
            char cert_port_buf[8];
            const auto [cert_port_end, cert_port_ec2] = std::to_chars(cert_port_buf, cert_port_buf + sizeof(cert_port_buf), port);
            auto [connect_ec, conn] = co_await connect::async_forward(router, host, std::string_view(cert_port_buf, std::distance(cert_port_buf, cert_port_end)));
            if (fault::failed(connect_ec) || !conn.valid())
            {
                trace::warn("{} connect to dest for cert failed: {}", HsTag, fault::describe(connect_ec));
                co_return std::pair{fault::code::reality_certfail, empty_cert};
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
                co_return std::pair{fault::code::reality_certfail, empty_cert};
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
                // safe: BIO returns char* to internal memory, casting to uint8_t for DER certificate extraction
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
                co_return std::pair{fault::code::reality_certfail, empty_cert};
            }

            trace::debug("{} fetched dest certificate ({} bytes)", HsTag, cert_der.size());
            co_return std::pair{fault::code::success, std::move(cert_der)};
        }
        catch (const std::exception &e)
        {
            trace::warn("{} exception fetching cert: {}", HsTag, e.what());
            co_return std::pair{fault::code::reality_certfail, empty_cert};
        }
    }

    // ============================================================
    // 握手子流程
    // ============================================================

    // 用正确的 finished_key 重算 Finished 并加密握手记录
    static auto derive_and_encrypt_finished(const key_material &keys, shello_result &sh_result, std::span<const std::uint8_t> chello_raw)
        -> fault::code
    {
        constexpr std::size_t FINISHED_MSG_SIZE = 36; // Type(1) + Length(3) + verify_data(32)
        const auto &old_plaintext = sh_result.enc_hs_plain;

        if (old_plaintext.size() < FINISHED_MSG_SIZE)
        {
            trace::warn("{} plaintext too short for Finished: {}", HsTag, old_plaintext.size());
            return fault::code::reality_kdferr;
        }

        const auto ee_cert_cv = std::span<const std::uint8_t>(
            old_plaintext.data(), old_plaintext.size() - FINISHED_MSG_SIZE);

        const auto transcript_for_finished = crypto::sha256(
            chello_raw,
            sh_result.shello_msg,
            ee_cert_cv);

        const auto verify_data = compute_finished_verify(
            keys.server_finkey, transcript_for_finished);

        trace::debug("{} server Finished transcript computed", HsTag);
        trace::debug("{} server Finished verify_data computed", HsTag);

        memory::vector<std::uint8_t> correct_plaintext(ee_cert_cv.begin(), ee_cert_cv.end());
        correct_plaintext.push_back(tls::HS_FINISHED);
        correct_plaintext.push_back(0x00);
        correct_plaintext.push_back(0x00);
        correct_plaintext.push_back(static_cast<std::uint8_t>(verify_data.size()));
        correct_plaintext.insert(correct_plaintext.end(), verify_data.begin(), verify_data.end());

        auto [enc_ec, encrypted_record] = encrypt_record(
            encrypt_params{
                keys.server_hskey,
                keys.server_hsiv,
                0,
                tls::CT_HANDSHAKE,
                correct_plaintext});

        if (fault::failed(enc_ec))
        {
            trace::warn("{} failed to encrypt handshake record", HsTag);
            return enc_ec;
        }

        sh_result.enc_hs_plain = std::move(correct_plaintext);
        sh_result.enc_hs_record = std::move(encrypted_record);
        return fault::code::success;
    }

    // 读取并消费客户端 CCS + Finished
    static auto consume_client_finished(transport::transmission &inbound, const key_material &keys)
        -> net::awaitable<fault::code>
    {
        bool consumed = false;
        while (!consumed)
        {
            std::array<std::byte, tls::RECORD_HDR_LEN> rec_hdr{};
            if (!co_await read_exact(inbound, rec_hdr))
            {
                trace::warn("{} failed to read client record header", HsTag);
                co_return fault::code::io_error;
            }

        // safe: casting byte array to uint8_t to parse TLS record header fields
            const auto *hdr_raw = reinterpret_cast<const std::uint8_t *>(rec_hdr.data());
            const auto rec_ctype = hdr_raw[0];
            const auto rec_len = (static_cast<std::size_t>(hdr_raw[3]) << 8) |
                                 static_cast<std::size_t>(hdr_raw[4]);

            trace::debug("{} client rec: type=0x{:02x} len={}", HsTag,
                         static_cast<unsigned>(rec_ctype), rec_len);

            memory::vector<std::byte> rec_body(rec_len);
            if (rec_len > 0 && !co_await read_exact(inbound, rec_body))
            {
                trace::warn("{} failed to read client record body", HsTag);
                co_return fault::code::io_error;
            }

            if (rec_ctype == tls::CT_CHANGE_CIPHER_SPEC)
            {
                trace::debug("{} skipping client CCS record", HsTag);
                continue;
            }

            // 非 CCS 记录：尝试解密以判断是 Finished 还是 Alert
            {
                std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_nonce{};
                std::memcpy(client_nonce.data(), keys.client_hsiv.data(), tls::AEAD_NONCE_LEN);

                // safe: casting byte array to uint8_t span for AEAD additional data
                const auto ad_span = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(rec_hdr.data()), rec_hdr.size());
                // safe: casting byte vector to uint8_t span for AEAD ciphertext input
                const auto ct_span = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(rec_body.data()), rec_body.size());

                crypto::aead_context client_aead(
                    crypto::aead_cipher::aes_128_gcm,
                    std::span<const std::uint8_t>(keys.client_hskey.data(), keys.client_hskey.size()));

                const auto pt_size = crypto::aead_context::open_output_size(rec_body.size());
                memory::vector<std::uint8_t> decrypted(pt_size);
                const auto nonce_span = std::span<const std::uint8_t>(client_nonce.data(), client_nonce.size());

                const auto open_ec = client_aead.open(decrypted, ct_span, nonce_span, ad_span);

                if (!fault::failed(open_ec) && decrypted.size() >= 2)
                {
                    const auto inner_ctype = decrypted.back();
                    if (inner_ctype == tls::CT_ALERT && decrypted.size() >= 3)
                    {
                        trace::error("{} client sent TLS ALERT: level={}, desc=0x{:02x} — server Finished was rejected",
                                     HsTag,
                                     static_cast<unsigned>(decrypted[0]),
                                     static_cast<unsigned>(decrypted[1]));
                        co_return fault::code::reality_hsfail;
                    }
                    else
                    {
                        trace::debug("{} consumed client Finished record ({} bytes, inner_type=0x{:02x})",
                                     HsTag, rec_len, static_cast<unsigned>(inner_ctype));
                    }
                }
                else
                {
                    trace::warn("{} failed to decrypt client record (ec={}), raw {} bytes",
                                HsTag, static_cast<int>(open_ec), rec_len);
                    co_return fault::code::reality_hsfail;
                }
            }
            consumed = true;
        }

        co_return fault::code::success;
    }

    // ============================================================
    // Step 1-3: 读取 ClientHello + 解码私钥 + Reality 认证
    // ============================================================

    struct auth_stage_result
    {
        bool done = false;
        stealth::handshake_result result;
        memory::vector<std::uint8_t> raw_record;
        tls::hello_features ch_features;
        std::span<const std::uint8_t> decoded_privkey;
        auth_result auth_res;
    };

    static auto authenticate_client(
        transport::shared_transmission inbound_ptr,
        const psm::config &cfg,
        psm::context::session &session,
        net::steady_timer &deadline)
        -> net::awaitable<auth_stage_result>
    {
        auth_stage_result out;
        auto &inbound = *inbound_ptr;
        const auto &reality_cfg = cfg.stealth.reality;

        // 1. 读取 ClientHello
        auto [read_ec, raw_record] = co_await recognition::tls::read_tls_record(inbound);
        if (fault::failed(read_ec))
        {
            deadline.cancel();
            trace::warn("{} failed to read TLS record: {}", HsTag, fault::describe(read_ec));
            out.result.error = read_ec;
            if (read_ec == fault::code::canceled)
                out.result.error = fault::code::timeout;
            co_return out;
        }

        auto [parse_ec, ch_features] = recognition::tls::parse_client_hello(raw_record);
        if (fault::failed(parse_ec))
        {
            deadline.cancel();
            trace::warn("{} failed to parse ClientHello: {}", HsTag, fault::describe(parse_ec));
            const auto fb_ec = co_await fallback_dest(session, inbound_ptr, raw_record);
            if (fault::succeeded(fb_ec))
            {
                out.result.scheme = "reality";
                out.result.error = fault::code::success;
            }
            else
            {
                out.result.error = fb_ec;
            }
            co_return out;
        }

        trace::debug("{} ClientHello parsed, SNI: {}", HsTag, ch_features.server_name);

        // 2. 解码私钥
        const auto private_key_str = std::string(reality_cfg.private_key.data(), reality_cfg.private_key.size());
        auto decoded_key_str = crypto::base64_decode(private_key_str);
        if (decoded_key_str.size() != tls::REALITY_KEY_LEN)
        {
            deadline.cancel();
            trace::warn("{} invalid private key length: {}", HsTag, decoded_key_str.size());
            const auto fb_ec = co_await fallback_dest(session, inbound_ptr, raw_record);
            if (fault::succeeded(fb_ec))
            {
                out.result.scheme = "reality";
                out.result.error = fault::code::success;
            }
            else
            {
                out.result.error = fb_ec;
            }
            co_return out;
        }

        out.raw_record = std::move(raw_record);
        out.ch_features = std::move(ch_features);
        // safe: decoded_key_str is a local string, but we keep it alive via the decoded_key storage
        out.decoded_privkey = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(decoded_key_str.data()), decoded_key_str.size());

        // 3. Reality 认证
        auto [auth_ec, auth_res] = authenticate(reality_cfg, out.ch_features, out.decoded_privkey);
        if (!auth_res.authenticated)
        {
            deadline.cancel();
            // safe: casting uint8_t record data to byte iterators for preread buffer assignment
            auto set_preread = [&](stealth::handshake_result &r)
            {
                r.transport = inbound_ptr;
                r.detected = protocol::protocol_type::tls;
                r.preread.assign(
                    reinterpret_cast<const std::byte *>(out.raw_record.data()),
                    reinterpret_cast<const std::byte *>(out.raw_record.data() + out.raw_record.size()));
            };

            if (auth_ec == fault::code::reality_badsni)
            {
                trace::debug("{} SNI mismatch, falling back to standard TLS", HsTag);
                set_preread(out.result);
                co_return out;
            }
            if (out.ch_features.server_name.empty())
            {
                trace::debug("{} auth failed with empty SNI, falling back to standard TLS", HsTag);
                set_preread(out.result);
                co_return out;
            }
            trace::debug("{} auth failed: {}, not Reality, passing to next scheme", HsTag, fault::describe(auth_ec));
            set_preread(out.result);
            co_return out;
        }

        trace::info("{} authentication successful", HsTag);
        out.auth_res = std::move(auth_res);
        out.done = true;
        co_return out;
    }

    // ============================================================
    // Step 4-6: ECDH 密钥交换 + ServerHello 生成 + 密钥派生
    // ============================================================

    struct negotiate_result
    {
        bool done = false;
        stealth::handshake_result result;
        key_material keys;
        shello_result sh_result;
        memory::vector<std::uint8_t> shared_secret;
    };

    static auto negotiate_tls(
        const tls::hello_features &ch_features,
        const auth_result &auth_res,
        net::steady_timer &deadline)
        -> negotiate_result
    {
        negotiate_result out;

        // 4. TLS ECDH 密钥交换
        auto [ephemeral_ec, shared_secret] = crypto::x25519(
            std::span<const std::uint8_t>(auth_res.server_ephkey.private_key.data(),
                                          auth_res.server_ephkey.private_key.size()),
            std::span<const std::uint8_t>(ch_features.x25519_key.data(),
                                          ch_features.x25519_key.size()));
        if (fault::failed(ephemeral_ec))
        {
            deadline.cancel();
            trace::warn("{} ephemeral X25519 key exchange failed", HsTag);
            out.result.error = ephemeral_ec;
            return out;
        }

        // 5. 生成 ServerHello
        key_material dummy_keys{};
        auto [sh_ec, sh_result] = generate_shello(
            hello_request{
                ch_features,
                auth_res.server_ephkey.public_key,
                dummy_keys,
                {},
                ch_features.raw_hs_msg,
                std::span<const std::uint8_t>(auth_res.auth_key.data(), auth_res.auth_key.size())});

        if (fault::failed(sh_ec))
        {
            deadline.cancel();
            trace::warn("{} failed to generate ServerHello: {}", HsTag, fault::describe(sh_ec));
            out.result.error = sh_ec;
            return out;
        }

        auto [ks_ec, keys] = derive_handshake_keys(
            shared_secret,
            ch_features.raw_hs_msg,
            sh_result.shello_msg);

        if (fault::failed(ks_ec))
        {
            deadline.cancel();
            trace::warn("{} failed to derive keys: {}", HsTag, fault::describe(ks_ec));
            out.result.error = ks_ec;
            return out;
        }

        // 6. 用正确密钥重算 Finished
        const auto finished_ec = derive_and_encrypt_finished(keys, sh_result, ch_features.raw_hs_msg);
        if (fault::failed(finished_ec))
        {
            deadline.cancel();
            out.result.error = finished_ec;
            return out;
        }

        out.keys = std::move(keys);
        out.sh_result = std::move(sh_result);
        out.shared_secret.assign(shared_secret.begin(), shared_secret.end());
        out.done = true;
        return out;
    }

    // ============================================================
    // Step 7-8: 发送握手记录 + 消费客户端 Finished
    // ============================================================

    static auto complete_hello(
        transport::transmission &inbound,
        const key_material &keys,
        const shello_result &sh_result,
        net::steady_timer &deadline)
        -> net::awaitable<std::pair<fault::code, bool>>
    {
        // 7. 发送握手记录（合并写入）
        {
            std::error_code write_ec;
            const auto &sh_rec = sh_result.shello_record;
            const auto &ccs_rec = sh_result.ccs_record;
            const auto &ehs_rec = sh_result.enc_hs_record;
            const std::size_t hs_total = sh_rec.size() + ccs_rec.size() + ehs_rec.size();
            memory::vector<std::byte> hs_combined(hs_total);
            std::size_t hs_off = 0;
            std::memcpy(hs_combined.data() + hs_off, sh_rec.data(), sh_rec.size());
            hs_off += sh_rec.size();
            std::memcpy(hs_combined.data() + hs_off, ccs_rec.data(), ccs_rec.size());
            hs_off += ccs_rec.size();
            std::memcpy(hs_combined.data() + hs_off, ehs_rec.data(), ehs_rec.size());
            co_await transport::async_write(inbound, hs_combined, write_ec);
            if (write_ec)
            {
                deadline.cancel();
                trace::warn("{} failed to send handshake records: {}", HsTag, write_ec.message());
                auto err = fault::to_code(write_ec);
                if (err == fault::code::canceled)
                    err = fault::code::timeout;
                co_return std::pair{err, false};
            }
        }

        // 8. 消费客户端 CCS + Finished
        const auto consumed_ec = co_await consume_client_finished(inbound, keys);
        if (fault::failed(consumed_ec))
        {
            deadline.cancel();
            co_return std::pair{consumed_ec, false};
        }

        co_return std::pair{fault::code::success, true};
    }

    // ============================================================
    // handshake 主入口
    // ============================================================

    auto handshake(transport::shared_transmission inbound, const psm::config &cfg, psm::context::session &session)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!inbound)
        {
            result.error = fault::code::io_error;
            co_return result;
        }

        // 握手超时保护：30 秒内必须完成
        net::steady_timer deadline(inbound->executor(), std::chrono::seconds(30));
        deadline.async_wait(
            [&inbound](const boost::system::error_code &ec)
            {
                if (!ec)
                {
                    inbound->cancel();
                }
            });

        // Steps 1-3: 认证客户端
        auto auth = co_await authenticate_client(inbound, cfg, session, deadline);
        if (!auth.done)
            co_return auth.result;

        // Steps 4-6: TLS 密钥协商
        auto nego = negotiate_tls(auth.ch_features, auth.auth_res, deadline);
        if (!nego.done)
            co_return nego.result;

        // Steps 7-8: 发送握手记录 + 消费客户端 Finished
        auto [hello_ec, hello_ok] = co_await complete_hello(*inbound, nego.keys, nego.sh_result, deadline);
        if (!hello_ok)
        {
            result.error = hello_ec;
            if (result.error == fault::code::canceled)
                result.error = fault::code::timeout;
            co_return result;
        }

        // 9. 派生应用数据密钥
        const auto full_transcript_hash = crypto::sha256(
            std::span<const std::uint8_t>(auth.ch_features.raw_hs_msg.data(), auth.ch_features.raw_hs_msg.size()),
            std::span<const std::uint8_t>(nego.sh_result.shello_msg.data(), nego.sh_result.shello_msg.size()),
            std::span<const std::uint8_t>(nego.sh_result.enc_hs_plain.data(), nego.sh_result.enc_hs_plain.size()));

        const auto app_ec = derive_application_keys(nego.keys.master_secret,
                                                    {full_transcript_hash.data(), full_transcript_hash.size()}, nego.keys);
        if (fault::failed(app_ec))
        {
            deadline.cancel();
            trace::warn("{} failed to derive application keys", HsTag);
            result.error = app_ec;
            co_return result;
        }

        // 10. 创建加密传输层 + 预读内层数据
        auto reality_session = std::make_shared<seal>(
            std::move(inbound), nego.keys);

        constexpr std::size_t preread_size = 64;
        memory::vector<std::byte> inner_buf(preread_size);
        std::error_code read_inner_ec;
        const auto inner_n = co_await reality_session->async_read_some(
            std::span<std::byte>(inner_buf.data(), preread_size), read_inner_ec);

        if (read_inner_ec || inner_n == 0)
        {
            deadline.cancel();
            trace::warn("{} failed to read inner data: {}", HsTag, read_inner_ec.message());
            result.error = fault::to_code(read_inner_ec);
            co_return result;
        }

        result.transport = std::move(reality_session);
        result.detected = protocol::protocol_type::vless;
        result.preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));
        result.scheme = "reality";
        result.error = fault::code::success;

        deadline.cancel();
        trace::info("{} handshake completed successfully", HsTag);
        co_return result;
    }
} // namespace psm::stealth::reality
