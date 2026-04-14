#include <prism/protocol/reality/handshake.hpp>
#include <prism/protocol/reality/request.hpp>
#include <prism/protocol/reality/auth.hpp>
#include <prism/protocol/reality/keygen.hpp>
#include <prism/protocol/reality/response.hpp>
#include <prism/protocol/reality/session.hpp>
#include <prism/protocol/reality/config.hpp>
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
#include <string>

namespace psm::protocol::reality
{
    constexpr std::string_view HsTag = "[Reality.Handshake]";

    auto parse_dest(const std::string_view dest, std::string &host, std::uint16_t &port) -> bool
    {
        // 解析 Reality dest 配置字符串为 host + port。
        // 支持三种格式：
        //   "example.com"        → host=example.com, port=443（默认）
        //   "example.com:8443"   → host=example.com, port=8443
        //   "[::1]:8443"         → host=::1, port=8443（IPv6）
        // 用 rfind(':') 而不是 find(':') 是因为 IPv6 地址本身含冒号，
        // 最后一个冒号才是端口分隔符。

        if (dest.empty())
        {
            return false;
        }

        // 从右侧找冒号，区分端口分隔符和 IPv6 地址中的冒号
        const auto colon_pos = dest.rfind(':');
        if (colon_pos == std::string_view::npos)
        {
            // 没有冒号 → 纯主机名，使用默认端口 443（HTTPS）
            host = dest;
            port = 443;
            return true;
        }

        // 有方括号说明是 IPv6 地址，格式为 [address]:port
        if (dest.find(']') != std::string_view::npos)
        {
            const auto bracket_end = dest.find(']');
            if (bracket_end == std::string_view::npos)
            {
                return false;
            }
            // 去掉方括号取出 IPv6 地址
            host = dest.substr(1, bracket_end - 1);
            if (bracket_end + 2 < dest.size() && dest[bracket_end + 1] == ':')
            {
                port = static_cast<std::uint16_t>(std::stoi(std::string(dest.substr(bracket_end + 2))));
            }
            else
            {
                port = 443;
            }
            return true;
        }

        // 普通的 host:port 格式
        host = dest.substr(0, colon_pos);
        try
        {
            port = static_cast<std::uint16_t>(std::stoi(std::string(dest.substr(colon_pos + 1))));
        }
        catch (...)
        {
            return false;
        }
        return true;
    }

    auto fallback_to_dest(psm::agent::session_context &ctx, const std::span<const std::uint8_t> raw_record)
        -> net::awaitable<fault::code>
    {
        // 当 Reality 认证失败但 SNI 匹配时，将连接透明转发到配置的 dest 目标服务器。
        // 这样做的好处：对非 Reality 客户端来说，看起来就像在访问一个正常的 TLS 网站。
        //
        // 关键：必须把已经读走的 ClientHello 原始记录写回给 dest 服务器，
        // 因为 dest 服务器需要完整的 TLS 握手数据，而我们已经从传输层读走了这些字节。

        const auto &reality_cfg = ctx.server.cfg.reality;

        // 解析 dest 地址
        std::string dest_host;
        std::uint16_t dest_port = 443;
        if (!parse_dest(std::string_view(reality_cfg.dest.data(), reality_cfg.dest.size()), dest_host, dest_port))
        {
            trace::error("{} invalid dest config: {}", HsTag, reality_cfg.dest);
            co_return fault::code::reality_dest_unreachable;
        }

        trace::info("{} falling back to {}:{}", HsTag, dest_host, dest_port);

        // 异步解析 dest 地址

        // TODO 还未接入解析层默认使用boost::asio的解析，后续需要改为解析层接口
        net::ip::tcp::socket dest_socket(ctx.worker.io_context);
        auto resolver = net::ip::tcp::resolver(ctx.worker.io_context);
        boost::system::error_code resolve_ec;
        auto endpoints = co_await resolver.async_resolve(
            dest_host, std::to_string(dest_port),
            net::redirect_error(net::use_awaitable, resolve_ec));
        if (resolve_ec)
        {
            trace::warn("{} resolve dest failed: {}", HsTag, resolve_ec.message());
            co_return fault::code::reality_dest_unreachable;
        }

        // 异步连接到 dest 服务器
        boost::system::error_code connect_ec;
        co_await net::async_connect(dest_socket, endpoints,
                                    net::redirect_error(net::use_awaitable, connect_ec));
        if (connect_ec)
        {
            trace::warn("{} connect to dest failed: {}", HsTag, connect_ec.message());
            co_return fault::code::reality_dest_unreachable;
        }

        // 将已读取的 ClientHello 完整数据异步写入 dest
        boost::system::error_code write_ec;
        co_await net::async_write(dest_socket, net::buffer(raw_record.data(), raw_record.size()),
                                  net::redirect_error(net::use_awaitable, write_ec));
        if (write_ec)
        {
            trace::warn("{} write to dest failed: {}", HsTag, write_ec.message());
            co_return fault::code::reality_dest_unreachable;
        }

        // 创建 dest 传输层
        auto dest_trans = channel::transport::make_reliable(std::move(dest_socket));

        // 进入双向隧道
        co_await pipeline::primitives::tunnel(ctx.inbound, std::move(dest_trans), ctx);

        trace::debug("{} fallback tunnel completed", HsTag);
        co_return fault::code::success;
    }

    auto fetch_dest_certificate(const std::string_view host, const std::uint16_t port, const net::any_io_executor executor)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        memory::vector<std::uint8_t> empty_cert;

        try
        {
            // 异步解析地址
            net::ip::tcp::socket socket(executor);
            auto resolver = net::ip::tcp::resolver(executor);
            boost::system::error_code ec;
            auto endpoints = co_await resolver.async_resolve(
                std::string(host), std::to_string(port),
                net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                trace::warn("{} resolve dest for cert failed: {}", HsTag, ec.message());
                co_return std::pair{fault::code::reality_certificate_error, empty_cert};
            }

            // 异步连接
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await net::async_connect(socket, endpoints, token);
            if (ec)
            {
                trace::warn("{} connect to dest for cert failed: {}", HsTag, ec.message());
                co_return std::pair{fault::code::reality_certificate_error, empty_cert};
            }

            // TLS 握手（仅获取证书）
            namespace ssl_local = net::ssl;
            ssl_local::context ssl_ctx(ssl_local::context::tls_client);
            // 不验证证书（我们只需要获取它）
            ssl_ctx.set_verify_mode(ssl_local::verify_none);

            ssl_local::stream<net::ip::tcp::socket> ssl_stream(std::move(socket), ssl_ctx);
            SSL_set_tlsext_host_name(ssl_stream.native_handle(), std::string(host).c_str());

            co_await ssl_stream.async_handshake(ssl_local::stream_base::client,
                                                net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                trace::warn("{} TLS handshake to dest failed: {}", HsTag, ec.message());
                co_return std::pair{fault::code::reality_certificate_error, empty_cert};
            }

            // 获取证书（BoringSSL: SSL_get_peer_certificate 获取叶子证书）
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

            // 关闭连接
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
            // 解析失败，回退到 dest
            const auto fb_ec = co_await fallback_to_dest(ctx, raw_record);
            result.type = (fault::succeeded(fb_ec)) ? handshake_result_type::fallback : handshake_result_type::failed;
            result.error = fb_ec;
            co_return result;
        }

        trace::debug("{} ClientHello parsed, SNI: {}", HsTag, client_hello.server_name);

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

        auto [auth_ec, auth_res] = authenticate(reality_cfg, client_hello, decoded_private_key);
        if (!auth_res.authenticated)
        {
            // SNI 不匹配说明是普通 TLS 客户端，不透传到 dest，让 session 走标准 TLS
            if (auth_ec == fault::code::reality_sni_mismatch)
            {
                trace::debug("{} SNI mismatch, falling back to standard TLS", HsTag);
                result.type = handshake_result_type::not_reality;
                result.raw_tls_record.assign(
                    reinterpret_cast<const std::byte *>(raw_record.data()),
                    reinterpret_cast<const std::byte *>(raw_record.data() + raw_record.size()));
                co_return result;
            }
            // SNI 为空 + auth 失败 → 非 Reality 客户端（IP 地址连接不发 SNI），走标准 TLS
            if (client_hello.server_name.empty())
            {
                trace::debug("{} auth failed with empty SNI, falling back to standard TLS", HsTag);
                result.type = handshake_result_type::not_reality;
                result.raw_tls_record.assign(
                    reinterpret_cast<const std::byte *>(raw_record.data()),
                    reinterpret_cast<const std::byte *>(raw_record.data() + raw_record.size()));
                co_return result;
            }
            // SNI 匹配但其他 auth 失败（如 short_id 错误、key 不匹配）→ 透传到 dest
            trace::debug("{} auth failed: {}, falling back to dest", HsTag, fault::describe(auth_ec));
            const auto fb_ec = co_await fallback_to_dest(ctx, raw_record);
            result.type = (fault::succeeded(fb_ec)) ? handshake_result_type::fallback : handshake_result_type::failed;
            result.error = fb_ec;
            co_return result;
        }

        trace::info("{} authentication successful", HsTag);

        std::string dest_host;
        std::uint16_t dest_port = 443;
        parse_dest(std::string_view(reality_cfg.dest.data(), reality_cfg.dest.size()), dest_host, dest_port);

        auto [cert_ec, dest_cert] = co_await fetch_dest_certificate(
            dest_host, dest_port, ctx.inbound->executor());
        if (fault::failed(cert_ec))
        {
            trace::warn("{} failed to fetch dest certificate", HsTag);
            result.error = cert_ec;
            co_return result;
        }

        // 6a. 计算 TLS 握手用的 ECDH 共享密钥
        // 注意：auth_res.shared_secret 是 Reality 认证用的（长期私钥 × 客户端公钥），
        // TLS 1.3 握手必须使用临时密钥对的 ECDH（临时私钥 × 客户端公钥）。
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

        // 6b. 先生成 ServerHello 获取消息字节
        // 用 dummy 密钥生成——只需要 server_hello_msg/record/CCS 和明文中的
        // EE + Cert + CV 部分（这些不依赖密钥）。Finished 会用正确密钥重算。
        key_material dummy_keys{};
        auto [sh_ec, sh_result] = generate_server_hello(
            client_hello,
            auth_res.server_ephemeral_key.public_key,
            dummy_keys,
            dest_cert,
            client_hello.raw_message,
            std::span<const std::uint8_t>(auth_res.auth_key.data(), auth_res.auth_key.size()));

        if (fault::failed(sh_ec))
        {
            trace::warn("{} failed to generate ServerHello: {}", HsTag, fault::describe(sh_ec));
            result.error = sh_ec;
            co_return result;
        }

        // 6c. 用 TLS 共享密钥和实际 ServerHello 消息派生握手密钥
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

        // 6d. 用正确的 finished_key 重算 Finished，重建明文并加密
        // sh_result.encrypted_handshake_plaintext 中末尾 36 字节是 Finished 消息
        // (type=0x14 + length=0x000020 + verify_data=32B)
        // 前面的 EE + Cert + CV 不依赖密钥，可以直接复用
        {
            constexpr std::size_t FINISHED_MSG_SIZE = 36; // Type(1) + Length(3) + verify_data(32)
            const auto &old_plaintext = sh_result.encrypted_handshake_plaintext;

            if (old_plaintext.size() < FINISHED_MSG_SIZE)
            {
                trace::warn("{} plaintext too short for Finished: {}", HsTag, old_plaintext.size());
                result.error = fault::code::reality_key_schedule_error;
                co_return result;
            }

            // EE + Cert + CV 部分
            const auto ee_cert_cv = std::span<const std::uint8_t>(
                old_plaintext.data(), old_plaintext.size() - FINISHED_MSG_SIZE);

            // transcript hash = SHA-256(CH || SH || EE || Cert || CV)
            const auto transcript_for_finished = crypto::sha256(
                client_hello.raw_message,
                sh_result.server_hello_msg,
                ee_cert_cv);

            // 用正确的 finished_key 计算 verify_data
            const auto verify_data = compute_finished_verify_data(
                keys.server_finished_key, transcript_for_finished);

            // 构建正确的明文: EE + Cert + CV + Finished
            memory::vector<std::uint8_t> correct_plaintext(ee_cert_cv.begin(), ee_cert_cv.end());
            correct_plaintext.push_back(tls::HANDSHAKE_TYPE_FINISHED);
            correct_plaintext.push_back(0x00);
            correct_plaintext.push_back(0x00);
            correct_plaintext.push_back(static_cast<std::uint8_t>(verify_data.size()));
            correct_plaintext.insert(correct_plaintext.end(), verify_data.begin(), verify_data.end());

            // 用正确的密钥加密
            auto [enc_ec, encrypted_record] = encrypt_tls_record(
                keys.server_handshake_key,
                keys.server_handshake_iv,
                0, // sequence = 0
                tls::CONTENT_TYPE_HANDSHAKE,
                correct_plaintext);

            if (fault::failed(enc_ec))
            {
                trace::warn("{} failed to encrypt handshake record", HsTag);
                result.error = enc_ec;
                co_return result;
            }

            // 更新 sh_result 的明文和加密记录
            sh_result.encrypted_handshake_plaintext = std::move(correct_plaintext);
            sh_result.encrypted_handshake_record = std::move(encrypted_record);
        }

        // 6e. 发送所有握手记录到客户端
        std::error_code write_ec;

        // ServerHello 记录
        co_await ctx.inbound->async_write(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(sh_result.server_hello_record.data()),
                sh_result.server_hello_record.size()),
            write_ec);
        if (write_ec)
        {
            trace::warn("{} failed to send ServerHello: {}", HsTag, write_ec.message());
            result.error = fault::to_code(write_ec);
            co_return result;
        }

        // ChangeCipherSpec 记录
        co_await ctx.inbound->async_write(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(sh_result.change_cipher_spec_record.data()),
                sh_result.change_cipher_spec_record.size()),
            write_ec);
        if (write_ec)
        {
            trace::warn("{} failed to send ChangeCipherSpec: {}", HsTag, write_ec.message());
            result.error = fault::to_code(write_ec);
            co_return result;
        }

        // 加密握手记录（用正确的密钥加密的版本）
        co_await ctx.inbound->async_write(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(sh_result.encrypted_handshake_record.data()),
                sh_result.encrypted_handshake_record.size()),
            write_ec);
        if (write_ec)
        {
            trace::warn("{} failed to send encrypted handshake: {}", HsTag, write_ec.message());
            result.error = fault::to_code(write_ec);
            co_return result;
        }

        // 6e. 读取并丢弃客户端 CCS + Finished
        // TLS 1.3 客户端在收到服务端 Finished 后依次发送：
        //   1. ChangeCipherSpec 兼容记录（content type 0x14，可选）
        //   2. 加密的 ClientFinished（content type 0x17，用客户端握手密钥加密）
        // 必须在切换到应用密钥之前消费这些记录。
        {
            auto read_exact = [&](std::span<std::byte> buf) -> net::awaitable<bool> {
                std::size_t done = 0;
                while (done < buf.size())
                {
                    std::error_code ec;
                    const auto n = co_await ctx.inbound->async_read_some(
                        std::span<std::byte>(buf.data() + done, buf.size() - done), ec);
                    if (ec || n == 0)
                    {
                        co_return false;
                    }
                    done += n;
                }
                co_return true;
            };

            bool consumed_client_finished = false;
            while (!consumed_client_finished)
            {
                // 读取 TLS 记录头（5 字节）
                std::array<std::byte, tls::RECORD_HEADER_LEN> rec_hdr{};
                if (!co_await read_exact(rec_hdr))
                {
                    trace::warn("{} failed to read client record header", HsTag);
                    result.error = fault::code::io_error;
                    co_return result;
                }

                const auto *hdr_raw = reinterpret_cast<const std::uint8_t *>(rec_hdr.data());
                const auto rec_content_type = hdr_raw[0];
                const auto rec_len = (static_cast<std::size_t>(hdr_raw[3]) << 8) |
                                     static_cast<std::size_t>(hdr_raw[4]);

                trace::debug("{} [KEYDBG] client rec: type=0x{:02x} len={}", HsTag,
                             static_cast<unsigned>(rec_content_type), rec_len);

                // 读取记录体
                memory::vector<std::byte> rec_body(rec_len);
                if (rec_len > 0 && !co_await read_exact(rec_body))
                {
                    trace::warn("{} failed to read client record body", HsTag);
                    result.error = fault::code::io_error;
                    co_return result;
                }

                if (rec_content_type == tls::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
                {
                    trace::debug("{} skipping client CCS record", HsTag);
                    continue;
                }

                // 非 CCS 记录：尝试解密以判断是 Finished 还是 Alert
                {
                    // nonce = client_iv XOR sequence(0) = client_iv
                    std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_nonce{};
                    std::memcpy(client_nonce.data(), keys.client_handshake_iv.data(),
                                tls::AEAD_NONCE_LEN);

                    // additional_data = 5 字节 TLS 记录头
                    const auto ad_span = std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(rec_hdr.data()),
                        rec_hdr.size());

                    const auto ct_span = std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(rec_body.data()),
                        rec_body.size());

                    crypto::aead_context client_aead(
                        crypto::aead_cipher::aes_128_gcm,
                        std::span<const std::uint8_t>(
                            keys.client_handshake_key.data(),
                            keys.client_handshake_key.size()));

                    const auto pt_size = crypto::aead_context::open_output_size(rec_body.size());
                    memory::vector<std::uint8_t> decrypted(pt_size);
                    const auto nonce_span = std::span<const std::uint8_t>(
                        client_nonce.data(), client_nonce.size());

                    const auto open_ec = client_aead.open(decrypted, ct_span, nonce_span, ad_span);

                    if (!fault::failed(open_ec) && decrypted.size() >= 2)
                    {
                        const auto inner_content_type = decrypted.back();
                        if (inner_content_type == tls::CONTENT_TYPE_ALERT && decrypted.size() >= 3)
                        {
                            trace::error("{} client sent TLS ALERT: level={}, desc={} (0x{:02x})",
                                         HsTag,
                                         static_cast<unsigned>(decrypted[0]),
                                         static_cast<unsigned>(decrypted[1]),
                                         static_cast<unsigned>(decrypted[1]));
                        }
                        else
                        {
                            trace::debug("{} consumed client Finished record ({} bytes, inner_type=0x{:02x})",
                                         HsTag, rec_len,
                                         static_cast<unsigned>(inner_content_type));
                        }
                    }
                    else
                    {
                        trace::warn("{} failed to decrypt client record (ec={}), raw {} bytes",
                                    HsTag, static_cast<int>(open_ec), rec_len);
                    }
                }
                consumed_client_finished = true;
            }
        }

        // 6g. 派生应用数据密钥
        // RFC 8446: application traffic secret 使用 transcript hash（不是原始 transcript）
        // transcript = CH + SH + EE + Cert + CV + Finished → SHA-256 → hash
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

        auto reality_session = std::make_shared<session>(
            std::move(ctx.inbound), std::move(keys));

        // 读取少量内层数据作为预读
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

        trace::info("{} Reality handshake completed successfully", HsTag);
        co_return result;
    }
} // namespace psm::protocol::reality
