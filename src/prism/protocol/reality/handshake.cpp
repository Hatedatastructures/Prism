/**
 * @file handshake.cpp
 * @brief Reality 握手状态机实现
 * @details Reality 协议的核心实现，协调所有子模块完成握手流程。
 */

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
        if (dest.empty())
        {
            return false;
        }

        const auto colon_pos = dest.rfind(':');
        if (colon_pos == std::string_view::npos)
        {
            host = dest;
            port = 443;
            return true;
        }

        // 检查是否为 IPv6
        if (dest.find(']') != std::string_view::npos)
        {
            const auto bracket_end = dest.find(']');
            if (bracket_end == std::string_view::npos)
            {
                return false;
            }
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

        // ================================================================
        // Step 1: 读取完整 ClientHello
        // ================================================================
        auto [read_ec, raw_record] = co_await read_tls_record(*ctx.inbound, preread);
        if (fault::failed(read_ec))
        {
            trace::warn("{} failed to read TLS record: {}", HsTag, fault::describe(read_ec));
            result.error = read_ec;
            co_return result;
        }

        // ================================================================
        // Step 2: 解析 ClientHello
        // ================================================================
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

        // ================================================================
        // Step 3: 解码私钥
        // ================================================================
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

        // ================================================================
        // Step 4: Reality 认证
        // ================================================================
        auto [auth_ec, auth_res] = authenticate(reality_cfg, client_hello, decoded_private_key);
        if (!auth_res.authenticated)
        {
            trace::debug("{} auth failed: {}, falling back to dest", HsTag, fault::describe(auth_ec));
            const auto fb_ec = co_await fallback_to_dest(ctx, raw_record);
            result.type = (fault::succeeded(fb_ec)) ? handshake_result_type::fallback : handshake_result_type::failed;
            result.error = fb_ec;
            co_return result;
        }

        trace::info("{} authentication successful", HsTag);

        // ================================================================
        // Step 5: 获取 dest 证书
        // ================================================================
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

        // ================================================================
        // Step 6: TLS 1.3 握手
        // ================================================================

        // 6a. 派生握手密钥
        auto [ks_ec, keys] = derive_handshake_keys(
            auth_res.shared_secret,
            client_hello.raw_message,
            {} // server_hello_msg 在生成后填充
        );

        // 先生成 ServerHello 获取消息字节
        auto [sh_ec, sh_result] = generate_server_hello(
            client_hello,
            auth_res.server_ephemeral_key.public_key,
            keys,
            dest_cert,
            client_hello.raw_message);

        if (fault::failed(sh_ec))
        {
            trace::warn("{} failed to generate ServerHello: {}", HsTag, fault::describe(sh_ec));
            result.error = sh_ec;
            co_return result;
        }

        // 6b. 用 ServerHello 消息重新派生密钥
        std::tie(ks_ec, keys) = derive_handshake_keys(
            auth_res.shared_secret,
            client_hello.raw_message,
            sh_result.server_hello_msg);

        if (fault::failed(ks_ec))
        {
            trace::warn("{} failed to derive keys: {}", HsTag, fault::describe(ks_ec));
            result.error = ks_ec;
            co_return result;
        }

        // 6c. 重新生成加密握手记录（使用正确的密钥）
        auto [sh_ec2, sh_result2] = generate_server_hello(
            client_hello,
            auth_res.server_ephemeral_key.public_key,
            keys,
            dest_cert,
            client_hello.raw_message);

        if (fault::failed(sh_ec2))
        {
            result.error = sh_ec2;
            co_return result;
        }

        // 6d. 发送所有握手记录到客户端
        std::error_code write_ec;

        // ServerHello 记录
        co_await ctx.inbound->async_write(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(sh_result2.server_hello_record.data()),
                sh_result2.server_hello_record.size()),
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
                reinterpret_cast<const std::byte *>(sh_result2.change_cipher_spec_record.data()),
                sh_result2.change_cipher_spec_record.size()),
            write_ec);
        if (write_ec)
        {
            trace::warn("{} failed to send ChangeCipherSpec: {}", HsTag, write_ec.message());
            result.error = fault::to_code(write_ec);
            co_return result;
        }

        // 加密握手记录
        co_await ctx.inbound->async_write(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(sh_result2.encrypted_handshake_record.data()),
                sh_result2.encrypted_handshake_record.size()),
            write_ec);
        if (write_ec)
        {
            trace::warn("{} failed to send encrypted handshake: {}", HsTag, write_ec.message());
            result.error = fault::to_code(write_ec);
            co_return result;
        }

        // 6e. 派生应用数据密钥
        // RFC 8446: application traffic secret 使用 transcript hash（不是原始 transcript）
        // transcript = CH + SH + EE + Cert + CV + Finished → SHA-256 → hash
        const auto full_transcript_hash = crypto::sha256(
            {client_hello.raw_message.data(), client_hello.raw_message.size()},
            {sh_result2.server_hello_msg.data(), sh_result2.server_hello_msg.size()},
            {sh_result2.encrypted_handshake_plaintext.data(), sh_result2.encrypted_handshake_plaintext.size()});

        const auto app_ec = derive_application_keys(keys.master_secret,
                                                    {full_transcript_hash.data(), full_transcript_hash.size()}, keys);
        if (fault::failed(app_ec))
        {
            trace::warn("{} failed to derive application keys", HsTag);
            result.error = app_ec;
            co_return result;
        }

        // ================================================================
        // Step 7: 创建加密传输层
        // ================================================================
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
