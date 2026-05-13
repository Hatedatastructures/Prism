/**
 * @file handshake.cpp
 * @brief ShadowTLS v3 服务端握手实现
 * @details 完全参照 sing-shadowtls service.go NewConnection case 3 的逻辑。
 *
 * ShadowTLS v3 服务端完整流程：
 * 1. 接收已读取的 ClientHello（由 Recognition 层预读），验证 HMAC 标签
 * 2. 认证成功后 → 建立到后端服务器的 TCP 连接，转发 ClientHello
 * 3. 从后端读取 ServerHello，返回给客户端
 * 4. 从 ServerHello 中提取 ServerRandom（32 字节）
 * 5. 双工转发握手阶段数据：
 *    - 客户端→后端：持续读取客户端帧，用 HMAC-SHA1(password, serverRandom+"C") 验证
 *      匹配成功 → 剥离 HMAC 头，作为第一个客户端数据帧返回
 *      不匹配 → 原样转发到后端
 *    - 后端→客户端：读取后端帧，对 Application Data 用 SHA256(password+serverRandom)
 *      XOR 加密 + 添加 HMAC-SHA1(password, serverRandom+"S") 标签
 * 6. 握手完成，返回认证后的客户端首帧
 */

#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/stealth/shadowtls/auth.hpp>
#include <prism/stealth/shadowtls/constants.hpp>
#include <prism/trace.hpp>
#include <prism/fault/code.hpp>

#include <boost/asio.hpp>
#include <openssl/hmac.h>

#include <cstring>
#include <algorithm>

namespace psm::stealth::shadowtls
{
    namespace net = boost::asio;

    // ═══════════════════════════════════════════════════════════
    // TLS 帧读取
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 从 socket 读取一个完整的 TLS 记录帧
     * @return TLS 记录帧（含 5 字节 header），失败返回空
     */
    static auto read_tls_frame(net::ip::tcp::socket &sock)
        -> net::awaitable<std::optional<std::vector<std::byte>>>
    {
        std::array<std::byte, tls_header_size> header{};

        boost::system::error_code header_ec;
        auto header_n = co_await net::async_read(
            sock, net::buffer(header.data(), tls_header_size),
            net::redirect_error(net::use_awaitable, header_ec));

        if (header_ec || header_n < tls_header_size)
        {
            co_return std::nullopt;
        }

        const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
        const std::uint16_t record_length = (static_cast<std::uint16_t>(raw[3]) << 8) | raw[4];

        std::vector<std::byte> frame(tls_header_size + record_length);
        std::memcpy(frame.data(), header.data(), tls_header_size);

        if (record_length > 0)
        {
            auto payload = std::span<std::byte>(frame.data() + tls_header_size, record_length);
            boost::system::error_code payload_ec;
            auto payload_n = co_await net::async_read(
                sock, net::buffer(payload.data(), payload.size()),
                net::redirect_error(net::use_awaitable, payload_ec));

            if (payload_ec || payload_n < record_length)
            {
                co_return std::nullopt;
            }
        }

        co_return frame;
    }

    // ═══════════════════════════════════════════════════════════
    // ServerHello 解析
    // ═══════════════════════════════════════════════════════════

    static auto extract_server_random(std::span<const std::byte> server_hello)
        -> std::optional<std::array<std::byte, tls_random_size>>
    {
        if (server_hello.size() < tls_header_size + 1 + 3 + 2 + tls_random_size)
        {
            return std::nullopt;
        }

        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        if (raw[0] != content_type_handshake || raw[5] != handshake_type_server_hello)
        {
            return std::nullopt;
        }

        std::array<std::byte, tls_random_size> server_random{};
        std::memcpy(server_random.data(), raw + tls_header_size + 1 + 3 + 2, tls_random_size);
        return server_random;
    }

    static bool is_server_hello_tls13(std::span<const std::byte> server_hello)
    {
        if (server_hello.size() < session_id_length_index)
        {
            return false;
        }

        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        std::size_t offset = session_id_length_index + 1;
        const std::uint8_t session_id_len = raw[session_id_length_index];
        offset += session_id_len;

        if (offset + 3 > server_hello.size())
            return false;
        offset += 3; // cipher_suite(2) + legacy_compression_method(1)

        if (offset + 2 > server_hello.size())
            return false;
        const std::uint16_t ext_list_len =
            (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
        offset += 2;

        const std::size_t ext_end = offset + ext_list_len;
        while (offset + 4 <= ext_end && offset < server_hello.size())
        {
            const std::uint16_t ext_type =
                (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
            const std::uint16_t ext_len =
                (static_cast<std::uint16_t>(raw[offset + 2]) << 8) | raw[offset + 3];
            offset += 4;

            if (ext_type == extension_supported_versions && ext_len == 2)
            {
                if (offset + 2 <= server_hello.size())
                {
                    const std::uint16_t version =
                        (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
                    return version == tls_version_1_3;
                }
            }
            offset += ext_len;
        }
        return false;
    }

    // ═══════════════════════════════════════════════════════════
    // XOR 辅助函数
    // ═══════════════════════════════════════════════════════════

    static void xor_with_key(std::span<std::byte> data, std::span<const std::uint8_t> key)
    {
        for (std::size_t i = 0; i < data.size(); ++i)
        {
            data[i] = static_cast<std::byte>(
                static_cast<std::uint8_t>(data[i]) ^ key[i % key.size()]);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 握手阶段数据帧处理（sing-shadowtls copyByFrameUntilHMACMatches）
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 持续读取客户端帧直到 HMAC 匹配
     * @details 读取 TLS Application Data 帧，验证 HMAC-SHA1(password, serverRandom+"C"+payload)
     * 匹配则剥离 HMAC 头返回；不匹配则转发到后端连接
     * @param client_sock 客户端 socket
     * @param backend_sock 后端 socket
     * @param password 密码
     * @param server_random ServerRandom
     * @return 认证成功返回首帧数据，失败返回 nullopt
     */
    /**
     * @brief 读取客户端帧直到 HMAC 匹配
     * @details 读取客户端发送的 TLS 记录。非 Application Data 和 HMAC 不匹配的帧
     * 转发到后端（如 TLS 握手记录）。HMAC 匹配的 Application Data 帧
     * 是客户端的首帧认证数据，剥离 HMAC 后返回。
     */
    static auto read_until_hmac_match(net::ip::tcp::socket &client_sock,
                                      net::ip::tcp::socket &backend_sock,
                                      std::string_view password,
                                      std::span<const std::byte> server_random)
        -> net::awaitable<std::optional<std::vector<std::byte>>>
    {
        while (true)
        {
            auto frame_opt = co_await read_tls_frame(client_sock);
            if (!frame_opt)
            {
                co_return std::nullopt;
            }

            auto &frame = *frame_opt;
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

            trace::info("[ShadowTLS] relay read: type=0x{:02x}, size={}, hex={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                raw[0], frame.size(),
                frame.size() > 0 ? raw[0] : 0, frame.size() > 1 ? raw[1] : 0,
                frame.size() > 2 ? raw[2] : 0, frame.size() > 3 ? raw[3] : 0,
                frame.size() > 4 ? raw[4] : 0, frame.size() > 5 ? raw[5] : 0,
                frame.size() > 6 ? raw[6] : 0, frame.size() > 7 ? raw[7] : 0,
                frame.size() > 8 ? raw[8] : 0, frame.size() > 9 ? raw[9] : 0);

            // 检查是否为 Application Data 且长度足够包含 HMAC
            if (raw[0] == content_type_application_data &&
                frame.size() > tls_hmac_header_size)
            {
                // 提取客户端 HMAC（TLS header 后的 4 字节）
                std::array<std::uint8_t, 4> client_hmac{};
                std::memcpy(client_hmac.data(), raw + tls_header_size, hmac_size);

                // HMAC 输入 = TLS header 之后的全部数据（含 HMAC + payload）
                // 与 Go 服务端 copyByFrameUntilHMACMatches 一致：
                // hmacVerify.Write(frame[tlsHmacHeaderSize:]) → offset 9 开始
                // 但 Go 的 verifyClientHello 用的是 frame[5:hmacIndex] + 0000 + frame[hmacIndex+4:]
                // 而 relay 阶段用的是：HMAC-SHA1(password, serverRandom + "C" + payload)
                // 其中 payload = frame[tlsHmacHeaderSize:] (offset 9, 不含 TLS header)
                auto payload = std::span<const std::byte>(
                    frame.data() + tls_hmac_header_size,
                    frame.size() - tls_hmac_header_size);

                if (verify_frame_hmac(password, server_random, payload, client_hmac))
                {
                    // HMAC 匹配！返回去掉 HMAC 头的帧
                    std::vector<std::byte> result(frame.size() - hmac_size);
                    std::memcpy(result.data(), raw, tls_header_size);
                    std::memcpy(result.data() + tls_header_size,
                                frame.data() + tls_hmac_header_size,
                                frame.size() - tls_hmac_header_size);
                    co_return result;
                }
            }

            // HMAC 不匹配或不是 Application Data → 转发到后端
            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(frame.data(), frame.size()),
                net::redirect_error(net::use_awaitable, write_ec));

            if (write_ec)
            {
                co_return std::nullopt;
            }
        }
    }

    /**
     * @brief 转发后端服务器握手数据到客户端（透传，不修改）
     * @details 握手阶段所有后端记录原样转发到客户端，不做 XOR/HMAC 修改。
     * TLS 1.3 AEAD 要求密文长度精确匹配，修改会破坏解密。
     * XOR+HMAC 包装是数据阶段的事，不是握手阶段的。
     */
    static auto relay_backend_to_client_passthrough(
        net::ip::tcp::socket &backend_sock,
        net::ip::tcp::socket &client_sock) -> net::awaitable<void>
    {
        while (true)
        {
            auto frame_opt = co_await read_tls_frame(backend_sock);
            if (!frame_opt)
            {
                co_return;
            }

            auto &frame = *frame_opt;
            boost::system::error_code write_ec;
            co_await net::async_write(
                client_sock,
                net::buffer(frame.data(), frame.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                co_return;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 主握手函数
    // ═══════════════════════════════════════════════════════════

    auto handshake(net::ip::tcp::socket &client_sock,
                   const config &cfg,
                   memory::vector<std::byte> client_hello)
        -> net::awaitable<handshake_result>
    {
        handshake_result result;

        if (client_hello.empty())
        {
            trace::warn("[ShadowTLS] Empty ClientHello");
            result.error = std::make_error_code(std::errc::invalid_argument);
            co_return result;
        }

        auto executor = client_sock.get_executor();

        // Step 1: 验证 ClientHello HMAC（多用户匹配）
        std::string matched_user;
        auto client_hello_span = std::span<const std::byte>(
            client_hello.data(), client_hello.size());

        if (cfg.version == 3)
        {
            for (const auto &u : cfg.users)
            {
                if (u.password.empty())
                    continue;
                if (verify_client_hello(client_hello_span, u.password))
                {
                    matched_user = u.name;
                    result.matched_user = matched_user;
                    break;
                }
            }
        }
        else
        {
            // v2 兼容模式
            if (!cfg.password.empty() && verify_client_hello(client_hello_span, cfg.password))
            {
                matched_user = "default";
            }
        }

        if (matched_user.empty())
        {
            trace::debug("[ShadowTLS] ClientHello HMAC verification failed");
            result.error = std::make_error_code(std::errc::permission_denied);
            co_return result;
        }

        trace::debug("[ShadowTLS] Client authenticated (user: {})", matched_user);

        // 获取匹配用户的密码
        std::string_view password;
        if (cfg.version == 3)
        {
            for (const auto &u : cfg.users)
            {
                if (u.name == matched_user)
                {
                    password = u.password;
                    break;
                }
            }
        }
        else
        {
            password = cfg.password;
        }

        // Step 3: 建立到后端服务器的连接
        // 解析 handshake_dest (host:port)
        std::string backend_host = cfg.handshake_dest;
        std::uint16_t backend_port = 443;
        if (auto pos = backend_host.find(':'); pos != std::string::npos)
        {
            backend_port = static_cast<std::uint16_t>(std::stoi(backend_host.substr(pos + 1)));
            backend_host = backend_host.substr(0, pos);
        }

        net::ip::tcp::resolver resolver(executor);
        auto endpoints = co_await resolver.async_resolve(backend_host, std::to_string(backend_port));

        net::ip::tcp::socket backend_sock(executor);
        boost::system::error_code connect_ec;
        auto connected_endpoint = co_await net::async_connect(
            backend_sock, endpoints,
            net::redirect_error(net::use_awaitable, connect_ec));
        (void)connected_endpoint;

        if (connect_ec)
        {
            trace::warn("[ShadowTLS] Backend connection failed: {}", connect_ec.message());
            result.error = std::make_error_code(std::errc::connection_refused);
            co_return result;
        }

        // Step 4: 转发 ClientHello 到后端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(client_hello.data(), client_hello.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                result.error = std::make_error_code(std::errc::connection_aborted);
                co_return result;
            }
        }

        // Step 5: 读取后端 ServerHello
        auto server_hello_opt = co_await read_tls_frame(backend_sock);
        if (!server_hello_opt)
        {
            trace::warn("[ShadowTLS] Failed to read ServerHello from backend");
            result.error = std::make_error_code(std::errc::connection_aborted);
            co_return result;
        }

        // Step 6: 将 ServerHello 返回给客户端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                client_sock,
                net::buffer(server_hello_opt->data(), server_hello_opt->size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                result.error = std::make_error_code(std::errc::connection_aborted);
                co_return result;
            }
        }

        // Step 7: 提取 ServerRandom
        auto server_hello_span = std::span<const std::byte>(
            server_hello_opt->data(), server_hello_opt->size());
        auto server_random_opt = extract_server_random(server_hello_span);

        if (!server_random_opt)
        {
            trace::warn("[ShadowTLS] Failed to extract ServerRandom");
            result.error = std::make_error_code(std::errc::protocol_error);
            co_return result;
        }

        auto server_random = std::span<const std::byte>(
            server_random_opt->data(), server_random_opt->size());

        // 检查 strict_mode + TLS 1.3
        if (cfg.strict_mode && !is_server_hello_tls13(server_hello_span))
        {
            trace::warn("[ShadowTLS] Backend does not support TLS 1.3, strict mode enabled");
            result.error = std::make_error_code(std::errc::protocol_not_supported);
            co_return result;
        }

        auto *sr_raw = reinterpret_cast<const std::uint8_t *>(server_random_opt->data());
        trace::info("[ShadowTLS] ServerRandom: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}, TLS1.3={}",
                    sr_raw[0], sr_raw[1], sr_raw[2], sr_raw[3],
                    sr_raw[4], sr_raw[5], sr_raw[6], sr_raw[7],
                    is_server_hello_tls13(server_hello_span));

        // Step 8: 双工握手阶段数据转发
        // 启动后台协程：后端 → 客户端（带 XOR + HMAC 修改）
        auto relay_done = std::make_shared<bool>(false);
        auto backend_relay = [&]() -> net::awaitable<void>
        {
            co_await relay_backend_to_client_passthrough(backend_sock, client_sock);
            *relay_done = true;
        };
        net::co_spawn(executor, std::move(backend_relay), net::detached);

        // 前台：读取客户端直到 HMAC 匹配
        auto first_frame_opt = co_await read_until_hmac_match(
            client_sock, backend_sock, password, server_random);

        // 关闭后端 socket，让 relay 协程退出
        {
            boost::system::error_code close_ec;
            backend_sock.shutdown(net::ip::tcp::socket::shutdown_both, close_ec);
            backend_sock.close(close_ec);
        }

        // 等待 relay 协程退出（最多 1 秒）
        for (int i = 0; i < 100 && !*relay_done; ++i)
        {
            net::steady_timer timer(executor);
            timer.expires_after(std::chrono::milliseconds(10));
            co_await timer.async_wait(net::use_awaitable);
        }

        if (!first_frame_opt)
        {
            trace::warn("[ShadowTLS] HMAC match failed during handshake relay");
            result.error = std::make_error_code(std::errc::protocol_error);
            co_return result;
        }

        trace::debug("[ShadowTLS] Handshake complete, returning first authenticated frame");
        result.authenticated = true;
        result.client_first_frame = std::move(*first_frame_opt);
        co_return result;
    }
} // namespace psm::stealth::shadowtls
