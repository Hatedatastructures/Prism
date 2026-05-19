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
 *    - 客户端→后端：持续读取客户端帧，用 HMAC-SHA1(password, serverRandom+"C"+payload) 验证
 *      （参照 sing-shadowtls hmacAdd/hmacVerify，含 "C" 标签）
 *      匹配成功 → 剥离 HMAC 头，作为第一个客户端数据帧返回
 *      不匹配 → 原样转发到后端
 *    - 后端→客户端：读取后端帧，对 Application Data 用 SHA256(password+serverRandom)
 *      XOR 加密 + 添加累积 HMAC-SHA1(password, serverRandom || all_payloads)[:4] 标签
 * 6. 握手完成，返回认证后的客户端首帧
 */

#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/stealth/shadowtls/auth.hpp>
#include <prism/stealth/shadowtls/constants.hpp>
#include <prism/trace.hpp>
#include <prism/fault/code.hpp>

#include <boost/asio.hpp>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#include <atomic>
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
     * @details 读取客户端发送的 TLS 记录。非 Application Data 和 HMAC 不匹配的帧
     * 转发到后端（如 TLS 握手记录）。HMAC 匹配的 Application Data 帧
     * 是客户端的首帧认证数据，剥离 HMAC 后返回。
     * @note 客户端→服务端方向握手阶段每帧独立 HMAC: HMAC-SHA1(password, serverRandom+"C"+payload)
     *       匹配成功后，将 payload 和 HMAC[:4] 加入 hmac_verify 状态，供传输阶段使用
     *       参照 sing-shadowtls copyByFrameUntilHMACMatches
     */
    static auto read_until_hmac_match(net::ip::tcp::socket &client_sock,
                                      net::ip::tcp::socket &backend_sock,
                                      std::string_view password,
                                      std::span<const std::byte> server_random,
                                      std::shared_ptr<HMAC_CTX> &hmac_verify_out)
        -> net::awaitable<std::optional<std::vector<std::byte>>>
    {
        auto sr_data = reinterpret_cast<const unsigned char *>(server_random.data());
        constexpr unsigned char tag_c = 'C';

        while (true)
        {
            auto frame_opt = co_await read_tls_frame(client_sock);
            if (!frame_opt)
            {
                trace::warn("[ShadowTLS.Relay] read_tls_frame from client returned nullopt");
                co_return std::nullopt;
            }

            auto &frame = *frame_opt;
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

            // 检查是否为 Application Data 且长度足够包含 HMAC
            if (raw[0] == content_type_application_data &&
                frame.size() > tls_hmac_header_size)
            {
                // 提取客户端 HMAC（TLS header 后的 4 字节）
                std::array<std::uint8_t, 4> client_hmac{};
                std::memcpy(client_hmac.data(), raw + tls_header_size, hmac_size);

                // payload = HMAC 之后的实际数据
                auto payload = std::span<const std::byte>(
                    frame.data() + tls_hmac_header_size,
                    frame.size() - tls_hmac_header_size);

                // 计算 HMAC(password, SR + "C" + payload)[:4]
                std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
                unsigned int md_len = 0;
                {
                    HMAC_CTX *h = HMAC_CTX_new();
                    HMAC_Init_ex(h, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
                    HMAC_Update(h, sr_data, server_random.size());
                    HMAC_Update(h, &tag_c, 1);
                    HMAC_Update(h, reinterpret_cast<const unsigned char *>(payload.data()), payload.size());
                    HMAC_Final(h, md.data(), &md_len);
                    HMAC_CTX_free(h);
                }

                bool match = CRYPTO_memcmp(md.data(), client_hmac.data(), hmac_size) == 0;
                trace::debug("[ShadowTLS.Relay] client frame HMAC: client={:02x}{:02x}{:02x}{:02x}, expected={:02x}{:02x}{:02x}{:02x}, match={}, frame_size={}, payload_size={}",
                    client_hmac[0], client_hmac[1], client_hmac[2], client_hmac[3],
                    md[0], md[1], md[2], md[3], match,
                    frame.size(), payload.size());

                if (match)
                {
                    trace::info("[ShadowTLS.Relay] client first frame HMAC matched, payload_size={}", payload.size());

                    // 参照 sing-shadowtls copyByFrameUntilHMACMatches:
                    // 匹配成功后，重置 HMAC，写入 payload + HMAC[:4]
                    // 这样 hmacVerify 状态 = password + SR + "C" + payload + HMAC[:4]
                    // 供传输阶段 verifiedConn 使用
                    auto hmac_verify = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
                    if (hmac_verify)
                    {
                        HMAC_Init_ex(hmac_verify.get(), password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
                        HMAC_Update(hmac_verify.get(), sr_data, server_random.size());
                        HMAC_Update(hmac_verify.get(), &tag_c, 1);
                        HMAC_Update(hmac_verify.get(),
                                    reinterpret_cast<const unsigned char *>(payload.data()),
                                    payload.size());
                        HMAC_Update(hmac_verify.get(), client_hmac.data(), hmac_size);
                        hmac_verify_out = hmac_verify;
                        trace::debug("[ShadowTLS.Relay] initialized hmac_verify for transport phase");
                    }

                    std::vector<std::byte> result(frame.size() - hmac_size);
                    std::memcpy(result.data(), raw, tls_header_size);
                    std::memcpy(result.data() + tls_header_size,
                                frame.data() + tls_hmac_header_size,
                                frame.size() - tls_hmac_header_size);
                    co_return result;
                }
            }

            // 非 Application Data 或 HMAC 不匹配 → 转发到后端
            trace::debug("[ShadowTLS.Relay] forwarding client frame to backend, type=0x{:02x}, size={}", raw[0], frame.size());
            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(frame.data(), frame.size()),
                net::redirect_error(net::use_awaitable, write_ec));

            if (write_ec)
            {
                trace::warn("[ShadowTLS.Relay] write to backend failed: {}", write_ec.message());
                co_return std::nullopt;
            }
        }
    }

    /**
     * @brief 转发后端服务器数据到客户端（带 XOR + 累积 HMAC 修改）
     * @details 参照 sing-shadowtls copyByFrameWithModification：
     * - 非 ApplicationData 帧（如 ChangeCipherSpec）：原样转发
     * - ApplicationData 帧：XOR 加密 payload + 累积 HMAC 标签
     *   帧格式：[TLS Header(5)] [HMAC(4)] [XOR'd payload(N)]
     *   HMAC = HMAC-SHA1(password, serverRandom || all_previous_XOR'd_payloads || current_XOR'd_payload)[:4]
     *   WriteKey = SHA256(password + serverRandom)
     * @note HMAC 上下文在整个 relay 过程中累积（参照 Go hmac.Write 不重置）
     *       使用 HMAC_CTX_copy 计算当前帧 HMAC，保留主状态继续累积
     *       HMAC 上下文通过 shared_ptr 传出，供后续 ShadowTLS transport 使用
     */
    static auto relay_backend_to_client_with_modification(
        net::ip::tcp::socket &backend_sock,
        net::ip::tcp::socket &client_sock,
        std::string_view password,
        std::span<const std::byte> server_random,
        std::shared_ptr<HMAC_CTX> &hmac_out) -> net::awaitable<void>
    {
        // 初始化 XOR 密钥
        auto write_key = compute_write_key(password, server_random);

        // 初始化累积 HMAC: HMAC(password, serverRandom)
        // 参照 sing-shadowtls service.go: hmacWrite := hmac.New(sha1.New, []byte(user.Password))
        //                              hmacWrite.Write(serverRandom)
        auto sr_bytes = reinterpret_cast<const unsigned char *>(server_random.data());

        auto hmac_main = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
        if (!hmac_main)
        {
            trace::warn("[ShadowTLS.Relay] failed to create HMAC_CTX");
            co_return;
        }

        HMAC_Init_ex(hmac_main.get(), password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(hmac_main.get(), sr_bytes, server_random.size());

        std::size_t frame_count = 0;
        std::size_t total_payload_bytes = 0;

        trace::debug("[ShadowTLS.Relay] initialized cumulative HMAC with serverRandom");

        while (true)
        {
            auto frame_opt = co_await read_tls_frame(backend_sock);
            if (!frame_opt)
            {
                trace::warn("[ShadowTLS.Relay] backend closed (nullopt), total_frames={}, total_payload_bytes={}",
                           frame_count, total_payload_bytes);
                // 传递 HMAC 上下文给调用者
                hmac_out = hmac_main;
                co_return;
            }

            auto &frame = *frame_opt;
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());
            frame_count++;

            trace::debug("[ShadowTLS.Relay] read backend frame #{}: type=0x{:02x}, size={}",
                        frame_count, raw[0], frame.size());

            if (raw[0] == content_type_application_data && frame.size() > tls_header_size)
            {
                auto payload = std::span<std::byte>(
                    frame.data() + tls_header_size, frame.size() - tls_header_size);

                trace::debug("[ShadowTLS.Relay] frame #{} is ApplicationData, payload_size={}", frame_count, payload.size());

                // 1. XOR 加密（Go: xorSlice）
                xor_with_key(payload, write_key);

                // 2. 累积 HMAC：将 XOR'd payload 加入主 HMAC 状态
                HMAC_Update(hmac_main.get(), reinterpret_cast<const unsigned char *>(payload.data()), payload.size());
                total_payload_bytes += payload.size();

                // 3. 计算当前帧 HMAC：复制状态并 finalize
                // Go: hmacHash := hmacWrite.Sum(nil)[:4]  (Sum 不改变状态)
                // OpenSSL: HMAC_CTX_copy + HMAC_Final
                std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
                unsigned int md_len = 0;
                {
                    HMAC_CTX *hmac_copy = HMAC_CTX_new();
                    HMAC_CTX_copy(hmac_copy, hmac_main.get());
                    HMAC_Final(hmac_copy, md.data(), &md_len);
                    HMAC_CTX_free(hmac_copy);
                }

                std::array<std::uint8_t, 4> hmac_tag{};
                std::memcpy(hmac_tag.data(), md.data(), hmac_size);

                trace::info("[ShadowTLS.Relay] frame #{} cumulative HMAC: {:02x}{:02x}{:02x}{:02x}, cumulative_payload_bytes={}",
                           frame_count, hmac_tag[0], hmac_tag[1], hmac_tag[2], hmac_tag[3],
                           total_payload_bytes);

                // 构建新帧：[TLS Header(5)] [HMAC(4)] [XOR'd payload(N)]
                const std::uint16_t new_payload_len = static_cast<std::uint16_t>(hmac_size + payload.size());
                std::vector<std::byte> new_frame(tls_header_size + new_payload_len);
                new_frame[0] = std::byte{content_type_application_data};
                new_frame[1] = std::byte{0x03};
                new_frame[2] = std::byte{0x03};
                new_frame[3] = static_cast<std::byte>(new_payload_len >> 8);
                new_frame[4] = static_cast<std::byte>(new_payload_len & 0xFF);
                std::memcpy(new_frame.data() + tls_header_size, hmac_tag.data(), hmac_size);
                std::memcpy(new_frame.data() + tls_hmac_header_size, payload.data(), payload.size());

                boost::system::error_code write_ec;
                co_await net::async_write(client_sock, net::buffer(new_frame.data(), new_frame.size()),
                    net::redirect_error(net::use_awaitable, write_ec));
                if (write_ec)
                {
                    trace::warn("[ShadowTLS.Relay] write to client failed: {}", write_ec.message());
                    // 即使失败也要传递 HMAC 上下文
                    hmac_out = hmac_main;
                    co_return;
                }

                trace::debug("[ShadowTLS.Relay] sent modified frame #{} to client, new_size={}", frame_count, new_frame.size());
            }
            else
            {
                // 非 ApplicationData 原样转发
                boost::system::error_code write_ec;
                co_await net::async_write(client_sock, net::buffer(frame.data(), frame.size()),
                    net::redirect_error(net::use_awaitable, write_ec));
                if (write_ec)
                {
                    trace::warn("[ShadowTLS.Relay] write passthrough failed: {}", write_ec.message());
                    hmac_out = hmac_main;
                    co_return;
                }

                trace::info("[ShadowTLS.Relay] sent passthrough frame #{} to client, type=0x{:02x}, size={}",
                           frame_count, raw[0], frame.size());
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

        trace::info("[ShadowTLS] handshake start, client_hello size={}", client_hello.size());
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
        std::string backend_host = cfg.handshake_dest;
        std::uint16_t backend_port = 443;
        if (auto pos = backend_host.find(':'); pos != std::string::npos)
        {
            backend_port = static_cast<std::uint16_t>(std::stoi(backend_host.substr(pos + 1)));
            backend_host = backend_host.substr(0, pos);
        }

        trace::debug("[ShadowTLS] connecting to backend: {}:{}", backend_host, backend_port);

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

        trace::debug("[ShadowTLS] backend connected");

        // Step 4: 转发 ClientHello 到后端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(client_hello.data(), client_hello.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn("[ShadowTLS] write ClientHello to backend failed: {}", write_ec.message());
                result.error = std::make_error_code(std::errc::connection_aborted);
                co_return result;
            }
        }

        trace::debug("[ShadowTLS] sent ClientHello to backend");

        // Step 5: 读取后端 ServerHello
        auto server_hello_opt = co_await read_tls_frame(backend_sock);
        if (!server_hello_opt)
        {
            trace::warn("[ShadowTLS] Failed to read ServerHello from backend");
            result.error = std::make_error_code(std::errc::connection_aborted);
            co_return result;
        }

        trace::debug("[ShadowTLS] received ServerHello from backend, size={}", server_hello_opt->size());

        // Step 6: 将 ServerHello 返回给客户端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                client_sock,
                net::buffer(server_hello_opt->data(), server_hello_opt->size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn("[ShadowTLS] write ServerHello to client failed: {}", write_ec.message());
                result.error = std::make_error_code(std::errc::connection_aborted);
                co_return result;
            }
        }

        trace::debug("[ShadowTLS] sent ServerHello to client");

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
        // 使用 shared_ptr 存储 HMAC 上下文，让 relay 协程和主协程可以共享
        auto hmac_relay_ctx = std::make_shared<std::shared_ptr<HMAC_CTX>>(nullptr);
        auto relay_done = std::make_shared<std::atomic<bool>>(false);
        auto cancel_signal = std::make_shared<net::cancellation_signal>();

        auto backend_relay = [relay_done, hmac_relay_ctx, &backend_sock, &client_sock, password, server_random]() -> net::awaitable<void>
        {
            // relay 函数会将 HMAC 上下文写入 hmac_relay_ctx
            // 这是握手阶段用的 HMAC，初始状态 = password + serverRandom
            co_await relay_backend_to_client_with_modification(
                backend_sock, client_sock, password, server_random, *hmac_relay_ctx);
            relay_done->store(true);
        };

        // 启动 relay 协程，使用 cancellation_signal
        net::co_spawn(executor, std::move(backend_relay),
                      net::bind_cancellation_slot(cancel_signal->slot(), net::detached));

        trace::debug("[ShadowTLS] started backend relay coroutine");

        // 前台：读取客户端直到 HMAC 匹配
        // 同时初始化读取方向的累积 HMAC（password + SR + "C" + payload + HMAC[:4]）
        std::shared_ptr<HMAC_CTX> hmac_verify_ctx;
        auto first_frame_opt = co_await read_until_hmac_match(
            client_sock, backend_sock, password, server_random, hmac_verify_ctx);

        // 关闭后端 socket，让 relay 协程退出
        {
            boost::system::error_code close_ec;
            backend_sock.shutdown(net::ip::tcp::socket::shutdown_both, close_ec);
            backend_sock.close(close_ec);
        }

        trace::debug("[ShadowTLS] closed backend socket");

        // 发送 cancellation signal 取消 relay 协程
        cancel_signal->emit(net::cancellation_type::all);

        // 等待 relay 协程退出（最多 500ms）
        for (int i = 0; i < 50 && !relay_done->load(); ++i)
        {
            net::steady_timer timer(executor);
            timer.expires_after(std::chrono::milliseconds(10));
            co_await timer.async_wait(net::use_awaitable);
        }

        if (!relay_done->load())
        {
            trace::warn("[ShadowTLS] relay coroutine did not exit within timeout, socket may be corrupted");
        }
        else
        {
            trace::debug("[ShadowTLS] relay coroutine exited cleanly");
        }

        if (!first_frame_opt || !hmac_verify_ctx)
        {
            trace::warn("[ShadowTLS] HMAC match failed during handshake relay");
            result.error = std::make_error_code(std::errc::protocol_error);
            co_return result;
        }

        trace::info("[ShadowTLS] Handshake complete, first_frame_size={}", first_frame_opt->size());
        result.authenticated = true;
        result.client_first_frame = std::move(*first_frame_opt);
        // 保存 server_random 和 matched_password 用于后续 ShadowTLS transport
        std::memcpy(result.server_random.data(), server_random.data(), 32);
        result.matched_password = std::string(password);

        // 参照 sing-shadowtls service.go case 3:
        // 传输阶段 hmacWrite (hmacAdd): password + serverRandom + "S"
        // 注意：握手阶段的 hmacWrite (hmac_relay_ctx) 不用于传输阶段
        // 传输阶段需要新建 HMAC 上下文，初始状态 = password + SR + "S"
        auto sr_data = reinterpret_cast<const unsigned char *>(server_random.data());
        constexpr unsigned char tag_s = 'S';
        auto hmac_write_transport = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
        if (hmac_write_transport)
        {
            HMAC_Init_ex(hmac_write_transport.get(), password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
            HMAC_Update(hmac_write_transport.get(), sr_data, server_random.size());
            HMAC_Update(hmac_write_transport.get(), &tag_s, 1);
            trace::debug("[ShadowTLS] initialized hmac_write_ctx for transport: password + SR + 'S'");
        }
        result.hmac_write_ctx = hmac_write_transport;
        result.hmac_read_ctx = hmac_verify_ctx;
        trace::debug("[ShadowTLS] HMAC contexts transferred to result");
        co_return result;
    }
} // namespace psm::stealth::shadowtls