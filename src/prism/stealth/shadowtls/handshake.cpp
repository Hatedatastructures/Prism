#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/stealth/shadowtls/util/auth.hpp>
#include <prism/stealth/shadowtls/util/constants.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>
#include <prism/fault/code.hpp>

#include <boost/asio.hpp>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#include <atomic>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <optional>

namespace psm::stealth::shadowtls
{
    namespace net = boost::asio;

    // ═══════════════════════════════════════════════════════════
    // ServerHello 解析
    // ═══════════════════════════════════════════════════════════

    static auto extract_server_random(std::span<const std::byte> server_hello)
        -> std::optional<std::array<std::byte, tls_rndsize>>
    {
        if (server_hello.size() < tls_hdrsize + 1 + 3 + 2 + tls_rndsize)
        {
            return std::nullopt;
        }

        // safe: casting byte buffer to uint8_t to parse TLS ServerHello header for validation
        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        if (raw[0] != content_handshake || raw[5] != hs_type_serverhello)
        {
            return std::nullopt;
        }

        std::array<std::byte, tls_rndsize> server_random{};
        std::memcpy(server_random.data(), raw + tls_hdrsize + 1 + 3 + 2, tls_rndsize);
        return server_random;
    }

    static bool is_server_hello_tls13(std::span<const std::byte> server_hello)
    {
        if (server_hello.size() < session_id_len_idx)
        {
            return false;
        }

        // safe: casting byte buffer to uint8_t to parse TLS ServerHello for version detection
        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        std::size_t offset = session_id_len_idx + 1;
        const std::uint8_t session_id_len = raw[session_id_len_idx];
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

            if (ext_type == ext_supported_versions && ext_len == 2)
            {
                if (offset + 2 <= server_hello.size())
                {
                    const std::uint16_t version =
                        (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
                    return version == tls_ver13;
                }
            }
            offset += ext_len;
        }
        return false;
    }

    // ═══════════════════════════════════════════════════════════
    // 握手阶段数据帧处理（sing-shadowtls copyByFrameUntilHMACMatches）
    // ═══════════════════════════════════════════════════════════

    // 持续读取客户端帧直到 HMAC 匹配
    // 读取客户端发送的 TLS 记录。非 Application Data 和 HMAC 不匹配的帧
    // 转发到后端（如 TLS 握手记录）。HMAC 匹配的 Application Data 帧
    // 是客户端的首帧认证数据，剥离 HMAC 后返回。
    // 客户端→服务端方向握手阶段每帧独立 HMAC: HMAC-SHA1(password, serverRandom+"C"+payload)
    // 匹配成功后，将 payload 和 HMAC[:4] 加入 hmac_verify 状态，供传输阶段使用
    // 参照 sing-shadowtls copyByFrameUntilHMACMatches
    static auto read_until_hmac_match(net::ip::tcp::socket &client_sock,
                                      net::ip::tcp::socket &backend_sock,
                                      std::string_view password,
                                      std::span<const std::byte> server_random,
                                      std::shared_ptr<HMAC_CTX> &hmac_verify_out)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        // safe: SSL HMAC API requires unsigned char*, byte span data is read-only
        auto sr_data = reinterpret_cast<const std::uint8_t *>(server_random.data());
        constexpr std::uint8_t tag_c = 'C';

        while (true)
        {
            std::error_code frame_ec;
            auto frame_opt = co_await common::read_raw_tls_frame(client_sock, frame_ec);
            if (frame_ec || !frame_opt)
            {
                trace::warn("[ShadowTLS.Relay] read_tls_frame from client returned nullopt");
                co_return std::nullopt;
            }

            auto &frame = *frame_opt;
            // safe: casting byte frame buffer to uint8_t for TLS content type inspection and HMAC extraction
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());
            if (raw[0] == content_appdata &&
                frame.size() > tls_hmac_hdrsize)
            {
                // 提取客户端 HMAC（TLS header 后的 4 字节）
                std::array<std::uint8_t, 4> client_hmac{};
                std::memcpy(client_hmac.data(), raw + tls_hdrsize, hmac_size);

                // payload = HMAC 之后的实际数据
                auto payload = std::span<const std::byte>(
                    frame.data() + tls_hmac_hdrsize,
                    frame.size() - tls_hmac_hdrsize);

                // 计算 HMAC(password, SR + "C" + payload)[:4]
                std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
                std::uint32_t md_len = 0;
                {
                    HMAC_CTX *h = HMAC_CTX_new();
                    HMAC_Init_ex(h, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
                    HMAC_Update(h, sr_data, server_random.size());
                    HMAC_Update(h, &tag_c, 1);
                    // safe: SSL HMAC API requires unsigned char*, payload data is read-only
                    HMAC_Update(h, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
                    HMAC_Final(h, md.data(), &md_len);
                    HMAC_CTX_free(h);
                }

                const bool match = CRYPTO_memcmp(md.data(), client_hmac.data(), hmac_size) == 0;

                if (match)
                {
                    trace::debug("[ShadowTLS.Relay] client first frame HMAC matched, payload_size={}", payload.size());

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
                                    // safe: SSL HMAC API requires unsigned char*, payload data is read-only
                                    reinterpret_cast<const std::uint8_t *>(payload.data()),
                                    payload.size());
                        HMAC_Update(hmac_verify.get(), client_hmac.data(), hmac_size);
                        hmac_verify_out = hmac_verify;
                        trace::debug("[ShadowTLS.Relay] initialized hmac_verify for transport phase");
                    }

                    memory::vector<std::byte> result(frame.size() - hmac_size);
                    std::memcpy(result.data(), raw, tls_hdrsize);
                    std::memcpy(result.data() + tls_hdrsize,
                                frame.data() + tls_hmac_hdrsize,
                                frame.size() - tls_hmac_hdrsize);
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

    // 转发后端服务器数据到客户端（带 XOR + 累积 HMAC 修改）
    // 参照 sing-shadowtls copyByFrameWithModification：
    // - 非 ApplicationData 帧（如 ChangeCipherSpec）：原样转发
    // - ApplicationData 帧：XOR 加密 payload + 累积 HMAC 标签
    //   帧格式：[TLS Header(5)] [HMAC(4)] [XOR'd payload(N)]
    //   HMAC = HMAC-SHA1(password, serverRandom || all_previous_XOR'd_payloads || current_XOR'd_payload)[:4]
    //   WriteKey = SHA256(password + serverRandom)
    // HMAC 上下文在整个 relay 过程中累积（参照 Go hmac.Write 不重置）
    // 使用 HMAC_CTX_copy 计算当前帧 HMAC，保留主状态继续累积
    // HMAC 上下文通过 shared_ptr 传出，供后续 ShadowTLS transport 使用
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
        // safe: SSL HMAC API requires unsigned char*, server_random byte data is read-only
        auto sr_bytes = reinterpret_cast<const std::uint8_t *>(server_random.data());

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
            std::error_code frame_ec;
            auto frame_opt = co_await common::read_raw_tls_frame(backend_sock, frame_ec);
            if (frame_ec || !frame_opt)
            {
                trace::warn("[ShadowTLS.Relay] backend closed (nullopt), total_frames={}, total_payload_bytes={}",
                           frame_count, total_payload_bytes);
                // 传递 HMAC 上下文给调用者
                hmac_out = hmac_main;
                co_return;
            }

            auto &frame = *frame_opt;
            // safe: casting byte frame buffer to uint8_t for TLS content type inspection
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

            trace::debug("[ShadowTLS.Relay] read backend frame #{}: type=0x{:02x}, size={}",
                        frame_count, raw[0], frame.size());

            if (raw[0] == content_appdata && frame.size() > tls_hdrsize)
            {
                auto payload = std::span<std::byte>(
                    frame.data() + tls_hdrsize, frame.size() - tls_hdrsize);

                trace::debug("[ShadowTLS.Relay] frame #{} is ApplicationData, payload_size={}", frame_count, payload.size());

                // 1. XOR 加密（Go: xorSlice）
                common::xor_with_key(payload, write_key);

                // 2. 累积 HMAC：将 XOR'd payload 加入主 HMAC 状态
                // safe: casting byte payload to uint8_t pointer for HMAC update, binary-compatible types
                HMAC_Update(hmac_main.get(), reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
                total_payload_bytes += payload.size();

                // 3. 计算当前帧 HMAC：复制状态并 finalize
                // Go: hmacHash := hmacWrite.Sum(nil)[:4]  (Sum 不改变状态)
                // OpenSSL: HMAC_CTX_copy + HMAC_Final
                std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
                std::uint32_t md_len = 0;
                {
                    HMAC_CTX *hmac_copy = HMAC_CTX_new();
                    HMAC_CTX_copy(hmac_copy, hmac_main.get());
                    HMAC_Final(hmac_copy, md.data(), &md_len);
                    HMAC_CTX_free(hmac_copy);
                }

                std::array<std::uint8_t, 4> hmac_tag{};
                std::memcpy(hmac_tag.data(), md.data(), hmac_size);

                // 构建新帧：[TLS Header(5)] [HMAC(4)] [XOR'd payload(N)]
                const std::uint16_t new_payload_len = static_cast<std::uint16_t>(hmac_size + payload.size());
                std::vector<std::byte> new_frame(tls_hdrsize + new_payload_len);
                new_frame[0] = std::byte{content_appdata};
                new_frame[1] = std::byte{0x03};
                new_frame[2] = std::byte{0x03};
                new_frame[3] = static_cast<std::byte>(new_payload_len >> 8);
                new_frame[4] = static_cast<std::byte>(new_payload_len & 0xFF);
                std::memcpy(new_frame.data() + tls_hdrsize, hmac_tag.data(), hmac_size);
                std::memcpy(new_frame.data() + tls_hmac_hdrsize, payload.data(), payload.size());

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

                trace::debug("[ShadowTLS.Relay] sent passthrough frame #{} to client, type=0x{:02x}, size={}",
                           frame_count, raw[0], frame.size());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 握手子函数
    // ═══════════════════════════════════════════════════════════

    struct auth_info
    {
        std::string matched_user;
        std::string_view password;
    };

    struct backend_result
    {
        memory::vector<std::byte> server_hello;
        fault::code error = fault::code::success;
    };

    struct relay_outputs
    {
        memory::vector<std::byte> first_frame;
        std::shared_ptr<HMAC_CTX> hmac_verify_ctx;
        std::array<std::byte, 32> server_random;
    };

    // Step 1-2: 验证 ClientHello HMAC，查找匹配用户并获取密码
    static auto verify_client(const config &cfg, std::span<const std::byte> client_hello)
        -> std::optional<auth_info>
    {
        auth_info auth;

        if (cfg.version == 3)
        {
            for (const auto &u : cfg.users)
            {
                if (u.password.empty())
                    continue;
                if (verify_client_hello(client_hello, u.password))
                {
                    auth.matched_user = u.name;
                    auth.password = u.password;
                    break;
                }
            }
        }
        else
        {
            // v2 兼容模式
            if (!cfg.password.empty() && verify_client_hello(client_hello, cfg.password))
            {
                auth.matched_user = "default";
                auth.password = cfg.password;
            }
        }

        if (auth.matched_user.empty())
        {
            trace::debug("[ShadowTLS] ClientHello HMAC verification failed");
            return std::nullopt;
        }

        trace::debug("[ShadowTLS] Client authenticated (user: {})", auth.matched_user);
        return auth;
    }

    // Step 3-6: 连接后端 TLS 服务器，转发 ClientHello/ServerHello
    static auto connect_backend(net::ip::tcp::socket &client_sock,
                                net::ip::tcp::socket &backend_sock,
                                const config &cfg,
                                memory::vector<std::byte> &client_hello)
        -> net::awaitable<backend_result>
    {
        backend_result res;
        auto executor = client_sock.get_executor();

        // 解析后端地址
        std::string backend_host(cfg.handshake_dest.begin(), cfg.handshake_dest.end());
        std::uint16_t backend_port = 443;
        if (auto pos = backend_host.find(':'); pos != std::string::npos)
        {
            const auto port_sv = std::string_view(backend_host).substr(pos + 1);
            std::uint16_t port_tmp = 0;
            const auto [ptr, fc_ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port_tmp);
            if (fc_ec != std::errc())
            {
                trace::error("[ShadowTLS] invalid backend port: {}", port_sv);
                res.error = fault::code::bad_message;
                co_return res;
            }
            backend_port = port_tmp;
            backend_host = backend_host.substr(0, pos);
        }

        trace::debug("[ShadowTLS] connecting to backend: {}:{}", backend_host, backend_port);

        // 解析并连接
        net::ip::tcp::resolver resolver(executor);
        auto endpoints = co_await resolver.async_resolve(backend_host, std::to_string(backend_port));

        boost::system::error_code connect_ec;
        auto connected_endpoint = co_await net::async_connect(
            backend_sock, endpoints,
            net::redirect_error(net::use_awaitable, connect_ec));
        (void)connected_endpoint;

        if (connect_ec)
        {
            trace::warn("[ShadowTLS] Backend connection failed: {}", connect_ec.message());
            res.error = fault::code::connection_refused;
            co_return res;
        }

        trace::debug("[ShadowTLS] backend connected");

        // 转发 ClientHello 到后端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(client_hello.data(), client_hello.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn("[ShadowTLS] write ClientHello to backend failed: {}", write_ec.message());
                res.error = fault::code::connection_refused;
                co_return res;
            }
        }

        trace::debug("[ShadowTLS] sent ClientHello to backend");

        // 读取后端 ServerHello
        std::error_code server_hello_ec;
        auto server_hello_opt = co_await common::read_raw_tls_frame(backend_sock, server_hello_ec);
        if (server_hello_ec || !server_hello_opt)
        {
            trace::warn("[ShadowTLS] Failed to read ServerHello from backend");
            res.error = fault::code::connection_refused;
            co_return res;
        }

        trace::debug("[ShadowTLS] received ServerHello from backend, size={}", server_hello_opt->size());

        // 转发 ServerHello 给客户端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                client_sock,
                net::buffer(server_hello_opt->data(), server_hello_opt->size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn("[ShadowTLS] write ServerHello to client failed: {}", write_ec.message());
                res.error = fault::code::connection_refused;
                co_return res;
            }
        }

        trace::debug("[ShadowTLS] sent ServerHello to client");

        res.server_hello = std::move(*server_hello_opt);
        co_return res;
    }

    // Step 7-8: 提取 ServerRandom，执行双工握手阶段数据转发
    static auto run_relay(net::ip::tcp::socket &client_sock,
                          net::ip::tcp::socket &backend_sock,
                          const config &cfg,
                          std::string_view password,
                          std::span<const std::byte> server_hello)
        -> net::awaitable<std::optional<relay_outputs>>
    {
        // 提取 ServerRandom
        auto server_random_opt = extract_server_random(server_hello);
        if (!server_random_opt)
        {
            trace::warn("[ShadowTLS] Failed to extract ServerRandom");
            co_return std::nullopt;
        }

        auto server_random_span = std::span<const std::byte>(
            server_random_opt->data(), server_random_opt->size());

        // 检查 strict_mode + TLS 1.3
        if (cfg.strict_mode && !is_server_hello_tls13(server_hello))
        {
            trace::warn("[ShadowTLS] Backend does not support TLS 1.3, strict mode enabled");
            co_return std::nullopt;
        }

        trace::debug("[ShadowTLS] ServerRandom extracted, TLS1.3={}",
                    is_server_hello_tls13(server_hello));

        // 双工握手阶段数据转发
        auto hmac_relay_ctx = std::make_shared<std::shared_ptr<HMAC_CTX>>(nullptr);
        auto relay_done = std::make_shared<std::atomic<bool>>(false);
        auto cancel_signal = std::make_shared<net::cancellation_signal>();

        auto executor = client_sock.get_executor();

        auto backend_relay = [relay_done, hmac_relay_ctx, &backend_sock, &client_sock, password, server_random_span]() -> net::awaitable<void>
        {
            co_await relay_backend_to_client_with_modification(
                backend_sock, client_sock, password, server_random_span, *hmac_relay_ctx);
            relay_done->store(true);
        };

        net::co_spawn(executor, std::move(backend_relay),
                      net::bind_cancellation_slot(cancel_signal->slot(), net::detached));

        trace::debug("[ShadowTLS] started backend relay coroutine");

        // 前台：读取客户端直到 HMAC 匹配
        std::shared_ptr<HMAC_CTX> hmac_verify_ctx;
        auto first_frame_opt = co_await read_until_hmac_match(
            client_sock, backend_sock, password, server_random_span, hmac_verify_ctx);

        // 关闭后端 socket，让 relay 协程退出
        {
            boost::system::error_code close_ec;
            backend_sock.shutdown(net::ip::tcp::socket::shutdown_both, close_ec);
            backend_sock.close(close_ec);
        }

        trace::debug("[ShadowTLS] closed backend socket");

        cancel_signal->emit(net::cancellation_type::all);

        // 等待 relay 协程退出（最多 500ms）
        {
            net::steady_timer exit_timer(executor);
            exit_timer.expires_after(std::chrono::milliseconds(500));
            boost::system::error_code wait_ec;
            co_await exit_timer.async_wait(net::redirect_error(net::use_awaitable, wait_ec));
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
            co_return std::nullopt;
        }

        trace::debug("[ShadowTLS] Handshake complete, first_frame_size={}", first_frame_opt->size());

        co_return relay_outputs{
            std::move(*first_frame_opt),
            std::move(hmac_verify_ctx),
            *server_random_opt
        };
    }

    // ═══════════════════════════════════════════════════════════
    // 主握手函数
    // ═══════════════════════════════════════════════════════════

    auto handshake(net::ip::tcp::socket &client_sock,
                   const config &cfg,
                   memory::vector<std::byte> client_hello,
                   handshake_detail &detail)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (client_hello.empty())
        {
            trace::warn("[ShadowTLS] Empty ClientHello");
            result.error = fault::code::bad_message;
            co_return result;
        }

        trace::debug("[ShadowTLS] handshake start, client_hello size={}", client_hello.size());
        auto executor = client_sock.get_executor();

        // Step 1-2: 验证 ClientHello HMAC
        auto auth = verify_client(cfg, std::span<const std::byte>(client_hello.data(), client_hello.size()));
        if (!auth)
        {
            result.error = fault::code::auth_failed;
            co_return result;
        }

        // Step 3-6: 连接后端 TLS 服务器并交换握手消息
        net::ip::tcp::socket backend_sock(executor);
        auto backend = co_await connect_backend(client_sock, backend_sock, cfg, client_hello);
        if (backend.error != fault::code::success)
        {
            result.error = backend.error;
            co_return result;
        }

        // connect_backend 成功：ServerHello 已写入客户端，后续失败不可 rewind
        result.polluted = true;

        // Step 7-8: 提取 ServerRandom 并执行双工握手阶段数据转发
        auto server_hello_span = std::span<const std::byte>(
            backend.server_hello.data(), backend.server_hello.size());
        auto relay = co_await run_relay(client_sock, backend_sock, cfg, auth->password, server_hello_span);
        if (!relay)
        {
            result.error = fault::code::protocol_error;
            co_return result;
        }

        trace::debug("[ShadowTLS] Handshake complete, first_frame_size={}", relay->first_frame.size());

        // 填充 detail 输出参数
        detail.client_firstframe = std::move(relay->first_frame);
        detail.matched_user = std::move(auth->matched_user);
        detail.matched_password = std::string(auth->password);
        detail.server_random = relay->server_random;

        // 参照 sing-shadowtls service.go case 3:
        // 传输阶段 hmacWrite: password + serverRandom + "S"
        // safe: SSL HMAC API requires unsigned char*, server_random byte data is read-only
        auto sr_data = reinterpret_cast<const std::uint8_t *>(detail.server_random.data());
        constexpr std::uint8_t tag_s = 'S';
        auto hmac_write_transport = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
        if (hmac_write_transport)
        {
            HMAC_Init_ex(hmac_write_transport.get(), auth->password.data(), static_cast<int>(auth->password.size()), EVP_sha1(), nullptr);
            HMAC_Update(hmac_write_transport.get(), sr_data, detail.server_random.size());
            HMAC_Update(hmac_write_transport.get(), &tag_s, 1);
            trace::debug("[ShadowTLS] initialized hmac_write_ctx for transport: password + SR + 'S'");
        }
        detail.hmac_write_ctx = hmac_write_transport;
        detail.hmac_read_ctx = std::move(relay->hmac_verify_ctx);

        // 填充 stealth::handshake_result
        result.error = fault::code::success;
        result.detected = protocol::protocol_type::tls;
        result.scheme = "shadowtls";

        trace::debug("[ShadowTLS] HMAC contexts transferred to detail");
        co_return result;
    }
} // namespace psm::stealth::shadowtls
