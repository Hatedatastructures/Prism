#include <prism/stealth/facade/shadowtls/handshake.hpp>

#include <prism/fault/code.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/stealth/common.hpp>
#include <prism/stealth/facade/shadowtls/util/auth.hpp>
#include <prism/stealth/facade/shadowtls/util/constants.hpp>
#include <prism/trace.hpp>

#include <boost/asio.hpp>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include <atomic>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>

using namespace psm::trace;

namespace psm::stealth::shadowtls
{

    namespace net = boost::asio;

    namespace
    {


    auto extract_random(std::span<const std::byte> server_hello)
        -> std::optional<std::array<std::byte, tls_rndsize>>
    {
        if (server_hello.size() < tls_hdrsize + 1 + 3 + 2 + tls_rndsize)
        {
            return std::nullopt;
        }

        // 安全：将 byte 缓冲区转为 uint8_t 解析 TLS ServerHello 头部做验证，二进制兼容
        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        if (raw[0] != content_handshake || raw[5] != hs_type_serverhello)
        {
            return std::nullopt;
        }

        std::array<std::byte, tls_rndsize> server_random{};
        std::memcpy(server_random.data(), raw + tls_hdrsize + 1 + 3 + 2, tls_rndsize);
        return server_random;
    }


    auto is_tls13_hello(std::span<const std::byte> server_hello) -> bool
    {
        if (server_hello.size() < session_id_len_idx)
        {
            return false;
        }

        // 安全：将 byte 缓冲区转为 uint8_t 解析 TLS ServerHello 做版本检测，二进制兼容
        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        std::size_t offset = session_id_len_idx + 1;
        const std::uint8_t session_id_len = raw[session_id_len_idx];
        offset += session_id_len;

        if (offset + 3 > server_hello.size())
            return false;
        offset += 3; // 密码套件(2) + legacy_compression_method(1)

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


    struct hmac_read_args
    {
        net::ip::tcp::socket &client_sock;
        std::shared_ptr<net::ip::tcp::socket> backend_sock;
        std::string_view password;
        std::span<const std::byte> server_random;
        std::shared_ptr<HMAC_CTX> &hmac_verify_out;
    };

    struct backend_relay_args
    {
        std::shared_ptr<net::ip::tcp::socket> backend_sock;
        net::ip::tcp::socket &client_sock;
        std::string_view password;
        std::span<const std::byte> server_random;
        std::shared_ptr<HMAC_CTX> &hmac_out;
    };

    struct relay_args
    {
        net::ip::tcp::socket &client_sock;
        std::shared_ptr<net::ip::tcp::socket> backend_sock;
        const config &cfg;
        std::string_view password;
        std::span<const std::byte> server_hello;
    };

    struct modified_frame_args
    {
        net::ip::tcp::socket &client_sock;
        const std::shared_ptr<HMAC_CTX> &hmac_main;
        std::span<std::byte> payload;
        std::size_t frame_idx;
        std::span<const std::uint8_t> write_key;
    };

    struct passthrough_frame_args
    {
        net::ip::tcp::socket &client_sock;
        std::span<const std::byte> frame;
        const std::uint8_t *raw;
        std::size_t frame_idx;
    };


    auto read_hmac_match(const hmac_read_args &args)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>
    {
        // 安全：SSL HMAC API 要求 unsigned char*，byte span 数据仅读取，不修改
        auto sr_data = reinterpret_cast<const std::uint8_t *>(args.server_random.data());
        constexpr std::uint8_t tag_c = 'C';

        while (true)
        {
            std::error_code frame_ec;
            auto frame_opt = co_await common::read_tls_frame(args.client_sock, frame_ec);
            if (frame_ec || !frame_opt)
            {
                trace::warn<flt::conn | flt::protocol>("read_tls_frame from client returned nullopt");
                co_return std::nullopt;
            }

            auto &frame = *frame_opt;
            // 安全：将 byte 帧缓冲区转为 uint8_t 检查 TLS 内容类型并提取 HMAC，二进制兼容
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());
            if (raw[0] == content_appdata &&
                frame.size() > tls_hmac_hdrsize)
            {
                std::array<std::uint8_t, 4> client_hmac{};
                std::memcpy(client_hmac.data(), raw + tls_hdrsize, hmac_size);

                auto payload = std::span<const std::byte>(
                    frame.data() + tls_hmac_hdrsize,
                    frame.size() - tls_hmac_hdrsize);

                std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
                std::uint32_t md_len = 0;
                {
                    HMAC_CTX *h = HMAC_CTX_new();
                    HMAC_Init_ex(h, args.password.data(), static_cast<int>(args.password.size()), EVP_sha1(), nullptr);
                    HMAC_Update(h, sr_data, args.server_random.size());
                    HMAC_Update(h, &tag_c, 1);
                    // 安全：SSL HMAC API 要求 unsigned char*，payload 数据仅读取
                    HMAC_Update(h, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
                    HMAC_Final(h, md.data(), &md_len);
                    HMAC_CTX_free(h);
                }

                const bool match = CRYPTO_memcmp(md.data(), client_hmac.data(), hmac_size) == 0;

                if (match)
                {
                    trace::debug<flt::conn | flt::protocol>("client first frame HMAC matched, payload_size={}", payload.size());

                    auto hmac_verify = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
                    if (hmac_verify)
                    {
                        auto pwd_data = args.password.data();
                        auto pwd_len = static_cast<int>(args.password.size());
                        HMAC_Init_ex(hmac_verify.get(), pwd_data, pwd_len, EVP_sha1(), nullptr);
                        HMAC_Update(hmac_verify.get(), sr_data, args.server_random.size());
                        HMAC_Update(hmac_verify.get(), &tag_c, 1);
                        HMAC_Update(hmac_verify.get(),
                                    // 安全：SSL HMAC API 要求 unsigned char*，payload 数据仅读取
                                    reinterpret_cast<const std::uint8_t *>(payload.data()),
                                    payload.size());
                        HMAC_Update(hmac_verify.get(), client_hmac.data(), hmac_size);
                        args.hmac_verify_out = hmac_verify;
                        trace::debug<flt::conn | flt::protocol>("initialized hmac_verify for transport phase");
                    }

                    memory::vector<std::byte> result(frame.size() - hmac_size);
                    std::memcpy(result.data(), raw, tls_hdrsize);
                    std::memcpy(result.data() + tls_hdrsize,
                                frame.data() + tls_hmac_hdrsize,
                                frame.size() - tls_hmac_hdrsize);
                    co_return result;
                }
            }

            trace::debug<flt::conn | flt::protocol>("forwarding client frame to backend, type=0x{:02x}, size={}", raw[0], frame.size());
            boost::system::error_code write_ec;
            co_await net::async_write(
                *args.backend_sock,
                net::buffer(frame.data(), frame.size()),
                net::redirect_error(trace::use_prefix_awaitable, write_ec));

            if (write_ec)
            {
                trace::warn<flt::conn | flt::protocol>("write to backend failed: {}", write_ec.message());
                co_return std::nullopt;
            }
        }
    }


    auto send_modified(const modified_frame_args &args)
        -> net::awaitable<bool>
    {
        // 安全：将 byte payload 转为 uint8_t 指针用于 HMAC 更新，二进制兼容类型
        HMAC_Update(args.hmac_main.get(), reinterpret_cast<const std::uint8_t *>(args.payload.data()), args.payload.size());

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        {
            HMAC_CTX *hmac_copy = HMAC_CTX_new();
            HMAC_CTX_copy(hmac_copy, args.hmac_main.get());
            HMAC_Final(hmac_copy, md.data(), &md_len);
            HMAC_CTX_free(hmac_copy);
        }

        std::array<std::uint8_t, 4> hmac_tag{};
        std::memcpy(hmac_tag.data(), md.data(), hmac_size);

        const std::uint16_t new_payload_len = static_cast<std::uint16_t>(hmac_size + args.payload.size());
        memory::vector<std::byte> hmac_payload(new_payload_len);
        std::memcpy(hmac_payload.data(), hmac_tag.data(), hmac_size);
        std::memcpy(hmac_payload.data() + hmac_size, args.payload.data(), args.payload.size());

        auto frame = ::psm::tls::record::builder()
                         .type(content_appdata)
                         .version(0x0303)
                         .payload(hmac_payload)
                         .build();
        auto frame_bytes = frame.serialize();

        boost::system::error_code write_ec;
        co_await net::async_write(args.client_sock, net::buffer(frame_bytes.data(), frame_bytes.size()),
            net::redirect_error(trace::use_prefix_awaitable, write_ec));
        if (write_ec)
        {
            trace::warn<flt::conn | flt::protocol>("write to client failed: {}", write_ec.message());
            co_return false;
        }

        trace::debug<flt::conn | flt::protocol>("sent modified frame #{} to client, new_size={}", args.frame_idx, frame_bytes.size());
        co_return true;
    }


    auto send_passthrough(const passthrough_frame_args &args)
        -> net::awaitable<bool>
    {
        boost::system::error_code write_ec;
        co_await net::async_write(args.client_sock, net::buffer(args.frame.data(), args.frame.size()),
            net::redirect_error(trace::use_prefix_awaitable, write_ec));
        if (write_ec)
        {
            trace::warn<flt::conn | flt::protocol>("write passthrough failed: {}", write_ec.message());
            co_return false;
        }

        trace::debug<flt::conn | flt::protocol>("sent passthrough frame #{} to client, type=0x{:02x}, size={}",
                   args.frame_idx, args.raw[0], args.frame.size());
        co_return true;
    }


    auto relay_modified(const backend_relay_args &args)
        -> net::awaitable<void>
    {
        auto write_key = compute_write_key(args.password, args.server_random);

        // 安全：SSL HMAC API 要求 unsigned char*，server_random byte 数据仅读取
        auto sr_bytes = reinterpret_cast<const std::uint8_t *>(args.server_random.data());

        auto hmac_main = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
        if (!hmac_main)
        {
            trace::warn<flt::conn | flt::protocol>("failed to create HMAC_CTX");
            co_return;
        }

        HMAC_Init_ex(hmac_main.get(), args.password.data(), static_cast<int>(args.password.size()), EVP_sha1(), nullptr);
        HMAC_Update(hmac_main.get(), sr_bytes, args.server_random.size());

        std::size_t frame_count = 0;

        trace::debug<flt::conn | flt::protocol>("initialized cumulative HMAC with serverRandom");

        while (true)
        {
            std::error_code frame_ec;
            auto frame_opt = co_await common::read_tls_frame(*args.backend_sock, frame_ec);
            if (frame_ec || !frame_opt)
            {
                trace::warn<flt::conn | flt::protocol>("backend closed (nullopt), total_frames={}", frame_count);
                args.hmac_out = hmac_main;
                co_return;
            }

            auto &frame = *frame_opt;
            // 安全：将 byte 帧缓冲区转为 uint8_t 检查 TLS 内容类型，二进制兼容
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

            trace::debug<flt::conn | flt::protocol>("read backend frame #{}: type=0x{:02x}, size={}",
                        frame_count, raw[0], frame.size());

            if (raw[0] == content_appdata && frame.size() > tls_hdrsize)
            {
                auto payload = std::span<std::byte>(
                    frame.data() + tls_hdrsize, frame.size() - tls_hdrsize);

                trace::debug<flt::conn | flt::protocol>("frame #{} is ApplicationData, payload_size={}", frame_count, payload.size());

                common::xor_key(payload, write_key);

                bool ok = co_await send_modified(
                    modified_frame_args{args.client_sock, hmac_main, payload, frame_count, write_key});
                if (!ok)
                {
                    args.hmac_out = hmac_main;
                    co_return;
                }
            }
            else
            {
                bool ok = co_await send_passthrough(
                    passthrough_frame_args{args.client_sock, frame, raw, frame_count});
                if (!ok)
                {
                    args.hmac_out = hmac_main;
                    co_return;
                }
            }

            ++frame_count;
        }
    }


    struct auth_info
    {
        memory::string matched_user;
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

    auto verify_client(const config &cfg, std::span<const std::byte> client_hello)
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
            if (!cfg.password.empty() && verify_client_hello(client_hello, cfg.password))
            {
                auth.matched_user = "default";
                auth.password = cfg.password;
            }
        }

        if (auth.matched_user.empty())
        {
            trace::debug<flt::conn | flt::protocol>("ClientHello HMAC verification failed");
            return std::nullopt;
        }

        trace::debug<flt::conn | flt::protocol>("Client authenticated (user: {})", auth.matched_user);
        return auth;
    }


    struct backend_opts
    {
        net::ip::tcp::socket &client_sock;
        std::shared_ptr<net::ip::tcp::socket> backend_sock;
        const config &cfg;
        memory::vector<std::byte> &client_hello;
    };

    auto connect_backend(const backend_opts &opts)
        -> net::awaitable<backend_result>
    {
        backend_result res;
        auto executor = opts.client_sock.get_executor();

        memory::string backend_host(opts.cfg.handshake_dest.begin(), opts.cfg.handshake_dest.end());
        std::uint16_t backend_port = 443;
        if (auto pos = backend_host.find(':'); pos != memory::string::npos)
        {
            const auto port_sv = std::string_view(backend_host).substr(pos + 1);
            std::uint16_t port_tmp = 0;
            const auto [ptr, fc_ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port_tmp);
            if (fc_ec != std::errc())
            {
                trace::error<flt::conn | flt::protocol>("invalid backend port: {}", port_sv);
                res.error = fault::code::bad_message;
                co_return res;
            }
            backend_port = port_tmp;
            backend_host = backend_host.substr(0, pos);
        }

        trace::debug<flt::conn | flt::protocol>("connecting to backend: {}:{}", backend_host, backend_port);

        net::ip::tcp::resolver resolver(executor);
        auto endpoints = co_await resolver.async_resolve(backend_host, std::to_string(backend_port));

        boost::system::error_code connect_ec;
        auto connected_endpoint = co_await net::async_connect(
            *opts.backend_sock, endpoints,
            net::redirect_error(trace::use_prefix_awaitable, connect_ec));
        (void)connected_endpoint;

        if (connect_ec)
        {
            trace::warn<flt::conn | flt::protocol>("Backend connection failed: {}", connect_ec.message());
            res.error = fault::code::connection_refused;
            co_return res;
        }

        trace::debug<flt::conn | flt::protocol>("backend connected");

        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                *opts.backend_sock,
                net::buffer(opts.client_hello.data(), opts.client_hello.size()),
                net::redirect_error(trace::use_prefix_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn<flt::conn | flt::protocol>("write ClientHello to backend failed: {}", write_ec.message());
                res.error = fault::code::connection_refused;
                co_return res;
            }
        }

        trace::debug<flt::conn | flt::protocol>("sent ClientHello to backend");

        std::error_code server_hello_ec;
        auto server_hello_opt = co_await common::read_tls_frame(*opts.backend_sock, server_hello_ec);
        if (server_hello_ec || !server_hello_opt)
        {
            trace::warn<flt::conn | flt::protocol>("Failed to read ServerHello from backend");
            res.error = fault::code::connection_refused;
            co_return res;
        }

        trace::debug<flt::conn | flt::protocol>("received ServerHello from backend, size={}", server_hello_opt->size());

        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                opts.client_sock,
                net::buffer(server_hello_opt->data(), server_hello_opt->size()),
                net::redirect_error(trace::use_prefix_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn<flt::conn | flt::protocol>("write ServerHello to client failed: {}", write_ec.message());
                res.error = fault::code::connection_refused;
                co_return res;
            }
        }

        trace::debug<flt::conn | flt::protocol>("sent ServerHello to client");

        res.server_hello = std::move(*server_hello_opt);
        co_return res;
    }


    auto run_relay(const relay_args &args)
        -> net::awaitable<std::optional<relay_outputs>>
    {
        auto server_random_opt = extract_random(args.server_hello);
        if (!server_random_opt)
        {
            trace::warn<flt::conn | flt::protocol>("Failed to extract ServerRandom");
            co_return std::nullopt;
        }

        auto server_random_span = std::span<const std::byte>(
            server_random_opt->data(), server_random_opt->size());

        if (args.cfg.strict_mode && !is_tls13_hello(args.server_hello))
        {
            trace::warn<flt::conn | flt::protocol>("Backend does not support TLS 1.3, strict mode enabled");
            co_return std::nullopt;
        }

        trace::debug<flt::conn | flt::protocol>("ServerRandom extracted, TLS1.3={}",
                    is_tls13_hello(args.server_hello));

        auto hmac_relay_ctx = std::make_shared<std::shared_ptr<HMAC_CTX>>(nullptr);
        auto relay_done = std::make_shared<std::atomic<bool>>(false);
        auto cancel_signal = std::make_shared<net::cancellation_signal>();

        auto executor = args.client_sock.get_executor();

        auto backend_relay = [relay_done, hmac_relay_ctx, backend_sock = args.backend_sock,
                              client_sock_ptr = std::shared_ptr<net::ip::tcp::socket>(&args.client_sock, [](auto *) {}),
                              password = args.password,
                              server_random_span]() -> net::awaitable<void>
        {
            std::shared_ptr<HMAC_CTX> hmac_out;
            co_await relay_modified(
                backend_relay_args{std::move(backend_sock), *client_sock_ptr, password, server_random_span, hmac_out});
            *hmac_relay_ctx = std::move(hmac_out);
            relay_done->store(true);
        };

        net::co_spawn(executor, std::move(backend_relay), net::bind_cancellation_slot(cancel_signal->slot(), net::detached));

        trace::debug<flt::conn | flt::protocol>("started backend relay coroutine");

        std::shared_ptr<HMAC_CTX> hmac_verify_ctx;
        hmac_read_args read_args{
            args.client_sock, args.backend_sock, args.password,
            server_random_span, hmac_verify_ctx};
        auto first_frame_opt = co_await read_hmac_match(read_args);

        {
            boost::system::error_code close_ec;
            if (args.backend_sock->is_open())
            {
                args.backend_sock->shutdown(net::ip::tcp::socket::shutdown_both, close_ec);
                if (close_ec)
                {
                    trace::debug<flt::conn | flt::protocol>("backend shutdown error: {}", close_ec.message());
                }
                args.backend_sock->close(close_ec);
                if (close_ec)
                {
                    trace::debug<flt::conn | flt::protocol>("backend close error: {}", close_ec.message());
                }
            }
        }

        trace::debug<flt::conn | flt::protocol>("closed backend socket");

        cancel_signal->emit(net::cancellation_type::all);

        {
            net::steady_timer exit_timer(executor);
            exit_timer.expires_after(std::chrono::milliseconds(500));
            boost::system::error_code wait_ec;
            co_await exit_timer.async_wait(net::redirect_error(trace::use_prefix_awaitable, wait_ec));
        }

        if (!relay_done->load())
        {
            trace::warn<flt::conn | flt::protocol>("relay coroutine did not exit within timeout, socket may be corrupted");
        }
        else
        {
            trace::debug<flt::conn | flt::protocol>("relay coroutine exited cleanly");
        }

        if (!first_frame_opt || !hmac_verify_ctx)
        {
            trace::warn<flt::conn | flt::protocol>("HMAC match failed during handshake relay");
            co_return std::nullopt;
        }

        trace::debug<flt::conn | flt::protocol>("Handshake complete, first_frame_size={}", first_frame_opt->size());

        co_return relay_outputs{
            std::move(*first_frame_opt),
            std::move(hmac_verify_ctx),
            *server_random_opt
        };
    }


    } // namespace


    auto handshake(handshake_opts opts)
        -> net::awaitable<stealth::handshake_result>
    {
        auto &client_sock = opts.client_sock;
        auto &cfg = opts.cfg;
        auto &detail = opts.detail;

        stealth::handshake_result result;

        if (opts.client_hello.empty())
        {
            trace::warn<flt::conn | flt::protocol>("Empty ClientHello");
            result.error = fault::code::bad_message;
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>("handshake start, client_hello size={}", opts.client_hello.size());
        auto executor = client_sock.get_executor();

        auto auth = verify_client(cfg, std::span<const std::byte>(opts.client_hello.data(), opts.client_hello.size()));
        if (!auth)
        {
            result.error = fault::code::auth_failed;
            co_return result;
        }

        // 将已认证用户写入前缀
        auto *pfx = trace::active_prefix;
        if (pfx)
        {
            std::strncpy(pfx->user, auth->matched_user.c_str(), sizeof(pfx->user) - 1);
        }

        auto backend_sock = std::make_shared<net::ip::tcp::socket>(executor);
        auto backend = co_await connect_backend(
            backend_opts{client_sock, backend_sock, cfg, opts.client_hello});
        if (backend.error != fault::code::success)
        {
            result.error = backend.error;
            co_return result;
        }

        result.polluted = true;

        auto server_hello_span = std::span<const std::byte>(
            backend.server_hello.data(), backend.server_hello.size());
        auto relay = co_await run_relay(
            relay_args{client_sock, backend_sock, cfg, auth->password, server_hello_span});
        if (!relay)
        {
            result.error = fault::code::protocol_error;
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>("Handshake complete, first_frame_size = {}", relay->first_frame.size());

        detail.client_firstframe = std::move(relay->first_frame);
        detail.matched_user = std::move(auth->matched_user);
        detail.matched_password = std::string(auth->password);
        detail.server_random = relay->server_random;

        // 安全：SSL HMAC API 要求 unsigned char*，server_random 数据仅读取，类型转换安全
        auto sr_data = reinterpret_cast<const std::uint8_t *>(detail.server_random.data());
        constexpr std::uint8_t tag_s = 'S';
        auto hmac_write_transport = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
        if (hmac_write_transport)
        {
            auto pwd_data = auth->password.data();
            auto pwd_len = static_cast<int>(auth->password.size());
            HMAC_Init_ex(hmac_write_transport.get(), pwd_data, pwd_len, EVP_sha1(), nullptr);
            HMAC_Update(hmac_write_transport.get(), sr_data, detail.server_random.size());
            HMAC_Update(hmac_write_transport.get(), &tag_s, 1);
            trace::debug<flt::conn | flt::protocol>("initialized hmac_write_ctx for transport: password + SR + 'S'");
        }
        detail.hmac_write_ctx = hmac_write_transport;
        detail.hmac_read_ctx = std::move(relay->hmac_verify_ctx);

        result.error = fault::code::success;
        result.detected = protocol::protocol_type::tls;
        result.scheme = "shadowtls";

        trace::debug<flt::conn | flt::protocol>("HMAC contexts transferred to detail");
        co_return result;
    }
} // namespace psm::stealth::shadowtls
