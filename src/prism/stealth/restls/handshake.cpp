#include <prism/stealth/restls/handshake.hpp>

#include <prism/fault/code.hpp>
#include <prism/stealth/common.hpp>
#include <prism/stealth/restls/crypto.hpp>
#include <prism/stealth/restls/transport.hpp>
#include <prism/trace.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>

namespace psm::stealth::restls
{

    namespace net = boost::asio;


    struct backend_relay_opts
    {
        net::ip::tcp::socket &backend_sock;
        net::ip::tcp::socket &client_sock;
        std::span<const std::uint8_t, hs_maclen> auth_mask;
        tls_version version;
        memory::vector<std::byte> &first_encrypted;
    };

    struct client_relay_opts
    {
        net::ip::tcp::socket &client_sock;
        net::ip::tcp::socket &backend_sock;
        tls_version version;
        memory::vector<std::uint8_t> &client_finished;
    };

    struct duplex_relay_opts
    {
        net::ip::tcp::socket &client_sock;
        net::ip::tcp::socket &backend_sock;
        tls_version version;
        std::array<std::uint8_t, hs_maclen> auth_mask;
        memory::vector<std::uint8_t> &client_finished;
        memory::vector<std::byte> &first_encrypted;
    };

    struct server_info
    {
        std::array<std::uint8_t, 32> server_random;
        std::array<std::uint8_t, hs_maclen> auth_mask;
        tls_version version;
    };


    namespace
    {
        auto extract_server_random(std::span<const std::byte> server_hello)
            -> std::optional<std::array<std::uint8_t, 32>>
        {
            if (server_hello.size() < tls_hdrsize + 1 + 3 + 2 + 32)
            {
                return std::nullopt;
            }

            // safe: casting byte buffer to uint8_t to parse TLS ServerHello for server random extraction
            const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
            std::array<std::uint8_t, 32> random{};
            std::memcpy(random.data(), raw + tls_hdrsize + 1 + 3 + 2, 32);
            return random;
        }

        auto is_tls13_server_hello(std::span<const std::byte> server_hello)
            -> bool
        {
            if (server_hello.size() < tls_hdrsize + 1 + 3 + 2 + 32 + 1)
            {
                return false;
            }

            // safe: casting byte buffer to uint8_t to parse TLS ServerHello for version detection
            const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
            std::size_t offset = tls_hdrsize + 1 + 3 + 2 + 32;

            if (offset >= server_hello.size())
                return false;
            const std::uint8_t session_id_len = raw[offset];
            offset += 1 + session_id_len;

            if (offset + 3 > server_hello.size())
                return false;
            offset += 3;

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

                if (ext_type == 43 && ext_len == 2 && offset + 2 <= server_hello.size())
                {
                    const std::uint16_t version =
                        (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
                    return version == 0x0304; // TLS 1.3
                }
                offset += ext_len;
            }
            return false;
        }


        auto parse_host_port(std::string_view host_port)
            -> std::pair<std::string, std::uint16_t>
        {
            std::string host(host_port.begin(), host_port.end());
            std::uint16_t port = 443;
            if (auto pos = host.find(':'); pos != std::string::npos)
            {
                const auto port_sv = std::string_view(host).substr(pos + 1);
                std::uint16_t tmp = 0;
                if (std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), tmp).ec == std::errc{})
                {
                    port = tmp;
                }
                host = host.substr(0, pos);
            }
            return {std::move(host), port};
        }


        auto relay_backend_to_client(const backend_relay_opts &opts)
            -> net::awaitable<bool>
        {
            const bool is_tls13 = (opts.version == tls_version::v13);
            bool first_app_data = true;

            while (true)
            {
                std::error_code frame_ec;
                auto frame_opt = co_await common::read_tls_frame(opts.backend_sock, frame_ec);
                if (frame_ec || !frame_opt)
                {
                    co_return true;
                }

                auto &frame = *frame_opt;
                // safe: casting byte frame buffer to uint8_t for TLS content type inspection and XOR processing
                const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

                if (first_app_data && raw[0] == 0x17 && frame.size() > tls_hdrsize)
                {
                    std::size_t xor_offset = tls_hdrsize;
                    if (!is_tls13)
                        xor_offset = tls_hdrsize + 8;
                    // safe: casting mutable byte buffer region to uint8_t span for in-place XOR masking
                    auto payload = std::span<std::uint8_t>(
                        reinterpret_cast<std::uint8_t *>(frame.data()) + xor_offset,
                        frame.size() - xor_offset);
                    xor_with_mask(payload, opts.auth_mask);

                    opts.first_encrypted.assign(frame.begin(), frame.end());
                    first_app_data = false;
                }

                boost::system::error_code write_ec;
                co_await net::async_write(
                    opts.client_sock,
                    net::buffer(frame.data(), frame.size()),
                    net::redirect_error(net::use_awaitable, write_ec));
                if (write_ec)
                {
                    co_return false;
                }
            }
        }


        auto relay_client_to_backend(const client_relay_opts &opts)
            -> net::awaitable<bool>
        {
            bool first_app_data = true;

            while (true)
            {
                std::error_code frame_ec;
                auto frame_opt = co_await common::read_tls_frame(opts.client_sock, frame_ec);
                if (frame_ec || !frame_opt)
                {
                    co_return false;
                }

                auto &frame = *frame_opt;
                // safe: casting byte frame buffer to uint8_t pointer for TLS record parsing
                const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

                if (first_app_data && raw[0] == 0x17 && frame.size() > tls_hdrsize)
                {
                    // safe: casting byte frame buffer to uint8_t iterators for clientFinished capture
                    opts.client_finished.assign(
                        reinterpret_cast<const std::uint8_t *>(frame.data()),
                        reinterpret_cast<const std::uint8_t *>(frame.data()) + frame.size());
                    first_app_data = false;
                }

                boost::system::error_code write_ec;
                co_await net::async_write(
                    opts.backend_sock,
                    net::buffer(frame.data(), frame.size()),
                    net::redirect_error(net::use_awaitable, write_ec));
                if (write_ec)
                {
                    co_return false;
                }
            }
        }


        auto connect_to_backend(
            net::ip::tcp::socket::executor_type executor,
            const std::string &host,
            std::uint16_t port)
            -> net::awaitable<std::optional<net::ip::tcp::socket>>
        {
            net::ip::tcp::resolver resolver(executor);
            auto endpoints = co_await resolver.async_resolve(host, std::to_string(port));

            net::ip::tcp::socket backend_sock(executor);
            boost::system::error_code connect_ec;
            co_await net::async_connect(
                backend_sock, endpoints,
                net::redirect_error(net::use_awaitable, connect_ec));

            if (connect_ec)
            {
                trace::warn("[Restls] backend connection failed: {}", connect_ec.message());
                co_return std::nullopt;
            }

            co_return backend_sock;
        }

        auto extract_server_info(
            std::span<const std::byte> server_hello,
            std::span<const std::uint8_t, 32> secret_span)
            -> std::optional<server_info>
        {
            auto sr_opt = extract_server_random(server_hello);
            if (!sr_opt)
            {
                trace::warn("[Restls] failed to extract server_random");
                return std::nullopt;
            }

            const bool tls13 = is_tls13_server_hello(server_hello);
            tls_version version = tls_version::v12;
            if (tls13)
                version = tls_version::v13;
            auto server_random = *sr_opt;
            auto sr_span = std::span<const std::uint8_t, 32>(server_random);
            auto auth_mask = compute_server_mask(secret_span, sr_span);

            trace::debug("[Restls] server_random extracted, tls13={}", tls13);
            return server_info{
                .server_random = server_random,
                .auth_mask = auth_mask,
                .version = version};
        }

        auto run_duplex_relay(const duplex_relay_opts &opts)
            -> net::awaitable<void>
        {
            auto executor = opts.client_sock.get_executor();
            auto relay_done = std::make_shared<std::atomic<bool>>(false);
            auto cancel_signal = std::make_shared<net::cancellation_signal>();

            auto client_relay = [csock = &opts.client_sock,
                                 bsock = &opts.backend_sock,
                                 ver = opts.version,
                                 &cf_out = opts.client_finished,
                                 relay_done]()
                -> net::awaitable<void>
            {
                memory::vector<std::uint8_t> cf;
                co_await relay_client_to_backend(client_relay_opts{
                    *csock, *bsock, ver, cf});
                cf_out = std::move(cf);
                relay_done->store(true);
            };

            net::co_spawn(executor, std::move(client_relay),
                          net::bind_cancellation_slot(cancel_signal->slot(), net::detached));

            auto auth_span = std::span<const std::uint8_t, hs_maclen>(opts.auth_mask);
            co_await relay_backend_to_client(backend_relay_opts{
                opts.backend_sock, opts.client_sock,
                auth_span, opts.version, opts.first_encrypted});

            {
                boost::system::error_code close_ec;
                opts.backend_sock.shutdown(net::ip::tcp::socket::shutdown_both, close_ec);
                opts.backend_sock.close(close_ec);
            }

            cancel_signal->emit(net::cancellation_type::all);

            {
                net::steady_timer exit_timer(executor);
                exit_timer.expires_after(std::chrono::milliseconds(500));
                boost::system::error_code wait_ec;
                co_await exit_timer.async_wait(net::redirect_error(net::use_awaitable, wait_ec));
            }

            if (!relay_done->load())
            {
                trace::warn("[Restls] client relay did not exit within timeout");
            }
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
            result.error = fault::code::bad_message;
            co_return result;
        }

        trace::debug("[Restls] handshake start, client_hello size={}", opts.client_hello.size());
        auto executor = client_sock.get_executor();

        const auto secret = derive_secret(cfg.password);
        auto secret_span = std::span<const std::uint8_t, 32>(secret);

        auto [backend_host, backend_port] = parse_host_port(
            std::string_view(cfg.host.data(), cfg.host.size()));
        trace::debug("[Restls] connecting to backend: {}:{}", backend_host, backend_port);

        auto backend_opt = co_await connect_to_backend(executor, backend_host, backend_port);
        if (!backend_opt)
        {
            result.error = fault::code::connection_refused;
            co_return result;
        }
        auto backend_sock = std::move(*backend_opt);

        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(opts.client_hello.data(), opts.client_hello.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn("[Restls] write ClientHello failed: {}", write_ec.message());
                result.error = fault::code::connection_refused;
                co_return result;
            }
        }

        std::error_code sh_ec;
        auto server_hello_opt = co_await common::read_tls_frame(backend_sock, sh_ec);
        if (sh_ec || !server_hello_opt)
        {
            trace::warn("[Restls] failed to read ServerHello");
            result.error = fault::code::connection_refused;
            co_return result;
        }

        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                client_sock,
                net::buffer(server_hello_opt->data(), server_hello_opt->size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn("[Restls] write ServerHello failed: {}", write_ec.message());
                result.error = fault::code::connection_refused;
                result.polluted = true;
                co_return result;
            }
        }

        result.polluted = true;

        auto sh_span = std::span<const std::byte>(server_hello_opt->data(), server_hello_opt->size());
        auto info_opt = extract_server_info(sh_span, secret_span);
        if (!info_opt)
        {
            result.error = fault::code::protocol_error;
            co_return result;
        }

        memory::vector<std::uint8_t> client_finished;
        memory::vector<std::byte> first_encrypted;

        duplex_relay_opts relay_args{
            client_sock, backend_sock, info_opt->version,
            info_opt->auth_mask, client_finished, first_encrypted};
        co_await run_duplex_relay(relay_args);

        if (client_finished.empty())
        {
            trace::warn("[Restls] clientFinished not captured");
            result.error = fault::code::protocol_error;
            co_return result;
        }

        trace::debug("[Restls] handshake complete, client_finished size={}", client_finished.size());

        detail.restls_secret = secret;
        detail.server_random = info_opt->server_random;
        detail.client_finished = std::move(client_finished);
        detail.version = info_opt->version;
        detail.script = script_engine(
            std::string_view(cfg.restls_script.data(), cfg.restls_script.size()));

        result.error = fault::code::success;
        result.detected = protocol::protocol_type::tls;
        result.scheme = "restls";

        co_return result;
    }
} // namespace psm::stealth::restls
