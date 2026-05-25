#include <prism/stealth/restls/handshake.hpp>
#include <prism/stealth/restls/crypto.hpp>
#include <prism/stealth/restls/transport.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace.hpp>
#include <prism/fault/code.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>

namespace psm::stealth::restls
{
    namespace net = boost::asio;

    // ═══════════════════════════════════════════════════════════
    // ServerHello 解析
    // ═══════════════════════════════════════════════════════════

    static auto extract_server_random(std::span<const std::byte> server_hello)
        -> std::optional<std::array<std::uint8_t, 32>>
    {
        if (server_hello.size() < tls_hdrsize + 1 + 3 + 2 + 32)
        {
            return std::nullopt;
        }

        // safe: casting byte buffer to uint8_t to parse TLS ServerHello for server random extraction
        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        // TLS Header(5) + HandshakeType(1) + Length(3) + Version(2) + Random(32)
        std::array<std::uint8_t, 32> random{};
        std::memcpy(random.data(), raw + tls_hdrsize + 1 + 3 + 2, 32);
        return random;
    }

    static auto is_tls13_server_hello(std::span<const std::byte> server_hello)
        -> bool
    {
        if (server_hello.size() < tls_hdrsize + 1 + 3 + 2 + 32 + 1)
        {
            return false;
        }

        // safe: casting byte buffer to uint8_t to parse TLS ServerHello for version detection
        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        // 跳过 TLS Header(5) + HandshakeType(1) + Length(3) + Version(2) + Random(32)
        std::size_t offset = tls_hdrsize + 1 + 3 + 2 + 32;

        // SessionID Length(1)
        if (offset >= server_hello.size())
            return false;
        const std::uint8_t session_id_len = raw[offset];
        offset += 1 + session_id_len;

        // CipherSuite(2) + CompressionMethod(1)
        if (offset + 3 > server_hello.size())
            return false;
        offset += 3;

        // Extensions Length(2)
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

            // supported_versions (0x002B) 扩展
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

    // ═══════════════════════════════════════════════════════════
    // 解析 host:port
    // ═══════════════════════════════════════════════════════════

    static auto parse_host_port(std::string_view host_port)
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

    // ═══════════════════════════════════════════════════════════
    // 后端→客户端 relay（XOR 第一个 encrypted record）
    // ═══════════════════════════════════════════════════════════

    // 转发后端数据到客户端，XOR 第一个 encrypted record
    // 后端返回的第一个 ApplicationData 记录被 server_mask XOR。
    // 后续记录原样转发。检测到后端关闭后返回。
    static auto relay_backend_to_client(
        net::ip::tcp::socket &backend_sock,
        net::ip::tcp::socket &client_sock,
        std::span<const std::uint8_t, hs_maclen> auth_mask,
        tls_version version,
        memory::vector<std::byte> &first_encrypted)
        -> net::awaitable<bool>
    {
        const bool is_tls13 = (version == tls_version::v13);
        bool first_app_data = true;

        while (true)
        {
            std::error_code frame_ec;
            auto frame_opt = co_await common::read_raw_tls_frame(backend_sock, frame_ec);
            if (frame_ec || !frame_opt)
            {
                co_return true;
            }

            auto &frame = *frame_opt;
            // safe: casting byte frame buffer to uint8_t for TLS content type inspection and XOR processing
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

            if (first_app_data && raw[0] == 0x17 && frame.size() > tls_hdrsize)
            {
                // XOR 第一个 encrypted record
                const std::size_t xor_offset = is_tls13 ? tls_hdrsize : (tls_hdrsize + 8);
                // safe: casting mutable byte buffer region to uint8_t span for in-place XOR masking
                auto payload = std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t *>(frame.data()) + xor_offset,
                    frame.size() - xor_offset);
                xor_with_mask(payload, auth_mask);

                first_encrypted.assign(frame.begin(), frame.end());
                first_app_data = false;
            }

            boost::system::error_code write_ec;
            co_await net::async_write(
                client_sock,
                net::buffer(frame.data(), frame.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                co_return false;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 客户端→后端 relay（捕获 clientFinished）
    // ═══════════════════════════════════════════════════════════

    // 转发客户端数据到后端，捕获 clientFinished
    // 客户端的第一个 ApplicationData 记录是 clientFinished。
    // 后续记录原样转发。clientFinished 是完整加密 TLS record 含 header。
    static auto relay_client_to_backend(
        net::ip::tcp::socket &client_sock,
        net::ip::tcp::socket &backend_sock,
        tls_version version,
        memory::vector<std::uint8_t> &client_finished)
        -> net::awaitable<bool>
    {
        bool first_app_data = true;

        while (true)
        {
            std::error_code frame_ec;
            auto frame_opt = co_await common::read_raw_tls_frame(client_sock, frame_ec);
            if (frame_ec || !frame_opt)
            {
                co_return false;
            }

            auto &frame = *frame_opt;
            // safe: casting byte frame buffer to uint8_t pointer for TLS record parsing
            const auto *raw = reinterpret_cast<const std::uint8_t *>(frame.data());

            if (first_app_data && raw[0] == 0x17 && frame.size() > tls_hdrsize)
            {
                // 捕获 clientFinished（完整 TLS record 含 header）
                // safe: casting byte frame buffer to uint8_t iterators for clientFinished capture
                client_finished.assign(
                    reinterpret_cast<const std::uint8_t *>(frame.data()),
                    reinterpret_cast<const std::uint8_t *>(frame.data()) + frame.size());
                first_app_data = false;
            }

            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(frame.data(), frame.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                co_return false;
            }
        }
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
            result.error = fault::code::bad_message;
            co_return result;
        }

        trace::debug("[Restls] handshake start, client_hello size={}", client_hello.size());
        auto executor = client_sock.get_executor();

        // 派生 RestlsSecret
        const auto secret = derive_secret(cfg.password);
        auto secret_span = std::span<const std::uint8_t, 32>(secret);

        // Step 1: 连接后端 TLS 服务器
        auto [backend_host, backend_port] = parse_host_port(
            std::string_view(cfg.host.data(), cfg.host.size()));

        trace::debug("[Restls] connecting to backend: {}:{}", backend_host, backend_port);

        net::ip::tcp::resolver resolver(executor);
        auto endpoints = co_await resolver.async_resolve(backend_host, std::to_string(backend_port));

        net::ip::tcp::socket backend_sock(executor);
        boost::system::error_code connect_ec;
        co_await net::async_connect(
            backend_sock, endpoints,
            net::redirect_error(net::use_awaitable, connect_ec));

        if (connect_ec)
        {
            trace::warn("[Restls] backend connection failed: {}", connect_ec.message());
            result.error = fault::code::connection_refused;
            co_return result;
        }

        // Step 2: 转发 ClientHello 到后端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                backend_sock,
                net::buffer(client_hello.data(), client_hello.size()),
                net::redirect_error(net::use_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn("[Restls] write ClientHello failed: {}", write_ec.message());
                result.error = fault::code::connection_refused;
                co_return result;
            }
        }

        // Step 3: 读取 ServerHello
        std::error_code sh_ec;
        auto server_hello_opt = co_await common::read_raw_tls_frame(backend_sock, sh_ec);
        if (sh_ec || !server_hello_opt)
        {
            trace::warn("[Restls] failed to read ServerHello");
            result.error = fault::code::connection_refused;
            co_return result;
        }

        // Step 4: 转发 ServerHello 到客户端
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

        // Step 4 完成后，客户端已收到 ServerHello，后续失败不可 rewind
        result.polluted = true;

        // Step 5: 提取 server_random 和判断 TLS 版本
        auto sh_span = std::span<const std::byte>(server_hello_opt->data(), server_hello_opt->size());
        auto sr_opt = extract_server_random(sh_span);
        if (!sr_opt)
        {
            trace::warn("[Restls] failed to extract server_random");
            result.error = fault::code::protocol_error;
            co_return result;
        }

        const bool tls13 = is_tls13_server_hello(sh_span);
        const auto version = tls13 ? tls_version::v13 : tls_version::v12;
        auto server_random = *sr_opt;
        auto sr_span = std::span<const std::uint8_t, 32>(server_random);

        trace::debug("[Restls] server_random extracted, tls13={}", tls13);

        // Step 6: 计算 server_mask
        auto auth_mask = compute_server_mask(secret_span, sr_span);

        // Step 7: 双工转发
        // 后端→客户端：XOR 第一个 encrypted record
        // 客户端→后端：捕获 clientFinished
        memory::vector<std::uint8_t> client_finished;
        memory::vector<std::byte> first_encrypted;

        auto relay_done = std::make_shared<std::atomic<bool>>(false);
        auto cancel_signal = std::make_shared<net::cancellation_signal>();

        // 客户端→后端 relay（捕获 clientFinished）
        auto client_relay = [&client_sock, &backend_sock, version,
                             &client_finished, relay_done]()
            -> net::awaitable<void>
        {
            memory::vector<std::uint8_t> cf;
            co_await relay_client_to_backend(client_sock, backend_sock, version, cf);
            client_finished = std::move(cf);
            relay_done->store(true);
        };

        net::co_spawn(executor, std::move(client_relay),
                      net::bind_cancellation_slot(cancel_signal->slot(), net::detached));

        // 后端→客户端 relay（XOR 第一个 encrypted record）
        co_await relay_backend_to_client(
            backend_sock, client_sock,
            std::span<const std::uint8_t, hs_maclen>(auth_mask),
            version, first_encrypted);

        // 关闭后端连接
        {
            boost::system::error_code close_ec;
            backend_sock.shutdown(net::ip::tcp::socket::shutdown_both, close_ec);
            backend_sock.close(close_ec);
        }

        cancel_signal->emit(net::cancellation_type::all);

        // 等待客户端 relay 退出
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

        if (client_finished.empty())
        {
            trace::warn("[Restls] clientFinished not captured");
            result.error = fault::code::protocol_error;
            co_return result;
        }

        trace::debug("[Restls] handshake complete, client_finished size={}", client_finished.size());

        // 填充 detail
        detail.restls_secret = secret;
        detail.server_random = server_random;
        detail.client_finished = std::move(client_finished);
        detail.tls13 = tls13;
        detail.script = script_engine(
            std::string_view(cfg.restls_script.data(), cfg.restls_script.size()));

        // first_frame 暂时为空，后续由 transport 处理首帧
        result.error = fault::code::success;
        result.detected = protocol::protocol_type::tls;
        result.scheme = "restls";

        co_return result;
    }
} // namespace psm::stealth::restls
