/**
 * @file handshake.cpp
 * @brief Restls 服务端握手（中间人代理模式）
 * @details 转发 ClientHello 到真实 TLS 后端，中继握手，
 * 对第一个加密帧做 XOR auth，捕获 clientFinished。
 * 握手完成后把 raw socket 交给 restls_transport，返回成功。
 * 参照 ShadowTLS v3 的 relay 架构（operator|| + co_return 退出）。
 */

#include <prism/stealth/facade/restls/handshake.hpp>

#include <prism/core/fault/code.hpp>
#include <prism/stealth/common.hpp>
#include <prism/stealth/facade/restls/crypto.hpp>
#include <prism/stealth/facade/restls/script.hpp>
#include <prism/stealth/facade/restls/transport.hpp>
#include <prism/trace/trace.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <cstring>
#include <string_view>

using namespace psm::trace;

namespace psm::stealth::restls
{

    namespace
    {

        /// 解析 host:port 字符串
        auto parse_host_port(std::string_view host_port) -> std::pair<std::string, std::uint16_t>
        {
            const auto pos = host_port.rfind(':');
            if (pos == std::string_view::npos)
                return {std::string(host_port), 443};
            auto host = std::string(host_port.substr(0, pos));
            auto port_sv = host_port.substr(pos + 1);
            std::uint16_t port = 443;
            std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
            return {std::move(host), port};
        }

        /// 连接到真实 TLS 后端
        auto connect_to_backend(
            net::ip::tcp::socket::executor_type executor,
            const std::string &host, std::uint16_t port)
            -> net::awaitable<std::shared_ptr<net::ip::tcp::socket>>
        {
            net::ip::tcp::resolver resolver(executor);
            auto endpoints = co_await resolver.async_resolve(host, std::to_string(port));

            auto sock = std::make_shared<net::ip::tcp::socket>(executor);
            boost::system::error_code ec;
            co_await net::async_connect(
                *sock, endpoints,
                net::redirect_error(trace::use_prefix_awaitable, ec));

            if (ec)
            {
                trace::warn<flt::conn | flt::protocol>(
                    "restls: backend connection failed: {}", ec.message());
                co_return nullptr;
            }
            co_return sock;
        }

        /// 从 ServerHello 提取 server_random（offset 11，32 bytes）
        auto extract_server_random(std::span<const std::byte> hello) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> random{};
            if (hello.size() >= 11 + 32)
            {
                std::memcpy(random.data(),
                            reinterpret_cast<const std::uint8_t *>(hello.data()) + 11, 32);
            }
            return random;
        }

        /// 检测 ServerHello 是否为 TLS 1.3
        auto is_tls13_server_hello(std::span<const std::byte> hello) -> bool
        {
            return hello.size() >= 43;
        }


        auto relay_backend_to_client(
            std::shared_ptr<net::ip::tcp::socket> backend_sock,
            net::ip::tcp::socket &client_sock,
            std::span<const std::uint8_t> sr_mac,
            memory::vector<std::byte> &first_encrypted_out)
            -> net::awaitable<void>
        {
            bool first_app_data = true;
            bool first_encrypted_captured = false;

            while (true)
            {
                std::error_code ec;
                auto frame_opt = co_await common::read_tls_frame(*backend_sock, ec);
                if (ec || !frame_opt)
                    co_return;

                auto &frame = *frame_opt;
                auto *raw = reinterpret_cast<std::uint8_t *>(frame.data());

                if (first_app_data && raw[0] == 0x17 && frame.size() > 5)
                {
                    // 只对 payload 前 hs_maclen 字节做 XOR（与 client 端 xorWithMac 行为一致）
                    const std::size_t payload_len = frame.size() - tls_hdrsize;
                    const std::size_t xor_len = std::min(hs_maclen, payload_len);
                    for (std::size_t i = 0; i < xor_len; ++i)
                        raw[tls_hdrsize + i] ^= sr_mac[i];
                    first_app_data = false;

                    trace::debug<flt::conn | flt::protocol>(
                        "restls: XOR applied to first backend→client record, payload_len={}, xor_len={}",
                        payload_len, xor_len);
                }

                if (!first_encrypted_captured && raw[0] == 0x17)
                {
                    first_encrypted_out.assign(frame.begin(), frame.end());
                    first_encrypted_captured = true;
                }

                boost::system::error_code write_ec;
                co_await net::async_write(
                    client_sock,
                    net::buffer(frame.data(), frame.size()),
                    net::redirect_error(trace::use_prefix_awaitable, write_ec));
                if (write_ec)
                    co_return;
            }
        }


        auto relay_client_to_backend(
            net::ip::tcp::socket &client_sock,
            std::shared_ptr<net::ip::tcp::socket> backend_sock,
            memory::vector<std::byte> &client_finished_out)
            -> net::awaitable<void>
        {
            bool first_app_data = true;

            while (true)
            {
                std::error_code ec;
                auto frame_opt = co_await common::read_tls_frame(client_sock, ec);
                if (ec || !frame_opt)
                    co_return;

                auto &frame = *frame_opt;
                auto *raw = reinterpret_cast<std::uint8_t *>(frame.data());

                if (first_app_data && raw[0] == 0x17 && frame.size() > 5)
                {
                    client_finished_out.assign(frame.begin(), frame.end());
                    first_app_data = false;

                    boost::system::error_code write_ec;
                    co_await net::async_write(
                        *backend_sock,
                        net::buffer(frame.data(), frame.size()),
                        net::redirect_error(trace::use_prefix_awaitable, write_ec));

                    trace::debug<flt::conn | flt::protocol>(
                        "restls: clientFinished captured, payload_len={}", frame.size());
                    co_return;
                }

                boost::system::error_code write_ec;
                co_await net::async_write(
                    *backend_sock,
                    net::buffer(frame.data(), frame.size()),
                    net::redirect_error(trace::use_prefix_awaitable, write_ec));
                if (write_ec)
                    co_return;
            }
        }

    } // namespace


    auto handshake(handshake_opts opts)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;
        auto &raw_trans = opts.raw_trans;
        auto &cfg = opts.cfg;
        auto &client_sock = raw_trans->native_socket();
        auto &detail = opts.detail;

        // 1. 派生 RestlsSecret
        auto password_sv = std::string_view(cfg.password.data(), cfg.password.size());
        detail.restls_secret = derive_secret(password_sv);

        // 2. 解析后端地址
        auto host_port_sv = std::string_view(cfg.host.data(), cfg.host.size());
        auto [backend_host, backend_port] = parse_host_port(host_port_sv);
        trace::debug<flt::conn | flt::protocol>(
            "restls: connecting to backend {}:{}", backend_host, backend_port);

        // 3. 连接后端
        auto executor = client_sock.get_executor();
        auto backend_sock = co_await connect_to_backend(executor, backend_host, backend_port);
        if (!backend_sock)
        {
            result.error = fault::code::connection_refused;
            result.polluted = true;
            co_return result;
        }

        // 4. 转发 ClientHello 到后端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                *backend_sock,
                net::buffer(opts.client_hello.data(), opts.client_hello.size()),
                net::redirect_error(trace::use_prefix_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn<flt::conn | flt::protocol>(
                    "restls: write ClientHello failed: {}", write_ec.message());
                result.error = fault::code::connection_refused;
                result.polluted = true;
                co_return result;
            }
        }

        // 5. 读 ServerHello
        std::error_code sh_ec;
        auto server_hello_opt = co_await common::read_tls_frame(*backend_sock, sh_ec);
        if (sh_ec || !server_hello_opt)
        {
            trace::warn<flt::conn | flt::protocol>("restls: failed to read ServerHello");
            result.error = fault::code::connection_refused;
            result.polluted = true;
            co_return result;
        }

        // 6. 提取 server_random + 计算 sr_mac
        auto sh_span = std::span<const std::byte>(server_hello_opt->data(), server_hello_opt->size());
        detail.server_random = extract_server_random(sh_span);
        auto secret_span = std::span<const std::uint8_t, 32>(detail.restls_secret);
        auto sr_span = std::span<const std::uint8_t, 32>(detail.server_random);
        auto sr_mac = compute_server_mask(secret_span, sr_span);

        const bool tls13 = is_tls13_server_hello(sh_span);
        detail.version = tls13 ? tls_version::v13 : tls_version::v12;

        trace::debug<flt::conn | flt::protocol>(
            "restls: ServerHello received, tls13={}, sr_mac[0..3]={:02x}{:02x}{:02x}{:02x}",
            tls13, sr_mac[0], sr_mac[1], sr_mac[2], sr_mac[3]);

        // 7. 转发 ServerHello 到客户端
        {
            boost::system::error_code write_ec;
            co_await net::async_write(
                client_sock,
                net::buffer(server_hello_opt->data(), server_hello_opt->size()),
                net::redirect_error(trace::use_prefix_awaitable, write_ec));
            if (write_ec)
            {
                trace::warn<flt::conn | flt::protocol>(
                    "restls: write ServerHello failed: {}", write_ec.message());
                result.error = fault::code::connection_refused;
                result.polluted = true;
                co_return result;
            }
        }

        result.polluted = true;

        // 8. 解析 script
        auto scheme_sv = std::string_view(cfg.restls_script.data(), cfg.restls_script.size());
        detail.script = script_engine(scheme_sv);

        // 9. 双工中继
        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (
            relay_backend_to_client(backend_sock, client_sock, sr_mac, detail.first_encrypted) ||
            relay_client_to_backend(client_sock, backend_sock, detail.client_finished));

        // 10. 关闭后端
        {
            boost::system::error_code ec;
            backend_sock->shutdown(net::ip::tcp::socket::shutdown_both, ec);
            backend_sock->close(ec);
        }

        // 11. 检查 clientFinished
        if (detail.client_finished.empty())
        {
            trace::warn<flt::conn | flt::protocol>("restls: clientFinished not captured");
            result.error = fault::code::protocol_error;
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>(
            "restls: handshake complete, clientFinished={}B, first_encrypted={}B",
            detail.client_finished.size(), detail.first_encrypted.size());

        // 12. 把 raw_trans 所有权交给 restls_transport
        result.transport = std::make_shared<restls_transport>(
            std::move(raw_trans),
            restls_handover{
                .secret = std::span<const std::uint8_t, 32>(detail.restls_secret),
                .server_random = std::span<const std::uint8_t, 32>(detail.server_random),
                .script = detail.script,
                .version = detail.version,
                .client_finished = std::move(detail.client_finished),
            });
        result.detected = protocol::protocol_type::tls;
        result.scheme = "restls";

        co_return result;
    }

} // namespace psm::stealth::restls
