#include <prism/resolve/dns/upstream.hpp>
#include <prism/trace.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>

#include <openssl/ssl.h>

namespace psm::resolve::dns
{
    // SNI 回调：设置 TLS ClientHello 中的 server_name 扩展
    static int sni_callback(SSL *ssl, int *, void *arg)
    {
        SSL_set_tlsext_host_name(ssl, static_cast<const char *>(arg));
        return SSL_TLSEXT_ERR_OK;
    }

    // 检查是否为超时错误（timer 回调取消 socket 导致的 operation_aborted）
    static bool is_timeout(const boost::system::error_code &ec)
    {
        return ec == net::error::operation_aborted;
    }

    upstream::upstream(net::io_context &ioc, memory::resource_pointer mr)
        : ioc_(ioc), mr_(mr ? mr : memory::current_resource()), servers_(mr_), ssl_cache_(mr_)
    {
    }

    auto upstream::get_ssl_context(const dns_remote &server) -> std::shared_ptr<ssl::context>
    {
        const auto hostname = server.hostname.empty() ? server.address : server.hostname;
        const bool verify_peer = !server.no_check_certificate;
        ssl_cache_key key{memory::string(hostname, mr_), verify_peer};

        if (auto it = ssl_cache_.find(key); it != ssl_cache_.end())
        {
            return it->second;
        }

        auto ctx = std::make_shared<ssl::context>(ssl::context::tls);
        ctx->set_default_verify_paths();
        ctx->set_verify_mode(verify_peer ? ssl::verify_peer : ssl::verify_none);

        if (!hostname.empty())
        {
            // 注意：hostname 字符串必须比 context 长命
            // 这里使用 server 引用（来自 servers_ 成员），生命周期由 resolver 管理
            SSL_CTX_set_tlsext_servername_arg(
                ctx->native_handle(),
                const_cast<char *>(server.hostname.c_str()));
            SSL_CTX_set_tlsext_servername_callback(
                ctx->native_handle(),
                sni_callback);
        }

        ssl_cache_[key] = ctx;
        return ctx;
    }

    void upstream::set_servers(const memory::vector<dns_remote> servers)
    {
        servers_ = servers;
    }

    void upstream::set_mode(const resolve_mode mode)
    {
        mode_ = mode;
    }

    void upstream::set_timeout(const uint32_t ms)
    {
        timeout_ms_ = ms;
    }

    // ─── 传输层基础设施 ─────────────────────────────────────

    namespace
    {
        /// 传输操作中间结果，包含解析结果和 DNS 响应报文
        struct transport_result
        {
            query_result result;           // RTT、server_addr、error 已填充
            std::optional<message> response; // 解析后的 DNS 响应（TC 检查需要）
        };

        /// 为 TCP socket 装配超时回调
        auto arm_tcp(net::steady_timer &timer, const std::shared_ptr<net::ip::tcp::socket> &sock,
                     uint32_t timeout_ms) -> void
        {
            timer.expires_after(std::chrono::milliseconds(timeout_ms));
            timer.async_wait([sock](boost::system::error_code e)
                             {
                if (e != net::error::operation_aborted)
                {
                    sock->cancel();
                } });
        }

        /// 为 SSL stream 装配超时回调
        auto arm_ssl_stream(net::steady_timer &timer, const std::shared_ptr<ssl::stream<net::ip::tcp::socket>> &ssl_sock,
                            uint32_t timeout_ms) -> void
        {
            timer.expires_after(std::chrono::milliseconds(timeout_ms));
            timer.async_wait([ssl_sock](boost::system::error_code e)
                             {
                if (e != net::error::operation_aborted)
                {
                    ssl_sock->lowest_layer().cancel();
                } });
        }

        /// 共享逻辑：建立 TCP 连接（被 TCP、TLS、DoH 复用）
        auto tcp_connect(net::io_context &ioc, const net::ip::tcp::endpoint &target,
                         net::steady_timer &timer, uint32_t timeout_ms, boost::system::error_code &ec)
            -> net::awaitable<std::shared_ptr<net::ip::tcp::socket>>
        {
            auto sock = std::make_shared<net::ip::tcp::socket>(ioc);
            auto token = net::redirect_error(net::use_awaitable, ec);

            arm_tcp(timer, sock, timeout_ms);
            co_await sock->async_connect(target, token);
            timer.cancel();

            co_return sock;
        }

        /// 共享逻辑：TLS 握手（被 TLS、DoH 复用）
        auto tls_handshake(std::shared_ptr<net::ip::tcp::socket> sock, std::shared_ptr<ssl::context> ssl_ctx,
                           net::steady_timer &timer, uint32_t timeout_ms, boost::system::error_code &ec)
            -> net::awaitable<std::shared_ptr<ssl::stream<net::ip::tcp::socket>>>
        {
            auto ssl_sock = std::make_shared<ssl::stream<net::ip::tcp::socket>>(
                std::move(*sock), *ssl_ctx);
            auto token = net::redirect_error(net::use_awaitable, ec);

            arm_ssl_stream(timer, ssl_sock, timeout_ms);
            co_await ssl_sock->async_handshake(ssl::stream_base::client, token);
            timer.cancel();

            co_return ssl_sock;
        }

        /// 共享逻辑：读取 2 字节长度前缀帧（被 TCP、TLS 复用）
        auto read_dns_frame(auto &stream, memory::resource_pointer mr, net::steady_timer &timer, uint32_t timeout_ms,
                            boost::system::error_code &ec)
            -> net::awaitable<memory::vector<uint8_t>>
        {
            auto token = net::redirect_error(net::use_awaitable, ec);

            // 读取 2 字节长度前缀
            uint8_t recv_len[2]{};
            co_await net::async_read(stream, net::buffer(recv_len, 2), token);
            timer.cancel();
            if (ec)
            {
                co_return memory::vector<uint8_t>(mr);
            }

            const auto resp_len = static_cast<std::size_t>(
                (static_cast<uint16_t>(recv_len[0]) << 8) | recv_len[1]);

            if (resp_len == 0 || resp_len > 65535) [[unlikely]]
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return memory::vector<uint8_t>(mr);
            }

            // 读取响应体
            memory::vector<uint8_t> body(mr);
            body.resize(resp_len);

            // 需要重新 arm，因为上次 arm 已被消费
            // 这里的 stream 类型可能是 tcp::socket 或 ssl::stream，
            // 但 read_dns_frame 不负责 arm——由调用方在调用前 arm
            co_await net::async_read(stream, net::buffer(body), token);
            timer.cancel();

            co_return body;
        }

        // ─── UDP 传输 ─────────────────────────────────────

        struct udp_transport
        {
            std::shared_ptr<net::ip::udp::socket> sock;
            net::ip::udp::endpoint target;

            auto connect(net::io_context &ioc, const dns_remote &server, net::steady_timer &timer, uint32_t timeout_ms,
                         boost::system::error_code &ec) -> net::awaitable<void>
            {
                sock = std::make_shared<net::ip::udp::socket>(ioc);
                boost::system::error_code sock_ec;
                const auto addr = net::ip::make_address(server.address, sock_ec);
                if (sock_ec) [[unlikely]]
                {
                    ec = sock_ec;
                    co_return;
                }
                target = net::ip::udp::endpoint(addr, server.port);
                sock->open(addr.is_v6() ? net::ip::udp::v6() : net::ip::udp::v4(), sock_ec);
                if (sock_ec) [[unlikely]]
                {
                    ec = sock_ec;
                    co_return;
                }
                co_return;
            }

            auto send(const memory::vector<uint8_t> &payload, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec) -> net::awaitable<void>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);
                // UDP 超时：取消 socket
                timer.expires_after(std::chrono::milliseconds(timeout_ms));
                timer.async_wait([s = sock](boost::system::error_code e)
                                 {
                    if (e != net::error::operation_aborted)
                    {
                        s->cancel();
                    } });
                co_await sock->async_send_to(net::buffer(payload), target, token);
                timer.cancel();
            }

            auto recv(memory::resource_pointer mr, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec)
                -> net::awaitable<memory::vector<uint8_t>>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);
                memory::vector<uint8_t> buf(mr);
                buf.resize(4096);

                timer.expires_after(std::chrono::milliseconds(timeout_ms));
                timer.async_wait([s = sock](boost::system::error_code e)
                                 {
                    if (e != net::error::operation_aborted)
                    {
                        s->cancel();
                    } });
                net::ip::udp::endpoint sender;
                const auto n = co_await sock->async_receive_from(net::buffer(buf), sender, token);
                timer.cancel();

                if (!ec)
                {
                    buf.resize(n);
                }
                co_return buf;
            }

            void close()
            {
                if (sock)
                {
                    sock->close();
                }
            }
        };

        // ─── TCP 传输 ─────────────────────────────────────

        struct tcp_transport
        {
            std::shared_ptr<net::ip::tcp::socket> sock;

            auto connect(net::io_context &ioc, const dns_remote &server, net::steady_timer &timer, uint32_t timeout_ms,
                         boost::system::error_code &ec) -> net::awaitable<void>
            {
                boost::system::error_code addr_ec;
                const auto addr = net::ip::make_address(server.address, addr_ec);
                if (addr_ec) [[unlikely]]
                {
                    ec = addr_ec;
                    co_return;
                }
                sock = co_await tcp_connect(ioc, net::ip::tcp::endpoint(addr, server.port),
                                            timer, timeout_ms, ec);
            }

            auto send(const memory::vector<uint8_t> &payload, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec) -> net::awaitable<void>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);
                // 构造 TCP 帧：2 字节大端长度前缀 + DNS 报文
                const uint16_t payload_len = static_cast<uint16_t>(payload.size());
                uint8_t frame_header[2];
                frame_header[0] = static_cast<uint8_t>(payload_len >> 8);
                frame_header[1] = static_cast<uint8_t>(payload_len & 0xFF);

                std::array<net::const_buffer, 2> write_bufs = {
                    net::buffer(frame_header), net::buffer(payload)};
                arm_tcp(timer, sock, timeout_ms);
                co_await net::async_write(*sock, write_bufs, token);
                timer.cancel();

                if (ec)
                {
                    sock->close();
                }
            }

            auto recv(memory::resource_pointer mr, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec)
                -> net::awaitable<memory::vector<uint8_t>>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);
                arm_tcp(timer, sock, timeout_ms);
                auto body = co_await read_dns_frame(*sock, mr, timer, timeout_ms, ec);
                if (!ec)
                {
                    sock->close();
                }
                co_return body;
            }

            void close()
            {
                if (sock)
                {
                    sock->close();
                }
            }
        };

        // ─── TLS 传输 ─────────────────────────────────────

        struct tls_transport
        {
            std::shared_ptr<ssl::stream<net::ip::tcp::socket>> ssl_sock;
            std::shared_ptr<ssl::context> ssl_ctx;
            bool handshake_ok{false};

            auto connect(net::io_context &ioc, const dns_remote &server, net::steady_timer &timer, uint32_t timeout_ms,
                         boost::system::error_code &ec) -> net::awaitable<void>
            {
                boost::system::error_code addr_ec;
                const auto addr = net::ip::make_address(server.address, addr_ec);
                if (addr_ec) [[unlikely]]
                {
                    ec = addr_ec;
                    co_return;
                }
                auto raw_sock = co_await tcp_connect(
                    ioc, net::ip::tcp::endpoint(addr, server.port),
                    timer, timeout_ms, ec);
                if (ec)
                {
                    co_return;
                }

                ssl_sock = co_await tls_handshake(
                    std::move(raw_sock), ssl_ctx, timer, timeout_ms, ec);
                if (!ec)
                {
                    handshake_ok = true;
                }
            }

            auto send(const memory::vector<uint8_t> &payload, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec) -> net::awaitable<void>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);
                const uint16_t payload_len = static_cast<uint16_t>(payload.size());
                uint8_t frame_header[2];
                frame_header[0] = static_cast<uint8_t>(payload_len >> 8);
                frame_header[1] = static_cast<uint8_t>(payload_len & 0xFF);

                std::array<net::const_buffer, 2> write_bufs = {
                    net::buffer(frame_header), net::buffer(payload)};
                arm_ssl_stream(timer, ssl_sock, timeout_ms);
                co_await net::async_write(*ssl_sock, write_bufs, token);
                timer.cancel();

                if (ec)
                {
                    ssl_sock->lowest_layer().close();
                }
            }

            auto recv(memory::resource_pointer mr, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec)
                -> net::awaitable<memory::vector<uint8_t>>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);
                arm_ssl_stream(timer, ssl_sock, timeout_ms);
                auto body = co_await read_dns_frame(*ssl_sock, mr, timer, timeout_ms, ec);
                if (!ec)
                {
                    ssl_sock->lowest_layer().close();
                }
                co_return body;
            }

            void close()
            {
                if (ssl_sock)
                {
                    ssl_sock->lowest_layer().close();
                }
            }
        };

        // ─── HTTPS 传输 ─────────────────────────────────────

        struct https_transport
        {
            std::shared_ptr<ssl::stream<net::ip::tcp::socket>> ssl_sock;
            std::shared_ptr<ssl::context> ssl_ctx;
            memory::string http_path;   // 请求路径
            memory::string host_header; // Host 头值
            bool handshake_ok{false};

            auto connect(net::io_context &ioc, const dns_remote &server, net::steady_timer &timer, uint32_t timeout_ms,
                         boost::system::error_code &ec) -> net::awaitable<void>
            {
                boost::system::error_code addr_ec;
                const auto addr = net::ip::make_address(server.address, addr_ec);
                if (addr_ec) [[unlikely]]
                {
                    ec = addr_ec;
                    co_return;
                }
                auto raw_sock = co_await tcp_connect(
                    ioc, net::ip::tcp::endpoint(addr, server.port),
                    timer, timeout_ms, ec);
                if (ec)
                {
                    co_return;
                }

                ssl_sock = co_await tls_handshake(
                    std::move(raw_sock), ssl_ctx, timer, timeout_ms, ec);
                if (!ec)
                {
                    handshake_ok = true;
                }
            }

            auto send(const memory::vector<uint8_t> &payload, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec) -> net::awaitable<void>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);

                // 构造 HTTP POST 请求（RFC 8484）
                memory::string http_request(payload.get_allocator());
                http_request.reserve(256 + payload.size());
                http_request.append("POST ");
                http_request.append(http_path);
                http_request.append(" HTTP/1.1\r\n");
                http_request.append("Host: ");
                http_request.append(host_header);
                http_request.append("\r\n");
                http_request.append("Content-Type: application/dns-message\r\n");
                http_request.append("Content-Length: ");
                http_request.append(std::to_string(payload.size()));
                http_request.append("\r\n");
                http_request.append("Accept: application/dns-message\r\n");
                http_request.append("Connection: close\r\n");
                http_request.append("\r\n");

                std::array<net::const_buffer, 2> write_bufs = {
                    net::buffer(http_request), net::buffer(payload)};
                arm_ssl_stream(timer, ssl_sock, timeout_ms);
                co_await net::async_write(*ssl_sock, write_bufs, token);
                timer.cancel();

                if (ec)
                {
                    ssl_sock->lowest_layer().close();
                }
            }

            auto recv(memory::resource_pointer mr, net::steady_timer &timer, uint32_t timeout_ms,
                      boost::system::error_code &ec)
                -> net::awaitable<memory::vector<uint8_t>>
            {
                auto token = net::redirect_error(net::use_awaitable, ec);

                // 读取 HTTP 响应头，循环直到找到 "\r\n\r\n"
                arm_ssl_stream(timer, ssl_sock, timeout_ms);
                memory::vector<uint8_t> recv_buf(mr);
                recv_buf.resize(4096);
                memory::string header_data(mr);
                std::size_t content_length = 0;

                while (header_data.find("\r\n\r\n") == memory::string::npos)
                {
                    const auto n = co_await ssl_sock->async_read_some(net::buffer(recv_buf), token);
                    if (ec) [[unlikely]]
                    {
                        break;
                    }
                    header_data.append(reinterpret_cast<const char *>(recv_buf.data()), n);
                    if (header_data.size() > 65536) [[unlikely]]
                    {
                        ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
                        break;
                    }
                }
                timer.cancel();

                if (ec)
                {
                    co_return memory::vector<uint8_t>(mr);
                }

                // 解析 HTTP 响应头
                const auto header_end = header_data.find("\r\n\r\n");
                if (header_end == memory::string::npos) [[unlikely]]
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                    co_return memory::vector<uint8_t>(mr);
                }

                const auto header_view = std::string_view(header_data).substr(0, header_end);

                // 检查 HTTP 状态码（必须为 200）
                if (!header_view.starts_with("HTTP/1.1 200") && !header_view.starts_with("HTTP/1.0 200"))
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                    co_return memory::vector<uint8_t>(mr);
                }

                // 提取 Content-Length 头部
                const auto cl_key = std::string_view("Content-Length: ");
                const auto cl_pos = header_view.find(cl_key);
                if (cl_pos != std::string_view::npos)
                {
                    auto cl_value = header_view.substr(cl_pos + cl_key.size());
                    const auto cl_end = cl_value.find("\r\n");
                    if (cl_end != std::string_view::npos)
                    {
                        cl_value = cl_value.substr(0, cl_end);
                    }
                    content_length = 0;
                    for (const auto ch : cl_value)
                    {
                        if (ch >= '0' && ch <= '9')
                        {
                            content_length = content_length * 10 + static_cast<std::size_t>(ch - '0');
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                // 收集响应体，先处理响应头中已包含的部分
                memory::vector<uint8_t> body_buf(mr);
                const auto body_start = header_end + 4;
                if (body_start < header_data.size())
                {
                    const auto already = header_data.size() - body_start;
                    body_buf.resize(already);
                    std::memcpy(body_buf.data(), header_data.data() + body_start, already);
                }

                // 按需读取剩余的响应体
                if (body_buf.size() < content_length && content_length > 0)
                {
                    const auto remaining = content_length - body_buf.size();
                    body_buf.resize(content_length);

                    arm_ssl_stream(timer, ssl_sock, timeout_ms);
                    co_await net::async_read(*ssl_sock,
                                             net::buffer(body_buf.data() + body_buf.size() - remaining, remaining), token);
                    timer.cancel();
                }

                ssl_sock->lowest_layer().close();
                co_return body_buf;
            }

            void close()
            {
                if (ssl_sock)
                {
                    ssl_sock->lowest_layer().close();
                }
            }
        };

        // ─── 公共查询管道 ─────────────────────────────────────

        /// 执行完整的 DNS 查询流程：connect → send → recv → parse → validate
        template <typename Transport>
        auto query_via(Transport transport, net::io_context &ioc, const dns_remote &server, const message &query,
                       uint32_t default_timeout, memory::resource_pointer mr)
            -> net::awaitable<transport_result>
        {
            const auto start = std::chrono::steady_clock::now();
            auto result = query_result(mr);
            transport_result tr;

            // 计算有效超时
            const auto effective_timeout = server.timeout_ms > 0 ? server.timeout_ms : default_timeout;
            net::steady_timer timer(ioc);
            boost::system::error_code ec;

            // 1. 建立连接
            co_await transport.connect(ioc, server, timer, effective_timeout, ec);
            if (ec) [[unlikely]]
            {
                if (is_timeout(ec))
                {
                    trace::warn("[Resolve] connect to {}:{} timed out", server.address, server.port);
                    result.error = fault::code::timeout;
                }
                else
                {
                    trace::warn("[Resolve] connect to {}:{} failed: {}", server.address, server.port, ec.message());
                    result.error = fault::code::io_error;
                }
                tr.result = std::move(result);
                co_return tr;
            }

            // 2. 序列化并发送查询
            auto payload = query.pack();
            co_await transport.send(payload, timer, effective_timeout, ec);
            if (ec) [[unlikely]]
            {
                trace::warn("[Resolve] write to {} failed: {}", server.address, ec.message());
                result.error = is_timeout(ec) ? fault::code::timeout : fault::code::io_error;
                tr.result = std::move(result);
                co_return tr;
            }

            // 3. 接收响应
            auto response_buf = co_await transport.recv(mr, timer, effective_timeout, ec);

            // 4. 关闭连接（确保在错误路径上也关闭）
            transport.close();

            // 5. 计算 RTT
            const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - start)
                                 .count();
            result.rtt_ms = static_cast<uint64_t>(rtt);
            result.server_addr = memory::string(server.address, mr);

            if (ec) [[unlikely]]
            {
                if (is_timeout(ec))
                {
                    trace::warn("[Resolve] recv from {} timed out ({}ms)", server.address, effective_timeout);
                    result.error = fault::code::timeout;
                }
                else
                {
                    trace::warn("[Resolve] recv from {} failed: {}", server.address, ec.message());
                    result.error = fault::code::io_error;
                }
                tr.result = std::move(result);
                co_return tr;
            }

            // 6. 解析响应报文
            if (response_buf.empty()) [[unlikely]]
            {
                trace::warn("[Resolve] empty response from {}", server.address);
                result.error = fault::code::bad_message;
                tr.result = std::move(result);
                co_return tr;
            }

            auto resp = message::unpack(
                std::span<const uint8_t>(response_buf.data(), response_buf.size()), mr);
            if (!resp || resp->id != query.id) [[unlikely]]
            {
                trace::warn("[Resolve] bad response from {}", server.address);
                result.error = fault::code::bad_message;
                tr.result = std::move(result);
                co_return tr;
            }

            // 7. 检查 RCODE（0 = NoError, 3 = NXDomain 均视为可处理）
            if (resp->rcode != 0 && resp->rcode != 3) [[unlikely]]
            {
                trace::warn("[Resolve] rcode={} from {}", resp->rcode, server.address);
                result.response = std::move(*resp);
                result.error = fault::code::dns_failed;
                tr.result = std::move(result);
                co_return tr;
            }

            // 8. 成功
            result.response = std::move(*resp);
            result.ips = result.response.extract_ips();
            result.error = fault::code::success;
            tr.result = std::move(result);
            tr.response = result.response; // 保留副本用于 TC 检查
            co_return tr;
        }

    } // anonymous namespace

    // ─── 查询方法（薄包装） ─────────────────────────────────────

    auto upstream::query_udp(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto [result, resp] = co_await query_via(
            udp_transport{}, ioc_, server, query, timeout_ms_, mr_);

        // TC 截断回退：UDP 响应被截断时自动重试 TCP
        if (succeeded(result.error) && resp && resp->tc) [[unlikely]]
        {
            trace::debug("[Resolve] truncated response from {}, retrying via TCP", server.address);
            co_return co_await query_tcp(server, query);
        }
        co_return std::move(result);
    }

    auto upstream::query_tcp(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto [result, resp] = co_await query_via(
            tcp_transport{}, ioc_, server, query, timeout_ms_, mr_);
        co_return std::move(result);
    }

    auto upstream::query_tls(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto ssl_ctx = get_ssl_context(server);
        auto [result, resp] = co_await query_via(
            tls_transport{nullptr, ssl_ctx}, ioc_, server, query, timeout_ms_, mr_);
        co_return std::move(result);
    }

    auto upstream::query_https(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto ssl_ctx = get_ssl_context(server);
        const auto host_header = server.hostname.empty() ? server.address : server.hostname;
        auto [result, resp] = co_await query_via(
            https_transport{
                nullptr, ssl_ctx,
                memory::string(server.http_path, mr_),
                memory::string(host_header, mr_)},
            ioc_, server, query, timeout_ms_, mr_);
        co_return std::move(result);
    }

    // ─── 解析编排 ────────────────────────────────────────────

    auto upstream::resolve(std::string_view domain, qtype qt)
        -> net::awaitable<query_result>
    {
        // 构造 DNS 查询报文
        auto query_msg = message::make_query(domain, qt, mr_);

        // 生成半随机 ID：域名哈希 XOR 时间戳低位，降低冲突概率
        const auto domain_hash = std::hash<std::string_view>{}(domain);
        const auto timestamp = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        query_msg.id = static_cast<uint16_t>(domain_hash ^ timestamp);

        // 无上游服务器时直接返回失败
        if (servers_.empty()) [[unlikely]]
        {
            trace::warn("[Resolve] upstream list is empty, domain={}", domain);
            auto fallback = query_result(mr_);
            fallback.error = fault::code::dns_failed;
            co_return fallback;
        }

        // fallback 模式：顺序尝试上游服务器
        if (mode_ == resolve_mode::fallback)
        {
            for (const auto &server : servers_)
            {
                auto result = query_result(mr_);
                // 根据协议类型选择查询方法
                switch (server.protocol)
                {
                case dns_protocol::udp:
                    result = co_await query_udp(server, query_msg);
                    break;
                case dns_protocol::tcp:
                    result = co_await query_tcp(server, query_msg);
                    break;
                case dns_protocol::tls:
                    result = co_await query_tls(server, query_msg);
                    break;
                case dns_protocol::https:
                    result = co_await query_https(server, query_msg);
                    break;
                }

                trace::debug("[Resolve] query to {} completed: code={}, ips={}, rtt={}ms", server.address,
                             fault::describe(result.error), result.ips.size(), result.rtt_ms);

                // 成功获取结果即返回
                if (succeeded(result.error) && !result.ips.empty())
                {
                    co_return result;
                }
            }
            auto fallback = query_result(mr_);
            fallback.error = fault::code::dns_failed;
            co_return fallback;
        }

        // first / fastest 模式：并发查询所有上游
        // 使用 shared_ptr 延长生命周期，确保 detached 任务安全访问
        auto query_shared = std::make_shared<message>(std::move(query_msg));
        auto results_shared = std::make_shared<memory::vector<query_result>>(mr_);
        results_shared->resize(servers_.size());
        for (auto &r : *results_shared)
        {
            r = query_result(mr_);
        }

        // 信号机制：替代零延时轮询，查询完成时主动唤醒主协程
        auto completion_signal = std::make_shared<net::steady_timer>(ioc_);
        completion_signal->expires_at(net::steady_timer::time_point::max());
        auto completed_count = std::make_shared<std::atomic<std::size_t>>(0);
        const auto total_count = servers_.size();

        // 为每个上游服务器启动独立的查询协程
        for (std::size_t i = 0; i < servers_.size(); ++i)
        {
            const auto &server = servers_[i];

            auto task = [this, &server, query_shared, results_shared, i,
                         completion_signal, completed_count]() -> net::awaitable<void>
            {
                auto &result = (*results_shared)[i];
                switch (server.protocol)
                {
                case dns_protocol::udp:
                    result = co_await query_udp(server, *query_shared);
                    break;
                case dns_protocol::tcp:
                    result = co_await query_tcp(server, *query_shared);
                    break;
                case dns_protocol::tls:
                    result = co_await query_tls(server, *query_shared);
                    break;
                case dns_protocol::https:
                    result = co_await query_https(server, *query_shared);
                    break;
                }

                trace::debug("[Resolve] query to {} completed: code={}, ips={}, rtt={}ms", server.address,
                             fault::describe(result.error), result.ips.size(), result.rtt_ms);

                // 完成后递增计数器并唤醒主协程
                completed_count->fetch_add(1);
                completion_signal->cancel();
            };
            net::co_spawn(ioc_, std::move(task), net::detached);
        }

        // 判断结果是否仍在等待中
        const auto is_pending = [](const query_result &r)
        {
            return r.error == fault::code::success && r.ips.empty() && r.server_addr.empty();
        };

        // 信号驱动等待：查询完成时通过 timer 取消唤醒，而非忙等待轮询
        while (true)
        {
            boost::system::error_code wait_ec;
            co_await completion_signal->async_wait(
                net::redirect_error(net::use_awaitable, wait_ec));

            // 被取消说明有查询完成，重置定时器用于下一次等待
            if (wait_ec == net::error::operation_aborted)
            {
                completion_signal->expires_at(net::steady_timer::time_point::max());
            }

            // first 模式：收到第一个成功响应即返回
            if (mode_ == resolve_mode::first)
            {
                for (auto &r : *results_shared)
                {
                    if (!is_pending(r) && succeeded(r.error) && !r.ips.empty())
                    {
                        co_return std::move(r);
                    }
                }
            }

            // 检查是否所有查询都已完成
            if (completed_count->load() >= total_count)
            {
                break;
            }
        }

        // fastest 模式：选择 RTT 最低的成功响应
        query_result *best = nullptr;
        for (auto &r : *results_shared)
        {
            if (succeeded(r.error) && !r.ips.empty())
            {
                if (!best || r.rtt_ms < best->rtt_ms)
                {
                    best = &r;
                }
            }
        }
        if (best)
        {
            co_return std::move(*best);
        }

        // 所有查询都失败，返回第一个结果
        if (!results_shared->empty())
        {
            co_return std::move(results_shared->front());
        }

        auto fallback = query_result(mr_);
        fallback.error = fault::code::dns_failed;
        co_return fallback;
    }

} // namespace psm::resolve::dns
