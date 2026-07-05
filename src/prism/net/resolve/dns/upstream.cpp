#include <prism/net/resolve/dns/upstream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <prism/trace/trace.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>

using namespace psm::trace;

namespace psm::resolve::dns
{

    namespace
    {
        int sni_callback(SSL *ssl, int *, void *arg)
        {
            SSL_set_tlsext_host_name(ssl, static_cast<const char *>(arg));
            return SSL_TLSEXT_ERR_OK;
        }

        auto is_timeout(const boost::system::error_code &ec) -> bool
        {
            return ec == net::error::operation_aborted;
        }
    } // namespace

    upstream::upstream(net::io_context &ioc, memory::resource_pointer mr)
        : ioc_(ioc), mr_(memory::current_resource()), servers_(mr_), ssl_cache_(mr_)
    {
        if (mr)
        {
            mr_ = mr;
        }
    }

    auto upstream::get_ssl_ctx(const dns_remote &server)
        -> std::shared_ptr<ssl::context>
    {
        memory::string hostname_str;
        if (server.hostname.empty())
        {
            hostname_str = memory::string(server.address, mr_);
        }
        else
        {
            hostname_str = memory::string(server.hostname, mr_);
        }
        const auto hostname = std::string_view(hostname_str);
        const bool verify_peer = !server.skip_cert_check;
        ssl_key key{memory::string(hostname, mr_), verify_peer};

        if (auto it = ssl_cache_.find(key); it != ssl_cache_.end())
        {
            return it->second;
        }

        auto ctx = std::make_shared<ssl::context>(ssl::context::tls);
        ctx->set_default_verify_paths();
        auto verify_mode = ssl::verify_none;
        if (verify_peer)
        {
            verify_mode = ssl::verify_peer;
        }
        ctx->set_verify_mode(verify_mode);

        // 先插入缓存，确保 ssl_key 中的 hostname 持久存储可用
        ssl_cache_[key] = ctx;

        if (!hostname.empty())
        {
            // hostname 持久存储在 ssl_key 中，生命周期与 ssl context 绑定
            auto &stored_hostname = ssl_cache_.find(key)->first.hostname;
            SSL_CTX_set_tlsext_servername_arg(
                ctx->native_handle(),
                const_cast<void *>(static_cast<const void *>(stored_hostname.data())));
            SSL_CTX_set_tlsext_servername_callback(
                ctx->native_handle(),
                sni_callback);
        }

        return ctx;
    }

    void upstream::set_servers(const memory::vector<dns_remote>& servers)
    {
        servers_ = servers;
    }

    void upstream::set_mode(const resolve_mode mode)
    {
        mode_ = mode;
    }

    void upstream::set_timeout(const std::uint32_t ms)
    {
        timeout_ms_ = ms;
    }

    // ─── 传输层基础设施 ─────────────────────────────────────

    namespace
    {
        // 传输操作中间结果，包含解析结果和 DNS 响应报文
        struct transport_result
        {
            query_result result;             // RTT、server_addr、error 已填充
            std::optional<message> response; // 解析后的 DNS 响应（TC 检查需要）
        };

        // 传输上下文：聚合超时定时器和超时时间，消除重复传递
        struct transport_context
        {
            net::steady_timer timer;
            std::uint32_t timeout_ms;

            explicit transport_context(net::io_context &ioc, std::uint32_t timeout)
                : timer(ioc), timeout_ms(timeout) {}
        };

        /// TCP 连接目标：聚合 io_context 和远端端点
        struct dial_target
        {
            net::io_context &ioc;
            net::ip::tcp::endpoint endpoint;
        };

        /// TLS 握手材料：聚合 socket 和 SSL 上下文
        struct tls_material
        {
            std::shared_ptr<net::ip::tcp::socket> sock;
            std::shared_ptr<ssl::context> ssl_ctx;
        };

        /// DNS 帧读取上下文：聚合内存资源和错误码
        struct frame_context
        {
            memory::resource_pointer mr;
            boost::system::error_code &ec;
        };

        // 为 TCP socket 装配超时回调
        void arm_tcp(transport_context &ctx, const std::shared_ptr<net::ip::tcp::socket> &sock)
        {
            ctx.timer.expires_after(std::chrono::milliseconds(ctx.timeout_ms));
            auto on_timeout = [sock](boost::system::error_code e)
            {
                if (e != net::error::operation_aborted)
                {
                    sock->cancel();
                }
            };
            ctx.timer.async_wait(std::move(on_timeout));
        }

        // 为 SSL stream 装配超时回调
        void arm_ssl_stream(transport_context &ctx, const std::shared_ptr<ssl::stream<net::ip::tcp::socket>> &ssl_sock)
        {
            ctx.timer.expires_after(std::chrono::milliseconds(ctx.timeout_ms));
            auto on_timeout = [ssl_sock](boost::system::error_code e)
            {
                if (e != net::error::operation_aborted)
                {
                    ssl_sock->lowest_layer().cancel();
                }
            };
            ctx.timer.async_wait(std::move(on_timeout));
        }

        // 共享逻辑：建立 TCP 连接（被 TCP、TLS、DoH 复用）
        auto tcp_connect(const dial_target &target, transport_context &ctx,
                         boost::system::error_code &ec)
            -> net::awaitable<std::shared_ptr<net::ip::tcp::socket>>
        {
            auto sock = std::make_shared<net::ip::tcp::socket>(target.ioc);
            auto token = net::redirect_error(trace::use_prefix_awaitable, ec);

            arm_tcp(ctx, sock);
            co_await sock->async_connect(target.endpoint, token);
            ctx.timer.cancel();

            co_return sock;
        }

        // 共享逻辑：TLS 握手（被 TLS、DoH 复用）
        auto tls_handshake(const tls_material &mat, transport_context &ctx,
                           boost::system::error_code &ec)
            -> net::awaitable<std::shared_ptr<ssl::stream<net::ip::tcp::socket>>>
        {
            auto ssl_sock = std::make_shared<ssl::stream<net::ip::tcp::socket>>(
                std::move(*mat.sock), *mat.ssl_ctx);
            auto token = net::redirect_error(trace::use_prefix_awaitable, ec);

            arm_ssl_stream(ctx, ssl_sock);
            co_await ssl_sock->async_handshake(ssl::stream_base::client, token);
            ctx.timer.cancel();

            co_return ssl_sock;
        }

        // 共享逻辑：读取 2 字节长度前缀帧（被 TCP、TLS 复用）
        auto read_dns_frame(auto &stream, const frame_context &fctx,
                            transport_context &ctx)
            -> net::awaitable<memory::vector<std::uint8_t>>
        {
            auto token = net::redirect_error(trace::use_prefix_awaitable, fctx.ec);

            // 读取 2 字节长度前缀
            std::uint8_t recv_len[2]{};
            co_await net::async_read(stream, net::buffer(recv_len, 2), token);
            ctx.timer.cancel();
            if (fctx.ec)
            {
                co_return memory::vector<std::uint8_t>(fctx.mr);
            }

            const auto resp_len = static_cast<std::size_t>(
                (static_cast<std::uint16_t>(recv_len[0]) << 8) | recv_len[1]);

            if (resp_len == 0 || resp_len > 65535) [[unlikely]]
            {
                fctx.ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return memory::vector<std::uint8_t>(fctx.mr);
            }

            // 读取响应体
            memory::vector<std::uint8_t> body(fctx.mr);
            body.resize(resp_len);

            co_await net::async_read(stream, net::buffer(body), token);
            ctx.timer.cancel();

            co_return body;
        }

        // ─── UDP 传输 ─────────────────────────────────────

        struct udp_transport
        {
            std::shared_ptr<net::ip::udp::socket> sock;
            net::ip::udp::endpoint target;

            auto connect(net::io_context &ioc, const dns_remote &server,
                         transport_context & /*ctx*/, boost::system::error_code &ec) -> net::awaitable<void>
            {
                (void)ioc; (void)server; (void)ec;
                sock = std::make_shared<net::ip::udp::socket>(ioc);
                boost::system::error_code sock_ec;
                const auto addr = net::ip::make_address(server.address, sock_ec);
                if (sock_ec) [[unlikely]]
                {
                    ec = sock_ec;
                    co_return;
                }
                target = net::ip::udp::endpoint(addr, server.port);
                auto protocol = net::ip::udp::v4();
                if (addr.is_v6())
                {
                    protocol = net::ip::udp::v6();
                }
                sock->open(protocol, sock_ec);
                if (sock_ec) [[unlikely]]
                {
                    ec = sock_ec;
                    co_return;
                }
                co_return;
            }

            auto send(const memory::vector<std::uint8_t> &payload, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<void>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
                ctx.timer.expires_after(std::chrono::milliseconds(ctx.timeout_ms));
                auto on_timeout = [s = sock](boost::system::error_code e)
                {
                    if (e != net::error::operation_aborted)
                    {
                        s->cancel();
                    }
                };
                ctx.timer.async_wait(std::move(on_timeout));
                co_await sock->async_send_to(net::buffer(payload), target, token);
                ctx.timer.cancel();
            }

            auto recv(memory::resource_pointer mr, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<memory::vector<std::uint8_t>>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
                memory::vector<std::uint8_t> buf(mr);
                buf.resize(4096);

                ctx.timer.expires_after(std::chrono::milliseconds(ctx.timeout_ms));
                auto on_timeout = [s = sock](boost::system::error_code e)
                {
                    if (e != net::error::operation_aborted)
                    {
                        s->cancel();
                    }
                };
                ctx.timer.async_wait(std::move(on_timeout));
                net::ip::udp::endpoint sender;
                const auto n = co_await sock->async_receive_from(net::buffer(buf), sender, token);
                ctx.timer.cancel();

                if (!ec)
                {
                    // 验证响应来源与目标一致，防止 DNS 劫持/伪造
                    if (sender.address() != target.address() || sender.port() != target.port())
                    {
                        ec = net::error::connection_refused;
                        co_return buf;
                    }
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

            auto connect(net::io_context &ioc, const dns_remote &server,
                         transport_context &ctx, boost::system::error_code &ec) -> net::awaitable<void>
            {
                boost::system::error_code addr_ec;
                const auto addr = net::ip::make_address(server.address, addr_ec);
                if (addr_ec) [[unlikely]]
                {
                    ec = addr_ec;
                    co_return;
                }
                sock = co_await tcp_connect(dial_target{ioc, net::ip::tcp::endpoint(addr, server.port)}, ctx, ec);
            }

            auto send(const memory::vector<std::uint8_t> &payload, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<void>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
                const std::uint16_t payload_len = static_cast<std::uint16_t>(payload.size());
                std::uint8_t frame_header[2];
                frame_header[0] = static_cast<std::uint8_t>(payload_len >> 8);
                frame_header[1] = static_cast<std::uint8_t>(payload_len & 0xFF);

                std::array<net::const_buffer, 2> write_bufs = {
                    net::buffer(frame_header), net::buffer(payload)};
                arm_tcp(ctx, sock);
                co_await net::async_write(*sock, write_bufs, token);
                ctx.timer.cancel();

                if (ec)
                {
                    sock->close();
                }
            }

            auto recv(memory::resource_pointer mr, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<memory::vector<std::uint8_t>>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
                arm_tcp(ctx, sock);
                auto body = co_await read_dns_frame(*sock, frame_context{mr, ec}, ctx);
                if (ec)
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

            auto connect(net::io_context &ioc, const dns_remote &server,
                         transport_context &ctx, boost::system::error_code &ec) -> net::awaitable<void>
            {
                boost::system::error_code addr_ec;
                const auto addr = net::ip::make_address(server.address, addr_ec);
                if (addr_ec) [[unlikely]]
                {
                    ec = addr_ec;
                    co_return;
                }
                auto raw_sock = co_await tcp_connect(
                    dial_target{ioc, net::ip::tcp::endpoint(addr, server.port)}, ctx, ec);
                if (ec)
                {
                    co_return;
                }

                ssl_sock = co_await tls_handshake(tls_material{std::move(raw_sock), ssl_ctx}, ctx, ec);
                if (!ec)
                {
                    handshake_ok = true;
                }
            }

            auto send(const memory::vector<std::uint8_t> &payload, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<void>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
                const std::uint16_t payload_len = static_cast<std::uint16_t>(payload.size());
                std::uint8_t frame_header[2];
                frame_header[0] = static_cast<std::uint8_t>(payload_len >> 8);
                frame_header[1] = static_cast<std::uint8_t>(payload_len & 0xFF);

                std::array<net::const_buffer, 2> write_bufs = {
                    net::buffer(frame_header), net::buffer(payload)};
                arm_ssl_stream(ctx, ssl_sock);
                co_await net::async_write(*ssl_sock, write_bufs, token);
                ctx.timer.cancel();

                if (ec)
                {
                    ssl_sock->lowest_layer().close();
                }
            }

            auto recv(memory::resource_pointer mr, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<memory::vector<std::uint8_t>>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
                arm_ssl_stream(ctx, ssl_sock);
                auto body = co_await read_dns_frame(*ssl_sock, frame_context{mr, ec}, ctx);
                if (ec)
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

            auto connect(net::io_context &ioc, const dns_remote &server,
                         transport_context &ctx, boost::system::error_code &ec) -> net::awaitable<void>
            {
                boost::system::error_code addr_ec;
                const auto addr = net::ip::make_address(server.address, addr_ec);
                if (addr_ec) [[unlikely]]
                {
                    ec = addr_ec;
                    co_return;
                }
                auto raw_sock = co_await tcp_connect(
                    dial_target{ioc, net::ip::tcp::endpoint(addr, server.port)}, ctx, ec);
                if (ec)
                {
                    co_return;
                }

                ssl_sock = co_await tls_handshake(tls_material{std::move(raw_sock), ssl_ctx}, ctx, ec);
                if (!ec)
                {
                    handshake_ok = true;
                }
            }

            auto send(const memory::vector<std::uint8_t> &payload, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<void>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);

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
                arm_ssl_stream(ctx, ssl_sock);
                co_await net::async_write(*ssl_sock, write_bufs, token);
                ctx.timer.cancel();

                if (ec)
                {
                    ssl_sock->lowest_layer().close();
                }
            }

            auto recv(memory::resource_pointer mr, transport_context &ctx, boost::system::error_code &ec)
                -> net::awaitable<memory::vector<std::uint8_t>>
            {
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);

                // 读取 HTTP 响应头，循环直到找到 "\r\n\r\n"
                arm_ssl_stream(ctx, ssl_sock);
                memory::vector<std::uint8_t> recv_buf(mr);
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
                    // 安全：将可变缓冲区转为 const char* 追加到字符串，数据来自 socket 读取
                    header_data.append(reinterpret_cast<const char *>(recv_buf.data()), n);
                    if (header_data.size() > 65536) [[unlikely]]
                    {
                        ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
                        break;
                    }
                }
                ctx.timer.cancel();

                if (ec)
                {
                    co_return memory::vector<std::uint8_t>(mr);
                }

                // 解析 HTTP 响应头
                const auto header_end = header_data.find("\r\n\r\n");
                if (header_end == memory::string::npos) [[unlikely]]
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                    co_return memory::vector<std::uint8_t>(mr);
                }

                const auto header_view = std::string_view(header_data).substr(0, header_end);

                // 检查 HTTP 状态码（必须为 200）
                if (!header_view.starts_with("HTTP/1.1 200") && !header_view.starts_with("HTTP/1.0 200"))
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                    co_return memory::vector<std::uint8_t>(mr);
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
                memory::vector<std::uint8_t> body_buf(mr);
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

                    arm_ssl_stream(ctx, ssl_sock);
                    co_await net::async_read(*ssl_sock,
                                             net::buffer(body_buf.data() + body_buf.size() - remaining, remaining), token);
                    ctx.timer.cancel();
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

        // 查询上下文：聚合 query_via 的多个参数，避免函数参数超过 3 个
        struct query_context
        {
            const dns_remote &server;                  ///< 目标上游服务器配置
            const message &query;                      ///< DNS 查询报文
            std::uint32_t default_timeout;                  ///< 默认超时（毫秒）
            memory::resource_pointer mr;               ///< PMR 内存资源
        };

        // 执行完整的 DNS 查询流程：connect -> send -> recv -> parse -> validate
        template <typename Transport>
        auto query_via(Transport transport, net::io_context &ioc, query_context qctx)
            -> net::awaitable<transport_result>
        {
            const auto start = std::chrono::steady_clock::now();
            auto result = query_result(qctx.mr);
            transport_result tr;

            std::uint32_t effective_timeout;
            if (qctx.server.timeout_ms > 0)
            {
                effective_timeout = qctx.server.timeout_ms;
            }
            else
            {
                effective_timeout = qctx.default_timeout;
            }
            transport_context ctx(ioc, effective_timeout);
            boost::system::error_code ec;

            // 1. 建立连接
            co_await transport.connect(ioc, qctx.server, ctx, ec);
            if (ec) [[unlikely]]
            {
                if (is_timeout(ec))
                {
                    trace::warn("connect to {}:{} timed out", qctx.server.address, qctx.server.port);
                    result.error = fault::code::timeout;
                }
                else
                {
                    trace::warn("connect to {}:{} failed: {}", qctx.server.address, qctx.server.port, ec.message());
                    result.error = fault::code::io_error;
                }
                tr.result = std::move(result);
                co_return tr;
            }

            // 2. 序列化并发送查询
            auto payload = qctx.query.pack();
            co_await transport.send(payload, ctx, ec);
            if (ec) [[unlikely]]
            {
                trace::warn("write to {} failed: {}", qctx.server.address, ec.message());
                fault::code send_ec;
                if (is_timeout(ec))
                {
                    send_ec = fault::code::timeout;
                }
                else
                {
                    send_ec = fault::code::io_error;
                }
                result.error = send_ec;
                tr.result = std::move(result);
                co_return tr;
            }

            // 3. 接收响应
            auto response_buf = co_await transport.recv(qctx.mr, ctx, ec);

            // 4. 关闭连接（确保在错误路径上也关闭）
            transport.close();

            // 5. 计算 RTT
            const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - start)
                                 .count();
            result.rtt_ms = static_cast<std::uint64_t>(rtt);
            result.server_addr = memory::string(qctx.server.address, qctx.mr);

            if (ec) [[unlikely]]
            {
                if (is_timeout(ec))
                {
                    trace::warn("recv from {} timed out ({}ms)", qctx.server.address, effective_timeout);
                    result.error = fault::code::timeout;
                }
                else
                {
                    trace::warn("recv from {} failed: {}", qctx.server.address, ec.message());
                    result.error = fault::code::io_error;
                }
                tr.result = std::move(result);
                co_return tr;
            }

            // 6. 解析响应报文
            if (response_buf.empty()) [[unlikely]]
            {
                trace::warn("empty response from {}", qctx.server.address);
                result.error = fault::code::bad_message;
                tr.result = std::move(result);
                co_return tr;
            }

            auto resp = message::unpack(
                std::span<const std::uint8_t>(response_buf.data(), response_buf.size()), qctx.mr);
            if (!resp || resp->id != qctx.query.id) [[unlikely]]
            {
                trace::warn("bad response from {}", qctx.server.address);
                result.error = fault::code::bad_message;
                tr.result = std::move(result);
                co_return tr;
            }

            // 7. 检查 RCODE（0 = NoError, 3 = NXDomain 均视为可处理）
            if (resp->rcode != 0 && resp->rcode != 3) [[unlikely]]
            {
                trace::warn("rcode={} from {}", resp->rcode, qctx.server.address);
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

    // ─── 协议分发 ────────────────────────────────────────────

    auto upstream::query_server(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        switch (server.protocol)
        {
        case dns_protocol::udp:
            co_return co_await query_udp(server, query);
        case dns_protocol::tcp:
            co_return co_await query_tcp(server, query);
        case dns_protocol::tls:
            co_return co_await query_tls(server, query);
        case dns_protocol::https:
            co_return co_await query_https(server, query);
        }
        co_return co_await query_udp(server, query);
    }

    // ─── 查询方法（薄包装） ─────────────────────────────────────

    auto upstream::query_udp(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto [result, resp] = co_await query_via(
            udp_transport{}, ioc_, {server, query, timeout_ms_, mr_});

        // TC 截断回退：UDP 响应被截断时自动重试 TCP
        if (succeeded(result.error) && resp && resp->tc) [[unlikely]]
        {
            trace::debug("truncated response from {}, retrying via TCP", server.address);
            co_return co_await query_tcp(server, query);
        }
        co_return std::move(result);
    }

    auto upstream::query_tcp(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto [result, resp] = co_await query_via(
            tcp_transport{}, ioc_, {server, query, timeout_ms_, mr_});
        co_return std::move(result);
    }

    auto upstream::query_tls(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto ssl_ctx = get_ssl_ctx(server);
        auto [result, resp] = co_await query_via(
            tls_transport{nullptr, ssl_ctx}, ioc_, {server, query, timeout_ms_, mr_});
        co_return std::move(result);
    }

    auto upstream::query_https(const dns_remote &server, const message &query)
        -> net::awaitable<query_result>
    {
        auto ssl_ctx = get_ssl_ctx(server);
        memory::string host_header;
        if (server.hostname.empty())
        {
            host_header = memory::string(server.address, mr_);
        }
        else
        {
            host_header = memory::string(server.hostname, mr_);
        }
        auto [result, resp] = co_await query_via(
            https_transport{
                nullptr, ssl_ctx,
                memory::string(server.http_path, mr_),
                memory::string(host_header, mr_)},
            ioc_, {server, query, timeout_ms_, mr_});
        co_return std::move(result);
    }

    // ─── 解析编排 ────────────────────────────────────────────

    auto upstream::resolve_fallback(std::string_view domain, const message &query_msg)
        -> net::awaitable<query_result>
    {
        for (const auto &server : servers_)
        {
            auto result = co_await query_server(server, query_msg);

            trace::debug("query to {} completed: code={}, ips={}, rtt={}ms", server.address,
                         fault::describe(result.error), result.ips.size(), result.rtt_ms);

            // 成功获取结果即返回
            if (succeeded(result.error) && !result.ips.empty())
            {
                co_return result;
            }
        }

        trace::warn("all upstream failed in fallback mode, domain={}", domain);
        auto fallback = query_result(mr_);
        fallback.error = fault::code::dns_failed;
        co_return fallback;
    }

    auto upstream::resolve_concurrent(const message &query_msg)
        -> net::awaitable<query_result>
    {
        // 使用 shared_ptr 延长生命周期，确保 detached 任务安全访问
        auto query_shared = std::make_shared<message>(query_msg);
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
                result = co_await query_server(server, *query_shared);

                trace::debug("query to {} completed: code={}, ips={}, rtt={}ms", server.address,
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
                net::redirect_error(trace::use_prefix_awaitable, wait_ec));

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

        co_return select_best_result(*results_shared);
    }

    auto upstream::select_best_result(memory::vector<query_result> &results)
        -> query_result
    {
        // fastest 模式：选择 RTT 最低的成功响应
        query_result *best = nullptr;
        for (auto &r : results)
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
            return std::move(*best);
        }

        // 所有查询都失败，返回第一个结果
        if (!results.empty())
        {
            return std::move(results.front());
        }

        auto fallback = query_result(mr_);
        fallback.error = fault::code::dns_failed;
        return fallback;
    }

    auto upstream::resolve(std::string_view domain, qtype qt)
        -> net::awaitable<query_result>
    {
        // 构造 DNS 查询报文
        auto query_msg = message::make_query(domain, qt, mr_);

        // 生成半随机 ID：域名哈希 XOR 时间戳低位，降低冲突概率
        const auto domain_hash = std::hash<std::string_view>{}(domain);
        const auto timestamp = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        query_msg.id = static_cast<std::uint16_t>(domain_hash ^ timestamp);

        // 无上游服务器时直接返回失败
        if (servers_.empty()) [[unlikely]]
        {
            trace::warn("upstream list is empty, domain={}", domain);
            auto fallback = query_result(mr_);
            fallback.error = fault::code::dns_failed;
            co_return fallback;
        }

        // fallback 模式：顺序尝试上游服务器
        if (mode_ == resolve_mode::fallback)
        {
            co_return co_await resolve_fallback(domain, query_msg);
        }

        // first / fastest 模式：并发查询所有上游
        co_return co_await resolve_concurrent(query_msg);
    }

} // namespace psm::resolve::dns
