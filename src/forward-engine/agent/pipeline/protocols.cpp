#include <forward-engine/agent/pipeline/protocols.hpp>
#include <forward-engine/protocol/trojan.hpp>
#include <forward-engine/channel/transport/secure.hpp>
#include <forward-engine/agent/account/directory.hpp>

namespace ngx::agent::pipeline
{
    auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        ngx::channel::connector stream(std::move(ctx.inbound));
        ngx::channel::transport::transmission_pointer outbound;

        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});

        if (!data.empty())
        {
            auto dest = read_buffer.prepare(data.size());
            std::memcpy(dest.data(), data.data(), data.size());
            read_buffer.commit(data.size());
        }

        protocol::http::request req(mr);
        {
            const auto ec = co_await protocol::http::async_read(stream, req, read_buffer, mr);
            if (gist::failed(ec))
                co_return;

            const auto target = protocol::analysis::resolve(req);
            trace::info("[Pipeline] Http analysis target = [host: {}, port: {}, positive: {}]", target.host, target.port, target.positive);

            std::shared_ptr<distribution::router> router_ptr(&ctx.worker.router, [](distribution::router *) {});
            auto [fst, snd] = co_await primitives::dial(router_ptr, "HTTP", target, true, false);
            if (gist::failed(fst) || !snd)
                co_return;
            outbound = std::move(snd);
        }

        if (req.method() == protocol::http::verb::connect)
        {
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            boost::system::error_code write_ec;
            co_await net::async_write(stream, net::buffer(resp), net::redirect_error(net::use_awaitable, write_ec));
            if (!write_ec)
            {
                co_await primitives::original_tunnel(stream.release(), std::move(outbound), ctx);
            }
            co_return;
        }

        std::error_code ec;
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write(
            std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write(span, ec);
            if (ec)
                co_return;
        }

        co_await primitives::original_tunnel(stream.release(), std::move(outbound), ctx);
    }

    auto socks5(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        auto inbound = std::move(ctx.inbound);
        if (!inbound)
        {
            trace::warn("[Pipeline] SOCKS5 inbound transmission missing.");
            co_return;
        }

        if (!data.empty())
        {
            inbound = std::make_unique<primitives::preview>(std::move(inbound), data);
        }

        const auto agent = protocol::socks5::make_relay(std::move(inbound), ctx.server.cfg.socks5);
        auto [ec, request] = co_await agent->handshake();
        if (gist::failed(ec))
        {
            trace::error("[Pipeline] SOCKS5 handshake failed: {}", gist::cached_message(ec));
            co_return;
        }

        switch (request.cmd)
        {
        case protocol::socks5::command::connect:
        {
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(request.destination_port);
            target.positive = true;
            trace::info("[Pipeline] SOCKS5 CONNECT target = [host: {}, port: {}]", target.host, target.port);

            const auto router_ptr = std::shared_ptr<distribution::router>(&ctx.worker.router, [](distribution::router *) {});
            auto [conn_ec, outbound] = co_await primitives::dial(router_ptr, "SOCKS5", target, true, true);
            if (gist::failed(conn_ec) || !outbound)
            {
                co_await agent->async_write_error(protocol::socks5::reply_code::host_unreachable);
                co_return;
            }

            if (gist::failed(co_await agent->async_write_success(request)))
            {
                co_return;
            }
            auto trans_ptr = agent->release();
            co_await primitives::original_tunnel(std::move(trans_ptr), std::move(outbound), ctx);
            break;
        }
        case protocol::socks5::command::udp_associate:
        {
            trace::info("[Pipeline] SOCKS5 UDP_ASSOCIATE");

            const auto router_ptr = std::shared_ptr<distribution::router>(&ctx.worker.router, [](distribution::router *) {});
            auto route_callback = [router_ptr](const std::string_view host, const std::string_view port)
                -> net::awaitable<std::pair<gist::code, net::ip::udp::endpoint>>
            {
                co_return co_await router_ptr->resolve_datagram_target(host, port);
            };
            static_cast<void>(co_await agent->async_associate(request, std::move(route_callback)));
            break;
        }
        default:
            trace::warn("[Pipeline] SOCKS5 BIND command not supported");
            co_await agent->async_write_error(protocol::socks5::reply_code::command_not_supported);
            break;
        }
    }

    auto tls(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        auto [handshake_ec, ssl_stream] = co_await primitives::ssl_handshake(ctx, data);
        if (gist::failed(handshake_ec) || !ssl_stream)
        {
            trace::warn("[Pipeline] TLS handshake failed: {}", gist::describe(handshake_ec));
            co_return;
        }

        trace::debug("[Pipeline] TLS handshake succeeded, detecting inner protocol");

        // 注册活跃流清理回调，确保 session.close() 能关闭 TLS 流
        ctx.active_stream_cancel = [ssl_stream]() noexcept
        {
            ssl_stream->lowest_layer().transmission().cancel();
        };
        ctx.active_stream_close = [ssl_stream]() noexcept
        {
            // 直接关闭底层传输（SSL shutdown 需要 read_some 接口，connector 不支持）
            ssl_stream->lowest_layer().transmission().close();
        };

        constexpr std::size_t min_detect_size = 60;
        constexpr std::chrono::seconds probe_timeout(5);

        memory::vector<std::byte> probe_buffer(ctx.frame_arena.get());
        probe_buffer.reserve(min_detect_size);

        auto inner_type = protocol::inner_protocol::undetermined;

        while (probe_buffer.size() < min_detect_size)
        {
            std::array<std::byte, 64> temp_buffer{};
            boost::system::error_code read_ec;
            auto token = net::redirect_error(net::use_awaitable, read_ec);

            net::steady_timer timeout_timer(ssl_stream->get_executor());
            timeout_timer.expires_after(probe_timeout);
            bool timeout_occurred = false;

            auto read_op = ssl_stream->async_read_some(net::buffer(temp_buffer.data(), temp_buffer.size()), token);
            auto timeout_op = timeout_timer.async_wait(net::use_awaitable);

            using namespace boost::asio::experimental::awaitable_operators;
            auto result = co_await (std::move(read_op) || std::move(timeout_op));

            if (result.index() == 1)
            {
                timeout_occurred = true;
            }

            if (timeout_occurred)
            {
                trace::warn("[Pipeline] TLS inner protocol probe timeout after {} bytes", probe_buffer.size());
                inner_type = protocol::inner_protocol::http;
                break;
            }

            if (read_ec)
            {
                trace::warn("[Pipeline] TLS inner protocol probe read failed: {}", read_ec.message());
                co_return;
            }

            const auto bytes_read = std::get<0>(result);
            probe_buffer.insert(probe_buffer.end(), temp_buffer.begin(), temp_buffer.begin() + bytes_read);

            inner_type = protocol::analysis::detect_inner(std::string_view(reinterpret_cast<const char *>(probe_buffer.data()), probe_buffer.size()));

            if (inner_type != protocol::inner_protocol::undetermined)
            {
                break;
            }

            trace::debug("[Pipeline] TLS inner protocol undetermined after {} bytes, continuing probe", probe_buffer.size());
        }

        trace::debug("[Pipeline] TLS inner protocol detected: {}", protocol::to_string_view(inner_type));

        const auto preread = std::span<const std::byte>(probe_buffer.data(), probe_buffer.size());

        switch (inner_type)
        {
        case protocol::inner_protocol::trojan:
            co_await trojan(ctx, std::move(ssl_stream), preread);
            break;
        case protocol::inner_protocol::http:
        case protocol::inner_protocol::undetermined:
        default:
            co_await https(ctx, std::move(ssl_stream), preread);
            break;
        }
    }

    auto https(session_context &ctx, primitives::shared_ssl_stream ssl_stream, std::span<const std::byte> preread)
        -> net::awaitable<void>
    {
        if (!ssl_stream)
        {
            trace::error("[Pipeline] HTTPS ssl_stream is null");
            co_return;
        }

        ngx::channel::transport::transmission_pointer outbound;

        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});

        if (!preread.empty())
        {
            auto dest = read_buffer.prepare(preread.size());
            std::memcpy(dest.data(), preread.data(), preread.size());
            read_buffer.commit(preread.size());
        }

        protocol::http::request req(mr);
        const auto read_ec = co_await protocol::http::async_read(*ssl_stream, req, read_buffer, mr);
        if (gist::failed(read_ec))
        {
            trace::warn("[Pipeline] HTTPS read failed: {}", gist::describe(read_ec));
            co_return;
        }

        const auto target = protocol::analysis::resolve(req);
        trace::info("[Pipeline] HTTPS analysis target = [host: {}, port: {}, positive: {}]",target.host, target.port, target.positive);

        std::shared_ptr<distribution::router> router_ptr(&ctx.worker.router, [](distribution::router *) {});
        auto [dial_ec, outbound_ptr] = co_await primitives::dial(router_ptr, "HTTPS", target, true, false);
        if (gist::failed(dial_ec) || !outbound_ptr)
            co_return;
        outbound = std::move(outbound_ptr);

        if (req.method() == protocol::http::verb::connect)
        {
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            boost::system::error_code write_ec;
            auto token = net::redirect_error(net::use_awaitable, write_ec);
            co_await net::async_write(*ssl_stream, net::buffer(resp),token);
            if (!write_ec)
            {
                co_await primitives::original_tunnel(ssl_stream, std::move(outbound), ctx);
            }
            co_return;
        }

        std::error_code ec;
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write( std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write(span, ec);
            if (ec)
                co_return;
        }

        co_await primitives::original_tunnel(ssl_stream, std::move(outbound), ctx);
    }

    auto trojan(session_context &ctx, primitives::shared_ssl_stream ssl_stream, std::span<const std::byte> preread)
        -> net::awaitable<void>
    {
        if (!ssl_stream)
        {
            trace::error("[Pipeline] Trojan ssl_stream is null");
            co_return;
        }
        // 包装一层抹平的函数差异
        auto tls_trans = std::make_unique<ngx::channel::transport::secure>(ssl_stream);
        // 获取凭证验证器，将 lease 存入 session_context 以保持整个连接生命周期
        auto verifier = [&ctx](const std::string_view credential) -> bool
        {
            if (!ctx.account_directory_ptr)
            {
                trace::warn("[Pipeline] Trojan account directory not configured");
                return false;
            }
            auto lease = account::try_acquire(*ctx.account_directory_ptr, credential);
            if (!lease)
            {
                trace::warn("[Pipeline] Trojan credential verification failed or connection limit reached");
                return false;
            }
            // 将 lease 移动到 session_context 中持有，连接结束时自动释放
            ctx.account_lease = std::move(lease);
            trace::debug("[Pipeline] Trojan credential verified, lease acquired and stored in session context");
            return true;
        };
        ngx::channel::transport::transmission_pointer trans = std::move(tls_trans);
        if (!preread.empty())
        {
            trans = std::make_unique<primitives::preview>(std::move(trans), preread);
        }

        const auto trojan_relay = protocol::trojan::make_relay(
            std::move(trans), ctx.server.cfg.trojan, std::move(verifier));

        auto [handshake_ec, req] = co_await trojan_relay->handshake();
        if (gist::failed(handshake_ec))
        {
            trace::warn("[Pipeline] Trojan handshake failed: {}", gist::describe(handshake_ec));
            co_return;
        }

        // trace::debug("[Pipeline] Trojan handshake success, command: {}", static_cast<int>(req.cmd));

        switch (req.cmd)
        {
        case protocol::trojan::command::connect:
        {   // 解析请求拿到目标地址和端口
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::trojan::to_string(req.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(req.port);
            target.positive = true;
            trace::info("[Pipeline] Trojan CONNECT target = [host: {}, port: {}]", target.host, target.port);

            const std::shared_ptr<distribution::router> router_ptr(&ctx.worker.router, [](distribution::router *) {});
            auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "Trojan", target, true, true);
            if (gist::failed(dial_ec) || !outbound) // 获取出站流失败
            {   
                co_return;
            }

            auto raw_trans = trojan_relay->release();
            co_await primitives::original_tunnel(std::move(raw_trans), std::move(outbound), ctx);
            break; // 忙转发
        }
        case protocol::trojan::command::udp_associate:
        {
            trace::info("[Pipeline] Trojan UDP_ASSOCIATE not yet implemented");
            break;
        }
        default:
            trace::warn("[Pipeline] Trojan unknown command: {}", static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace ngx::agent::pipeline
