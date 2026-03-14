#include <forward-engine/agent/pipeline/protocols.hpp>

namespace ngx::agent::pipeline
{
    auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        transport::connector stream(std::move(ctx.inbound));
        transport::transmission_pointer outbound;

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
            boost::system::error_code ec;
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            co_await stream.async_write_some(net::buffer(resp), net::redirect_error(net::use_awaitable, ec));
            if (!ec)
            {
                co_await primitives::original_tunnel(stream.release(), std::move(outbound), mr, ctx.buffer_size);
            }
            co_return;
        }

        std::error_code ec;
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write_some(std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write_some(span, ec);
            if (ec)
                co_return;
        }

        co_await primitives::original_tunnel(stream.release(), std::move(outbound), mr, ctx.buffer_size);
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
        const auto agent = protocol::socks5::make_stream(std::move(inbound));
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
            co_await primitives::original_tunnel(std::move(trans_ptr), std::move(outbound), ctx.frame_arena.get(), ctx.buffer_size);
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

    auto tls(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        using connector = transport::connector<transport::transmission_pointer>;
        connector stream(std::move(ctx.inbound), data);

        if (!data.empty())
        {
            trace::warn("[Pipeline] TLS pipeline received preread data (len={}), handshake may fail.", data.size());
        }

        auto ssl_stream = std::make_shared<ssl::stream<connector>>(std::move(stream), *ctx.server.ssl_ctx);

        boost::system::error_code ec;
        co_await ssl_stream->async_handshake(ssl::stream_base::server, net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            trace::warn("[Pipeline] TLS handshake failed: {}", ec.message());
            co_return;
        }

        transport::transmission_pointer outbound;
        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});
        protocol::http::request req(mr);

        const auto read_ec = co_await protocol::http::async_read(*ssl_stream, req, read_buffer, mr);
        if (gist::failed(read_ec))
        {
            trace::warn("[Pipeline] TLS/HTTP read failed: {}", gist::describe(read_ec));
            co_return;
        }

        const auto target = protocol::analysis::resolve(req);
        trace::info("[Pipeline] Tls analysis target = [host: {}, port: {}, positive: {}]", target.host, target.port, target.positive);
        std::shared_ptr<distribution::router> router_ptr(&ctx.worker.router, [](distribution::router *) {});
        auto res = co_await primitives::dial(router_ptr, "HTTPS", target, true, false);
        if (gist::failed(res.first) || !res.second)
            co_return;
        outbound = std::move(res.second);

        if (req.method() == protocol::http::verb::connect)
        {
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await net::async_write(*ssl_stream, net::buffer(resp), token);
            if (!ec)
            {
                co_await primitives::original_tunnel(ssl_stream, std::move(outbound), mr, ctx.buffer_size);
            }
            co_return;
        }

        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write_some(std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write_some(span, ec);
            if (ec)
                co_return;
        }

        co_await primitives::original_tunnel(ssl_stream, std::move(outbound), mr, ctx.buffer_size);
    }
} // namespace ngx::agent::pipeline
