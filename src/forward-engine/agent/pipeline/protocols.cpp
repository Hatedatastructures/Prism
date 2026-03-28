#include <forward-engine/agent/pipeline/protocols.hpp>
#include <protocol.hpp>
#include <forward-engine/channel/transport/encrypted.hpp>
#include <forward-engine/channel/smux/multiplexer.hpp>
#include <forward-engine/agent/account/directory.hpp>
#include <forward-engine/memory/container.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace ngx::agent::pipeline
{
    auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        channel::connector stream(std::move(ctx.inbound));
        channel::transport::shared_transmission outbound;

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
            if (fault::failed(co_await protocol::http::async_read(stream, req, read_buffer, mr)))
            {
                trace::warn("[Pipeline] HTTP read request failed");
                co_return;
            }

            const auto target = protocol::analysis::resolve(req);
            trace::info("[Pipeline] HTTP request: {} {} -> {}:{}", req.method_string(), req.target(), target.host, target.port);

            std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
            auto [fst, snd] = co_await primitives::dial(router_ptr, "HTTP", target, true, false);
            if (fault::failed(fst) || !snd)
            {
                trace::warn("[Pipeline] HTTP dial failed, target: {}:{}", target.host, target.port);
                // 给客户端返回 502 Bad Gateway
                constexpr std::string_view resp_502 = {"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"};

                boost::system::error_code write_ec;
                auto token = net::redirect_error(net::use_awaitable, write_ec);
                co_await net::async_write(stream, net::buffer(resp_502), token);
                co_return;
            }
            outbound = std::move(snd);
        }

        if (req.method() == protocol::http::verb::connect)
        {   // HTTP CONNECT 方法需要先回复 200 Connection Established 说明连接成功了，然后再进入隧道模式
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            boost::system::error_code write_ec;
            co_await net::async_write(stream, net::buffer(resp), net::redirect_error(net::use_awaitable, write_ec));
            if (!write_ec)
            {
                co_await primitives::tunnel(stream.release(), std::move(outbound), ctx);
            }
            co_return;
        }

        std::error_code ec;
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write(std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        if (read_buffer.size() > 0)
        {   // 将预读的 HTTP 请求数据转发到目标服务器来获取响应确定建立的是一个正常的http连接
            auto buf = read_buffer.data();
            std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write(span, ec);
            if (ec)
                co_return;
        }
        // HTTP 协议后续的请求和响应数据直接在隧道中转发，complete_write 参数设置为 false 可以降低延迟
        co_await primitives::tunnel(stream.release(), std::move(outbound), ctx);
    } // function http

    auto socks5(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        auto inbound = std::move(ctx.inbound);
        if (!inbound)
        {   // 检查入站传输对象是否存在，SOCKS5 协议需要它来完成握手和数据转发
            trace::warn("[Pipeline] SOCKS5 inbound transmission missing.");
            co_return;
        }

        if (!data.empty())
        {   // 如果有预读数据，包装一层 preview 传输对象来提供预读功能，避免修改原有的传输接口导致大规模改动
            inbound = std::make_shared<primitives::preview>(std::move(inbound), data, ctx.frame_arena.get());
        }

        const auto agent = protocol::socks5::make_relay(std::move(inbound), ctx.server.cfg.socks5);
        auto [ec, request] = co_await agent->handshake();
        if (fault::failed(ec))
        {   // 协商失败，退出处理流程，agent raii 队象
            trace::error("[Pipeline] SOCKS5 handshake failed: {}", fault::cached_message(ec));
            co_return;
        }

        switch (request.cmd)
        {
        case protocol::socks5::command::connect:
        {   // tcp 连接请求，解析目标地址并建立连接
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(request.destination_port);
            target.positive = true;
            trace::info("[Pipeline] SOCKS5 CONNECT -> {}:{}", target.host, target.port);

            const auto router_ptr = std::shared_ptr<resolve::router>(&ctx.worker.router, [](resolve::router *) {});
            auto [conn_ec, outbound] = co_await primitives::dial(router_ptr, "SOCKS5", target, true, true);
            if (fault::failed(conn_ec) || !outbound)
            {
                trace::warn("[Pipeline] SOCKS5 dial failed: {}, target: {}:{}", fault::describe(conn_ec), target.host, target.port);
                co_await agent->async_write_error(protocol::socks5::reply_code::host_unreachable);
                co_return;
            }

            if (fault::failed(co_await agent->async_write_success(request)))
            {
                co_return;
            }
            auto trans = agent->release();
            trace::debug("[Pipeline] SOCKS5 CONNECT tunnel opened, target: {}:{}", target.host, target.port);
            co_await primitives::tunnel(std::move(trans), std::move(outbound), ctx);
            trace::debug("[Pipeline] SOCKS5 CONNECT tunnel closed, target: {}:{}", target.host, target.port);
            break;
        }
        case protocol::socks5::command::udp_associate:
        {   // UDP 关联请求，解析目标地址并进入 UDP 转发模式
            const auto target_host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            const auto target_port = std::to_string(request.destination_port);
            trace::info("[Pipeline] SOCKS5 UDP_ASSOCIATE -> {}:{}", target_host, target_port);

            const auto router_ptr = std::shared_ptr<resolve::router>(&ctx.worker.router, [](resolve::router *) {});
            auto route_callback = [router_ptr](const std::string_view host, const std::string_view port)
                -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
            {
                co_return co_await router_ptr->resolve_datagram_target(host, port);
            };
            const auto associate_ec = co_await agent->async_associate(request, std::move(route_callback));
            if (fault::failed(associate_ec))
            {
                trace::warn("[Pipeline] SOCKS5 UDP_ASSOCIATE failed: {}", fault::describe(associate_ec));
            }
            break;
        }
        default:
            trace::warn("[Pipeline] SOCKS5 BIND command not supported");
            co_await agent->async_write_error(protocol::socks5::reply_code::command_not_supported);
            break;
        }
    }

    auto trojan(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 1. TLS 握手
        auto [handshake_ec, ssl_stream] = co_await primitives::ssl_handshake(ctx, data);
        if (fault::failed(handshake_ec) || !ssl_stream)
        {
            trace::warn("[Pipeline] Trojan TLS handshake failed: {}", fault::describe(handshake_ec));
            co_return;
        }

        // 注册活跃流清理回调，确保 session.close() 能关闭 TLS 流
        ctx.active_stream_cancel = [ssl_stream]() noexcept
        {
            ssl_stream->lowest_layer().transmission().cancel();
        };
        ctx.active_stream_close = [ssl_stream]() noexcept
        {
            ssl_stream->lowest_layer().transmission().close();
        };

        // 2. 读取 Trojan 握手数据
        constexpr std::size_t min_detect_size = 60;
        memory::vector<std::byte> preread_buffer(ctx.frame_arena.get());
        preread_buffer.reserve(min_detect_size);

        while (preread_buffer.size() < min_detect_size)
        {   // 等待客户端发送完整的握手数据，至少 56 字节凭据 + 4 字节协议头部
            std::array<std::byte, 64> temp_buffer{};
            boost::system::error_code read_ec;
            auto token = net::redirect_error(net::use_awaitable, read_ec);
            const auto n = co_await ssl_stream->async_read_some(net::buffer(temp_buffer.data(), temp_buffer.size()), token);
            if (read_ec || n == 0)
            {
                trace::warn("[Pipeline] Trojan preread failed: {}", read_ec.message());
                co_return;
            }
            preread_buffer.insert(preread_buffer.end(), temp_buffer.begin(), temp_buffer.begin() + n);
        }

        // 3. 包装 TLS 流
        channel::transport::shared_transmission trans = std::make_shared<channel::transport::encrypted>(ssl_stream);
        if (!preread_buffer.empty())
        {
            const auto preread_span = std::span<const std::byte>(preread_buffer.data(), preread_buffer.size());
            trans = std::make_shared<primitives::preview>(std::move(trans), preread_span, ctx.frame_arena.get());
        }

        // 4. 凭证验证器
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
            ctx.account_lease = std::move(lease);
            return true;
        };

        // 5. Trojan 握手
        const auto agent = protocol::trojan::make_relay(std::move(trans), ctx.server.cfg.trojan, std::move(verifier));

        auto [trojan_ec, req] = co_await agent->handshake();
        if (fault::failed(trojan_ec))
        {
            trace::warn("[Pipeline] Trojan handshake failed: {}", fault::describe(trojan_ec));
            co_return;
        }

        // 6. 命令处理
        switch (req.cmd)
        {
        case protocol::trojan::command::connect:
        {
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::trojan::to_string(req.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(req.port);

            // Mihomo smux 兼容：客户端用 CONNECT + 虚假地址标记 mux 连接
            // 检测 mux 标记地址，命中则走 smux 多路复用逻辑
            if (ctx.server.cfg.mux.enabled &&
                target.host.size() >= 18 &&
                target.host.substr(target.host.size() - 18) == ".mux.sing-box.arpa")
            {
                trace::info("[Pipeline] Trojan CONNECT with mux marker, creating sing-mux session");
                // 清除 session 流关闭回调，transport 生命周期由 multiplexer 接管
                ctx.active_stream_close = nullptr;
                ctx.active_stream_cancel = nullptr;
                auto smux_session = std::make_shared<channel::smux::multiplexer>(
                    agent->release(), ctx.worker.router, ctx.server.cfg.mux, true);
                smux_session->start();
                co_return;
            }

            target.positive = true;
            trace::info("[Pipeline] Trojan CONNECT -> {}:{}", target.host, target.port);

            const std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
            auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "Trojan", target, true, true);
            if (fault::failed(dial_ec) || !outbound)
            {
                // IPv6 被禁用是预期行为，使用 debug 级别
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug("[Pipeline] Trojan IPv6 disabled, target: {}:{}", target.host, target.port);
                }
                else
                {
                    trace::warn("[Pipeline] Trojan dial failed: {}, target: {}:{}", fault::describe(dial_ec), target.host, target.port);
                }
                co_return;
            }

            auto raw_trans = agent->release();
            co_await primitives::tunnel(std::move(raw_trans), std::move(outbound), ctx);
            break;
        }
        case protocol::trojan::command::udp_associate:
            // TODO: Trojan UDP_ASSOCIATE 实现
            trace::warn("[Pipeline] Trojan UDP_ASSOCIATE not implemented");
            break;
        case protocol::trojan::command::mux:
        {
            if (!ctx.server.cfg.mux.enabled)
            {
                trace::warn("[Pipeline] Trojan MUX disabled, command ignored");
                co_return;
            }
            trace::info("[Pipeline] Trojan MUX, creating smux session");
            // 清除 session 流关闭回调，transport 生命周期由 multiplexer 接管
            ctx.active_stream_close = nullptr;
            ctx.active_stream_cancel = nullptr;
            auto smux_session = std::make_shared<channel::smux::multiplexer>(
                agent->release(), ctx.worker.router, ctx.server.cfg.mux, false);
            smux_session->start();
            co_return;
        }
        default:
            trace::warn("[Pipeline] Trojan unknown command: {}", static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace ngx::agent::pipeline
