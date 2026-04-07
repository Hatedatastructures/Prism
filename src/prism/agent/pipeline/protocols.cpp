#include <prism/agent/pipeline/protocols.hpp>
#include <protocol.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <prism/multiplex/bootstrap.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/memory/container.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <string_view>

constexpr std::string_view HttpStr = "[Pipeline.Http]";
constexpr std::string_view Socks5Str = "[Pipeline.Socks5]";
constexpr std::string_view TrojanStr = "[Pipeline.Trojan]";



namespace psm::agent::pipeline
{
    auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 创建 HTTP 流连接器
        channel::connector stream(std::move(ctx.inbound));
        channel::transport::shared_transmission outbound;

        // 重置帧内存池，准备处理请求
        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});

        // 如果有预读数据，填入缓冲区
        if (!data.empty())
        {
            auto dest = read_buffer.prepare(data.size());
            std::memcpy(dest.data(), data.data(), data.size());
            read_buffer.commit(data.size());
        }

        protocol::http::request req(mr);
        {
            // 读取并解析 HTTP 请求
            if (fault::failed(co_await protocol::http::async_read(stream, req, read_buffer, mr)))
            {
                trace::warn("{} read request failed", HttpStr);
                co_return;
            }

            // 解析目标地址
            const auto target = protocol::analysis::resolve(req);
            trace::info("{} {} {} -> {}:{}", HttpStr, req.method_string(), req.target(), target.host, target.port);

            // 连接目标服务器
            std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
            auto [fst, snd] = co_await primitives::dial(router_ptr, "HTTP", target, true, false);
            if (fault::failed(fst) || !snd)
            {
                trace::warn("{} dial failed, target: {}:{}", HttpStr, target.host, target.port);
                // 返回 502 Bad Gateway
                constexpr std::string_view resp_502 = {"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"};

                boost::system::error_code write_ec;
                auto token = net::redirect_error(net::use_awaitable, write_ec);
                co_await net::async_write(stream, net::buffer(resp_502), token);
                co_return;
            }
            outbound = std::move(snd);
        }

        // HTTP CONNECT 方法：先回复 200，再进入隧道模式
        if (req.method() == protocol::http::verb::connect)
        {
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            boost::system::error_code write_ec;
            co_await net::async_write(stream, net::buffer(resp), net::redirect_error(net::use_awaitable, write_ec));
            if (!write_ec)
            {
                co_await primitives::tunnel(stream.release(), std::move(outbound), ctx);
            }
            co_return;
        }

        // 普通 HTTP 请求：转发请求到目标服务器
        std::error_code ec;
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write(std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        // 转发预读的请求体数据
        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write(span, ec);
            if (ec)
                co_return;
        }

        // 进入双向隧道转发
        co_await primitives::tunnel(stream.release(), std::move(outbound), ctx);
    }

    auto socks5(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 取出入站传输对象
        auto inbound = std::move(ctx.inbound);
        // 检查入站传输对象是否存在，SOCKS5 协议需要它来完成握手和数据转发
        if (!inbound)
        {
            trace::warn("{} inbound missing", Socks5Str);
            co_return;
        }

        // 如果有预读数据，包装一层 preview 传输对象来提供预读功能
        if (!data.empty())
        {
            inbound = std::make_shared<primitives::preview>(std::move(inbound), data, ctx.frame_arena.get());
        }

        // 创建 SOCKS5 中继代理并执行握手
        const auto agent = protocol::socks5::make_relay(
            std::move(inbound), ctx.server.cfg.socks5, ctx.account_directory_ptr);
        auto [ec, request] = co_await agent->handshake();
        // 协商失败，退出处理流程，agent 对象通过 RAII 自动清理
        if (fault::failed(ec))
        {
            trace::error("{} handshake failed: {}", Socks5Str, fault::cached_message(ec));
            co_return;
        }

        // 根据命令类型分发处理
        switch (request.cmd)
        {
        case protocol::socks5::command::connect:
        {
            // TCP 连接请求：解析目标地址并建立连接
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(request.destination_port);
            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", Socks5Str, target.host, target.port);

            // 通过路由器建立到目标的连接
            const auto router_ptr = std::shared_ptr<resolve::router>(&ctx.worker.router, [](resolve::router *) {});
            auto [conn_ec, outbound] = co_await primitives::dial(router_ptr, "SOCKS5", target, true, true);
            if (fault::failed(conn_ec) || !outbound)
            {
                trace::warn("{} failed: {}, target: {}:{}", Socks5Str, fault::describe(conn_ec), target.host, target.port);
                // 连接失败，返回主机不可达错误
                co_await agent->async_write_error(protocol::socks5::reply_code::host_unreachable);
                co_return;
            }

            // 连接成功，发送成功响应给客户端
            if (fault::failed(co_await agent->async_write_success(request)))
            {
                co_return;
            }
            // 释放传输对象并进入双向隧道转发
            auto trans = agent->release();
            trace::debug("{} tunnel opened: {}:{}", Socks5Str, target.host, target.port);
            co_await primitives::tunnel(std::move(trans), std::move(outbound), ctx);
            trace::debug("{} tunnel closed: {}:{}", Socks5Str, target.host, target.port);
            break;
        }
        case protocol::socks5::command::udp_associate:
        {
            // UDP 关联请求：解析目标地址并进入 UDP 转发模式
            const auto target_host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            const auto target_port = std::to_string(request.destination_port);
            trace::info("{} UDP_ASSOCIATE -> {}:{}", Socks5Str, target_host, target_port);

            // 创建路由回调函数，用于解析 UDP 数据报目标地址
            const auto router_ptr = std::shared_ptr<resolve::router>(&ctx.worker.router, [](resolve::router *) {});
            auto route_callback = [router_ptr](const std::string_view host, const std::string_view port)
                -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
            {
                co_return co_await router_ptr->resolve_datagram_target(host, port);
            };
            // 启动 UDP 关联处理
            const auto associate_ec = co_await agent->async_associate(request, std::move(route_callback));
            if (fault::failed(associate_ec))
            {
                trace::warn("{} UDP_ASSOCIATE failed: {}", Socks5Str, fault::describe(associate_ec));
            }
            break;
        }
        default:
            // BIND 命令不支持，返回错误响应
            trace::warn("{} BIND not supported", Socks5Str);
            co_await agent->async_write_error(protocol::socks5::reply_code::command_not_supported);
            break;
        }
    }

    auto trojan(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 执行 TLS 握手，获取加密流
        auto [handshake_ec, ssl_stream] = co_await primitives::ssl_handshake(ctx, data);
        if (fault::failed(handshake_ec) || !ssl_stream)
        {
            trace::warn("{} TLS handshake failed: {}", TrojanStr, fault::describe(handshake_ec));
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

        // 读取 Trojan 握手数据，至少需要 56 字节凭据 + 4 字节协议头部
        constexpr std::size_t min_detect_size = 60;
        memory::vector<std::byte> preread_buffer(ctx.frame_arena.get());
        preread_buffer.reserve(min_detect_size);

        // 循环读取直到获得完整的握手数据
        while (preread_buffer.size() < min_detect_size)
        {
            std::array<std::byte, 64> temp_buffer{};
            boost::system::error_code read_ec;
            auto token = net::redirect_error(net::use_awaitable, read_ec);
            const auto n = co_await ssl_stream->async_read_some(net::buffer(temp_buffer.data(), temp_buffer.size()), token);
            if (read_ec || n == 0)
            {
                trace::warn("{} preread failed: {}", TrojanStr, read_ec.message());
                co_return;
            }
            preread_buffer.insert(preread_buffer.end(), temp_buffer.begin(), temp_buffer.begin() + n);
        }

        // 将 TLS 流包装为加密传输对象
        channel::transport::shared_transmission trans = std::make_shared<channel::transport::encrypted>(ssl_stream);
        if (!preread_buffer.empty())
        {
            const auto preread_span = std::span<const std::byte>(preread_buffer.data(), preread_buffer.size());
            // 使用全局内存池(nullptr)替代 ctx.frame_arena.get()
            // 在 mux 模式下 trans 会被移交给 smux_craft 并脱离当前 session 的生命周期
            // 使用 session 局部池会导致 smux_craft 析构时触发 UAF
            trans = std::make_shared<primitives::preview>(std::move(trans), preread_span, nullptr);
        }

        // 创建凭证验证器，检查账户目录和连接限制
        auto verifier = [&ctx](const std::string_view credential) -> bool
        {
            if (!ctx.account_directory_ptr)
            {
                trace::warn("{} account directory not configured", TrojanStr);
                return false;
            }
            // 尝试获取账户租约，验证凭证并检查连接限制
            auto lease = account::try_acquire(*ctx.account_directory_ptr, credential);
            if (!lease)
            {
                trace::warn("{} credential verification failed", TrojanStr);
                return false;
            }
            ctx.account_lease = std::move(lease);
            return true;
        };

        // 创建 Trojan 中继代理并执行握手
        const auto agent = protocol::trojan::make_relay(std::move(trans), ctx.server.cfg.trojan, std::move(verifier));

        auto [trojan_ec, req] = co_await agent->handshake();
        if (fault::failed(trojan_ec))
        {
            trace::warn("{} handshake failed: {}", TrojanStr, fault::describe(trojan_ec));
            co_return;
        }

        // 根据命令类型处理请求
        switch (req.cmd)
        {
        case protocol::trojan::command::connect:
        {
            // 解析目标地址
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::trojan::to_string(req.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(req.port);

            // Mihomo smux 兼容：客户端用 CONNECT + 虚假地址标记 mux 连接
            // 检测 mux 标记地址，命中则走 smux 多路复用逻辑
            if (ctx.server.cfg.mux.enabled && target.host.size() >= 18 && target.host.substr(target.host.size() - 18) == ".mux.sing-box.arpa")
            {
                trace::info("{} mux session started", TrojanStr);
                // 清除 session 流关闭回调，transport 生命周期由 multiplexer 接管
                ctx.active_stream_close = nullptr;
                ctx.active_stream_cancel = nullptr;
                // 创建多路复用会话（内部执行 sing-mux 协商，根据客户端选择协议）
                auto muxprotocol = co_await multiplex::bootstrap(agent->release(), ctx.worker.router, ctx.server.cfg.mux);
                if (muxprotocol)
                {
                    muxprotocol->start();
                }
                co_return;
            }

            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", TrojanStr, target.host, target.port);

            // 通过路由器建立到目标的连接
            const std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
            auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "Trojan", target, true, true);
            if (fault::failed(dial_ec) || !outbound)
            {
                // IPv6 被禁用是预期行为，使用 debug 级别
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug("{} IPv6 disabled: {}:{}", TrojanStr, target.host, target.port);
                }
                else
                {
                    trace::warn("{} dial failed: {}, target: {}:{}", TrojanStr, fault::describe(dial_ec), target.host, target.port);
                }
                co_return;
            }

            // 释放传输对象并进入双向隧道转发
            auto raw_trans = agent->release();
            co_await primitives::tunnel(std::move(raw_trans), std::move(outbound), ctx);
            break;
        }
        case protocol::trojan::command::udp_associate:
        {
            trace::info("{} UDP_ASSOCIATE started", TrojanStr);

            // 创建路由回调函数，用于解析 UDP 数据报目标地址
            const auto router_ptr = std::shared_ptr<resolve::router>(&ctx.worker.router, [](resolve::router *) {});
            auto route_callback = [router_ptr](const std::string_view host, const std::string_view port)
                -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
            {
                co_return co_await router_ptr->resolve_datagram_target(host, port);
            };

            // 启动 UDP 关联处理
            const auto associate_ec = co_await agent->async_associate(std::move(route_callback));
            if (fault::failed(associate_ec))
            {
                trace::warn("{} UDP_ASSOCIATE failed: {}", TrojanStr, fault::describe(associate_ec));
            }
            else
            {
                trace::info("{} UDP_ASSOCIATE completed", TrojanStr);
            }
            break;
        }
        default:
            // 未知命令类型
            trace::warn("{} unknown command: {}", TrojanStr, static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace psm::agent::pipeline
