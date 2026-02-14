/**
 * @file detection.hpp
 * @brief 协议检测和转发逻辑
 * @details 包含具体的协议处理器实现、转发辅助函数和协议处理管道。
 * 该文件实现了基于 `transmission` 抽象层的协议处理逻辑，支持 HTTP、SOCKS5、TLS 等协议。
 *
 * 架构说明：
 * 1. 具体的协议处理器类继承自 `ngx::agent::handler`，实现 `process` 方法
 * 2. 转发辅助函数在 `ngx::agent::pipeline` 命名空间中，提供协议无关的转发逻辑
 * 3. 协议处理函数在 `ngx::agent::pipeline` 命名空间中，实现具体协议的处理逻辑
 * 4. 注册函数 `register_handlers` 用于注册所有协议处理器到全局工厂
 */

#pragma once
#include <cstddef>
#include <cctype>

#include <memory>
#include <string>
#include <utility>
#include <functional>
#include <string_view>
#include <span>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/beast.hpp>

#include <forward-engine/memory/pool.hpp>
#include <forward-engine/agent/validator.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/protocol/socks5.hpp>
#include <forward-engine/transport/source.hpp>
#include <forward-engine/transport/adaptation.hpp>
#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/trace/spdlog.hpp>
#include <forward-engine/agent/handler.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/gist/handling.hpp>

namespace ngx::agent::pipeline
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    namespace beast = boost::beast;

    /**
     * @brief 关闭传输层资源
     * @details 安全关闭传输层资源，避免资源泄漏。如果指针非空，调用其 `close()` 方法。
     * @param trans 传输层对象指针，可为 `nullptr`
     * @note 该方法不释放指针指向的内存，仅调用关闭方法。
     * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
     */
    inline void shut_close(transport::transmission *trans)
    {
        if (trans)
        {
            trans->close();
        }
    }

    /**
     * @brief 关闭传输层资源 (unique_ptr)
     * @details 安全关闭传输层资源并释放所有权。如果智能指针非空，调用其 `close()` 方法后重置指针。
     * @param trans 传输层智能指针，可为空
     * @note 该方法会释放传输层对象的所有权，调用后指针为空。
     * @warning 关闭后传输层对象不再可用，所有对原始对象的引用都会悬垂。
     */
    inline void shut_close(transport::transmission_pointer &trans)
    {
        if (trans)
        {
            trans->close();
            trans.reset();
        }
    }

    /**
     * @brief 拨号上游服务器
     * @details 根据目标地址和路由策略（正向/反向）连接上游服务器。该函数是协议处理的核心组件，
     * 负责创建到目标服务的连接，支持正向代理和反向代理两种路由模式。
     *
     * 路由逻辑：
     * @details - 反向代理：如果 `allow_reverse` 为真且目标不是正向代理，调用 `distributor::route_reverse`；
     * @details - 正向代理：否则调用 `distributor::route_forward`；
     * @details - 连接验证：如果 `require_open` 为真，验证连接是否成功打开；
     * @details - 传输层包装：将原始 socket 包装为可靠的传输层对象。
     *
     * @param distributor 分发器，提供路由决策和连接池管理
     * @param label 协议标签（用于日志），如 "HTTP"、"SOCKS5"、"HTTPS"
     * @param target 目标地址信息，包含主机名、端口和路由模式
     * @param allow_reverse 是否允许反向代理路由
     * @param require_open 是否要求连接必须成功打开
     * @return `net::awaitable<std::pair<gist::code, transport::transmission_pointer>>`
     *         异步返回错误码和传输层对象指针，如果失败错误码非零且指针为空
     * @note 该函数会重用连接池中的连接，避免频繁创建新连接。
     * @warning 如果 `require_open` 为真但连接无效，返回 `connection_refused` 错误。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果路由或连接失败
     */
    inline auto dial(std::shared_ptr<distributor> distributor, std::string_view label,
                     const protocol::analysis::target &target, const bool allow_reverse, const bool require_open)
        -> net::awaitable<std::pair<gist::code, transport::transmission_pointer>>
    {
        gist::code ec = gist::code::success;
        transport::unique_sock socket;

        if (allow_reverse && !target.positive)
        {
            auto result = co_await distributor->route_reverse(target.host);
            ec = result.first;
            socket = std::move(result.second);
        }
        else
        {
            auto result = co_await distributor->route_forward(target.host, target.port);
            ec = result.first;
            socket = std::move(result.second);
        }

        if (gist::failed(ec))
        {
            trace::warn("[Pipeline] {} route failed: {}", label, ngx::gist::describe(ec));
            co_return std::make_pair(ec, nullptr);
        }

        if (require_open && (!socket || !socket->is_open()))
        {
            trace::error("[Pipeline] {} route to upstream failed (connection invalid).", label);
            co_return std::make_pair(gist::code::connection_refused, nullptr);
        }

        trace::info("[Pipeline] {} upstream connected.", label);
        // 包装为 reliable transmission
        co_return std::make_pair(ec, transport::make_reliable(std::move(*socket)));
    }

    /**
     * @brief 原始双向隧道
     * @details 在两个传输层对象之间建立全双工数据转发。这是协议处理的最终阶段，
     * 在客户端和服务端之间建立透明数据通道，支持任意协议数据转发。
     *
     * 转发特性：
     * @details - 全双工并发：两个方向的转发同时进行，互不阻塞；
     * @details - 零拷贝优化：使用共享内存池缓冲区，避免多次分配；
     * @details - 通用流适配：支持 `transmission_pointer` 和 SSL Stream 等多种流类型；
     * @details - 自动关闭：转发完成后自动关闭传输层资源。
     *
     * @tparam StreamInbound 入站流类型，通常是 `transport::transmission_pointer` 或 SSL Stream
     * @tparam StreamOutbound 出站流类型，通常是 `transport::transmission_pointer`
     * @param inbound 入站连接，通常是客户端连接，所有权将被转移
     * @param outbound 出站连接，通常是服务端连接，所有权将被转移
     * @param mr 内存资源指针，用于缓冲区分配（可选，默认为当前资源）
     * @return `net::awaitable<void>` 异步操作，转发完成后返回
     * @note 该函数会阻塞直到任意一个方向的转发完成（EOF 或错误）。
     * @warning 转发过程中会持有传输层对象的所有权，避免在转发完成前析构这些对象。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果转发过程中发生 IO 错误
     */
    template <typename StreamInbound, typename StreamOutbound>
    inline auto original_tunnel(StreamInbound inbound, StreamOutbound outbound,
                                memory::resource_pointer mr = memory::current_resource())
        -> net::awaitable<void>
    {
        // 检查有效性
        // 注意：Stream 可能是 transmission_pointer 也可能是引用或对象，根据类型特性判断
        // 这里简化处理，假设如果是指针则判空

        // 缓冲区：使用内存池分配，避免每次堆分配
        memory::vector<std::byte> buffer(8192, mr);
        std::span<std::byte> buf_span(buffer);
        auto left = buf_span.subspan(0, 4096);
        auto right = buf_span.subspan(4096);

        // 转发逻辑 Lambda
        // T1, T2 可能是 transmission_pointer (需解引用) 或 Stream (直接使用)
        auto forward = [](auto &from, auto &to, std::span<std::byte> buf) -> net::awaitable<void>
        {
            boost::system::error_code ec;
            while (true)
            {
                ec.clear();
                // 统一调用 async_read_some / async_write_some
                // 如果是 transmission_pointer，需要 ->
                // 如果是 Stream (如 ssl::stream)，需要 .
                // 使用通用适配层或 if constexpr
                std::size_t n = 0;
                if constexpr (requires { from->async_read_some(buf, ec); })
                    n = co_await from->async_read_some(buf, ec);
                else
                    n = co_await from->async_read_some(net::buffer(buf), net::redirect_error(net::use_awaitable, ec));

                if (ec || n == 0)
                    co_return;

                ec.clear();
                if constexpr (requires { to->async_write_some(buf.first(n), ec); })
                    co_await to->async_write_some(buf.first(n), ec);
                else
                    co_await to->async_write_some(net::buffer(buf.first(n)), net::redirect_error(net::use_awaitable, ec));

                if (ec)
                    co_return;
            }
        };

        using namespace boost::asio::experimental::awaitable_operators;

        // 启动双向转发
        // 注意：这里需要确保 inbound/outbound 在协程生命周期内有效
        // 传入的是移动后的对象，所以我们可以直接使用它们

        co_await (forward(inbound, outbound, left) || forward(outbound, inbound, right));

        // 关闭资源
        if constexpr (requires { shut_close(inbound); })
            shut_close(inbound);
        // 对于 SSL Stream 等对象，可能需要 shutdown，这里简化处理
        if constexpr (requires { shut_close(outbound); })
            shut_close(outbound);
    }

    /**
     * @brief HTTP 协议处理
     * @details 解析 HTTP 请求，连接上游，并建立隧道。支持 CONNECT 方法和普通 HTTP 请求。
     * 处理流程：
     * @details - 请求解析：解析 HTTP 请求头部和正文；
     * @details - 目标解析：从请求中提取目标主机和端口；
     * @details - 连接建立：调用 `dial()` 连接到上游服务器；
     * @details - CONNECT 处理：如果是 CONNECT 方法，发送成功响应后建立原始隧道；
     * @details - 请求转发：否则序列化请求并转发到上游；
     * @details - 隧道建立：建立双向数据隧道。
     *
     * @param inbound 入站连接，客户端 HTTP 连接，所有权将被转移
     * @param distributor 分发器，用于路由决策和连接建立
     * @param ctx 上下文，包含 SSL、内存池等运行时资源
     * @param data 预读数据，协议检测时读取的初始数据
     * @return `net::awaitable<void>` 异步操作，处理完成后返回
     * @note 支持 HTTP/1.1，自动处理 chunked 编码和连接复用。
     * @warning 如果请求解析失败或连接建立失败，会静默关闭连接而不返回错误。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果协议解析或隧道转发失败
     */
    inline auto http(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
                     const handler_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        transport::connector<transport::transmission_pointer> stream(std::move(inbound));
        transport::transmission_pointer outbound;

        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});

        if (!data.empty())
        { //
            auto dest = read_buffer.prepare(data.size());
            std::memcpy(dest.data(), data.data(), data.size());
            read_buffer.commit(data.size());
        }

        protocol::http::request req(mr);
        {
            // 使用适配后的 stream 读取 HTTP 请求
            const auto ec = co_await protocol::http::async_read(stream, req, read_buffer, mr);
            if (gist::failed(ec))
                co_return;

            const auto target = protocol::analysis::resolve(req);
            ngx::trace::debug("Http analysis target = [host: {}, port: {}, positive: {}]", target.host, target.port, target.positive);
            auto res = co_await dial(distributor, "HTTP", target, true, false);
            if (gist::failed(res.first) || !res.second)
                co_return;
            outbound = std::move(res.second);
        }

        if (req.method() == protocol::http::verb::connect)
        {
            boost::system::error_code ec;
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            co_await stream.async_write_some(net::buffer(resp), net::redirect_error(net::use_awaitable, ec));
            if (!ec)
            {
                // 释放 connector 所有权，转回 transmission，建立原始隧道
                co_await original_tunnel(stream.release(), std::move(outbound), mr);
            }
            co_return;
        }

        // 转发普通 HTTP 请求
        std::error_code ec;
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write_some(std::span<const std::byte>(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span<const std::byte> span(reinterpret_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write_some(span, ec);
            if (ec)
                co_return;
        }

        co_await original_tunnel(stream.release(), std::move(outbound), mr);
    }

    /**
     * @brief SOCKS5 协议处理
     * @details 处理 SOCKS5 握手、请求和转发。支持 SOCKS5 协议标准定义的所有命令和地址类型。
     * 处理流程：
     * @details - 握手协商：协商认证方法和协议版本；
     * @details - 请求解析：解析客户端请求，获取目标地址和端口；
     * @details - 连接建立：调用 `dial()` 连接到目标服务器；
     * @details - 响应发送：向客户端发送成功或错误响应；
     * @details - 隧道建立：建立双向数据隧道。
     *
     * @param inbound 入站连接，客户端 SOCKS5 连接，所有权将被转移
     * @param distributor 分发器，用于路由决策和连接建立
     * @param ctx 上下文，包含 SSL、内存池等运行时资源
     * @param data 预读数据，协议检测时读取的初始数据
     * @return `net::awaitable<void>` 异步操作，处理完成后返回
     * @note 支持 CONNECT、BIND 和 UDP ASSOCIATE 命令（实际只实现了 CONNECT）。
     * @warning SOCKS5 协议要求预读数据为空，否则握手可能失败。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果协议握手或隧道转发失败
     */
    inline auto socks5(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
                       const handler_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        using Connector = transport::connector<transport::transmission_pointer>;
        // 构造 SOCKS5 流，传入适配器
        auto agent = std::make_shared<protocol::socks5::stream<Connector>>(Connector(std::move(inbound), data));

        // 注意：如果 data 不为空，需要注入到 stream 中，目前 socks5::stream 实现可能不支持预读数据注入
        // 假设 socks5 握手前没有预读数据，或者 caller 保证 data 为空

        auto [ec, request] = co_await agent->handshake();
        if (gist::failed(ec))
            co_return;

        protocol::analysis::target target(ctx.frame_arena.get());
        target.host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
        target.port = std::to_string(request.destination_port);
        target.positive = true;

        ngx::trace::debug("Socks5 analysis target = [host: {}, port: {}, positive: {}]", target.host, target.port, target.positive);
        auto [conn_ec, outbound] = co_await dial(distributor, "SOCKS5", target, true, true);
        if (gist::failed(conn_ec) || !outbound)
        {
            static_cast<void>(co_await agent->send_error(protocol::socks5::reply_code::host_unreachable));
            co_return;
        }

        if (gist::failed(co_await agent->send_success(request)))
        {
            co_return;
        }

        // 从 agent 中取回底层 connector，再释放 transmission
        // 需确保 socks5::stream 提供了访问底层 socket 的方法
        auto trans_ptr = agent->socket().release();
        co_await original_tunnel(std::move(trans_ptr), std::move(outbound), ctx.frame_arena.get());
    }

    /**
     * @brief TLS 协议处理
     * @details 执行 TLS 握手，解密后作为 HTTPS 处理（目前假设内部为 HTTP）。
     * 处理流程：
     * @details - TLS 握手：执行服务器端 TLS 握手，支持 SNI 和 ALPN；
     * @details - HTTP 解析：将解密的流作为 HTTP 请求解析；
     * @details - 目标解析：从 HTTP 请求中提取目标主机和端口；
     * @details - 连接建立：调用 `dial()` 连接到上游服务器；
     * @details - CONNECT 处理：如果是 CONNECT 方法，建立原始隧道；
     * @details - 请求转发：否则序列化请求并转发；
     * @details - 隧道建立：建立双向数据隧道。
     *
     * @param inbound 入站连接，客户端 TLS 连接，所有权将被转移
     * @param distributor 分发器，用于路由决策和连接建立
     * @param ssl_ctx SSL 上下文，用于 TLS 握手和加密
     * @param ctx 处理上下文，包含内存池等运行时资源
     * @param data 预读数据，协议检测时读取的初始数据（TLS 协议应为空）
     * @return `net::awaitable<void>` 异步操作，处理完成后返回
     * @note 假设 TLS 内部是 HTTP/HTTPS 协议，不支持其他应用层协议。
     * @warning TLS 协议要求预读数据为空，否则握手会失败。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果 TLS 握手或协议处理失败
     */
    inline auto tls(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
                    std::shared_ptr<ssl::context> ssl_ctx, const handler_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        using Connector = transport::connector<transport::transmission_pointer>;
        Connector stream(std::move(inbound), data);

        // 构造 SSL 流
        // 注意：data 预读数据如果存在，会导致 SSL 握手失败（因为 SSL 帧头丢失）。
        // 必须确保 data 为空，或者使用 gather_msg 重新组合（复杂）。
        // 通常作为首个 Handler，data 应为空。
        if (!data.empty())
        {
            trace::warn("[Pipeline] TLS handler received preread data (len={}), handshake may fail.", data.size());
        }

        auto ssl_stream = std::make_shared<net::ssl::stream<Connector>>(std::move(stream), *ssl_ctx);

        boost::system::error_code ec;
        co_await ssl_stream->async_handshake(net::ssl::stream_base::server, net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            trace::warn("[Pipeline] TLS handshake failed: {}", ec.message());
            co_return;
        }

        // 握手成功后，作为 HTTPS 处理 (HTTP over TLS)
        // 解析 HTTP 请求
        transport::transmission_pointer outbound;
        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});
        protocol::http::request req(mr);

        // 使用 ssl_stream 读取
        // protocol::http::async_read 支持 AsyncReadStream
        const auto read_ec = co_await protocol::http::async_read(*ssl_stream, req, read_buffer, mr);
        if (gist::failed(read_ec))
        {
            trace::warn("[Pipeline] TLS/HTTP read failed: {}", gist::describe(read_ec));
            co_return;
        }

        const auto target = protocol::analysis::resolve(req);
        ngx::trace::debug("Tls analysis target = [host: {}, port: {}, positive: {}]", target.host, target.port, target.positive);
        auto res = co_await dial(distributor, "HTTPS", target, true, false);
        if (gist::failed(res.first) || !res.second)
            co_return;
        outbound = std::move(res.second);

        // 如果是 CONNECT，建立隧道
        if (req.method() == protocol::http::verb::connect)
        {
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            co_await net::async_write(*ssl_stream, net::buffer(resp), net::redirect_error(net::use_awaitable, ec));
            if (!ec)
            {
                // 隧道转发：SSL Stream (解密后) <-> Outbound (Transmission)
                co_await original_tunnel(ssl_stream, std::move(outbound), mr);
            }
            co_return;
        }

        // 普通请求转发
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write_some(std::span<const std::byte>(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span<const std::byte> span(reinterpret_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write_some(span, ec);
            if (ec)
                co_return;
        }

        // 隧道转发
        co_await original_tunnel(ssl_stream, std::move(outbound), mr);
    }

} // namespace ngx::agent::pipeline
