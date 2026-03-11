/**
 * @file pipeline.hpp
 * @brief 协议检测和转发逻辑
 * @details 包含具体的协议处理器实现、转发辅助函数和协议处理管道。
 * 该文件实现了基于 `transmission` 抽象层的协议处理逻辑，支持 HTTP、SOCKS5、TLS 等协议。
 *
 * 架构说明：
 * - 协议处理器：具体的协议处理器类继承自 `ngx::agent::handler`，实现 `process` 方法；
 * - 转发辅助：`ngx::agent::pipeline` 命名空间提供协议无关的转发逻辑；
 * - 协议处理：`ngx::agent::pipeline` 命名空间实现具体协议的处理逻辑；
 * - 处理器注册：`register_handlers` 函数用于注册所有协议处理器到全局工厂。
 *
 * 协议支持：
 * 1. HTTP/HTTPS：支持 HTTP/1.1，包括 GET、POST、CONNECT 等方法；
 * 2. SOCKS5：支持 SOCKS5 协议标准定义的认证和连接命令；
 * 3. TLS/Trojan：支持 TLS 握手和 Trojan/Obscura 加密代理协议。
 *
 * 设计特性：
 * - 零拷贝转发：使用共享缓冲区避免数据拷贝，提高性能；
 * - 协程并发：双向转发使用 `||` 操作符并发执行，充分利用网络带宽；
 * - 内存池化：缓冲区从线程局部内存池分配，提高缓存局部性；
 * - 异常安全：通过 `net::co_spawn` 的完成回调处理异常，避免协程泄漏。
 *
 * @note 协议检测在 `ngx::agent::session` 中完成，本文件专注于协议处理逻辑。
 * @warning 预读数据注入可能导致协议解析失败，请确保在正确的时机注入数据。
 */

#pragma once
#include <cstddef>
#include <cctype>
#include <cstring>
#include <algorithm>

#include <memory>
#include <string>
#include <utility>
#include <string_view>
#include <span>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/beast.hpp>

#include <forward-engine/memory/pool.hpp>
#include <forward-engine/agent/conduit.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/protocol/socks5.hpp>
#include <forward-engine/transport/source.hpp>
#include <forward-engine/transport/adaptation.hpp>
#include <forward-engine/protocol/http/deserialization.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/trace/spdlog.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/gist/code.hpp>

/**
 * @namespace ngx::agent::pipeline
 * @brief 协议处理管道
 * @warning - 该命名空间的内容主要用于协议处理逻辑，请勿在协议检测阶段调用。
 * @warning - 预读数据注入必须在协议握手之前完成，否则可能导致协议解析失败。
 * @throws 协议处理函数可能抛出 `std::bad_alloc`（内存不足）或 `std::runtime_error`（协议错误）
 * @details 定义了协议处理的核心逻辑，包括转发辅助函数和具体协议处理函数。
 * 该命名空间实现了基于 `transmission` 抽象层的协议处理管道，包含：
 * @details - 资源管理函数：`shut_close()` 用于安全关闭传输层资源；
 * @details - 连接建立函数：`dial()` 用于根据路由策略连接上游服务器；
 * @details - 原始转发函数：`original_tunnel()` 用于建立双向数据隧道；
 * @details - 协议处理函数：`http()`、`socks5()`、`tls()` 用于处理具体协议。
 *
 *
 * 处理流程：
 *
 * ```
 * 协议检测完成
 * ↓
 * 创建协议处理器
 * ↓
 * 解析协议请求
 * ↓
 * 连接上游服务器
 * ↓
 * 建立双向隧道
 * ↓
 * 转发数据直到任意方向关闭
 * ↓
 * 清理资源
 * ```
 */
namespace ngx::agent::pipeline
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    namespace beast = boost::beast;

    /**
     * @brief 关闭传输层资源
     * @details 安全关闭传输层资源，避免资源泄漏。如果指针非空，调用其 `close()` 方法。
     * 该函数是资源管理的基础工具，确保所有传输层对象在使用后被正确关闭。
     *
     * 关闭流程：
     * @details - 指针检查：检查传输层指针是否为空；
     * @details - 调用关闭：如果指针非空，调用 `close()` 方法；
     * @details - 资源释放：关闭后传输层资源被释放，但指针本身未被释放。
     *
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
     * 该函数是智能指针版本的重载，自动管理传输层对象的生命周期。
     *
     * 关闭流程：
     * @details - 指针检查：检查智能指针是否持有传输层对象；
     * @details - 调用关闭：如果指针非空，调用 `close()` 方法；
     * @details - 重置指针：关闭后重置智能指针，释放传输层对象的所有权。
     *
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
     * @brief 预读传输包装器
     * @details 将协议检测阶段读取到的 `pre_read_data` 重新注入读取链路。
     * 读取时优先返回预读缓存，缓存耗尽后再委托到底层 transmission。
     * 这样 SOCKS5 握手看到的字节序列与“未被预读消费”时保持一致，避免读偏移。
     */
    class preview final : public transport::transmission
    {
    public:
        /**
         * @brief 构造预读回灌包装器
         * @param inner 底层真实传输层，所有权转移
         * @param pre_read 协议检测阶段预读到的字节切片
         * @note `pre_read` 生命周期由外层 session 协程保证，本类仅顺序消费
         */
        explicit preview(transport::transmission_pointer inner, std::span<const std::byte> pre_read)
            : inner_(std::move(inner)), pre_read_(pre_read)
        {
        }

        /**
         * @brief 继承底层可靠性属性（TCP/UDP）
         */
        [[nodiscard]] bool is_reliable() const noexcept override
        {
            return inner_ && inner_->is_reliable();
        }

        /**
         * @brief 透传底层执行器，保持原有 strand/executor 上下文
         */
        [[nodiscard]] executor_type executor() const override
        {
            return inner_->executor();
        }

        /**
         * @brief 异步读取（核心）
         * @details
         * 1) 若预读缓存还有剩余，先拷贝到调用方 buffer 并立即返回；
         * 2) 若预读已耗尽，转发到底层 `inner_->async_read_some`。
         * @note 该函数保证“先回灌再透传”的读取顺序。
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (pre_read_offset_ < pre_read_.size())
            {
                const auto remaining = pre_read_.size() - pre_read_offset_;
                const auto to_copy = (std::min)(remaining, buffer.size());
                if (to_copy > 0)
                {
                    std::memcpy(buffer.data(), pre_read_.data() + pre_read_offset_, to_copy);
                    pre_read_offset_ += to_copy;
                }
                ec.clear();
                co_return to_copy;
            }

            co_return co_await inner_->async_read_some(buffer, ec);
        }

        /**
         * @brief 写入透传到底层传输层
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭底层连接
         */
        void close() override
        {
            if (inner_)
            {
                inner_->close();
            }
        }

        /**
         * @brief 取消底层未完成异步操作
         */
        void cancel() override
        {
            if (inner_)
            {
                inner_->cancel();
            }
        }

    private:
        transport::transmission_pointer inner_; ///< 底层真实传输层
        std::span<const std::byte> pre_read_;   ///< 预读数据视图
        std::size_t pre_read_offset_{0};        ///< 已消费预读偏移
    };

    /**
     * @brief 拨号连接上游服务器，从连接池内获取或新建连接
     * @details 根据目标地址和路由策略（正向/反向）连接上游服务器。该函数是协议处理的核心组件，
     * 负责创建到目标服务的连接，支持正向代理和反向代理两种路由模式。
     *
     * 路由逻辑：
     * @details - 反向代理：如果 `allow_reverse` 为真且目标不是正向代理，调用 `distributor::route_reverse`；
     * @details - 正向代理：否则调用 `distributor::route_forward`；
     * @details - 连接验证：如果 `require_open` 为真，验证连接是否成功打开；
     * @details - 传输层包装：将原始 socket 包装为可靠的传输层对象。
     *
     * 路由决策：
     * @details - 目标分析：根据目标主机和端口判断路由模式；
     * @details - 连接池复用：优先从连接池获取现有连接，避免频繁创建新连接；
     * @details - 超时控制：连接操作有超时限制，避免无限等待；
     * @details - 错误处理：连接失败返回错误码，便于上层处理。
     *
     * @param distributor 分发器，提供路由决策和连接池管理
     * @param label 协议标签（用于日志），如 "HTTP"、"SOCKS5"、"HTTPS"
     * @param target 目标地址信息，包含主机名、端口和路由模式
     * @param allow_reverse 是否允许反向代理路由
     * @param require_open 是否要求连接必须成功打开
     * @return `std::pair<gist::code, transport::transmission_pointer>`
     *         异步返回错误码和传输层对象指针，如果失败错误码非零且指针为空
     * @note 该函数会重用连接池中的连接，避免频繁创建新连接。
     * @warning 如果 `require_open` 为真但连接无效，返回 `connection_refused` 错误。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果路由或连接失败
     */
    inline auto dial(std::shared_ptr<conduit> distributor, std::string_view label,
                     const protocol::analysis::target &target, const bool allow_reverse, const bool require_open)
        -> net::awaitable<std::pair<gist::code, transport::transmission_pointer>>
    {
        auto ec = gist::code::success;
        transport::unique_sock socket;

        if (allow_reverse && !target.positive)
        {
            auto [fst, snd] = co_await distributor->route_reverse(target.host);
            ec = fst;
            socket = std::move(snd);
        }
        else
        {
            auto [fst, snd] = co_await distributor->route_forward(target.host, target.port);
            ec = fst;
            socket = std::move(snd);
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

        trace::debug("[Pipeline] {} upstream connected.", label);
        // 包装为 reliable transmission
        co_return std::make_pair(ec, transport::make_reliable(std::move(*socket)));
    } // function dial

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
     * 转发逻辑：
     * @details - 缓冲区分配：从内存池分配共享缓冲区，左右各 4KB；
     * @details - 双向读取：两个方向同时读取数据，使用 `||` 操作符并发执行；
     * @details - 数据写入：读取到的数据立即写入对方方向，避免延迟；
     * @details - 异常处理：任意方向出错或 EOF，终止整个转发过程。
     *
     * @tparam StreamInbound 入站流类型，通常是 `transport::transmission_pointer` 或 ssl stream
     * @tparam StreamOutbound 出站流类型，通常是 `transport::transmission_pointer`
     * @param inbound 入站连接，通常是客户端连接，所有权将被转移
     * @param outbound 出站连接，通常是服务端连接，所有权将被转移
     * @param mr 内存资源指针，用于缓冲区分配（可选，默认为当前资源）
     * @param buffer_size 缓冲区大小，默认为 256KB
     * @note 该函数会阻塞直到任意一个方向的转发完成（EOF 或错误）。
     * @warning 转发过程中会持有传输层对象的所有权，避免在转发完成前析构这些对象。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果转发过程中发生 IO 错误
     */
    template <typename StreamInbound, typename StreamOutbound>
    auto original_tunnel(StreamInbound inbound, StreamOutbound outbound, const memory::resource_pointer mr = memory::current_resource(),
                         const std::uint32_t buffer_size = 262144U)
        -> net::awaitable<void>
    {
        // 检查有效性
        // 注意：Stream 可能是 transmission_pointer 也可能是引用或对象，根据类型特性判断
        // 这里简化处理，假设如果是指针则判空

        // 缓冲区：使用内存池分配，避免每次堆分配
        memory::vector<std::byte> buffer(buffer_size, mr);
        std::span<std::byte> buf_span(buffer);
        auto left = buf_span.subspan(0, buffer_size / 2);
        auto right = buf_span.subspan(buffer_size / 2);

        // 转发逻辑 Lambda
        // T1, T2 可能是 transmission_pointer (需解引用) 或 stream (直接使用)
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
        // 传入的是移动后的对象，所以我们可以直接使用它们，两个转发任意一个完成就结束

        co_await (forward(inbound, outbound, left) || forward(outbound, inbound, right));

        // 关闭资源
        if constexpr (requires { shut_close(inbound); })
            shut_close(inbound);
        // 对于 ssl stream 等对象，可能需要 shutdown，这里简化处理
        if constexpr (requires { shut_close(outbound); })
            shut_close(outbound);
    } // function original_tunnel

    /**
     * @brief HTTP 协议处理
     * @details 解析 HTTP 请求，连接上游，并建立隧道。支持 CONNECT 方法和普通 HTTP 请求。
     *
     * 处理流程：
     * @details - 请求解析：解析 HTTP 请求头部和正文；
     * @details - 目标解析：从请求中提取目标主机和端口；
     * @details - 连接建立：调用 `dial()` 连接到上游服务器；
     * @details - CONNECT 处理：如果是 CONNECT 方法，发送成功响应后建立原始隧道；
     * @details - 请求转发：否则序列化请求并转发到上游；
     * @details - 隧道建立：建立双向数据隧道。
     *
     * CONNECT 方法处理：
     * @details - 请求识别：检测请求方法是否为 CONNECT；
     * @details - 成功响应：向客户端发送 "200 Connection Established" 响应；
     * @details - 原始隧道：建立客户端到上游的双向数据隧道；
     * @details - 透明转发：不解析后续 HTTP 流量，直接透传。
     *
     * 普通请求处理：
     * @details - 请求序列化：将 HTTP 请求对象序列化为字节数据；
     * @details - 上游转发：将请求数据发送到上游服务器；
     * @details - 预读转发：将预读的缓冲区数据也转发到上游；
     * @details - 响应隧道：建立双向数据隧道转发响应。
     *
     * @param ctx 会话上下文
     * @param data 预读数据，协议检测时读取的初始数据
     * @return `net::awaitable<void>` 异步操作，处理完成后返回
     * @note 支持 HTTP/1.1，自动处理 chunked 编码和连接复用。
     * @warning 如果请求解析失败或连接建立失败，会静默关闭连接而不返回错误。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果协议解析或隧道转发失败
     */
    inline auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        transport::connector stream(std::move(ctx.inbound));
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
            trace::info("[Pipeline] Http analysis target = [host: {}, port: {}, positive: {}]", target.host, target.port, target.positive);
            // 使用 std::shared_ptr 的别名构造函数，创建一个不拥有所有权的 shared_ptr
            std::shared_ptr<conduit> dist_ptr(&ctx.worker.distributor, [](conduit *) {});
            auto [fst, snd] = co_await dial(dist_ptr, "HTTP", target, true, false);
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
                // 释放 connector 所有权，转回 transmission，建立原始隧道
                co_await original_tunnel(stream.release(), std::move(outbound), mr, ctx.buffer_size);
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
            std::span<const std::byte> span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write_some(span, ec);
            if (ec)
                co_return;
        }

        co_await original_tunnel(stream.release(), std::move(outbound), mr, ctx.buffer_size);
    } // function http

    /**
     * @brief SOCKS5 协议处理
     * @details 处理 SOCKS5 握手、请求和转发。支持 SOCKS5 协议标准定义的所有命令和地址类型。
     *
     * 处理流程：
     * @details - 握手协商：协商认证方法和协议版本；
     * @details - 请求解析：解析客户端请求，获取目标地址和端口；
     * @details - 命令分发：根据命令类型分发到 TCP 隧道或 UDP 中继；
     * @details - 响应发送：向客户端发送成功或错误响应；
     * @details - 隧道建立：建立双向数据隧道。
     *
     * 命令处理：
     * @details - CONNECT：建立 TCP 隧道，透明转发数据；
     * @details - UDP_ASSOCIATE：创建 UDP 中继，返回绑定地址；
     * @details - BIND：发送错误响应（不支持）。
     *
     * @param ctx 上下文
     * @param data 预读数据，协议检测时读取的初始数据
     * @note 支持 CONNECT 和 UDP_ASSOCIATE 命令。
     * @warning SOCKS5 协议要求预读数据为空，否则握手可能失败。
     */
    inline auto socks5(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // trace::debug("[Pipeline] SOCKS5 detection");
        auto inbound = std::move(ctx.inbound);
        if (!inbound)
        {
            trace::warn("[Pipeline] SOCKS5 inbound transmission missing.");
            co_return;
        }
        if (!data.empty())
        {
            inbound = std::make_unique<preview>(std::move(inbound), data);
        }
        const auto agent = protocol::socks5::make_stream(std::move(inbound));
        // 握手协商，获取认证方法和协议版本
        auto [ec, request] = co_await agent->handshake();
        if (gist::failed(ec))
        {
            trace::error("[Pipeline] SOCKS5 handshake failed: {}", gist::cached_message(ec));
            co_return;
        }
        // trace::info("[Pipeline] SOCKS5 handshake cmd = {}", static_cast<int>(request.cmd));

        // 根据命令类型分发
        switch (request.cmd)
        {
        case protocol::socks5::command::connect:
        {
            // trace::debug("[Pipeline] SOCKS5 CONNECT");
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(request.destination_port);
            target.positive = true;
            trace::info("[Pipeline] SOCKS5 CONNECT target = [host: {}, port: {}]", target.host, target.port);
            const auto dist_ptr = std::shared_ptr<conduit>(&ctx.worker.distributor, [](conduit *) {});
            auto [conn_ec, outbound] = co_await dial(dist_ptr, "SOCKS5", target, true, true);
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
            co_await original_tunnel(std::move(trans_ptr), std::move(outbound), ctx.frame_arena.get(), ctx.buffer_size);
            break;
        }
        case protocol::socks5::command::udp_associate:
        {
            trace::info("[Pipeline] SOCKS5 UDP_ASSOCIATE");
            const auto dist_ptr = std::shared_ptr<conduit>(&ctx.worker.distributor, [](conduit *) {});
            auto route_callback = [dist_ptr](std::string_view host, std::string_view port)
                -> net::awaitable<std::pair<gist::code, net::ip::udp::endpoint>>
            {
                co_return co_await dist_ptr->resolve_udp_target(host, port);
            };
            static_cast<void>(co_await agent->async_associate(request, std::move(route_callback)));
            break;
        }
        default: // 不支持 bind 命令
            trace::warn("[Pipeline] SOCKS5 BIND command not supported");
            co_await agent->async_write_error(protocol::socks5::reply_code::command_not_supported);
            break;
        }
    }

    /**
     * @brief TLS 协议处理
     * @details 执行 TLS 握手，解密后作为 HTTPS 处理（目前假设内部为 HTTP）。
     *
     * 处理流程：
     * @details - TLS 握手：执行服务器端 TLS 握手，支持 SNI 和 ALPN；
     * @details - HTTP 解析：将解密的流作为 HTTP 请求解析；
     * @details - 目标解析：从 HTTP 请求中提取目标主机和端口；
     * @details - 连接建立：调用 `dial()` 连接到上游服务器；
     * @details - CONNECT 处理：如果是 CONNECT 方法，建立原始隧道；
     * @details - 请求转发：否则序列化请求并转发；
     * @details - 隧道建立：建立双向数据隧道。
     *
     * TLS 握手阶段：
     * @details - SNI 支持：解析客户端的 SNI 扩展，获取目标域名；
     * @details - ALPN 协商：协商应用层协议（通常是 http/1.1）；
     * @details - 证书验证：验证客户端证书（如果启用双向认证）；
     * @details - 会话恢复：支持 TLS 会话复用，减少握手延迟。
     *
     * HTTPS 处理阶段：
     * @details - 解密流量：TLS 握手后，所有流量自动解密；
     * @details - HTTP 解析：将解密后的流量作为 HTTP 请求解析；
     * @details - CONNECT 处理：支持 HTTPS CONNECT，建立原始隧道；
     * @details - 普通请求：支持 HTTPS GET、POST 等普通请求。
     *
     * @param ctx 会话上下文
     * @param data 预读数据，协议检测时读取的初始数据（TLS 协议应为空）
     * @note 假设 TLS 内部是 HTTP/HTTPS 协议，不支持其他应用层协议。
     * @warning TLS 协议要求预读数据为空，否则握手会失败。
     * @throws `std::bad_alloc` 如果内存分配失败
     * @throws `std::runtime_error` 如果 TLS 握手或协议处理失败
     */
    inline auto tls(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        using connector = transport::connector<transport::transmission_pointer>;
        connector stream(std::move(ctx.inbound), data);

        // 构造 SSL 流
        // 注意：data 预读数据如果存在，会导致 SSL 握手失败（因为 SSL 帧头丢失）。
        // 必须确保 data 为空，或者使用 gather_msg 重新组合（复杂）。
        // 通常作为首个 Handler，data 应为空。
        if (!data.empty())
        {
            trace::warn("[Pipeline] TLS handler received preread data (len={}), handshake may fail.", data.size());
        }

        auto ssl_stream = std::make_shared<ssl::stream<connector>>(std::move(stream), *ctx.server.ssl_ctx);

        boost::system::error_code ec;
        co_await ssl_stream->async_handshake(ssl::stream_base::server, net::redirect_error(net::use_awaitable, ec));
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
        trace::info("[Pipeline] Tls analysis target = [host: {}, port: {}, positive: {}]", target.host, target.port, target.positive);
        // 使用 std::shared_ptr 的别名构造函数，创建一个不拥有所有权的 shared_ptr
        std::shared_ptr<conduit> dist_ptr(&ctx.worker.distributor, [](conduit *) {});
        auto res = co_await dial(dist_ptr, "HTTPS", target, true, false);
        if (gist::failed(res.first) || !res.second)
            co_return;
        outbound = std::move(res.second);

        // 如果是 CONNECT，建立隧道
        if (req.method() == protocol::http::verb::connect)
        {
            constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await net::async_write(*ssl_stream, net::buffer(resp), token);
            if (!ec)
            {
                // 隧道转发：ssl stream (解密后) <-> Outbound (Transmission)
                co_await original_tunnel(ssl_stream, std::move(outbound), mr, ctx.buffer_size);
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
            std::span<const std::byte> span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write_some(span, ec);
            if (ec)
                co_return;
        }

        // 隧道转发
        co_await original_tunnel(ssl_stream, std::move(outbound), mr, ctx.buffer_size);
    } // function tls

} // namespace ngx::agent::pipeline
