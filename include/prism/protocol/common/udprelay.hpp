/**
 * @file udprelay.hpp
 * @brief 共享 UDP 中继辅助工具
 * @details 提供协议无关的 UDP 数据报中继基础设施，包括缓冲区管理和
 * 数据报转发函数。被 Trojan 和 VLESS 的 UDP over TLS 实现共用。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 */

#pragma once

#include <prism/fault.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <charconv>
#include <chrono>
#include <functional>
#include <string_view>
#include <tuple>


namespace psm::protocol::common
{
    using namespace psm::trace;

    namespace net = boost::asio;

    /**
     * @brief UDP 流量通知回调类型
     * @details 使用函数指针 + void* 避免热路径堆分配
     */
    using traffic_callback = void(*)(void *ctx, std::uint64_t up, std::uint64_t down) noexcept;

    /**
     * @struct loop_cfg (文档注释引用旧名)
     * @brief UDP 帧循环配置
     * @details 聚合 UDP over TLS 帧循环所需的定时器和参数配置，
     * 将 frame_loop 函数参数收敛到 4 个。
     */
    struct loop_cfg
    {
        net::steady_timer &idle_timer;      // 空闲超时计时器
        std::uint32_t idle_timeout;         // 空闲超时时间（秒）
        std::uint32_t max_datagram;         // 最大数据报长度
        traffic_callback on_traffic{nullptr}; // 流量通知回调
        void *traffic_ctx{nullptr};         // 回调上下文
    };

    /**
     * @struct udp_buffers
     * @brief UDP 会话缓冲区集合
     * @details 封装 UDP 帧循环所需的所有缓冲区，使用 PMR 分配器
     * 避免热路径堆分配。
     */
    struct udp_buffers
    {
        memory::vector<std::byte> recv;     // 接收缓冲区
        memory::vector<std::byte> send;     // 发送缓冲区
        memory::vector<std::byte> response; // 响应缓冲区

        explicit udp_buffers(const std::size_t max_datagram)
            : recv(max_datagram, memory::current_resource()),
              send(memory::current_resource()),
              response(max_datagram, memory::current_resource())
        {
        }
    };

    /**
     * @struct relay_opts
     * @brief relay_packet 参数聚合
     * @details 将 relay_packet 的 4 个参数收敛到单结构体，
     * 符合 Rule 1（函数参数不超过 3 个）。
     */
    struct relay_opts
    {
        net::ip::udp::socket &udp_socket;  ///< UDP socket 引用，延迟打开并复用
        const net::ip::udp::endpoint &target_ep; ///< 目标端点
        std::span<const std::byte> payload;      ///< 载荷数据
        udp_buffers &buf;                        ///< 缓冲区集合
    };

    /**
     * @brief 转发 UDP 数据包到目标并接收响应
     * @param opts 中继选项（udp_socket + target_ep + payload + buf）
     * @return 错误码、响应数据长度、发送者端点
     * @details 通过延迟打开的 UDP socket 转发数据报到目标地址，
     * 然后等待并接收单个响应。Socket 首次调用时按目标协议族打开，
     * 后续调用复用同一 socket，避免每包 open/close 的系统调用开销。
     */
    [[nodiscard]] inline auto relay_packet(relay_opts opts)
        -> net::awaitable<std::tuple<fault::code, std::size_t, net::ip::udp::endpoint>>
    {
        boost::system::error_code udp_ec;

        // 延迟打开 socket：首次调用时按目标协议族打开
        if (!opts.udp_socket.is_open())
        {
            opts.udp_socket.open(opts.target_ep.protocol(), udp_ec);
            if (udp_ec)
            {
                trace::warn<flt::conn | flt::protocol>("Socket open failed: {}", udp_ec.message());
                co_return std::tuple{fault::to_code(udp_ec), std::size_t{0}, net::ip::udp::endpoint{}};
            }
        }

        auto token = net::redirect_error(trace::use_prefix_awaitable, udp_ec);
        co_await opts.udp_socket.async_send_to(net::buffer(opts.payload.data(), opts.payload.size()), opts.target_ep, token);
        if (udp_ec)
        {
            trace::debug<flt::conn | flt::protocol>("Send failed: {}", udp_ec.message());
            co_return std::tuple{fault::to_code(udp_ec), std::size_t{0}, net::ip::udp::endpoint{}};
        }

        net::ip::udp::endpoint sender_ep;
        const auto resp_n = co_await opts.udp_socket.async_receive_from(
            net::buffer(opts.buf.response.data(), opts.buf.response.size()), sender_ep,
            net::redirect_error(trace::use_prefix_awaitable, udp_ec));
        if (udp_ec)
        {
            trace::debug<flt::conn | flt::protocol>("Receive failed: {}", udp_ec.message());
            co_return std::tuple{fault::to_code(udp_ec), std::size_t{0}, net::ip::udp::endpoint{}};
        }

        co_return std::tuple{fault::code::success, resp_n, sender_ep};
    }

    /**
     * @struct resp_ctx
     * @brief send_frame 参数聚合
     * @tparam BuildFn UDP 帧构建函数类型
     * @tparam UdpFrame UDP 帧结构类型
     * @details 将 send_frame 的参数收敛到单结构体，
     * 将函数参数降至 3 个（transport + ctx + buf）。
     */
    template <typename BuildFn, typename UdpFrame>
    struct resp_ctx
    {
        const net::ip::udp::endpoint &sender_ep;       // UDP 响应来源端点
        std::size_t resp_n;                            // 响应数据长度
        std::decay_t<BuildFn> build_fn;                // UDP 帧构建函数
    };

    /**
     * @struct frame_ctx
     * @brief frame_loop 参数聚合
     * @tparam ParseFn UDP 数据包解析函数类型
     * @tparam BuildFn UDP 帧构建函数类型
     * @tparam UdpFrame UDP 帧结构类型
     * @tparam UdpParseResult UDP 解析结果类型
     * @details 将 frame_loop 的回调参数收敛到单结构体，
     * 将函数参数降至 3 个（transport + ctx + config）。
     */
    template <typename ParseFn, typename BuildFn, typename UdpFrame, typename UdpParseResult>
    struct frame_ctx
    {
        std::decay_t<ParseFn> parse_fn;  // UDP 数据包解析函数
        std::decay_t<BuildFn> build_fn;  // UDP 帧构建函数
        std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)> route_cb; // 路由回调
    };

    /**
     * @brief 通过 TLS 传输层发送 UDP 帧响应
     * @tparam BuildFn UDP 帧构建函数类型
     * @tparam UdpFrame UDP 帧结构类型
     * @param transport TLS 传输层引用
     * @param ctx 响应上下文（sender_ep, resp_n, build_fn）
     * @param buf 缓冲区集合
     * @return 是否成功（失败应终止循环）
     * @details 将 UDP 响应封装为协议帧并通过 TLS 传输层发送。
     * 根据 sender_ep 的地址族自动选择 IPv4/IPv6 地址类型
     */
    template <typename BuildFn, typename UdpFrame>
    [[nodiscard]] auto send_frame(
        transport::transmission &transport,
        const resp_ctx<BuildFn, UdpFrame> &ctx,
        udp_buffers &buf)
            -> net::awaitable<bool>
    {
        buf.send.clear();
        UdpFrame frame;
        if (ctx.sender_ep.address().is_v4())
        {
            frame.destination_address = ipv4_address{ctx.sender_ep.address().to_v4().to_bytes()};
        }
        else
        {
            frame.destination_address = ipv6_address{ctx.sender_ep.address().to_v6().to_bytes()};
        }
        frame.destination_port = ctx.sender_ep.port();
        ctx.build_fn(frame, {buf.response.data(), ctx.resp_n}, buf.send);

        std::error_code write_ec;
        co_await transport::async_write(transport, {buf.send.data(), buf.send.size()}, write_ec);
        if (write_ec)
        {
            trace::warn<flt::conn | flt::protocol>("Write response failed: {}", write_ec.message());
            co_return false;
        }
        co_return true;
    }

    /**
     * @brief UDP over TLS 帧循环
     * @tparam ParseFn UDP 数据包解析函数类型
     * @tparam BuildFn UDP 帧构建函数类型
     * @tparam UdpFrame UDP 帧结构类型
     * @tparam UdpParseResult UDP 解析结果类型
     * @param tls_transport TLS 传输层引用
     * @param frame_ctx 帧循环回调上下文（parse_fn, build_fn, route_cb）
     * @param config 帧循环配置（定时器、超时、最大数据报长度）
     * @return net::awaitable<void> 异步操作
     * @details 从 TLS 流读取 UDP 数据包，解析并转发到目标地址，
     * 然后将响应封装回 TLS 流。支持空闲超时和错误处理。
     * 该模板合并了 Trojan 和 VLESS 中完全相同的 UDP 帧循环逻辑
     */
    template <typename ParseFn, typename BuildFn, typename UdpFrame, typename UdpParseResult>
    [[nodiscard]] auto frame_loop(
        transport::transmission &tls_transport,
        frame_ctx<ParseFn, BuildFn, UdpFrame, UdpParseResult> frame_ctx,
        loop_cfg config)
            -> net::awaitable<void>
    {
        using boost::asio::experimental::awaitable_operators::operator||;

        udp_buffers buf(config.max_datagram);
        net::ip::udp::socket udp_socket(tls_transport.executor());
        std::uint64_t uplink_bytes = 0;
        std::uint64_t downlink_bytes = 0;

        while (true)
        {
            config.idle_timer.expires_after(std::chrono::seconds(config.idle_timeout));

            auto do_read = [&]()
                -> net::awaitable<std::size_t>
            {
                std::error_code ec;
                const auto n = co_await tls_transport.async_read_some(
                    {buf.recv.data(), buf.recv.size()}, ec);
                if (ec || n == 0)
                {
                    co_return 0;
                }
                co_return n;
            };

            auto read_result = co_await (do_read() || config.idle_timer.async_wait(trace::use_prefix_awaitable));

            if (read_result.index() == 1)
            {
                trace::debug<flt::conn | flt::protocol>("Idle timeout");
                if (config.on_traffic)
                {
                    config.on_traffic(config.traffic_ctx, uplink_bytes, downlink_bytes);
                }
                co_return;
            }

            const auto n = std::get<0>(read_result);
            config.idle_timer.cancel();

            if (n == 0)
            {
                trace::debug<flt::conn | flt::protocol>("Read error or EOF");
                if (config.on_traffic)
                {
                    config.on_traffic(config.traffic_ctx, uplink_bytes, downlink_bytes);
                }
                co_return;
            }

            auto [parse_ec, parsed] = frame_ctx.parse_fn(std::span<const std::byte>{buf.recv.data(), n});
            if (fault::failed(parse_ec))
            {
                trace::warn<flt::conn | flt::protocol>("Packet parse failed");
                continue;
            }

            const auto target_host = addr_to_str(parsed.destination_address, memory::current_resource());
            char port_buf[8];
            const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), parsed.destination_port);
            const std::string_view target_port(port_buf, std::distance(port_buf, port_end));

            auto [route_ec, target_ep] = co_await frame_ctx.route_cb(target_host, target_port);
            if (fault::failed(route_ec))
            {
                trace::debug<flt::conn | flt::protocol>("Route failed for {}:{}", target_host, target_port);
                continue;
            }

            const auto payload = std::span<const std::byte>(buf.recv.data() + parsed.payload_offset, parsed.payload_size);
            auto [relay_ec, resp_n, sender_ep] = co_await relay_packet({udp_socket, target_ep, payload, buf});
            if (fault::failed(relay_ec))
            {
                continue;
            }

            uplink_bytes += static_cast<std::uint64_t>(payload.size());

            if (!co_await send_frame<BuildFn, UdpFrame>(
                    tls_transport,
                    resp_ctx<BuildFn, UdpFrame>{sender_ep, resp_n, frame_ctx.build_fn},
                    buf))
            {
                if (config.on_traffic)
                {
                    config.on_traffic(config.traffic_ctx, uplink_bytes, downlink_bytes);
                }
                co_return;
            }

            downlink_bytes += buf.send.size();
        }
    }

} // namespace psm::protocol::common
