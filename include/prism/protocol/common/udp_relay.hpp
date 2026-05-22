/**
 * @file udp_relay.hpp
 * @brief 共享 UDP 中继辅助工具
 * @details 提供协议无关的 UDP 数据报中继基础设施，包括缓冲区管理和
 * 数据报转发函数。被 Trojan 和 VLESS 的 UDP over TLS 实现共用。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 */

#pragma once

#include <boost/asio.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/memory/container.hpp>
#include <prism/fault.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>
#include <tuple>
#include <functional>
#include <charconv>
#include <string_view>
#include <chrono>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/protocol/common/target.hpp>

namespace psm::protocol::common
{
    namespace net = boost::asio;

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
     * @brief 转发 UDP 数据包到目标并接收响应
     * @param udp_socket UDP socket 引用，延迟打开并复用
     * @param target_ep 目标端点
     * @param payload 载荷数据
     * @param buf 缓冲区集合
     * @return 错误码、响应数据长度、发送者端点
     * @details 通过延迟打开的 UDP socket 转发数据报到目标地址，
     * 然后等待并接收单个响应。Socket 首次调用时按目标协议族打开，
     * 后续调用复用同一 socket，避免每包 open/close 的系统调用开销。
     */
    inline auto relay_udp_packet(net::ip::udp::socket &udp_socket,
                                 const net::ip::udp::endpoint &target_ep,
                                 std::span<const std::byte> payload,
                                 udp_buffers &buf)
        -> net::awaitable<std::tuple<fault::code, std::size_t, net::ip::udp::endpoint>>
    {
        boost::system::error_code udp_ec;

        // 延迟打开 socket：首次调用时按目标协议族打开
        if (!udp_socket.is_open())
        {
            udp_socket.open(target_ep.protocol(), udp_ec);
            if (udp_ec)
            {
                trace::warn("[UDP] Socket open failed: {}", udp_ec.message());
                co_return std::tuple{fault::to_code(udp_ec), std::size_t{0}, net::ip::udp::endpoint{}};
            }
        }

        auto token = net::redirect_error(net::use_awaitable, udp_ec);
        co_await udp_socket.async_send_to(net::buffer(payload.data(), payload.size()), target_ep, token);
        if (udp_ec)
        {
            trace::debug("[UDP] Send failed: {}", udp_ec.message());
            co_return std::tuple{fault::to_code(udp_ec), std::size_t{0}, net::ip::udp::endpoint{}};
        }

        net::ip::udp::endpoint sender_ep;
        const auto resp_n = co_await udp_socket.async_receive_from(
            net::buffer(buf.response.data(), buf.response.size()), sender_ep,
            net::redirect_error(net::use_awaitable, udp_ec));
        if (udp_ec)
        {
            trace::debug("[UDP] Receive failed: {}", udp_ec.message());
            co_return std::tuple{fault::to_code(udp_ec), std::size_t{0}, net::ip::udp::endpoint{}};
        }

        co_return std::tuple{fault::code::success, resp_n, sender_ep};
    }

    /**
     * @brief 通过 TLS 传输层发送 UDP 帧响应
     * @tparam BuildFn UDP 帧构建函数类型
     * @tparam UdpFrame UDP 帧结构类型
     * @param transport TLS 传输层引用
     * @param sender_ep UDP 响应来源端点（作为响应的目标地址）
     * @param resp_n 响应数据长度
     * @param buf 缓冲区集合
     * @param build_fn UDP 帧构建函数
     * @param log_tag 日志标签
     * @return 是否成功（失败应终止循环）
     * @details 将 UDP 响应封装为协议帧并通过 TLS 传输层发送。
     * 根据 sender_ep 的地址族自动选择 IPv4/IPv6 地址类型
     */
    template <typename BuildFn, typename UdpFrame>
    auto send_udp_frame_response(
        transport::transmission &transport,
        const net::ip::udp::endpoint &sender_ep,
        std::size_t resp_n,
        udp_buffers &buf,
        BuildFn &&build_fn,
        std::string_view log_tag) -> net::awaitable<bool>
    {
        buf.send.clear();
        UdpFrame frame;
        if (sender_ep.address().is_v4())
        {
            frame.destination_address = ipv4_address{sender_ep.address().to_v4().to_bytes()};
        }
        else
        {
            frame.destination_address = ipv6_address{sender_ep.address().to_v6().to_bytes()};
        }
        frame.destination_port = sender_ep.port();
        build_fn(frame, {buf.response.data(), resp_n}, buf.send);

        std::error_code write_ec;
        co_await transport.async_write({buf.send.data(), buf.send.size()}, write_ec);
        if (write_ec)
        {
            trace::debug("{} Write response failed: {}", log_tag, write_ec.message());
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
     * @param parse_fn UDP 数据包解析函数
     * @param build_fn UDP 帧构建函数
     * @param route_cb 路由回调函数，用于解析目标地址
     * @param idle_timer 空闲超时计时器
     * @param log_tag 日志标签
     * @param idle_timeout 空闲超时时间（秒）
     * @param max_datagram 最大数据报长度
     * @return net::awaitable<void> 异步操作
     * @details 从 TLS 流读取 UDP 数据包，解析并转发到目标地址，
     * 然后将响应封装回 TLS 流。支持空闲超时和错误处理。
     * 该模板合并了 Trojan 和 VLESS 中完全相同的 UDP 帧循环逻辑
     */
    template <typename ParseFn, typename BuildFn, typename UdpFrame, typename UdpParseResult>
    auto udp_over_tls_frame_loop(
        transport::transmission &tls_transport,
        ParseFn &&parse_fn,
        BuildFn &&build_fn,
        std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)> route_cb,
        net::steady_timer &idle_timer,
        std::string_view log_tag,
        std::uint32_t idle_timeout,
        std::uint32_t max_datagram) -> net::awaitable<void>
    {
        using namespace boost::asio::experimental::awaitable_operators;

        udp_buffers buf(max_datagram);
        net::ip::udp::socket udp_socket(tls_transport.executor());

        while (true)
        {
            idle_timer.expires_after(std::chrono::seconds(idle_timeout));

            auto do_read = [&]() -> net::awaitable<std::size_t>
            {
                std::error_code ec;
                const auto n = co_await tls_transport.async_read_some(
                    {buf.recv.data(), buf.recv.size()}, ec);
                if (ec || n == 0) { co_return 0; }
                co_return n;
            };

            auto read_result = co_await (do_read() || idle_timer.async_wait(net::use_awaitable));

            if (read_result.index() == 1)
            {
                trace::debug("{} Idle timeout", log_tag);
                co_return;
            }

            const auto n = std::get<0>(read_result);
            idle_timer.cancel();

            if (n == 0)
            {
                trace::debug("{} Read error or EOF", log_tag);
                co_return;
            }

            auto [parse_ec, parsed] = parse_fn(std::span<const std::byte>{buf.recv.data(), n});
            if (fault::failed(parse_ec))
            {
                trace::warn("{} Packet parse failed", log_tag);
                continue;
            }

            const auto target_host = address_to_string(parsed.destination_address, memory::current_resource());
            char port_buf[8];
            const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), parsed.destination_port);
            const std::string_view target_port(port_buf, std::distance(port_buf, port_end));

            auto [route_ec, target_ep] = co_await route_cb(target_host, target_port);
            if (fault::failed(route_ec))
            {
                trace::debug("{} Route failed for {}:{}", log_tag, target_host, target_port);
                continue;
            }

            const auto payload = std::span<const std::byte>(buf.recv.data() + parsed.payload_offset, parsed.payload_size);
            auto [relay_ec, resp_n, sender_ep] = co_await relay_udp_packet(udp_socket, target_ep, payload, buf);
            if (fault::failed(relay_ec)) { continue; }

            if (!co_await send_udp_frame_response<BuildFn, UdpFrame>(
                    tls_transport, sender_ep, resp_n, buf,
                    std::forward<BuildFn>(build_fn), log_tag))
            {
                co_return;
            }
        }
    }

} // namespace psm::protocol::common
