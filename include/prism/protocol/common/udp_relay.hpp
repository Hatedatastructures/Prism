/**
 * @file udp_relay.hpp
 * @brief 共享 UDP 中继辅助工具
 * @details 提供协议无关的 UDP 数据报中继基础设施，包括缓冲区管理和
 * 数据报转发函数。被 Trojan 和 VLESS 的 UDP over TLS 实现共用。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 */

#pragma once

#include <boost/asio.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/container.hpp>
#include <prism/fault.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>
#include <tuple>

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

} // namespace psm::protocol::common
