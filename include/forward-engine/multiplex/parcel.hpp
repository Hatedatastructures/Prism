/**
 * @file parcel.hpp
 * @brief 多路复用 UDP 数据报管道
 * @details multiplex::parcel 是协议无关的 UDP 中继管道。每个 PSH 帧
 * 承载一个 SOCKS5 UDP relay 格式数据报，可发往不同目标。上行方向
 * 通过 idle_timer 管理生命周期，超时自动关闭，串行处理数据报，
 * 由 frame_loop co_await 调用。通过 core 的虚函数接口发送帧，
 * 不依赖具体协议。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include <boost/asio.hpp>

#include <forward-engine/multiplex/config.hpp>
#include <forward-engine/memory/container.hpp>

// 前向声明
namespace ngx::resolve
{
    class router;
}

namespace ngx::multiplex
{
    class core;

    namespace net = boost::asio;

    /**
     * @class parcel
     * @brief 多路复用 UDP 数据报管道
     * @details 处理 mux 中的 UDP 流。每个数据帧承载 SOCKS5 UDP relay
     * 格式数据报。空闲超时自动关闭，串行处理保证线程安全。
     */
    class parcel : public std::enable_shared_from_this<parcel>
    {
    public:
        /**
         * @brief 构造 parcel
         * @param stream_id 流标识符
         * @param owner 所属 core
         * @param cfg mux 配置参数
         * @param router 路由器引用，用于 DNS 解析
         * @param mr PMR 内存资源
         */
        parcel(std::uint32_t stream_id, std::shared_ptr<core> owner,
               const config &cfg, resolve::router &router, memory::resource_pointer mr);

        ~parcel();

        /**
         * @brief 启动空闲超时监控
         */
        void start();

        /**
         * @brief 接收 mux 数据报并转发到目标
         * @param data SOCKS5 UDP relay 格式数据
         * @return 协程等待对象
         */
        auto on_mux_data(std::span<const std::byte> data) -> net::awaitable<void>;

        /**
         * @brief 关闭管道（幂等）
         */
        void close();

        /**
         * @brief 获取流标识符
         */
        [[nodiscard]] std::uint32_t stream_id() const noexcept
        {
            return id_;
        }

    private:
        /**
         * @brief 空闲超时监控循环
         */
        auto uplink_loop() -> net::awaitable<void>;

        /**
         * @brief 中继单个 UDP 数据报
         * @param udp_packet SOCKS5 UDP relay 格式数据报
         */
        auto relay_datagram(std::span<const std::byte> udp_packet) -> net::awaitable<void>;

        /**
         * @brief 重置空闲计时器
         */
        void touch_idle_timer();

        /**
         * @brief 确保 UDP socket 可用
         * @param protocol 目标协议类型（IPv4/IPv6）
         * @return 协程等待对象，返回 true 表示 socket 可用
         */
        auto ensure_socket(net::ip::udp::endpoint::protocol_type protocol) -> net::awaitable<bool>;

        std::uint32_t id_;
        std::shared_ptr<core> owner_;
        resolve::router &router_;
        const config &config_;
        memory::resource_pointer mr_;
        bool closed_ = false;

        net::steady_timer idle_timer_;
        std::optional<net::ip::udp::socket> egress_socket_;
        net::ip::udp::endpoint::protocol_type socket_protocol_{net::ip::udp::v4()};
        memory::vector<std::byte> recv_buffer_;
    }; // class parcel

} // namespace ngx::multiplex