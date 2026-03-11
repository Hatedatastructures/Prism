/**
 * @file udp_relay.hpp
 * @brief UDP 中继会话管理
 * @details 实现 UDP 关联（UDP ASSOCIATE）的会话管理，处理客户端与目标服务器之间的 UDP 数据转发。
 * 
 * 设计说明：
 * - 会话生命周期：由控制面 TCP 连接控制，TCP 关闭时 UDP 会话自动销毁
 * - NAT 映射：维护客户端端点到目标端点的映射，实现双向转发
 * - 线程安全：所有操作在单个 strand 内执行，无锁设计
 * 
 * SOCKS5 UDP 流程：
 * 1. 客户端发起 UDP_ASSOCIATE 请求
 * 2. 服务器创建 UDP socket 并返回绑定地址
 * 3. 客户端向该地址发送 UDP 数据报（带 SOCKS5 头部）
 * 4. 服务器解析头部，转发到目标地址
 * 5. 目标响应经服务器封装后返回客户端
 * 
 * Trojan UDP 流程：
 * 1. 客户端在 TLS 隧道内发送 UDP_ASSOCIATE 请求
 * 2. 后续 UDP 帧通过 TLS 隧道传输
 * 3. 服务器解封装后转发到目标
 * 
 * @note 性能关键路径，避免动态分配
 * @warning UDP 不保证可靠性，需处理丢包和乱序
 */

 // @bug 当前文件为弃用状态

#pragma once

#include <boost/asio.hpp>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <functional>
#include <forward-engine/gist.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/transport/unreliable.hpp>

namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @struct udp_relay_config
     * @brief UDP 中继配置
     */
    struct udp_relay_config
    {
        std::uint16_t bind_port = 0;
        std::uint32_t idle_timeout = 60;
        std::uint32_t max_datagram = 65535;
    };

    /**
     * @class udp_relay
     * @brief UDP 中继会话
     * @details 管理单个 UDP 关联的生命周期，处理客户端<->目标的双向转发。
     * 
     * 生命周期：
     * - 由 pipeline 创建，随控制面 TCP 连接关闭而销毁
     * - 通过 shared_ptr 管理，确保异步操作期间有效
     * 
     * 线程边界：
     * - 所有操作在单个 io_context strand 内执行
     * - 不支持并发访问，调用者需保证顺序执行
     * 
     * 所有权：
    * - 持有 UDP socket 的独占所有权
     * - NAT 映射表内部管理，随会话销毁自动清理
     */
    class udp_relay : public std::enable_shared_from_this<udp_relay>
    {
    public:
        using udp_socket = net::ip::udp::socket;
        using udp_endpoint = net::ip::udp::endpoint;
        using udp_resolver = net::ip::udp::resolver;

        /**
         * @brief 构造函数
         * @param executor 执行器
         * @param cfg 配置
         * @param mr 内存资源
         */
        explicit udp_relay(net::any_io_executor executor,
                          const udp_relay_config &cfg = {},
                          memory::resource_pointer mr = memory::current_resource())
            : socket_(executor)
            , strand_(net::make_strand(executor))
            , config_(cfg)
            , mr_(mr)
            , idle_timer_(executor)
        {
        }

        /**
         * @brief 启动 UDP 中继
         * @return 异步返回绑定端点和错误码
         * @details 绑定本地端口，准备接收 UDP 数据报
         */
        auto start() -> net::awaitable<std::pair<gist::code, udp_endpoint>>
        {
            boost::system::error_code ec;
            socket_.open(net::ip::udp::v6(), ec);
            if (ec)
            {
                // 尝试 IPv4
                socket_.open(net::ip::udp::v4(), ec);
                if (ec)
                {
                    co_return std::pair{gist::code::io_error, udp_endpoint{}};
                }
            }

            // 设置 socket 选项
            socket_.set_option(net::ip::udp::socket::reuse_address(true), ec);
            
            // 绑定端口
            udp_endpoint bind_ep(net::ip::udp::v6(), config_.bind_port);
            socket_.bind(bind_ep, ec);
            if (ec)
            {
                co_return std::pair{gist::code::io_error, udp_endpoint{}};
            }

            auto local_ep = socket_.local_endpoint(ec);
            if (ec)
            {
                co_return std::pair{gist::code::io_error, udp_endpoint{}};
            }

            // 启动空闲超时
            start_idle_timer();

            co_return std::pair{gist::code::success, local_ep};
        }

        /**
         * @brief 停止中继
         */
        void stop()
        {
            boost::system::error_code ec;
            socket_.close(ec);
            idle_timer_.cancel();
            nat_table_.clear();
        }

        /**
         * @brief 获取绑定的本地端点
         * @return 本地端点
         */
        auto local_endpoint() const -> std::optional<udp_endpoint>
        {
            boost::system::error_code ec;
            auto ep = socket_.local_endpoint(ec);
            if (ec)
            {
                return std::nullopt;
            }
            return ep;
        }

        /**
         * @brief 运行 UDP 中继循环
         * @param control_signal 控制信号（TCP 关闭时触发）
         * @details 持续接收并转发 UDP 数据报，直到控制信号触发
         */
        auto run(net::steady_timer &control_signal) -> net::awaitable<void>
        {
            memory::vector<std::byte> buffer(config_.max_datagram, mr_);
            udp_endpoint sender_endpoint;

            while (true)
            {
                boost::system::error_code ec;
                auto n = co_await socket_.async_receive_from(
                    net::buffer(buffer), sender_endpoint,
                    net::redirect_error(net::use_awaitable, ec));

                if (ec)
                {
                    if (ec == net::error::operation_aborted)
                    {
                        co_return;
                    }
                    continue;
                }

                // 重置空闲定时器
                reset_idle_timer();

                // 处理接收到的数据报
                // 由上层根据协议类型处理
                co_await handle_datagram(std::span(buffer.data(), n), sender_endpoint);
            }
        }

        /**
         * @brief 发送数据报到指定端点
         * @param data 数据
         * @param target 目标端点
         */
        auto send_to(std::span<const std::byte> data, const udp_endpoint &target)
            -> net::awaitable<gist::code>
        {
            boost::system::error_code ec;
            co_await socket_.async_send_to(
                net::buffer(data.data(), data.size()), target,
                net::redirect_error(net::use_awaitable, ec));
            co_return gist::to_code(ec);
        }

        /**
         * @brief 设置数据报处理回调
         * @param handler 处理函数
         */
        void set_datagram_handler(std::function<net::awaitable<void>(std::span<const std::byte>, const udp_endpoint &)> handler)
        {
            datagram_handler_ = std::move(handler);
        }

    private:
        /**
         * @brief 处理接收到的数据报
         */
        auto handle_datagram(std::span<const std::byte> data, const udp_endpoint &sender)
            -> net::awaitable<void>
        {
            if (datagram_handler_)
            {
                co_await datagram_handler_(data, sender);
            }
        }

        /**
         * @brief 启动空闲超时定时器
         */
        void start_idle_timer()
        {
            idle_timer_.expires_after(std::chrono::seconds(config_.idle_timeout));
            idle_timer_.async_wait([self = shared_from_this()](boost::system::error_code ec)
            {
                if (!ec)
                {
                    self->stop();
                }
            });
        }

        /**
         * @brief 重置空闲定时器
         */
        void reset_idle_timer()
        {
            idle_timer_.expires_after(std::chrono::seconds(config_.idle_timeout));
        }

        udp_socket socket_;
        net::strand<net::any_io_executor> strand_;
        udp_relay_config config_;
        memory::resource_pointer mr_;
        net::steady_timer idle_timer_;
        
        // NAT 映射表：客户端端点 -> 目标端点
        memory::unordered_map<udp_endpoint, udp_endpoint> nat_table_;
        
        std::function<net::awaitable<void>(std::span<const std::byte>, const udp_endpoint &)> datagram_handler_;
    };

    using udp_relay_ptr = std::shared_ptr<udp_relay>;

    inline udp_relay_ptr make_udp_relay(net::any_io_executor executor,
                                        const udp_relay_config &cfg = {},
                                        memory::resource_pointer mr = memory::current_resource())
    {
        return std::make_shared<udp_relay>(executor, cfg, mr);
    }
}
