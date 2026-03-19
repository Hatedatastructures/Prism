/**
 * @file router.hpp
 * @brief 分发层路由器
 * @details 该组件是分发层的顶层门面，整合了仲裁器、可靠传输解析器和数据报解析器等
 * 子组件，为上层提供统一的路由接口。路由器支持多种路由模式：反向代理
 * 路由、直连端点路由、正向代理路由和数据报路由。通过组合各类子组件，
 * 路由器实现了完整的请求分发逻辑，包括黑名单过滤、DNS 解析缓存、
 * 请求合并和连接池管理等高级特性。
 */
#pragma once

#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <forward-engine/agent/resolve/arbiter.hpp>
#include <forward-engine/agent/resolve/udpcache.hpp>
#include <forward-engine/agent/resolve/tcpcache.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/rule/blacklist.hpp>
#include <forward-engine/channel/pool/pool.hpp>

namespace ngx::agent::resolve
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using tcpool = ngx::channel::tcpool;
    using unique_sock = ngx::channel::unique_sock;
    using deleter = ngx::channel::deleter;

    /**
     * @class router
     * @brief 分发层路由器。
     * @details 路由器是分发层的顶层协调器，负责将各类路由请求分发到
     * 正确的子组件处理。它内部管理着仲裁器、可靠传输解析器、数据报解析器和黑名单
     * 等组件，并根据请求类型选择合适地处理路径。反向代理请求通过
     * 仲裁器查找预配置的路由表；直连请求直接通过传输源建立连接；
     * 正向代理请求通过可靠传输解析器进行 DNS 解析和连接建立；数据报请求则
     * 通过仲裁器进行黑名单过滤和地址解析。路由器还支持配置正向代理
     * 的默认上游端点，用于需要流量转发的场景。
     * @note 该类不是线程安全的，应在单个 strand 上下文中使用。
     * @warning 反向路由表在运行期间可被修改，调用方需确保线程安全。
     * @throws 不抛出任何异常，所有错误通过返回码表达。
     */
    class router
    {
    public:
        /**
         * @brief 构造分发路由器。
         * @param pool 共享 TCP 传输源，用于获取连接。
         * @param ioc IO 上下文，用于创建执行器和定时器。
         * @param mr 内存资源，用于内部存储分配。
         */
        explicit router(tcpool &pool, net::io_context &ioc,
                        memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 设置正向代理的默认上游端点。
         * @param host 上游服务器主机名。
         * @param port 上游服务器端口。
         * @details 配置后，正向代理请求将转发到该端点而非直接连接目标。
         */
        void set_positive_endpoint(std::string_view host, std::uint16_t port);

        /**
         * @brief 添加反向代理路由规则。
         * @param host 匹配的主机名。
         * @param ep 目标 TCP 端点。
         * @details 将指定主机名的请求路由到给定的目标端点。
         */
        void add_reverse_route(std::string_view host, const tcp::endpoint &ep);

        /**
         * @brief 异步路由反向代理请求。
         * @param host 目标主机名。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 通过仲裁器查找反向路由表，获取目标端点并建立连接。
         */
        [[nodiscard]] auto async_reverse(std::string_view host) const
            -> net::awaitable<std::pair<fault::code, unique_sock>>;

        /**
         * @brief 异步路由直连 TCP 端点。
         * @param ep 目标 TCP 端点。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 直接通过传输源获取到指定端点的连接，无需任何查找。
         */
        [[nodiscard]] auto async_direct(tcp::endpoint ep) const
            -> net::awaitable<std::pair<fault::code, unique_sock>>;

        /**
         * @brief 异步路由正向代理请求。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 若配置了正向代理端点，则转发到该端点；否则通过
         * 可靠传输解析器直接连接目标。解析器会利用 DNS 缓存和请求合并
         * 机制来优化连接建立过程。
         */
        [[nodiscard]] auto async_forward(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, unique_sock>>;

        /**
         * @brief 异步路由数据报请求。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 UDP 套接字的配对。
         * @details 通过仲裁器进行黑名单过滤和 DNS 解析，然后创建
         * UDP 套接字。若主机被列入黑名单，返回 blocked 错误码。
         */
        [[nodiscard]] auto async_datagram(std::string_view host, std::string_view port) const
            -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>;

        /**
         * @brief 解析数据报目标端点。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 UDP 端点的配对。
         * @details 与 async_datagram 类似，但仅返回解析后的端点信息，
         * 不创建套接字。适用于需要延迟创建套接字的场景。
         */
        [[nodiscard]] auto resolve_datagram_target(std::string_view host, std::string_view port) const
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>;

    private:
        /**
         * @brief 路由到正向代理端点。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 内部方法，用于处理配置了正向代理端点的情况。
         */
        [[nodiscard]] auto async_positive(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, unique_sock>>;

        tcp::resolver resolver_;                      // TCP 解析器
        rule::blacklist blacklist_;                   // 域名黑名单
        memory::resource_pointer mr_;                 // 内存资源
        udpcache datagram_dns_;                       // UDP 解析缓存
        arbiter::reverse_map reverse_map_;            // 反向路由表
        arbiter arbiter_;                             // 仲裁器
        tcpcache stream_dns_;                         // TCP 解析缓存
        std::optional<memory::string> positive_host_; // 正向代理主机名
        std::uint16_t positive_port_{0};              // 正向代理端口
    };
} // namespace ngx::agent::resolve
