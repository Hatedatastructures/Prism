/**
 * @file router.hpp
 * @brief 分发层路由器
 * @details 该组件是分发层的顶层门面，整合了 DNS 解析器、
 * 反向路由表和连接池等子组件，为上层提供统一的路由接口。
 * 路由器支持多种路由模式：反向代理路由、直连端点路由、
 * 正向代理路由和数据报路由。
 */
#pragma once

#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <forward-engine/resolve/recursor.hpp>
#include <forward-engine/channel/connection/pool.hpp>
#include <forward-engine/fault/code.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::resolve
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using connection_pool = ngx::channel::connection_pool;
    using pooled_connection = ngx::channel::pooled_connection;

    /**
     * @class router
     * @brief 分发层路由器。
     * @details 路由器是分发层的顶层协调器，负责将各类路由请求分发到
     * 正确的处理路径。它内部管理着 DNS 解析器、反向路由表和连接池，
     * 并根据请求类型选择合适的处理路径。反向代理请求通过查找
     * 预配置的路由表；直连请求直接通过传输源建立连接；正向代理
     * 请求通过 DNS 解析器进行域名解析并建立连接；数据报请求则
     * 通过 DNS 解析来获取目标地址。
     * @note 该类不是线程安全的，应在单个 strand 上下文中使用。
     * @warning 反向路由表在运行期间可被修改，调用方需确保线程安全。
     * @throws 不抛出任何异常，所有错误通过返回码表达。
     */
    class router
    {
    public:
        /**
         * @brief 透明字符串哈希函数对象。
         * @details 支持对 std::string_view 和 memory::string 进行
         * 哈希计算，无需进行类型转换。通过 is_transparent 类型别名
         * 启用透明查找特性。
         */
        struct string_hash
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const std::string_view value) const noexcept -> std::size_t
            {
                return std::hash<std::string_view>{}(value);
            }

            [[nodiscard]] auto operator()(const memory::string &value) const noexcept -> std::size_t
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        };

        /**
         * @brief 透明字符串相等比较函数对象。
         * @details 支持对 std::string_view 和 memory::string 进行
         * 混合比较，无需进行类型转换。
         */
        struct string_equal
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const std::string_view left, const std::string_view right) const noexcept -> bool
            {
                return left == right;
            }

            [[nodiscard]] auto operator()(const memory::string &left, const std::string_view right) const noexcept -> bool
            {
                return std::string_view(left) == right;
            }

            [[nodiscard]] auto operator()(const std::string_view left, const memory::string &right) const noexcept -> bool
            {
                return left == std::string_view(right);
            }

            [[nodiscard]] auto operator()(const memory::string &left, const memory::string &right) const noexcept -> bool
            {
                return left == right;
            }
        };

        template <typename Value>
        using hash_map = memory::unordered_map<memory::string, Value, string_hash, string_equal>;

        using reverse_map = hash_map<tcp::endpoint>;

        /**
         * @brief 构造分发路由器。
         * @param pool 共享 TCP 传输源，用于获取连接。
         * @param ioc IO 上下文，用于创建执行器和定时器。
         * @param dns_cfg DNS 解析器配置。
         * @param mr 内存资源，用于内部存储分配。
         */
        explicit router(connection_pool &pool, net::io_context &ioc, config dns_cfg,
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
         * @details 通过反向路由表查找目标端点并建立连接。
         */
        [[nodiscard]] auto async_reverse(std::string_view host) const
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;

        /**
         * @brief 查询是否禁用了 IPv6。
         * @return 是否禁用 IPv6。
         */
        [[nodiscard]] auto ipv6_disabled() const noexcept -> bool { return dns_.ipv6_disabled(); }

        /**
         * @brief 异步路由直连 TCP 端点。
         * @param ep 目标 TCP 端点。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 直接通过传输源获取到指定端点的连接，无需任何查找。
         */
        [[nodiscard]] auto async_direct(tcp::endpoint ep) const
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;

        /**
         * @brief 异步路由正向代理请求。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 通过 DNS 解析器进行域名解析并建立连接。解析器会利用
         * DNS 缓存和请求合并机制来优化连接建立过程。
         */
        [[nodiscard]] auto async_forward(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;

        /**
         * @brief 异步路由数据报请求。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 UDP 套接字的配对。
         * @details 通过 DNS 解析获取目标地址，然后创建 UDP 套接字。
         */
        [[nodiscard]] auto async_datagram(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>;

        /**
         * @brief 解析数据报目标端点。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 UDP 端点的配对。
         * @details 仅返回解析后的端点信息，不创建套接字。
         * 适用于需要延迟创建套接字的场景。
         */
        [[nodiscard]] auto resolve_datagram_target(std::string_view host, std::string_view port)
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
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;

        /**
         * @brief 从端点列表中尝试连接，最多尝试 3 个端点。
         * @param endpoints 候选端点列表。
         * @return 成功连接的套接字，或 nullptr。
         */
        [[nodiscard]] auto connect_with_retry(std::span<const tcp::endpoint> endpoints)
            -> net::awaitable<pooled_connection>;

        connection_pool &pool_;                       // 共享 TCP 传输源
        memory::resource_pointer mr_;                 // 内存资源
        recursor dns_;                                // DNS 解析器
        reverse_map reverse_map_;                     // 反向路由表
        net::any_io_executor executor_;               // 执行器（用于创建 UDP socket）
        std::optional<memory::string> positive_host_; // 正向代理主机名
        std::uint16_t positive_port_{0};              // 正向代理端口
    };

    /**
     * @brief 打开 UDP 套接字。
     * @param executor 用于创建套接字的执行器。
     * @param target 目标 UDP 端点，用于确定协议版本。
     * @return 包含结果码和 UDP 套接字的配对。
     * @details 根据目标端点的地址类型自动选择 IPv4 或 IPv6 协议，
     * 创建并打开对应的 UDP 套接字。
     */
    inline auto open_udp_socket(const net::any_io_executor &executor, const net::ip::udp::endpoint &target)
        -> std::pair<fault::code, net::ip::udp::socket>
    {
        boost::system::error_code ec;
        net::ip::udp::socket socket(executor);

        const auto protocol = target.address().is_v6() ? net::ip::udp::v6() : net::ip::udp::v4();
        socket.open(protocol, ec);
        if (ec)
        {
            return std::pair{fault::code::io_error, net::ip::udp::socket(executor)};
        }

        return std::pair{fault::code::success, std::move(socket)};
    }
} // namespace ngx::resolve
