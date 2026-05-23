/**
 * @file router.hpp
 * @brief 连接路由表
 * @details 包含反向路由表、正向代理配置和 DNS 解析器。
 * 路由器是分发层的顶层协调器，整合了 DNS 解析器、反向路由表和连接池，
 * 为上层提供统一的路由接口。
 */
#pragma once

#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <prism/resolve/dns/dns.hpp>
#include <prism/connect/pool/pool.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>

namespace psm::connect
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    /**
     * @class router
     * @brief 连接路由器
     * @details 管理反向路由映射、正向代理目标配置和 DNS 解析。
     * 整合了 DNS 解析器、反向路由表和连接池等子组件，为上层提供统一的路由接口。
     * 路由器支持多种路由模式：反向代理路由、直连端点路由、正向代理路由和数据报路由。
     * @note 该类不是线程安全的，应在单个 strand 上下文中使用
     * @warning 反向路由表在运行期间可被修改，调用方需确保线程安全
     */
    class router
    {
    public:
        /**
         * @struct string_hash
         * @brief 透明字符串哈希函数对象
         * @details 支持对 std::string_view 和 memory::string 进行
         * 哈希计算，无需进行类型转换。通过 is_transparent 类型别名
         * 启用透明查找特性。
         */
        struct string_hash
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const std::string_view value) const noexcept
                -> std::size_t
            {
                return std::hash<std::string_view>{}(value);
            }

            [[nodiscard]] auto operator()(const memory::string &value) const noexcept
                -> std::size_t
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        };

        /**
         * @struct string_equal
         * @brief 透明字符串相等比较函数对象
         * @details 支持对 std::string_view 和 memory::string 进行混合比较。
         */
        struct string_equal
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const std::string_view left, const std::string_view right) const noexcept
                -> bool
            {
                return left == right;
            }

            [[nodiscard]] auto operator()(const memory::string &left, const std::string_view right) const noexcept
                -> bool
            {
                return std::string_view(left) == right;
            }

            [[nodiscard]] auto operator()(const std::string_view left, const memory::string &right) const noexcept
                -> bool
            {
                return left == std::string_view(right);
            }

            [[nodiscard]] auto operator()(const memory::string &left, const memory::string &right) const noexcept
                -> bool
            {
                return left == right;
            }
        };

        /**
         * @brief 透明哈希映射模板别名
         * @details 支持使用 string_view 和 memory::string 混合查找的哈希表。
         */
        template <typename Value>
        using hash_map = memory::unordered_map<memory::string, Value, string_hash, string_equal>;

        using reverse_map = hash_map<tcp::endpoint>; // 反向路由表类型

        /**
         * @brief 构造分发路由器
         * @details 初始化 DNS 解析器、反向路由表和连接池。
         * @param pool 共享 TCP 传输源，用于获取连接
         * @param ioc IO 上下文，用于创建执行器和定时器
         * @param dns_cfg DNS 解析器配置
         * @param mr 内存资源，用于内部存储分配
         */
        explicit router(connection_pool &pool, net::io_context &ioc, resolve::dns::config dns_cfg,
                        memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 设置正向代理的默认上游端点
         * @details 配置后，正向代理请求将转发到该端点而非直接连接目标。
         * @param host 上游服务器主机名
         * @param port 上游服务器端口
         */
        void set_positive_endpoint(std::string_view host, std::uint16_t port);

        /**
         * @brief 添加反向代理路由规则
         * @details 将指定主机名的请求路由到给定的目标端点。
         * @param host 匹配的主机名
         * @param ep 目标 TCP 端点
         */
        void add_reverse_route(std::string_view host, const tcp::endpoint &ep);

        /**
         * @brief 异步路由反向代理请求
         * @details 通过反向路由表查找目标端点并建立连接。
         * @param host 目标主机名
         * @return 协程对象，返回结果码与 TCP 套接字的配对
         */
        [[nodiscard]] auto async_reverse(std::string_view host) const
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;

        /**
         * @brief 查询是否禁用了 IPv6
         * @details 委托给内部 DNS 解析器的配置查询。
         * @return 禁用 IPv6 返回 true，否则返回 false
         */
        [[nodiscard]] auto ipv6_disabled() const noexcept
            -> bool { return dns_->ipv6_disabled(); }

        /**
         * @brief 获取连接池引用
         * @return 连接池引用
         */
        [[nodiscard]] auto pool() noexcept
            -> connection_pool & { return pool_; }
        [[nodiscard]] auto pool() const noexcept
            -> const connection_pool & { return pool_; }

        /**
         * @brief 获取 DNS 解析器引用
         * @return DNS 解析器引用
         */
        [[nodiscard]] auto dns() noexcept
            -> resolve::dns::resolver & { return *dns_; }
        [[nodiscard]] auto dns() const noexcept
            -> const resolve::dns::resolver & { return *dns_; }

        /**
         * @brief 获取执行器
         * @return 执行器
         */
        [[nodiscard]] auto executor() const noexcept
            -> net::any_io_executor { return executor_; }

        /**
         * @brief 获取正向代理主机名
         * @return 正向代理主机名的 optional 引用
         */
        [[nodiscard]] auto positive_host() const noexcept
            -> const std::optional<memory::string> & { return positive_host_; }

        /**
         * @brief 获取正向代理端口
         * @return 正向代理端口
         */
        [[nodiscard]] auto positive_port() const noexcept
            -> std::uint16_t { return positive_port_; }

    private:
        connection_pool &pool_;                             // 共享 TCP 传输源
        memory::resource_pointer mr_;                       // 内存资源
        std::unique_ptr<resolve::dns::resolver> dns_;       // DNS 解析器
        reverse_map reverse_map_;                           // 反向路由表
        net::any_io_executor executor_;                     // 执行器（用于创建 UDP socket）
        std::optional<memory::string> positive_host_;       // 正向代理主机名
        std::uint16_t positive_port_{0};                    // 正向代理端口
    };

} // namespace psm::connect
