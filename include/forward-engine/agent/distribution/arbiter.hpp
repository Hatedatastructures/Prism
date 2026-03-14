/**
 * @file arbiter.hpp
 * @brief 轻量级分发仲裁器
 * @details 该组件不持有任何重量级资源，通过组合黑名单、数据报解析器、
 * 反向路由表和共享传输源来实现请求路由。作为分发层的核心协调器，
 * 它将各类基础设施组件粘合在一起，为上层提供统一的路由接口。
 * 仲裁器本身是无状态的，所有状态均由外部组件管理。
 */
#pragma once

#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <forward-engine/agent/distribution/datagram.hpp>
#include <forward-engine/gist.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/rule/blacklist.hpp>
#include <forward-engine/transport/source.hpp>

namespace ngx::agent::distribution
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using source = transport::source;
    using unique_sock = transport::unique_sock;

    /**
     * @class arbiter
     * @brief 轻量级分发仲裁器。
     * @details 仲裁器是分发层的核心协调组件，负责将请求路由到正确的
     * 目标端点。它支持三种路由模式：反向代理路由、直连端点路由和
     * 数据报目标路由。反向代理模式通过查找预配置的反向路由表确定目标；
     * 直连模式直接使用给定的 TCP 端点建立连接；数据报模式则结合
     * 黑名单过滤和 DNS 解析来获取目标地址。仲裁器本身不持有任何
     * 重量级资源，所有依赖均通过引用注入，这使得它具有极低的
     * 构造开销和良好地可测试性。
     * @note 该类设计为无状态协调器，不管理任何资源的生命周期。
     * @warning 所有注入的引用必须在仲裁器整个生命周期内保持有效。
     * @throws 不抛出任何异常，所有错误通过返回码表达。
     */
    class arbiter final
    {
    public:
        /**
         * @struct string_hash
         * @brief 透明字符串哈希函数对象。
         * @details 支持对 std::string_view 和 memory::string 进行
         * 哈希计算，无需进行类型转换。通过 is_transparent 类型别名
         * 启用透明查找特性，允许在 unordered_map 中使用异构键查找。
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
         * @struct string_equal
         * @brief 透明字符串相等比较函数对象。
         * @details 支持对 std::string_view 和 memory::string 进行
         * 混合比较，无需进行类型转换。通过 is_transparent 类型别名
         * 启用透明查找特性，允许在 unordered_map 中使用异构键查找。
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
         * @brief 构造分发仲裁器。
         * @param pool 共享 TCP 传输源，用于获取 TCP 连接。
         * @param blacklist 域名黑名单，用于过滤被禁止的目标。
         * @param udp_dns 数据报解析器，用于解析 UDP 目标地址。
         * @param reverse_routes 反向路由表，映射主机名到目标端点。
         * @param executor 执行器，用于创建 UDP 套接字。
         */
        arbiter(source &pool, rule::blacklist &blacklist, datagram_resolver &udp_dns,
                reverse_map &reverse_routes, net::any_io_executor executor) noexcept
            : pool_(pool), blacklist_(blacklist), datagram_dns_(udp_dns), reverse_routes_(reverse_routes),
              executor_(std::move(executor))
        {
        }

        /**
         * @brief 路由反向代理目标。
         * @param host 反向路由的主机名。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 首先在反向路由表中查找主机名对应的端点，
         * 若找不到则返回 bad_gateway。找到后通过传输源获取
         * 到该端点的 TCP 连接，连接失败同样返回 bad_gateway。
         */
        [[nodiscard]] auto route_reverse(const std::string_view host) const
            -> net::awaitable<std::pair<gist::code, unique_sock>>
        {
            const auto route = reverse_routes_.find(host);
            if (route == reverse_routes_.end())
            {
                co_return std::make_pair(gist::code::bad_gateway, nullptr);
            }

            auto socket = co_await pool_.acquire_tcp(route->second);
            if (!socket || !socket->is_open())
            {
                co_return std::make_pair(gist::code::bad_gateway, nullptr);
            }

            co_return std::make_pair(gist::code::success, std::move(socket));
        }

        /**
         * @brief 路由直连 TCP 端点。
         * @param endpoint 目标 TCP 端点。
         * @return 协程对象，返回结果码与 TCP 套接字的配对。
         * @details 直接通过传输源获取到指定端点的 TCP 连接，
         * 无需进行任何查找或解析操作。连接失败返回 bad_gateway。
         */
        [[nodiscard]] auto route_direct(const tcp::endpoint endpoint) const
            -> net::awaitable<std::pair<gist::code, unique_sock>>
        {
            auto socket = co_await pool_.acquire_tcp(endpoint);
            if (!socket || !socket->is_open())
            {
                co_return std::make_pair(gist::code::bad_gateway, nullptr);
            }

            co_return std::make_pair(gist::code::success, std::move(socket));
        }

        /**
         * @brief 为目标创建数据报套接字。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 UDP 套接字的配对。
         * @details 首先检查主机名是否在黑名单中，若被禁止则
         * 返回 blocked。否则通过数据报解析器解析目标地址，
         * 解析失败返回相应的错误码。解析成功后打开 UDP 套接字。
         */
        [[nodiscard]] auto route_datagram(const std::string_view host, const std::string_view port) const
            -> net::awaitable<std::pair<gist::code, net::ip::udp::socket>>
        {
            if (blacklist_.domain(host))
            {
                co_return std::pair{gist::code::blocked, net::ip::udp::socket{executor_}};
            }

            const auto [resolve_ec, target] = co_await datagram_dns_.resolve(host, port);
            if (gist::failed(resolve_ec))
            {
                co_return std::pair{resolve_ec, net::ip::udp::socket{executor_}};
            }

            co_return open_udp_socket(executor_, target);
        }

        /**
         * @brief 解析数据报目标但不打开套接字。
         * @param host 目标主机名。
         * @param port 目标服务端口。
         * @return 协程对象，返回结果码与 UDP 端点的配对。
         * @details 与 route_datagram 类似，但仅返回解析后的端点信息，
         * 不实际创建套接字。适用于需要延迟创建套接字或需要
         * 复用端点信息的场景。
         */
        [[nodiscard]] auto resolve_datagram_target(const std::string_view host, const std::string_view port) const
            -> net::awaitable<std::pair<gist::code, net::ip::udp::endpoint>>
        {
            if (blacklist_.domain(host))
            {
                co_return std::pair{gist::code::blocked, net::ip::udp::endpoint{}};
            }

            co_return co_await datagram_dns_.resolve(host, port);
        }

    private:
        source &pool_;                    // 共享 TCP 传输源
        rule::blacklist &blacklist_;      // 域名黑名单
        datagram_resolver &datagram_dns_; // 数据报解析器
        reverse_map &reverse_routes_;     // 反向路由表
        net::any_io_executor executor_;   // 执行器
    };
} // namespace ngx::agent::distribution
