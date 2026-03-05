/**
 * @file distributor.hpp
 * @brief 流量分发器
 * @details 负责管理网络连接池、DNS 解析以及根据路由规则分发流量。该组件是代理服务的核心路由引擎，
 * 实现了灵活的路由策略，包括正向代理、反向代理、直连和黑名单过滤。
 *
 * 核心功能：
 * - 连接池管理：复用到上游服务的 TCP 连接，减少连接建立开销；
 * - DNS 解析：异步解析域名，支持 DNS 缓存和过期策略；
 * - 路由决策：根据配置和请求特征选择最佳路由路径；
 * - 反向代理：静态路由表映射，将主机名映射到后端服务；
 * - 正向代理：支持上游 HTTP CONNECT 代理作为回退路径；
 * - 黑名单过滤：域名级别访问控制，拦截恶意或禁止的域名。
 *
 * 架构位置：
 * - 位于 `agent` 模块，被 `session` 和 `pipeline` 调用；
 * - 依赖 `transport::source` 连接池，管理到上游服务的 TCP 连接。
 */
#pragma once

#include <memory>
#include <functional>
#include <string>
#include <string_view>
#include <optional>
#include <boost/asio.hpp>
#include <utility>
#include <forward-engine/gist.hpp>
#include <forward-engine/transport/source.hpp>
#include <forward-engine/rule/blacklist.hpp>
#include <forward-engine/memory/container.hpp>
#include <chrono>
#include <vector>

namespace ngx::agent
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using source = ngx::transport::source;
    using unique_sock = transport::unique_sock;

    /**
     * @brief 连接分发器
     * @details 核心组件，负责路由决策和连接管理。该组件实现了完整的代理路由逻辑，
     * 支持多种路由模式和智能回退策略。
     *
     * 核心职责：
     * @details - 连接池维护：管理到上游服务的连接池 (`source`)，实现连接复用；
     * @details - DNS 解析：异步域名解析，内置缓存和过期机制；
     * @details - 路由表管理：维护反向代理静态路由表和黑名单；
     * @details - 路由决策：提供统一的路由接口 (`route_forward`, `route_reverse`, `route_direct`)；
     * @details - 正向代理：支持上游 HTTP CONNECT 代理作为回退路径。
     *
     * 路由策略：
     * @details - 直连优先：优先尝试直接连接到目标服务器；
     * @details - 黑名单过滤：检查域名是否在禁止访问列表中；
     * @details - 反向代理：根据主机名映射到预配置的后端服务；
     * @details - 正向代理回退：直连失败时使用上游代理建立隧道。
     *
     * 线程安全性设计：
     * @details - 每个 `distributor` 实例关联一个 `io_context`，所有操作在该上下文中顺序执行；
     * @details - 内部状态（路由表、DNS 缓存）通过哈希表保护，操作期间持有锁；
     * @details - 连接池 (`source`) 是线程安全的，支持多线程并发访问。
     *
     * @note 通常每个 `worker` 线程拥有独立的 `distributor` 实例，避免跨线程同步开销。
     * @warning DNS 缓存可能导致域名解析结果过期，默认缓存时间为 60 秒。
     *
     */
    class distributor
    {
        /**
         * @brief 透明字符串哈希
         * @details 支持 `std::string_view` 和 `memory::string` 的混合查找，避免不必要的内存分配。
         * @details `std::string_view` 作为键在 `memory::unordered_map<memory::string, ...>`
         * 中进行查找，避免构造临时 `memory::string` 对象。
         *
         * @note 透明哈希是 C++14 引入的特性，需要容器支持 `is_transparent`。
         * @warning 哈希函数必须对相同字符串内容产生相同哈希值，无论输入类型如何。
         */
        struct transparent_string_hash
        {
            /**
             * @brief 标记为透明哈希
             */
            using is_transparent = void;

            /**
             * @brief 计算 string_view 哈希
             */
            std::size_t operator()(const std::string_view value) const noexcept
            {
                return std::hash<std::string_view>{}(value);
            }

            /**
             * @brief 计算 memory::string 哈希
             */
            std::size_t operator()(const memory::string &value) const noexcept
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        }; // struct transparent_string_hash

        /**
         * @brief 透明字符串比较
         * @details 支持 `std::string_view` 和 `memory::string` 的混合比较。
         */
        struct transparent_string_equal
        {
            /**
             * @brief 标记为透明比较器
             */
            using is_transparent = void;

            /**
             * @brief string_view vs string_view
             */
            bool operator()(const std::string_view left, const std::string_view right) const noexcept
            {
                return left == right;
            }

            /**
             * @brief memory::string vs string_view
             */
            bool operator()(const memory::string &left, const std::string_view right) const noexcept
            {
                return std::string_view(left) == right;
            }

            /**
             * @brief string_view vs memory::string
             */
            bool operator()(const std::string_view left, const memory::string &right) const noexcept
            {
                return left == std::string_view(right);
            }

            /**
             * @brief memory::string vs memory::string
             */
            bool operator()(const memory::string &left, const memory::string &right) const noexcept
            {
                return left == right;
            }
        }; // struct transparent_string_equal

        /**
         * @brief 透明哈希映射类型别名
         * @details 基于 `memory::unordered_map`，使用透明哈希和相等比较器，支持 `std::string_view` 和 `memory::string` 的混合查找。
         * 该容器使用项目自定义的 `memory::allocator`，从线程局部内存池分配内存，避免全局堆碎片。
         * @tparam Key 键类型
         * @tparam Value 值类型
         */
        template <typename Key, typename Value>
        using hash_map = memory::unordered_map<Key, Value, transparent_string_hash, transparent_string_equal>;

    public:
        /**
         * @brief 构造分发器
         * @param pool 连接池引用，用于获取复用的 TCP 连接
         * @param ioc IO 上下文，用于 DNS 解析
         * @param mr 内存资源指针 (通常为线程局部池)
         */
        explicit distributor(source &pool, net::io_context &ioc, memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 设置上游正向代理 (HTTP `CONNECT`)
         * @details 当直连失败时，`route_forward` 会回退到上游正向代理模式。
         * @details - host 为空或 port 为 0 表示禁用上游代理
         * @details - 当前实现仅支持纯 `CONNECT` 隧道（不带认证头）
         * @param host 上游代理 `host`
         * @param port 上游代理 `port`
         * @note 该函数仅保存配置，不做网络连接。
         */
        void set_positive_endpoint(std::string_view host, std::uint16_t port);

        /**
         * @brief 添加反向代理路由规则
         * @param host 来源主机名 (Incoming Host)
         * @param ep 后端服务地址 (Backend Endpoint)
         */
        void add_reverse_route(std::string_view host, const tcp::endpoint &ep);

        /**
         * @brief 执行反向代理路由
         * @details 根据主机名 (Host Header) 查找预配置的静态路由表，获取对应的后端服务连接。
         * @param host 目标主机名
         * @return `std::pair<gist::code, unique_sock>` 包含结果代码和连接对象
         * @retval `gist::code::success` 路由成功，连接可用
         * @retval `gist::code::bad_gateway` 路由失败，未找到对应的后端服务
         */
        [[nodiscard]] auto route_reverse(std::string_view host)
            -> net::awaitable<std::pair<gist::code, unique_sock>>;

        /**
         * @brief 执行直接路由
         * @details 直接连接到指定的 `IP` 和端口，不经过 `DNS` 解析或黑名单检查。
         * 通常用于已解析出 IP 的场景。
         * @param ep 目标端点 (`IP` + `Port`)
         * @return net::awaitable<std::pair<gist::code, unique_sock>> 包含结果代码和连接对象的 pair
         */
        [[nodiscard]] auto route_direct(tcp::endpoint ep) const
            -> net::awaitable<std::pair<gist::code, unique_sock>>;

        /**
         * @brief 执行正向路由（优先直连，失败回退上游正向代理）
         * @details 路由优先级如下：
         * @details - 1. 黑名单检查：命中则直接返回 `blocked`。
         * @details - 2. 尝试直连：先做 `DNS` 解析，再从连接池获取到目标 `IP` 的连接。
         * @details - 3. 直连失败回退：当配置了上游正向代理时，使用 `HTTP` `CONNECT` 建立到目标的隧道。
         *
         * @note 该函数自身不实现 `HTTP` `CONNECT`，回退分支由 `route_positive` 完成。
         * @param host 目标主机名
         * @param port 目标端口字符串
         * @return `std::pair<gist::code, unique_sock>` 包含结果代码和连接对象
         * @retval `gist::code::blocked` 域名被黑名单拦截
         * @retval `gist::code::host_unreachable` 直连 `DNS` 解析失败且回退不可用
         * @retval `gist::code::bad_gateway` 直连建连失败且回退失败
         * @retval `gist::code::success` 连接建立成功（直连或回退）
         */
        [[nodiscard]] auto route_forward(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<gist::code, unique_sock>>;

    private:
        [[nodiscard]] auto try_connect_endpoints(const memory::vector<tcp::endpoint> &endpoints)
            -> net::awaitable<unique_sock>;

        [[nodiscard]] auto try_connect_cache(const memory::string &cache_key, std::chrono::steady_clock::time_point now)
            -> net::awaitable<unique_sock>;

        /**
         * @brief 通过上游正向代理建立到目标的 TCP 隧道
         * @details 该函数会：
         * @details - 1. 连接到上游代理 `positive_host_`:`positive_port_`
         * @details - 2. 发送 `CONNECT host:port HTTP/1.1` 请求
         * @details - 3. 读取代理响应头并解析状态码，只有 `200` 认为隧道建立成功
         * @param host 目标 `host`
         * @param port 目标 `port`（字符串形式）
         * @return `std::pair<gist::code, unique_sock>` 成功时返回 `success` 与可读写的已建隧道 socket
         * @note 该实现为最小可用版本：
         * @note - 仅解析状态行，不解析其他响应头
         * @note - 响应头读取上限为 8192 字节，防止异常响应导致内存膨胀
         */
        [[nodiscard]] auto route_positive(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<gist::code, unique_sock>>;

        source &pool_;                ///< 连接池引用，用于获取复用的 TCP 连接
        tcp::resolver resolver_;      ///< DNS 解析器，用于异步域名解析
        rule::blacklist blacklist_;   ///< 黑名单检查器，拦截禁止访问的域名
        memory::resource_pointer mr_; ///< 内存资源指针，通常指向线程局部内存池

        /**
         * @brief DNS 缓存条目
         * @details 存储域名解析结果和过期时间，用于减少重复的 DNS 查询开销。
         * 缓存策略基于 TTL（Time-To-Live），默认过期时间为 60 秒。
         */
        struct addresses
        {
            memory::vector<tcp::endpoint> endpoints;               ///< 解析得到的 IP 地址列表
            std::chrono::steady_clock::time_point expiration_time; ///< 缓存过期时间点
        };

        /// 反向代理路由表：主机名 -> 后端服务端点
        hash_map<memory::string, tcp::endpoint> reverse_map_;

        /// DNS 缓存：域名 -> 解析结果和过期时间
        hash_map<memory::string, addresses> dns_cache_;

        /// DNS 进行中请求表：域名 -> 广播唤醒定时器
        hash_map<memory::string, std::shared_ptr<net::steady_timer>> flight_map_;

        /// 上游正向代理主机名，为空表示禁用上游代理
        std::optional<memory::string> positive_host_;

        /// 上游正向代理端口，为 0 表示禁用上游代理
        std::uint16_t positive_port_{0};
    }; // class distributor
}
