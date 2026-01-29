/**
 * @file distributor.hpp
 * @brief 流量分发器
 * @details 负责管理网络连接池、DNS 解析以及根据路由规则分发流量。
 */
#pragma once

#include <memory>
#include <functional>
#include <string>
#include <string_view>
#include <memory/container.hpp>
#include <boost/asio.hpp>
#include <forward-engine/transport/obscura.hpp>
#include <forward-engine/transport/source.hpp>
#include <rule/blacklist.hpp>
#include <forward-engine/gist.hpp>
#include <utility>

namespace ngx::agent
{
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using source = ngx::transport::source;
    using unique_sock = transport::unique_sock;
    using route_result = std::pair<gist::code, unique_sock>;

    /**
     * @brief 分发器
     * @details 核心组件，负责：
     * 1. 维护到上游的连接池 `source`。
     * 2. 执行 DNS 解析。
     * 3. 管理反向代理路由表。
     * 4. 提供统一的路由接口 (`route_forward`, `route_reverse`, `route_direct`)。
     */
    class distributor
    {
        /**
         * @brief 透明字符串哈希
         * @details 支持 `std::string_view` 和 `memory::string` 的混合查找，避免不必要的内存分配。
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

        template <typename Key, typename Value>
        using unordered_map = memory::unordered_map<Key, Value, transparent_string_hash, transparent_string_equal>;

    public:
        /**
         * @brief 构造分发器
         * @param pool 连接池引用，用于获取复用的 TCP 连接
         * @param ioc IO 上下文，用于 DNS 解析
         * @param mr 内存资源指针，默认为当前资源
         */
        explicit distributor(source &pool, net::io_context &ioc, memory::resource_pointer mr = memory::current_resource());
        
        /**
         * @brief 添加反向代理路由规则
         * @param host 来源主机名 (Incoming Host)
         * @param ep 后端服务地址 (Backend Endpoint)
         */
        void add_reverse_route(std::string_view host, const tcp::endpoint& ep);

        /**
         * @brief 执行反向代理路由
         * @details 根据主机名 (Host Header) 查找预配置的静态路由表，获取对应的后端服务连接。
         * @param host 目标主机名
         * @return `route_result` 包含结果代码和连接对象的 pair
         * @retval gist::code::success 路由成功，连接可用
         * @retval gist::code::bad_gateway 路由失败，未找到对应的后端服务
         */
        [[nodiscard]] auto route_reverse(std::string_view host)
            -> net::awaitable<route_result>;

        /**
         * @brief 执行直接路由
         * @details 直接连接到指定的 IP 和端口，不经过 DNS 解析或黑名单检查。
         * 通常用于已解析出 IP 的场景。
         * @param ep 目标端点 (IP + Port)
         * @return net::awaitable<route_result> 包含结果代码和连接对象的 pair
         */
        [[nodiscard]] auto route_direct(tcp::endpoint ep) const
            -> net::awaitable<route_result>;

        /**
         * @brief 执行正向代理路由
         * @details 完整的正向代理流程：
         * 1. **黑名单检查**：检查目标域名是否在黑名单中。
         * 2. **DNS 解析**：异步解析目标域名。
         * 3. **连接获取**：从连接池获取到目标 IP 的连接。
         * @param host 目标主机名
         * @param port 目标端口字符串
         * @return `route_result` 包含结果代码和连接对象的 pair
         * @retval gist::code::blocked 域名被黑名单拦截
         * @retval gist::code::host_unreachable DNS 解析失败
         * @retval gist::code::success 连接建立成功
         */
        [[nodiscard]] auto route_forward(std::string_view host, std::string_view port)
            -> net::awaitable<route_result>;
    private:

        source &pool_;
        tcp::resolver resolver_;
        rule::blacklist blacklist_;
        memory::resource_pointer mr_;
        unordered_map<memory::string, tcp::endpoint> reverse_map_;
    }; // class distributor
}
