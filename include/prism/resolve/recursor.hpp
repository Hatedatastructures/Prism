/**
 * @file recursor.hpp
 * @brief 高性能 DNS 解析器门面
 * @details 整合自定义 DNS 客户端、缓存和规则引擎，
 * 替代系统 getaddrinfo 解析方式。提供完整的查询管道：
 * 规则匹配、缓存查找、请求合并、上游查询、IP 过滤、缓存存储。
 * 该组件设计为 per-worker 实例，不需要线程安全。
 * 复用现有的 coalescer 请求合并器避免重复查询。
 * @note 该组件不是线程安全的，应在单线程上下文中使用
 */

#pragma once

#include <atomic>
#include <memory>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <prism/resolve/coalescer.hpp>
#include <prism/resolve/cache.hpp>
#include <prism/resolve/config.hpp>
#include <prism/resolve/resolver.hpp>
#include <prism/resolve/rules.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>

namespace psm::resolve
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using udp = net::ip::udp;

    /**
     * @class recursor
     * @brief 高性能 DNS 解析器（自定义 DNS 客户端）
     * @details 替代系统 getaddrinfo 解析，直接构造和解析 DNS 二进制报文。
     * 内部集成了请求合并、结果缓存和域名规则引擎。
     * 查询管道流程为域名规范化（转小写、去末尾点号）、规则匹配
     * （address/cname/否定规则）、缓存查找（TTL 过期和 serve-stale）、
     * 请求合并（复用 coalescer）、上游查询（UDP/TCP/DoT/DoH）、
     * IP 过滤（黑名单和 bogus）、TTL 钳制与缓存存储。
     * @note 该类不是线程安全的，应在单个 io_context 线程中使用
     * @warning 上游服务器列表为空时，所有解析请求将失败
     */
    class recursor
    {
    public:
        /**
         * @brief 构造 DNS 解析器
         * @details 初始化上游解析器、缓存、规则引擎和请求合并器。
         * @param ioc IO 上下文引用
         * @param cfg DNS 解析器配置
         * @param mr 内存资源指针
         */
        explicit recursor(net::io_context &ioc, config cfg, memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 析构函数，停止后台协程
         * @details 通过设置存活标志通知后台协程安全退出。
         */
        ~recursor();

        /**
         * @brief 异步解析域名到 IP 地址列表
         * @details 同时查询 A 和 AAAA 记录，返回合并的 IP 地址列表。
         * @param host 主机名（自动规范化）
         * @return 包含错误码和 IP 地址列表的配对
         */
        [[nodiscard]] auto resolve(std::string_view host)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>;

        /**
         * @brief 解析到 TCP 端点列表
         * @details 先解析域名获取 IP 地址，再与端口组合为 TCP 端点列表。
         * @param host 主机名
         * @param port 服务端口字符串
         * @return 包含错误码和 TCP 端点列表的配对
         */
        [[nodiscard]] auto resolve_tcp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>>;

        /**
         * @brief 解析到 UDP 端点
         * @details 先解析域名获取 IP 地址，再与端口组合为 UDP 端点。
         * @param host 主机名
         * @param port 服务端口字符串
         * @return 包含错误码和 UDP 端点的配对
         */
        [[nodiscard]] auto resolve_udp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, udp::endpoint>>;

        /**
         * @brief 查询是否禁用了 IPv6
         * @details 返回配置中的 disable_ipv6 标志。
         * @return 禁用 IPv6 返回 true，否则返回 false
         */
        [[nodiscard]] auto ipv6_disabled() const noexcept -> bool { return config_.disable_ipv6; }

    private:
        /**
         * @brief 完整查询管道
         * @details 按顺序执行域名规则匹配、缓存查找、请求合并、
         * 上游查询、IP 过滤和缓存存储。
         * @param domain 已规范化的域名
         * @param qt 查询类型
         * @return 包含错误码和 IP 地址列表的配对
         */
        [[nodiscard]] auto query_pipeline(std::string_view domain, qtype qt)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>;

        /**
         * @brief 检查 IP 是否在黑名单中
         * @details 遍历配置的 IPv4 和 IPv6 黑名单，检查目标地址是否命中。
         * @param ip 待检查的 IP 地址
         * @return 在黑名单中返回 true，否则返回 false
         */
        [[nodiscard]] auto is_blacklisted(const net::ip::address &ip) const -> bool;

        /**
         * @brief 规范化域名
         * @details 将域名转换为小写并去掉末尾点号。
         * @param domain 原始域名
         * @param mr 内存资源指针
         * @return 规范化后的域名
         */
        [[nodiscard]] static auto normalize(std::string_view domain, memory::resource_pointer mr) -> memory::string;

        net::io_context &ioc_;                     // IO 上下文
        memory::resource_pointer mr_;              // 内存资源
        config config_;                            // DNS 配置
        resolver upstream_;                        // 上游 DNS 客户端
        cache cache_;                              // DNS 缓存
        rules_engine rules_;                       // 域名规则引擎
        coalescer coalescer_;                      // 请求合并器
        std::shared_ptr<std::atomic<bool>> alive_; // 生命周期标志，用于安全停止后台协程
    };

} // namespace psm::resolve
