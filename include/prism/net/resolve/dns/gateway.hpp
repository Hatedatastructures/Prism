/**
 * @file gateway.hpp
 * @brief DNS 网关
 * @details 从 connect::router 拆出的 DNS 子模块，封装 resolver + 端口组装 +
 * IPv6 策略。与 route_table/connection_pool 完全解耦。
 *
 * 设计目的：
 *   - 消除 router 上帝类（DNS + 路由 + 连接池 facade 三合一）
 *   - DNS 解析与上层"端点组装"分离：gateway 完成 host→endpoint，让上层
 *     connect::dial 直接拿到 tcp::endpoint 列表，无需关心端口字符串解析
 *
 * @note 单线程使用（每 worker 一个）
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/net/resolve/dns/config.hpp>
#include <prism/net/resolve/dns/dns.hpp>
#include <prism/trace/context.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>


namespace psm::resolve::dns
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @struct gateway_options
     * @brief DNS 网关构造参数
     */
    struct gateway_options
    {
        net::io_context &ioc;                                   ///< io_context
        config dns_cfg;                                         ///< DNS 配置
        memory::resource_pointer mr = memory::current_resource(); ///< 内存资源
    };

    /**
     * @struct gateway_stats
     * @brief DNS 网关累计统计
     */
    struct gateway_stats
    {
        std::uint64_t total_queries{0};    ///< 总查询次数
        std::uint64_t cache_hits{0};       ///< 缓存命中次数
        std::uint64_t upstream_queries{0}; ///< 上游查询次数
        std::uint64_t failures{0};         ///< 失败次数
        std::uint64_t ipv6_filtered{0};    ///< IPv6 过滤次数
    };

    /**
     * @class gateway
     * @brief DNS 网关
     * @details 封装 resolver + 端口组装 + IPv6 策略，提供 tcp/udp 端点解析。
     *          内部持 resolver unique_ptr，构造时根据 cfg 创建 cache/rules/coalescer。
     * @note 单线程使用（每 worker 一个）
     */
    class gateway
    {
    public:
        /**
         * @brief 构造 DNS 网关
         * @param opts 构造参数（io_context + DNS 配置 + 内存资源）
         */
        explicit gateway(gateway_options opts);

        ~gateway() noexcept = default;

        gateway(const gateway &) = delete;
        auto operator=(const gateway &) -> gateway & = delete;
        gateway(gateway &&) = delete;
        auto operator=(gateway &&) -> gateway & = delete;

        /**
         * @brief 解析为 TCP 端点列表
         * @param host 主机名
         * @param port 端口字符串
         * @param trace 日志前缀（可选）
         * @return 错误码和端点列表
         */
        [[nodiscard]] auto resolve_tcp(
            std::string_view host, std::string_view port,
            std::shared_ptr<trace::trace_context> trace = nullptr)
            -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>>;

        /**
         * @brief 解析为 UDP 端点
         * @param host 主机名
         * @param port 端口字符串
         * @param trace 日志前缀（可选）
         * @return 错误码和 UDP 端点
         */
        [[nodiscard]] auto resolve_udp(
            std::string_view host, std::string_view port,
            std::shared_ptr<trace::trace_context> trace = nullptr)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>;

        /**
         * @brief 查询是否禁用 IPv6
         * @return 配置中 disable_ipv6 标志
         */
        [[nodiscard]] auto ipv6_disabled() const noexcept -> bool;

        /**
         * @brief 获取统计快照
         * @return total_queries/cache_hits/upstream_queries/failures/ipv6_filtered
         */
        [[nodiscard]] auto stats() const noexcept -> gateway_stats;

    private:
        net::io_context &ioc_;
        memory::resource_pointer mr_;
        std::unique_ptr<resolver> resolver_;
        config cfg_;
        mutable std::atomic<std::uint64_t> total_queries_{0};
        mutable std::atomic<std::uint64_t> cache_hits_{0};
        mutable std::atomic<std::uint64_t> upstream_queries_{0};
        mutable std::atomic<std::uint64_t> failures_{0};
        mutable std::atomic<std::uint64_t> ipv6_filtered_{0};
    };

} // namespace psm::resolve::dns
