/**
 * @file dns.hpp
 * @brief DNS 解析器抽象接口 + 聚合头文件
 * @details 定义 resolver 纯虚接口，为上层模块提供统一的 DNS 解析
 * 抽象。所有 DNS 解析功能均通过此接口访问，内部实现细节（缓存、规则、
 * 报文编码等）隐藏在 detail/ 子目录中。
 *
 * 该文件同时作为 dns 模块的聚合头文件，引入子目录中所有公开头文件。
 * detail/ 下的内部头文件不在此暴露，外部模块不应直接 include。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/net/dns/config.hpp>
#include <prism/net/dns/upstream.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <string_view>
#include <utility>

namespace psm::dns
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @class resolver
     * @brief DNS 解析器抽象接口
     * @details 上层模块通过此接口进行 DNS 解析，不依赖具体实现。
     * 支持域名到 IP 地址的异步解析，以及 TCP/UDP 端点解析。
     * 内部实现包含规则匹配、缓存查找、请求合并、上游查询、
     * IP 过滤等完整查询管道。
     * @note 该接口应在单个 io_context 线程中使用，不是线程安全的
     */
    class resolver
    {
    public:
        /**
         * @brief 构造 DNS 解析器
         * @param ioc IO 上下文引用
         * @param cfg DNS 解析器配置
         * @param mr 内存资源指针，用于内部容器分配
         */
        explicit resolver(net::io_context &ioc, config cfg,
                          memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 析构 DNS 解析器
         */
        ~resolver() noexcept;

        resolver(const resolver &) = delete;
        auto operator=(const resolver &) -> resolver & = delete;
        resolver(resolver &&) = default;
        auto operator=(resolver &&) -> resolver & = default;

        /**
         * @brief 异步解析域名
         * @param host 待解析的域名
         * @return 结果码 + 解析出的 IP 地址列表
         */
        [[nodiscard]] auto resolve(std::string_view host)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>;

        /**
         * @brief 解析 TCP 目标端点
         * @param host 目标主机名
         * @param port 目标服务端口
         * @return 结果码 + TCP 端点列表
         */
        [[nodiscard]] auto resolve_tcp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>>;

        /**
         * @brief 解析 UDP 目标端点
         * @param host 目标主机名
         * @param port 目标服务端口
         * @return 结果码 + UDP 端点
         */
        [[nodiscard]] auto resolve_udp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>;

        /**
         * @brief 查询是否禁用了 IPv6
         * @return 禁用 IPv6 返回 true，否则返回 false
         */
        [[nodiscard]] auto ipv6_disabled() const noexcept -> bool;

        // 测试接口（原 resolver_impl 的公开方法）
        /**
         * @brief 查询地址是否命中黑名单
         * @param addr IP 地址
         * @return 命中黑名单返回 true，否则返回 false
         */
        [[nodiscard]] auto is_blacklisted(const net::ip::address &addr) const noexcept -> bool;

        /**
         * @brief 规范化域名
         * @details 去除末尾点号并将域名转换为小写。
         * @param domain 原始域名
         * @param mr 内存资源指针
         * @return 规范化后的域名
         */
        [[nodiscard]] static auto normalize(std::string_view domain,
                                            memory::resource_pointer mr = {}) noexcept -> memory::string;

    private:
        class impl;                                   // 内部实现（Pimpl 手法）
        std::unique_ptr<impl> impl_;                  // 内部实现指针
    };

} // namespace psm::dns
