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

#include <memory>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <prism/resolve/dns/config.hpp>
#include <prism/resolve/dns/upstream.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>

namespace psm::resolve::dns
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
        virtual ~resolver() = default;

        /**
         * @brief 异步解析域名到 IP 地址列表
         * @details 同时查询 A 和 AAAA 记录，返回合并的 IP 地址列表。
         * @param host 主机名（自动规范化为小写并去末尾点号）
         * @return 错误码和 IP 地址列表的配对
         */
        [[nodiscard]] virtual auto resolve(std::string_view host)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>> = 0;

        /**
         * @brief 异步解析到 TCP 端点列表
         * @details 先解析域名获取 IP 地址，再与端口组合为 TCP 端点列表。
         * @param host 主机名
         * @param port 服务端口字符串
         * @return 错误码和 TCP 端点列表的配对
         */
        [[nodiscard]] virtual auto resolve_tcp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>> = 0;

        /**
         * @brief 异步解析到 UDP 端点
         * @details 先解析域名获取 IP 地址（优先 A 记录，回退 AAAA），
         * 再与端口组合为 UDP 端点。
         * @param host 主机名
         * @param port 服务端口字符串
         * @return 错误码和 UDP 端点的配对
         */
        [[nodiscard]] virtual auto resolve_udp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>> = 0;

        /**
         * @brief 查询是否禁用了 IPv6
         * @details 返回配置中的 disable_ipv6 标志。
         * @return 禁用 IPv6 返回 true，否则返回 false
         */
        [[nodiscard]] virtual auto ipv6_disabled() const noexcept -> bool = 0;
    };

    /**
     * @brief 创建 DNS 解析器实例
     * @details 工厂函数，创建 resolver 的具体实现（内部持有 upstream、
     * cache、rules_engine、coalescer 等组件）。
     * @param ioc IO 上下文引用
     * @param cfg DNS 配置
     * @param mr 内存资源指针
     * @return 唯一所有权指向 resolver 实例
     */
    [[nodiscard]] auto make_resolver(net::io_context &ioc, config cfg,
                                     memory::resource_pointer mr = memory::current_resource())
        -> std::unique_ptr<resolver>;

} // namespace psm::resolve::dns
