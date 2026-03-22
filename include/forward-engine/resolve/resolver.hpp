/**
 * @file resolver.hpp
 * @brief DNS 查询客户端
 * @details 提供基于 Boost.Asio 协程的异步 DNS 查询能力，支持 UDP、TCP、
 * DoT (DNS over TLS) 和 DoH (DNS over HTTPS) 四种传输协议。客户端可配置
 * 多上游服务器，并根据指定策略（first / fallback / fastest）选择最优响应。
 * 所有内部缓冲区使用 PMR 多态内存资源分配，与项目内存管理基础设施无缝集成。
 *
 * 核心组件：
 * @details - resolve_result：封装单次 DNS 查询的完整结果，包括响应报文、
 * @details   提取的 IP 地址列表、往返时间和上游标识。
 * @details - resolver：DNS 解析器主类，管理上游列表与解析策略，
 * @details   通过协程并发查询并聚合结果。
 *
 * 传输协议：
 * @details - UDP：标准 DNS 查询，适用于小型响应（截断回退至 TCP）。
 * @details - TCP：带 2 字节长度前缀的 DNS 帧格式，适用于大型响应。
 * @details - DoT：在 TLS 连接上承载 TCP 帧格式，端口 853。
 * @details - DoH：在 HTTPS 上承载 HTTP POST 请求，端口 443。
 *
 * @note 所有异步接口返回 net::awaitable<T>，调用方需在协程中 co_await。
 * @warning 错误通过 fault::code 表达，不抛出异常。
 */
#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <forward-engine/resolve/packet.hpp>
#include <forward-engine/resolve/config.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/fault/code.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::resolve
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @struct resolve_result
     * @brief DNS 解析结果
     * @details 封装一次 DNS 查询的完整输出，包括原始响应报文、提取的 IP
     * 地址列表、往返时间（毫秒）、响应来源上游标识以及错误码。所有容器
     * 均使用 PMR 分配器，支持外部注入内存资源以优化分配性能。
     * @note 默认 error 为 success，但 ips 为空时应视为逻辑失败。
     */
    struct resolve_result
    {
        message response;                        // DNS 响应报文
        memory::vector<net::ip::address> ips;    // 从响应中提取的 IP 地址
        uint64_t rtt_ms{0};                      // 往返时间（毫秒）
        memory::string server_addr;              // 响应来自哪个上游服务器
        fault::code error{fault::code::success}; // 错误码

        /**
         * @brief 构造解析结果
         * @param mr 内存资源指针，用于内部容器分配。
         */
        explicit resolve_result(memory::resource_pointer mr = memory::current_resource())
            : response(mr), ips(mr), server_addr(mr)
        {
        }
    };

    /**
     * @class resolver
     * @brief 异步 DNS 解析器
     * @details 管理一组上游 DNS 服务器，根据配置的解析策略发起异步查询。
     * 支持 UDP、TCP、DoT、DoH 四种传输协议，可针对每个上游服务器独立
     * 配置协议类型、端口和超时时间。解析策略包括：
     * - first：遇到首个成功响应立即返回（顺序尝试）。
     * - fallback：依次尝试所有上游，直到获得成功响应。
     * - fastest：尝试所有上游，返回 RTT 最低的成功响应。
     *
     * @note 该类不是线程安全的，应在单个 io_context 线程或 strand 中使用。
     * @warning 上游服务器列表为空时，resolve() 将直接返回失败结果。
     */
    class resolver
    {
    public:
        /**
         * @brief 构造 DNS 解析器
         * @param ioc IO 上下文引用，用于创建套接字和定时器。
         * @param mr 内存资源指针，用于内部容器分配。
         */
        explicit resolver(net::io_context &ioc, memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 设置上游服务器列表
         * @param servers 上游服务器配置向量。
         * @details 替换当前所有上游服务器配置。每个 server 可独立配置
         * 协议、地址、端口和超时时间。
         */
        void set_servers(memory::vector<dns_remote> servers);

        /**
         * @brief 设置解析策略模式
         * @param mode 解析策略，支持 first / fallback / fastest。
         */
        void set_mode(resolve_mode mode);

        /**
         * @brief 设置默认超时时间
         * @param ms 超时时间（毫秒）。
         * @details 当上游服务器未配置独立超时时间时使用此默认值。
         */
        void set_timeout(uint32_t ms);

        /**
         * @brief 异步解析域名
         * @param domain 待解析的域名。
         * @param qt 查询类型（A / AAAA 等）。
         * @return 协程对象，返回 resolve_result。
         * @details 根据当前解析策略向配置的上游服务器发起查询，
         * 并按策略选择最佳响应返回。
         */
        [[nodiscard]] auto resolve(std::string_view domain, qtype qt)
            -> net::awaitable<resolve_result>;

    private:
        /**
         * @brief 通过 UDP 发送 DNS 查询
         * @param server 目标上游服务器配置。
         * @param query 序列化前的 DNS 查询报文。
         * @return 协程对象，返回该上游的解析结果。
         */
        [[nodiscard]] auto query_udp(const dns_remote &server, const message &query)
            -> net::awaitable<resolve_result>;

        /**
         * @brief 通过 TCP 发送 DNS 查询
         * @param server 目标上游服务器配置。
         * @param query 序列化前的 DNS 查询报文。
         * @return 协程对象，返回该上游的解析结果。
         * @details 使用 2 字节大端长度前缀的 TCP 帧格式收发 DNS 报文。
         */
        [[nodiscard]] auto query_tcp(const dns_remote &server, const message &query)
            -> net::awaitable<resolve_result>;

        /**
         * @brief 通过 DoT (DNS over TLS) 发送 DNS 查询
         * @param server 目标上游服务器配置。
         * @param query 序列化前的 DNS 查询报文。
         * @return 协程对象，返回该上游的解析结果。
         * @details 在 TLS 连接上承载 TCP 帧格式，默认端口 853。
         * 支持 SNI 主机名设置和证书验证控制。
         */
        [[nodiscard]] auto query_tls(const dns_remote &server, const message &query)
            -> net::awaitable<resolve_result>;

        /**
         * @brief 通过 DoH (DNS over HTTPS) 发送 DNS 查询
         * @param server 目标上游服务器配置。
         * @param query 序列化前的 DNS 查询报文。
         * @return 协程对象，返回该上游的解析结果。
         * @details 在 HTTPS 连接上使用 HTTP POST 方法发送 DNS 报文，
         * Content-Type 为 application/dns-message。默认端口 443。
         */
        [[nodiscard]] auto query_https(const dns_remote &server, const message &query)
            -> net::awaitable<resolve_result>;

        net::io_context &ioc_;                     // IO 上下文
        memory::resource_pointer mr_;              // 内存资源
        memory::vector<dns_remote> servers_;       // 上游服务器列表
        resolve_mode mode_{resolve_mode::fastest}; // 解析策略
        uint32_t timeout_ms_{4000};                // 默认超时（毫秒）
    };

} // namespace ngx::resolve
