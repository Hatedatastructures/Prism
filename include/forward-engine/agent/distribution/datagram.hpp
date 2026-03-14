/**
 * @file datagram.hpp
 * @brief 数据报解析器
 * @details 该组件为 UDP 数据报传输提供解析和套接字创建功能。集成了
 * DNS 解析缓存和请求合并机制，避免重复的 DNS 查询开销。UDP 是
 * 无连接的数据报协议，因此命名为 datagram_resolver。同时提供
 * UDP 套接字创建工具函数，根据目标端点自动选择 IPv4 或 IPv6 协议。
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>

#include <forward-engine/agent/distribution/coalescer.hpp>
#include <forward-engine/agent/distribution/transparent.hpp>
#include <forward-engine/gist/code.hpp>
#include <forward-engine/memory/container.hpp>

namespace ngx::agent::distribution
{
    namespace net = boost::asio;

    /**
     * @class datagram_resolver
     * @brief 数据报解析器。
     * @details 解析器负责解析主机名到 UDP 端点，并缓存解析结果
     * 以提升性能。它实现了两级优化策略：首先检查本地缓存，若缓存
     * 命中且未过期则直接返回缓存的端点；若缓存未命中，则检查是否
     * 有相同目标的解析请求正在进行中，若有则等待该请求完成后
     * 复用结果；否则发起新的 DNS 解析并将结果存入缓存。
     * 缓存采用 FIFO 淘汰策略，当记录数超过上限时移除最旧的条目。
     * 与 reliable_resolver 不同，该解析器仅存储单个端点而非端点列表，
     * 因为 UDP 场景通常不需要尝试多个地址。
     * @note 该类不是线程安全的，应在单个 strand 上下文中使用。
     * @warning 缓存的端点信息可能因目标服务器地址变更而失效，
     * 调用方应合理设置 TTL 参数。
     * @throws 不抛出任何异常，所有错误通过返回码表达。
     */
    class datagram_resolver final
    {
    public:
        using endpoint = net::ip::udp::endpoint;        // UDP 端点类型
        using result = std::pair<gist::code, endpoint>; // 解析结果类型

        /**
         * @brief 构造数据报解析器。
         * @param executor 执行器，用于解析器和请求合并定时器。
         * @param mr 内存资源，用于缓存存储分配。
         * @param ttl 缓存记录的生存时间，默认 120 秒。
         * @param max_entries 缓存最大记录数，默认 4096 条。
         */
        explicit datagram_resolver(net::any_io_executor executor, memory::resource_pointer mr = memory::current_resource(),
                                   std::chrono::seconds ttl = std::chrono::seconds(120), std::size_t max_entries = 4096);

        /**
         * @brief 解析数据报目标端点。
         * @param host 主机名。
         * @param port 服务端口。
         * @return 协程对象，返回状态码与 UDP 端点的配对。
         * @details 该方法是解析器的核心入口，实现了完整的解析流程。
         * 首先检查缓存是否存在有效记录，若存在则直接返回。否则
         * 检查是否有正在进行的相同请求，若有则等待其完成后复用结果。
         * 否则发起新的 UDP DNS 解析，将首个结果存入缓存并返回。
         * 解析失败时返回 host_unreachable 错误码。
         */
        [[nodiscard]] auto resolve(std::string_view host, std::string_view port) -> net::awaitable<result>;

    private:
        /**
         * @struct record
         * @brief 缓存记录结构体。
         * @details 存储已解析的单个端点和过期时间。
         */
        struct record
        {
            endpoint value;                               // 解析结果端点
            std::chrono::steady_clock::time_point expire; // 过期时间
        };

        using hash_map = memory::unordered_map<memory::string, record, transparent_hash, transparent_equal>;

        net::any_io_executor executor_;   // 执行器
        net::ip::udp::resolver resolver_; // UDP DNS 解析器
        memory::resource_pointer mr_;     // 内存资源
        std::chrono::seconds ttl_;        // 缓存生存时间
        std::size_t max_entries_;         // 最大缓存条目数
        hash_map records_;                // 端点缓存表
        coalescer coalescer_;             // 请求合并器
    };

    /**
     * @brief 打开 UDP 套接字。
     * @param executor 用于创建套接字的执行器。
     * @param target 目标 UDP 端点，用于确定协议版本。
     * @return 包含结果码和 UDP 套接字的配对。
     * @details 根据目标端点的地址类型自动选择 IPv4 或 IPv6 协议，
     * 创建并打开对应的 UDP 套接字。若套接字打开失败，返回 io_error
     * 错误码和一个无效的套接字对象。成功时返回 success 和已打开的套接字。
     * 该函数是同步操作，不会阻塞。
     */
    inline auto open_udp_socket(const net::any_io_executor &executor, const net::ip::udp::endpoint &target)
        -> std::pair<gist::code, net::ip::udp::socket>
    {
        boost::system::error_code ec;
        net::ip::udp::socket socket(executor);

        const auto protocol = target.address().is_v6() ? net::ip::udp::v6() : net::ip::udp::v4();
        socket.open(protocol, ec);
        if (ec)
        {
            return std::pair{gist::code::io_error, net::ip::udp::socket(executor)};
        }

        return std::pair{gist::code::success, std::move(socket)};
    }
} // namespace ngx::agent::distribution
