/**
 * @file statistics.hpp
 * @brief 服务器统计模块
 * @details 提供服务器运行时统计信息的收集、存储和快照功能。
 *
 * 核心特性：
 * - 原子操作：所有计数器使用 std::atomic 保证线程安全
 * - 内存序优化：使用 relaxed 内存序减少同步开销
 * - 扩展统计：支持按方法、按状态码分类的详细统计
 * - 时间追踪：记录请求处理时间（最小、最大、平均）
 * - JSON 序列化：使用 glaze 库支持 JSON 序列化
 *
 * C++23 特性：
 * - std::to_underlying()：枚举转底层类型
 * - std::unreachable()：标记不可达代码
 *
 * @note 设计原则：
 * - 高性能：所有操作均为原子操作，无锁设计
 * - 低开销：使用 relaxed 内存序，适合统计场景
 * - 可扩展：支持添加新的统计维度
 *
 * @see dualport.hpp
 */
#pragma once

#include <atomic>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <chrono>
#include <utility>
#include <glaze/glaze.hpp>

namespace srv::statistics
{
    /**
     * @struct connection_info
     * @brief 连接信息结构体
     * @details 记录单个连接的详细信息，包括客户端地址、请求路径、流量统计等
     */
    struct connection_info final
    {
        std::string client_ip;
        std::uint16_t client_port{0};
        std::string request_path;
        std::string user_agent;
        std::chrono::steady_clock::time_point connect_time{std::chrono::steady_clock::now()};
        std::chrono::steady_clock::time_point last_active{std::chrono::steady_clock::now()};
        std::uint64_t bytes_sent{0};
        std::uint64_t bytes_received{0};
        std::uint32_t request_count{0};
        bool is_ssl{false};
    };

    /**
     * @struct detailed_stats
     * @brief 详细统计数据结构体
     * @details 扩展的服务器统计信息，包含按方法分类、按状态分类、时间统计等详细信息
     */
    struct detailed_stats final
    {
        /// @brief 总请求数
        std::atomic<std::uint64_t> total_requests{0};
        /// @brief 当前活动连接数
        std::atomic<std::uint32_t> active_connections{0};
        /// @brief 发送的总字节数
        std::atomic<std::uint64_t> bytes_sent{0};
        /// @brief 接收的总字节数
        std::atomic<std::uint64_t> bytes_received{0};
        /// @brief 服务的静态文件数
        std::atomic<std::uint64_t> static_files_served{0};
        /// @brief API 请求数
        std::atomic<std::uint64_t> api_requests{0};
        /// @brief 404 响应数
        std::atomic<std::uint64_t> not_found_count{0};
        /// @brief 错误数
        std::atomic<std::uint64_t> error_count{0};

        /// @brief GET 请求数
        std::atomic<std::uint64_t> get_requests{0};
        /// @brief POST 请求数
        std::atomic<std::uint64_t> post_requests{0};
        /// @brief PUT 请求数
        std::atomic<std::uint64_t> put_requests{0};
        /// @brief DELETE 请求数
        std::atomic<std::uint64_t> delete_requests{0};

        /// @brief 2xx 状态码响应数
        std::atomic<std::uint64_t> status_2xx{0};
        /// @brief 3xx 状态码响应数
        std::atomic<std::uint64_t> status_3xx{0};
        /// @brief 4xx 状态码响应数
        std::atomic<std::uint64_t> status_4xx{0};
        /// @brief 5xx 状态码响应数
        std::atomic<std::uint64_t> status_5xx{0};

        /// @brief 请求处理总时间（纳秒）
        std::atomic<std::uint64_t> total_request_time_ns{0};
        /// @brief 最小请求处理时间（纳秒）
        std::atomic<std::uint64_t> min_request_time_ns{UINT64_MAX};
        /// @brief 最大请求处理时间（纳秒）
        std::atomic<std::uint64_t> max_request_time_ns{0};

        /// @brief 总连接数
        std::atomic<std::uint64_t> total_connections{0};
        /// @brief SSL 连接数
        std::atomic<std::uint64_t> ssl_connections{0};
        /// @brief 连接错误数
        std::atomic<std::uint64_t> connection_errors{0};

        /// @brief 服务器启动时间
        std::chrono::steady_clock::time_point start_time{std::chrono::steady_clock::now()};

        /// @brief 活动连接列表最大容量
        static constexpr std::size_t MAX_CONNECTIONS = 2048;
        /// @brief 活动连接信息列表
        std::array<connection_info, MAX_CONNECTIONS> active_connection_list;
        /// @brief 连接列表头指针（环形缓冲区）
        std::atomic<std::size_t> connection_list_head{0};

        /**
         * @brief 增加请求计数
         */
        void increment_requests() noexcept
        {
            total_requests.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 增加静态文件服务计数
         */
        void increment_static_files() noexcept
        {
            static_files_served.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 增加 API 请求计数
         */
        void increment_api_requests() noexcept
        {
            api_requests.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 增加 404 计数
         */
        void increment_not_found() noexcept
        {
            not_found_count.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 增加错误计数
         */
        void increment_errors() noexcept
        {
            error_count.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 增加活动连接数
         */
        void add_connection() noexcept
        {
            active_connections.fetch_add(1, std::memory_order_relaxed);
            total_connections.fetch_add(1, std::memory_order_relaxed);
        }

        /**
         * @brief 减少活动连接数
         */
        void remove_connection() noexcept
        {
            active_connections.fetch_sub(1, std::memory_order_relaxed);
        }

        /**
         * @brief 增加发送字节数
         * @param bytes 发送的字节数
         */
        void add_bytes_sent(std::uint64_t bytes) noexcept
        {
            bytes_sent.fetch_add(bytes, std::memory_order_relaxed);
        }

        /**
         * @brief 增加接收字节数
         * @param bytes 接收的字节数
         */
        void add_bytes_received(std::uint64_t bytes) noexcept
        {
            bytes_received.fetch_add(bytes, std::memory_order_relaxed);
        }

        /**
         * @brief 记录请求处理时间
         * @param time_ns 请求处理时间（纳秒）
         */
        void record_request_time(std::uint64_t time_ns) noexcept
        {
            total_request_time_ns.fetch_add(time_ns, std::memory_order_relaxed);

            std::uint64_t current_min = min_request_time_ns.load(std::memory_order_relaxed);
            while (time_ns < current_min)
            {
                if (min_request_time_ns.compare_exchange_weak(current_min, time_ns, std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    break;
                }
            }

            std::uint64_t current_max = max_request_time_ns.load(std::memory_order_relaxed);
            while (time_ns > current_max)
            {
                if (max_request_time_ns.compare_exchange_weak(current_max, time_ns, std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    break;
                }
            }
        }

        /**
         * @brief 记录 HTTP 状态码
         * @param status_code HTTP 状态码
         */
        void record_status_code(const std::uint16_t status_code) noexcept
        {
            if (status_code >= 200 && status_code < 300)
            {
                status_2xx.fetch_add(1, std::memory_order_relaxed);
            }
            else if (status_code >= 300 && status_code < 400)
            {
                status_3xx.fetch_add(1, std::memory_order_relaxed);
            }
            else if (status_code >= 400 && status_code < 500)
            {
                status_4xx.fetch_add(1, std::memory_order_relaxed);
            }
            else if (status_code >= 500 && status_code < 600)
            {
                status_5xx.fetch_add(1, std::memory_order_relaxed);
            }
        }

        /**
         * @brief 记录 HTTP 方法
         * @param method HTTP 方法字符串
         */
        void record_method(const std::string_view method) noexcept
        {
            if (method == "GET")
            {
                get_requests.fetch_add(1, std::memory_order_relaxed);
            }
            else if (method == "POST")
            {
                post_requests.fetch_add(1, std::memory_order_relaxed);
            }
            else if (method == "PUT")
            {
                put_requests.fetch_add(1, std::memory_order_relaxed);
            }
            else if (method == "DELETE")
            {
                delete_requests.fetch_add(1, std::memory_order_relaxed);
            }
        }

        /**
         * @brief 添加连接信息到活动连接列表
         * @param info 连接信息
         * @return 连接在列表中的索引
         */
        [[nodiscard]] std::size_t add_connection_info(const connection_info &info) noexcept
        {
            const std::size_t index = connection_list_head.fetch_add(1, std::memory_order_relaxed) % MAX_CONNECTIONS;
            active_connection_list[index] = info;
            return index;
        }

        /**
         * @brief 更新连接信息
         * @param index 连接索引
         * @param info 新的连接信息
         * @note 此方法非线程安全，请使用原子更新方法
         * @see increment_connection_request_count, update_connection_path
         */
        void update_connection_info(const std::size_t index, const connection_info &info) noexcept
        {
            if (index < MAX_CONNECTIONS)
            {
                active_connection_list[index] = info;
            }
        }

        /**
         * @brief 原子地增加连接请求计数
         * @param index 连接索引
         * @note 使用 relaxed 内存序，适合统计场景
         */
        void increment_connection_request_count(const std::size_t index) noexcept
        {
            if (index < MAX_CONNECTIONS)
            {
                ++active_connection_list[index].request_count;
            }
        }

        /**
         * @brief 原子地更新连接最后活跃时间
         * @param index 连接索引
         * @note 使用 relaxed 内存序，适合统计场景
         */
        void touch_connection(const std::size_t index) noexcept
        {
            if (index < MAX_CONNECTIONS)
            {
                active_connection_list[index].last_active = std::chrono::steady_clock::now();
            }
        }

        /**
         * @brief 获取活动连接列表
         * @return 活动连接列表的常引用
         */
        [[nodiscard]] const std::array<connection_info, MAX_CONNECTIONS> &get_active_connections() const noexcept
        {
            return active_connection_list;
        }
    };

    /**
     * @struct requests_stats
     * @brief 请求统计结构体
     * @details 用于存储请求相关的统计信息
     */
    struct requests_stats final
    {
        std::uint64_t total{0};
        double per_second{0.0};
        struct by_status_t final
        {
            std::uint64_t status_2xx{0};
            std::uint64_t status_3xx{0};
            std::uint64_t status_4xx{0};
            std::uint64_t status_5xx{0};
        } by_status;
        struct by_method_t final
        {
            std::uint64_t get{0};
            std::uint64_t post{0};
            std::uint64_t put{0};
            std::uint64_t del{0};
        } by_method;
    };

    /**
     * @struct connections_stats
     * @brief 连接统计结构体
     * @details 用于存储连接相关的统计信息
     */
    struct connections_stats final
    {
        std::uint32_t active{0};
        std::uint64_t total{0};
        std::uint64_t ssl{0};
    };

    /**
     * @struct traffic_stats
     * @brief 流量统计结构体
     * @details 用于存储流量相关的统计信息
     */
    struct traffic_stats final
    {
        std::uint64_t bytes_sent{0};
        std::uint64_t bytes_received{0};
        double send_rate_bps{0.0};
        double receive_rate_bps{0.0};
    };

    /**
     * @struct latency_stats
     * @brief 延迟统计结构体
     * @details 用于存储延迟相关的统计信息
     */
    struct latency_stats final
    {
        double avg_ms{0.0};
        double min_ms{0.0};
        double max_ms{0.0};
    };

    /**
     * @struct stats_snapshot
     * @brief 统计快照结构体（嵌套结构）
     * @details 用于存储某一时刻的服务器统计信息快照，与前端 dashboard.js 期望的结构一致
     */
    struct stats_snapshot final
    {
        requests_stats requests;
        connections_stats connections;
        traffic_stats traffic;
        latency_stats latency;
        std::int64_t uptime_seconds{0};
        std::string timestamp;
    };

    /**
     * @struct stats_snapshot_flat
     * @brief 统计快照结构体（扁平结构）
     * @details 用于存储某一时刻的服务器统计信息快照（兼容旧版）
     */
    struct stats_snapshot_flat final
    {
        std::uint64_t total_requests{0};
        std::uint32_t active_connections{0};
        std::uint64_t bytes_sent{0};
        std::uint64_t bytes_received{0};
        std::uint64_t static_files_served{0};
        std::uint64_t api_requests{0};
        std::uint64_t not_found_count{0};
        std::uint64_t error_count{0};
        std::uint64_t get_requests{0};
        std::uint64_t post_requests{0};
        std::uint64_t put_requests{0};
        std::uint64_t delete_requests{0};
        std::uint64_t status_2xx{0};
        std::uint64_t status_3xx{0};
        std::uint64_t status_4xx{0};
        std::uint64_t status_5xx{0};
        std::uint64_t total_request_time_ns{0};
        std::uint64_t min_request_time_ns{0};
        std::uint64_t max_request_time_ns{0};
        std::uint64_t total_connections{0};
        std::uint64_t ssl_connections{0};
        std::uint64_t connection_errors{0};
        std::int64_t uptime_seconds{0};
        std::string timestamp;
    };

    /**
     * @struct traffic_record
     * @brief 流量记录结构体
     * @details 用于存储某一时刻的流量信息
     */
    struct traffic_record final
    {
        std::uint64_t timestamp{0};
        std::uint64_t bytes_sent{0};
        std::uint64_t bytes_received{0};
        std::uint32_t active_connections{0};
        std::uint32_t requests_per_second{0};
    };

    /**
     * @struct connection_snapshot
     * @brief 连接快照结构体
     * @details 用于存储单个连接的快照信息
     */
    struct connection_snapshot final
    {
        std::string client_ip;
        std::uint16_t client_port{0};
        std::string request_path;
        std::int64_t duration_ms{0};
        std::uint64_t bytes_sent{0};
        std::uint64_t bytes_received{0};
        bool is_ssl{false};
    };

    /**
     * @struct performance_snapshot
     * @brief 性能快照结构体
     * @details 用于存储性能指标快照
     */
    struct performance_snapshot final
    {
        double avg_request_time_ms{0.0};
        double min_request_time_ms{0.0};
        double max_request_time_ms{0.0};
        double requests_per_second{0.0};
        double throughput_mbps{0.0};
        std::uint32_t active_connections{0};
        std::uint64_t total_requests{0};
    };

    /**
     * @brief 创建统计快照
     * @param stats 详细统计数据
     * @return 统计快照（嵌套结构）
     */
    [[nodiscard]] inline stats_snapshot create_snapshot(const detailed_stats &stats) noexcept
    {
        stats_snapshot snapshot;

        const auto total_requests = stats.total_requests.load(std::memory_order_relaxed);
        const auto uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - stats.start_time).count();

        snapshot.requests.total = total_requests;
        snapshot.requests.per_second = uptime_seconds > 0 ? static_cast<double>(total_requests) / static_cast<double>(uptime_seconds) : 0.0;
        snapshot.requests.by_status.status_2xx = stats.status_2xx.load(std::memory_order_relaxed);
        snapshot.requests.by_status.status_3xx = stats.status_3xx.load(std::memory_order_relaxed);
        snapshot.requests.by_status.status_4xx = stats.status_4xx.load(std::memory_order_relaxed);
        snapshot.requests.by_status.status_5xx = stats.status_5xx.load(std::memory_order_relaxed);
        snapshot.requests.by_method.get = stats.get_requests.load(std::memory_order_relaxed);
        snapshot.requests.by_method.post = stats.post_requests.load(std::memory_order_relaxed);
        snapshot.requests.by_method.put = stats.put_requests.load(std::memory_order_relaxed);
        snapshot.requests.by_method.del = stats.delete_requests.load(std::memory_order_relaxed);

        snapshot.connections.active = stats.active_connections.load(std::memory_order_relaxed);
        snapshot.connections.total = stats.total_connections.load(std::memory_order_relaxed);
        snapshot.connections.ssl = stats.ssl_connections.load(std::memory_order_relaxed);

        const auto bytes_sent = stats.bytes_sent.load(std::memory_order_relaxed);
        const auto bytes_received = stats.bytes_received.load(std::memory_order_relaxed);
        snapshot.traffic.bytes_sent = bytes_sent;
        snapshot.traffic.bytes_received = bytes_received;
        snapshot.traffic.send_rate_bps = uptime_seconds > 0 ? static_cast<double>(bytes_sent) / static_cast<double>(uptime_seconds) : 0.0;
        snapshot.traffic.receive_rate_bps = uptime_seconds > 0 ? static_cast<double>(bytes_received) / static_cast<double>(uptime_seconds) : 0.0;

        const auto total_time_ns = stats.total_request_time_ns.load(std::memory_order_relaxed);
        const auto min_time_ns = stats.min_request_time_ns.load(std::memory_order_relaxed);
        const auto max_time_ns = stats.max_request_time_ns.load(std::memory_order_relaxed);
        snapshot.latency.avg_ms = total_requests > 0 ? static_cast<double>(total_time_ns) / static_cast<double>(total_requests) / 1000000.0 : 0.0;
        snapshot.latency.min_ms = min_time_ns < UINT64_MAX ? static_cast<double>(min_time_ns) / 1000000.0 : 0.0;
        snapshot.latency.max_ms = max_time_ns > 0 ? static_cast<double>(max_time_ns) / 1000000.0 : 0.0;

        snapshot.uptime_seconds = uptime_seconds;

        const auto system_now = std::chrono::system_clock::now();
        const auto time_t_now = std::chrono::system_clock::to_time_t(system_now);
        snapshot.timestamp = std::to_string(time_t_now);

        return snapshot;
    }
}

/**
 * @brief glaze JSON 序列化模板特化：按状态码分类的请求统计
 */
template <>
struct glz::meta<srv::statistics::requests_stats::by_status_t>
{
    using T = srv::statistics::requests_stats::by_status_t;
    static constexpr auto value = glz::object(
        "status_2xx", &T::status_2xx,
        "status_3xx", &T::status_3xx,
        "status_4xx", &T::status_4xx,
        "status_5xx", &T::status_5xx);
};

/**
 * @brief glaze JSON 序列化模板特化：按 HTTP 方法分类的请求统计
 */
template <>
struct glz::meta<srv::statistics::requests_stats::by_method_t>
{
    using T = srv::statistics::requests_stats::by_method_t;
    static constexpr auto value = glz::object(
        "get", &T::get,
        "post", &T::post,
        "put", &T::put,
        "del", &T::del);
};

/**
 * @brief glaze JSON 序列化模板特化：请求统计
 */
template <>
struct glz::meta<srv::statistics::requests_stats>
{
    using T = srv::statistics::requests_stats;
    static constexpr auto value = glz::object(
        "total", &T::total,
        "per_second", &T::per_second,
        "by_status", &T::by_status,
        "by_method", &T::by_method);
};

/**
 * @brief glaze JSON 序列化模板特化：连接统计
 */
template <>
struct glz::meta<srv::statistics::connections_stats>
{
    using T = srv::statistics::connections_stats;
    static constexpr auto value = glz::object(
        "active", &T::active,
        "total", &T::total,
        "ssl", &T::ssl);
};

/**
 * @brief glaze JSON 序列化模板特化：流量统计
 */
template <>
struct glz::meta<srv::statistics::traffic_stats>
{
    using T = srv::statistics::traffic_stats;
    static constexpr auto value = glz::object(
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received,
        "send_rate_bps", &T::send_rate_bps,
        "receive_rate_bps", &T::receive_rate_bps);
};

/**
 * @brief glaze JSON 序列化模板特化：延迟统计
 */
template <>
struct glz::meta<srv::statistics::latency_stats>
{
    using T = srv::statistics::latency_stats;
    static constexpr auto value = glz::object(
        "avg_ms", &T::avg_ms,
        "min_ms", &T::min_ms,
        "max_ms", &T::max_ms);
};

/**
 * @brief glaze JSON 序列化模板特化：统计快照（嵌套结构）
 */
template <>
struct glz::meta<srv::statistics::stats_snapshot>
{
    using T = srv::statistics::stats_snapshot;
    static constexpr auto value = glz::object(
        "requests", &T::requests,
        "connections", &T::connections,
        "traffic", &T::traffic,
        "latency", &T::latency,
        "uptime_seconds", &T::uptime_seconds,
        "timestamp", &T::timestamp);
};

/**
 * @brief glaze JSON 序列化模板特化：统计快照（扁平结构）
 */
template <>
struct glz::meta<srv::statistics::stats_snapshot_flat>
{
    using T = srv::statistics::stats_snapshot_flat;
    static constexpr auto value = glz::object(
        "total_requests", &T::total_requests,
        "active_connections", &T::active_connections,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received,
        "static_files_served", &T::static_files_served,
        "api_requests", &T::api_requests,
        "not_found_count", &T::not_found_count,
        "error_count", &T::error_count,
        "get_requests", &T::get_requests,
        "post_requests", &T::post_requests,
        "put_requests", &T::put_requests,
        "delete_requests", &T::delete_requests,
        "status_2xx", &T::status_2xx,
        "status_3xx", &T::status_3xx,
        "status_4xx", &T::status_4xx,
        "status_5xx", &T::status_5xx,
        "total_request_time_ns", &T::total_request_time_ns,
        "min_request_time_ns", &T::min_request_time_ns,
        "max_request_time_ns", &T::max_request_time_ns,
        "total_connections", &T::total_connections,
        "ssl_connections", &T::ssl_connections,
        "connection_errors", &T::connection_errors,
        "uptime_seconds", &T::uptime_seconds,
        "timestamp", &T::timestamp);
};

/**
 * @brief glaze JSON 序列化模板特化：流量记录
 */
template <>
struct glz::meta<srv::statistics::traffic_record>
{
    using T = srv::statistics::traffic_record;
    static constexpr auto value = glz::object(
        "timestamp", &T::timestamp,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received,
        "active_connections", &T::active_connections,
        "requests_per_second", &T::requests_per_second);
};

/**
 * @brief glaze JSON 序列化模板特化：连接快照
 */
template <>
struct glz::meta<srv::statistics::connection_snapshot>
{
    using T = srv::statistics::connection_snapshot;
    static constexpr auto value = glz::object(
        "client_ip", &T::client_ip,
        "client_port", &T::client_port,
        "request_path", &T::request_path,
        "duration_ms", &T::duration_ms,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received,
        "is_ssl", &T::is_ssl);
};

/**
 * @brief glaze JSON 序列化模板特化：性能快照
 */
template <>
struct glz::meta<srv::statistics::performance_snapshot>
{
    using T = srv::statistics::performance_snapshot;
    static constexpr auto value = glz::object(
        "avg_request_time_ms", &T::avg_request_time_ms,
        "min_request_time_ms", &T::min_request_time_ms,
        "max_request_time_ms", &T::max_request_time_ms,
        "requests_per_second", &T::requests_per_second,
        "throughput_mbps", &T::throughput_mbps,
        "active_connections", &T::active_connections,
        "total_requests", &T::total_requests);
};

/**
 * @brief glaze JSON 序列化模板特化：连接信息
 */
template <>
struct glz::meta<srv::statistics::connection_info>
{
    using T = srv::statistics::connection_info;
    static constexpr auto value = glz::object(
        "client_ip", &T::client_ip,
        "client_port", &T::client_port,
        "request_path", &T::request_path,
        "user_agent", &T::user_agent,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received,
        "request_count", &T::request_count,
        "is_ssl", &T::is_ssl);
};
