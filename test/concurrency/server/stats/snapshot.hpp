/**
 * @file snapshot.hpp
 * @brief 统计快照定义
 * @details 定义了服务器统计快照的结构，用于序列化和导出统计数据。
 *
 * 核心特性：
 * - JSON 序列化：使用 glaze 库支持 JSON 序列化
 * - 时间戳：记录快照生成时间
 * - 完整统计：包含所有统计指标
 *
 * @note 设计原则：
 * - 简单数据载体：仅存储快照数据，不包含业务逻辑
 * - 序列化友好：所有字段均为可序列化类型
 *
 */
#pragma once

#include <cstdint>
#include <string>
#include <chrono>
#include <array>

#include "metrics.hpp"
#include <glaze/glaze.hpp>

namespace srv::stats
{
    /**
     * @struct stats_snapshot
     * @brief 统计快照结构体
     * @details 用于存储某一时刻的服务器统计信息快照
     */
    struct stats_snapshot final
    {
        std::uint64_t total_requests;
        std::uint32_t active_connections;
        std::uint64_t bytes_sent;
        std::uint64_t bytes_received;
        std::uint64_t static_files_served;
        std::uint64_t api_requests;
        std::uint64_t not_found_count;
        std::uint64_t error_count;
        std::uint64_t get_requests;
        std::uint64_t post_requests;
        std::uint64_t put_requests;
        std::uint64_t delete_requests;
        std::uint64_t status_2xx;
        std::uint64_t status_3xx;
        std::uint64_t status_4xx;
        std::uint64_t status_5xx;
        std::uint64_t total_request_time_ns;
        std::uint64_t min_request_time_ns;
        std::uint64_t max_request_time_ns;
        std::uint64_t total_connections;
        std::uint64_t ssl_connections;
        std::uint64_t connection_errors;
        std::int64_t uptime_seconds;
        std::string timestamp;
    };

    /**
     * @struct traffic_record
     * @brief 流量记录结构体
     * @details 用于存储某一时刻的流量信息
     */
    struct traffic_record final
    {
        std::uint64_t timestamp;
        std::uint64_t bytes_sent;
        std::uint64_t bytes_received;
        std::uint32_t active_connections;
        std::uint32_t requests_per_second;
    };

    /**
     * @struct connection_snapshot
     * @brief 连接快照结构体
     * @details 用于存储单个连接的快照信息
     */
    struct connection_snapshot final
    {
        std::string client_ip;
        std::uint16_t client_port;
        std::string request_path;
        std::int64_t duration_ms;
        std::uint64_t bytes_sent;
        std::uint64_t bytes_received;
        bool is_ssl;
    };

    /**
     * @struct performance_snapshot
     * @brief 性能快照结构体
     * @details 用于存储性能指标快照
     */
    struct performance_snapshot final
    {
        double avg_request_time_ms;
        double min_request_time_ms;
        double max_request_time_ms;
        double requests_per_second;
        double throughput_mbps;
        std::uint32_t active_connections;
        std::uint64_t total_requests;
    };

    [[nodiscard]] inline stats_snapshot create_snapshot(const detailed_stats &stats) noexcept
    {
        stats_snapshot snapshot;
        snapshot.total_requests = stats.total_requests.load(std::memory_order_relaxed);
        snapshot.active_connections = stats.active_connections.load(std::memory_order_relaxed);
        snapshot.bytes_sent = stats.bytes_sent.load(std::memory_order_relaxed);
        snapshot.bytes_received = stats.bytes_received.load(std::memory_order_relaxed);
        snapshot.static_files_served = stats.static_files_served.load(std::memory_order_relaxed);
        snapshot.api_requests = stats.api_requests.load(std::memory_order_relaxed);
        snapshot.not_found_count = stats.not_found_count.load(std::memory_order_relaxed);
        snapshot.error_count = stats.error_count.load(std::memory_order_relaxed);
        snapshot.get_requests = stats.get_requests.load(std::memory_order_relaxed);
        snapshot.post_requests = stats.post_requests.load(std::memory_order_relaxed);
        snapshot.put_requests = stats.put_requests.load(std::memory_order_relaxed);
        snapshot.delete_requests = stats.delete_requests.load(std::memory_order_relaxed);
        snapshot.status_2xx = stats.status_2xx.load(std::memory_order_relaxed);
        snapshot.status_3xx = stats.status_3xx.load(std::memory_order_relaxed);
        snapshot.status_4xx = stats.status_4xx.load(std::memory_order_relaxed);
        snapshot.status_5xx = stats.status_5xx.load(std::memory_order_relaxed);
        snapshot.total_request_time_ns = stats.total_request_time_ns.load(std::memory_order_relaxed);
        snapshot.min_request_time_ns = stats.min_request_time_ns.load(std::memory_order_relaxed);
        snapshot.max_request_time_ns = stats.max_request_time_ns.load(std::memory_order_relaxed);
        snapshot.total_connections = stats.total_connections.load(std::memory_order_relaxed);
        snapshot.ssl_connections = stats.ssl_connections.load(std::memory_order_relaxed);
        snapshot.connection_errors = stats.connection_errors.load(std::memory_order_relaxed);

        const auto now = std::chrono::steady_clock::now();
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats.start_time);
        snapshot.uptime_seconds = uptime.count();

        const auto system_now = std::chrono::system_clock::now();
        const auto time_t_now = std::chrono::system_clock::to_time_t(system_now);
        snapshot.timestamp = std::to_string(time_t_now);

        return snapshot;
    }
}

template <>
struct glz::meta<srv::stats::stats_snapshot>
{
    using T = srv::stats::stats_snapshot;
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

template <>
struct glz::meta<srv::stats::traffic_record>
{
    using T = srv::stats::traffic_record;
    static constexpr auto value = glz::object(
        "timestamp", &T::timestamp,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received,
        "active_connections", &T::active_connections,
        "requests_per_second", &T::requests_per_second);
};

template <>
struct glz::meta<srv::stats::connection_snapshot>
{
    using T = srv::stats::connection_snapshot;
    static constexpr auto value = glz::object(
        "client_ip", &T::client_ip,
        "client_port", &T::client_port,
        "request_path", &T::request_path,
        "duration_ms", &T::duration_ms,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received,
        "is_ssl", &T::is_ssl);
};

template <>
struct glz::meta<srv::stats::performance_snapshot>
{
    using T = srv::stats::performance_snapshot;
    static constexpr auto value = glz::object(
        "avg_request_time_ms", &T::avg_request_time_ms,
        "min_request_time_ms", &T::min_request_time_ms,
        "max_request_time_ms", &T::max_request_time_ms,
        "requests_per_second", &T::requests_per_second,
        "throughput_mbps", &T::throughput_mbps,
        "active_connections", &T::active_connections,
        "total_requests", &T::total_requests);
};

template <>
struct glz::meta<srv::stats::connection_info>
{
    using T = srv::stats::connection_info;
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
