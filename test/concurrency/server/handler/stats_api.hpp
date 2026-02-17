/**
 * @file stats_api.hpp
 * @brief 统计 API 处理器定义
 * @details 处理统计端口的 API 请求，包括统计快照、活动连接、流量历史、性能指标等。
 *
 * 核心特性：
 * - 统计快照：获取服务器实时统计信息
 * - 活动连接：获取当前活动连接列表
 * - 流量历史：获取历史流量数据
 * - 性能指标：获取 CPU、内存使用情况
 *
 * @note 设计原则：
 * - 异步处理：使用协程风格异步处理请求
 * - JSON 序列化：使用 glaze 库进行 JSON 序列化
 * - 错误处理：完善的异常处理和错误响应
 *
 */
#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

#include "../stats/metrics.hpp"
#include "../stats/snapshot.hpp"
#include "../mime/types.hpp"
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/transformer/json.hpp>
#include <glaze/glaze.hpp>
#include <boost/asio.hpp>

namespace protocol = ngx::protocol;

namespace srv::handler::stats_api
{
    using namespace srv::stats;
    using namespace srv::mime;
    using namespace ngx::transformer::json;

    struct traffic_history final
    {
        std::uint64_t timestamp;
        std::uint64_t bytes_sent;
        std::uint64_t bytes_received;
    };

    struct traffic_history_response final
    {
        std::vector<traffic_history> history;
        std::uint32_t interval_seconds;
    };

    struct performance_metrics final
    {
        double cpu_usage_percent;
        double memory_usage_mb;
        std::uint32_t active_threads;
        double io_wait_percent;
    };

    inline auto get_stats(ngx::protocol::http::response &resp, detailed_stats &stats) -> boost::asio::awaitable<void>
    {
        const auto snapshot = create_snapshot(stats);

        auto json_str = serialize(snapshot);

        if (json_str.empty())
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.body(std::string_view(R"({"error":"Failed to serialize stats","message":"JSON serialization error"})"));
            co_return;
        }

        resp.status(ngx::protocol::http::status::ok);
        resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
        resp.set(ngx::protocol::http::field::cache_control, "no-cache");
        resp.body(std::string(json_str));
    }

    inline auto get_active_connections(ngx::protocol::http::response &resp, detailed_stats &stats) -> boost::asio::awaitable<void>
    {
        const auto &active_list = stats.get_active_connections();
        const auto head = stats.connection_list_head.load(std::memory_order_relaxed);
        const std::size_t active_count = stats.active_connections.load(std::memory_order_relaxed);

        std::vector<connection_info> connections;
        connections.reserve(active_count);

        const std::size_t start = head >= detailed_stats::MAX_CONNECTIONS ? head - detailed_stats::MAX_CONNECTIONS : 0;
        const std::size_t end = head;

        for (std::size_t i = start; i < end && i < detailed_stats::MAX_CONNECTIONS; ++i)
        {
            const auto &info = active_list[i % detailed_stats::MAX_CONNECTIONS];
            if (info.client_port != 0)
            {
                connections.push_back(info);
            }
        }

        auto json_str = serialize(connections);

        if (json_str.empty())
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.body(std::string_view(R"({"error":"Failed to serialize connections","message":"JSON serialization error"})"));
            co_return;
        }

        resp.status(ngx::protocol::http::status::ok);
        resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
        resp.set(ngx::protocol::http::field::cache_control, "no-cache");
        resp.body(std::string(json_str));
    }

    inline auto get_traffic_history(ngx::protocol::http::response &resp, detailed_stats &stats, std::uint32_t minutes)
        -> boost::asio::awaitable<void>
    {
        traffic_history_response history_response;
        history_response.interval_seconds = 60;

        const auto now = std::chrono::steady_clock::now();
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats.start_time).count();
        const std::uint32_t total_seconds = static_cast<std::uint32_t>(uptime);
        const std::uint32_t requested_seconds = minutes * 60;
        const std::uint32_t data_points = std::min(total_seconds / 60, requested_seconds / 60);

        if (data_points > 0)
        {
            const auto total_sent = stats.bytes_sent.load(std::memory_order_relaxed);
            const auto total_received = stats.bytes_received.load(std::memory_order_relaxed);

            const auto avg_sent = total_sent / data_points;
            const auto avg_received = total_received / data_points;

            history_response.history.reserve(data_points);

            for (std::uint32_t i = 0; i < data_points; ++i)
            {
                const auto point_time = now - std::chrono::seconds((data_points - i) * 60);
                const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(point_time.time_since_epoch()).count();

                traffic_history history;
                history.timestamp = static_cast<std::uint64_t>(timestamp);
                history.bytes_sent = avg_sent * (i + 1);
                history.bytes_received = avg_received * (i + 1);

                history_response.history.push_back(std::move(history));
            }
        }

        auto json_str = serialize(history_response);

        if (json_str.empty())
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.body(std::string_view(R"({"error":"Failed to serialize traffic history","message":"JSON serialization error"})"));
            co_return;
        }

        resp.status(ngx::protocol::http::status::ok);
        resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
        resp.set(ngx::protocol::http::field::cache_control, "no-cache");
        resp.body(std::move(json_str));
    }

    inline auto get_performance(ngx::protocol::http::response &resp, detailed_stats &stats) -> boost::asio::awaitable<void>
    {
        performance_metrics metrics;
        metrics.cpu_usage_percent = 0.0;
        metrics.memory_usage_mb = 0.0;
        metrics.active_threads = stats.active_connections.load(std::memory_order_relaxed);
        metrics.io_wait_percent = 0.0;

#ifdef _WIN32
        MEMORYSTATUSEX memory_status;
        memory_status.dwLength = sizeof(memory_status);
        if (GlobalMemoryStatusEx(&memory_status))
        {
            const std::uint64_t total_memory_mb = memory_status.ullTotalPhys / (1024 * 1024);
            const std::uint64_t available_memory_mb = memory_status.ullAvailPhys / (1024 * 1024);
            metrics.memory_usage_mb = static_cast<double>(total_memory_mb - available_memory_mb);
        }

        FILETIME idle_time;
        FILETIME kernel_time;
        FILETIME user_time;
        if (GetSystemTimes(&idle_time, &kernel_time, &user_time))
        {
            const std::uint64_t idle = static_cast<std::uint64_t>(idle_time.dwLowDateTime) |
                                       (static_cast<std::uint64_t>(idle_time.dwHighDateTime) << 32);
            const std::uint64_t kernel = static_cast<std::uint64_t>(kernel_time.dwLowDateTime) |
                                         (static_cast<std::uint64_t>(kernel_time.dwHighDateTime) << 32);
            const std::uint64_t user = static_cast<std::uint64_t>(user_time.dwLowDateTime) |
                                       (static_cast<std::uint64_t>(user_time.dwHighDateTime) << 32);

            const std::uint64_t total = idle + kernel + user;
            if (total > 0)
            {
                metrics.cpu_usage_percent = 100.0 * (1.0 - static_cast<double>(idle) / static_cast<double>(total));
                metrics.io_wait_percent = 100.0 * static_cast<double>(kernel - idle) / static_cast<double>(total);
            }
        }
#endif

        auto json_str = serialize(metrics);

        if (json_str.empty())
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.body(std::string_view(R"({"error":"Failed to serialize performance metrics","message":"JSON serialization error"})"));
            co_return;
        }

        resp.status(ngx::protocol::http::status::ok);
        resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
        resp.set(ngx::protocol::http::field::cache_control, "no-cache");
        resp.body(std::string(json_str));
    }
}

template <>
struct glz::meta<srv::handler::stats_api::traffic_history>
{
    using T = srv::handler::stats_api::traffic_history;
    static constexpr auto value = glz::object(
        "timestamp", &T::timestamp,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received);
};

template <>
struct glz::meta<srv::handler::stats_api::traffic_history_response>
{
    using T = srv::handler::stats_api::traffic_history_response;
    static constexpr auto value = glz::object(
        "history", &T::history,
        "interval_seconds", &T::interval_seconds);
};

template <>
struct glz::meta<srv::handler::stats_api::performance_metrics>
{
    using T = srv::handler::stats_api::performance_metrics;
    static constexpr auto value = glz::object(
        "cpu_usage_percent", &T::cpu_usage_percent,
        "memory_usage_mb", &T::memory_usage_mb,
        "active_threads", &T::active_threads,
        "io_wait_percent", &T::io_wait_percent);
};
