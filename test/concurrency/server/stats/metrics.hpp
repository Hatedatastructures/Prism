/**
 * @file metrics.hpp
 * @brief 服务器统计指标定义
 * @details 定义了服务器运行时统计信息的存储结构，包括请求数、连接数、字节数等。
 *
 * 核心特性：
 * - 原子操作：所有计数器使用 std::atomic 保证线程安全
 * - 内存序优化：使用 relaxed 内存序减少同步开销
 * - 扩展统计：支持按方法、按状态码分类的详细统计
 * - 时间追踪：记录请求处理时间（最小、最大、平均）
 *
 * @note 设计原则：
 * - 高性能：所有操作均为原子操作，无锁设计
 * - 低开销：使用 relaxed 内存序，适合统计场景
 * - 可扩展：支持添加新的统计维度
 *
 */
#pragma once

#include <atomic>
#include <array>
#include <cstdint>
#include <string_view>
#include <chrono>
#include <limits>

#include "connection.hpp"

namespace srv::stats
{
    /**
     * @struct server_stats
     * @brief 服务器统计信息结构体
     * @details 用于跟踪服务器的各种运行时指标，包括请求数、连接数、字节数等
     */
    struct server_stats final
    {
        std::atomic<std::uint64_t> total_requests{0};
        std::atomic<std::uint32_t> active_connections{0};
        std::atomic<std::uint64_t> bytes_sent{0};
        std::atomic<std::uint64_t> bytes_received{0};
        std::atomic<std::uint64_t> static_files_served{0};
        std::atomic<std::uint64_t> api_requests{0};
        std::atomic<std::uint64_t> not_found_count{0};
        std::atomic<std::uint64_t> error_count{0};

        void increment_requests() noexcept
        {
            total_requests.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_static_files() noexcept
        {
            static_files_served.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_api_requests() noexcept
        {
            api_requests.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_not_found() noexcept
        {
            not_found_count.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_errors() noexcept
        {
            error_count.fetch_add(1, std::memory_order_relaxed);
        }

        void add_connection() noexcept
        {
            active_connections.fetch_add(1, std::memory_order_relaxed);
        }

        void remove_connection() noexcept
        {
            active_connections.fetch_sub(1, std::memory_order_relaxed);
        }

        void add_bytes_sent(std::uint64_t bytes) noexcept
        {
            bytes_sent.fetch_add(bytes, std::memory_order_relaxed);
        }

        void add_bytes_received(std::uint64_t bytes) noexcept
        {
            bytes_received.fetch_add(bytes, std::memory_order_relaxed);
        }
    };

    /**
     * @struct detailed_stats
     * @brief 详细统计数据结构体
     * @details 扩展的服务器统计信息，包含按方法分类、按状态分类、时间统计等详细信息
     */
    struct detailed_stats final
    {
        std::atomic<std::uint64_t> total_requests{0};
        std::atomic<std::uint32_t> active_connections{0};
        std::atomic<std::uint64_t> bytes_sent{0};
        std::atomic<std::uint64_t> bytes_received{0};
        std::atomic<std::uint64_t> static_files_served{0};
        std::atomic<std::uint64_t> api_requests{0};
        std::atomic<std::uint64_t> not_found_count{0};
        std::atomic<std::uint64_t> error_count{0};

        std::atomic<std::uint64_t> get_requests{0};
        std::atomic<std::uint64_t> post_requests{0};
        std::atomic<std::uint64_t> put_requests{0};
        std::atomic<std::uint64_t> delete_requests{0};

        std::atomic<std::uint64_t> status_2xx{0};
        std::atomic<std::uint64_t> status_3xx{0};
        std::atomic<std::uint64_t> status_4xx{0};
        std::atomic<std::uint64_t> status_5xx{0};

        std::atomic<std::uint64_t> total_request_time_ns{0};
        std::atomic<std::uint64_t> min_request_time_ns{UINT64_MAX};
        std::atomic<std::uint64_t> max_request_time_ns{0};

        std::atomic<std::uint64_t> total_connections{0};
        std::atomic<std::uint64_t> ssl_connections{0};
        std::atomic<std::uint64_t> connection_errors{0};

        std::chrono::steady_clock::time_point start_time;

        static constexpr std::size_t MAX_CONNECTIONS = 2048;
        std::array<connection_info, MAX_CONNECTIONS> active_connection_list;
        std::atomic<std::size_t> connection_list_head{0};

        detailed_stats() noexcept
            : start_time(std::chrono::steady_clock::now())
        {
        }

        void increment_requests() noexcept
        {
            total_requests.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_static_files() noexcept
        {
            static_files_served.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_api_requests() noexcept
        {
            api_requests.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_not_found() noexcept
        {
            not_found_count.fetch_add(1, std::memory_order_relaxed);
        }

        void increment_errors() noexcept
        {
            error_count.fetch_add(1, std::memory_order_relaxed);
        }

        void add_connection() noexcept
        {
            active_connections.fetch_add(1, std::memory_order_relaxed);
            total_connections.fetch_add(1, std::memory_order_relaxed);
        }

        void remove_connection() noexcept
        {
            active_connections.fetch_sub(1, std::memory_order_relaxed);
        }

        void add_bytes_sent(std::uint64_t bytes) noexcept
        {
            bytes_sent.fetch_add(bytes, std::memory_order_relaxed);
        }

        void add_bytes_received(std::uint64_t bytes) noexcept
        {
            bytes_received.fetch_add(bytes, std::memory_order_relaxed);
        }

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

        void record_status_code(std::uint16_t status_code) noexcept
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

        void record_method(std::string_view method) noexcept
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

        [[nodiscard]] std::size_t add_connection_info(const connection_info &info) noexcept
        {
            const std::size_t index = connection_list_head.fetch_add(1, std::memory_order_relaxed) % MAX_CONNECTIONS;
            active_connection_list[index] = info;
            return index;
        }

        void update_connection_info(std::size_t index, const connection_info &info) noexcept
        {
            if (index < MAX_CONNECTIONS)
            {
                active_connection_list[index] = info;
            }
        }

        [[nodiscard]] const std::array<connection_info, MAX_CONNECTIONS> &get_active_connections() const noexcept
        {
            return active_connection_list;
        }
    };
}
