/**
 * @file coalescer.hpp
 * @brief 请求合并器
 * @details 该组件实现了请求合并模式，用于将同一目标的并发请求合并为单次操作。
 * 当多个协程同时请求同一资源时，仅执行一次实际操作，其他协程等待结果复用。
 * 这在 DNS 解析等场景中特别有用，可以有效降低服务器压力。
 * @note 该组件不是线程安全的，应在单线程上下文中使用
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <string_view>

#include <boost/asio.hpp>

#include <prism/resolve/dns/detail/transparent.hpp>
#include <prism/memory/container.hpp>

namespace psm::resolve::dns::detail
{
    namespace net = boost::asio;

    /**
     * @class coalescer
     * @brief 请求合并器。
     * @details 该类实现了请求合并模式，用于优化并发请求场景。当多个协程
     * 同时请求同一目标时，仅执行一次实际操作，其他协程等待结果后复用。
     * 核心机制包括：请求标识，通过键字符串唯一标识一个请求。请求跟踪，
     * 使用 flight 结构体跟踪正在进行的请求。等待机制，使用定时器挂起
     * 等待的协程。结果广播，请求完成后通知所有等待者。延迟清理，使用
     * pending_cleanup 标记避免迭代器失效问题。
     * @note 该类不是线程安全的，应在单个线程上下文中使用。
     * @warning 等待的协程必须最终被通知，否则会永久挂起。
     */
    class coalescer
    {
    public:
        /**
         * @struct flight
         * @brief 请求合并结构体。
         * @details 用于跟踪正在进行的请求，支持多个协程等待同一请求完成。
         * 包含一个永不超时的定时器，用于挂起等待的协程。
         */
        struct flight
        {
            /**
             * @brief 构造请求合并记录
             * @details 初始化查找键和等待定时器，定时器设为永不超时，
             * 用于挂起等待的协程直到请求完成。
             * @param value 查找键字符串
             * @param executor 执行器，用于创建等待定时器
             */
            explicit flight(memory::string value, const net::any_io_executor &executor)
                : key(std::move(value)), timer(executor)
            {
                timer.expires_at(std::chrono::steady_clock::time_point::max());
            }

            memory::string key;          // 查找键
            net::steady_timer timer;     // 等待定时器
            std::size_t waiters{0};      // 等待者计数
            bool ready{false};           // 是否已完成
            bool pending_cleanup{false}; // 是否待清理
        };

        using flight_list = memory::list<flight>;                                                                              // 请求合并列表类型
        using flight_iterator = flight_list::iterator;                                                                         // 请求合并列表迭代器
        using flight_hash_map = memory::unordered_map<std::string_view, flight_iterator, transparent_hash, transparent_equal>; // 请求合并索引类型

        /**
         * @brief 构造请求合并器
         * @details 使用指定的内存资源初始化内部的请求合并列表和索引。
         * @param mr 内存资源，用于内部存储分配
         */
        explicit coalescer(const memory::resource_pointer mr = memory::current_resource())
            : mr_(mr), flights_(mr), flight_map_(mr)
        {
        }

        /**
         * @brief 构造查找键字符串
         * @details 将主机名和端口号拼接为 "host:port" 格式的键字符串，
         * 用于唯一标识一个请求目标。
         * @param host 主机名
         * @param port 服务端口
         * @return 格式为 "host:port" 的键字符串
         */
        [[nodiscard]] auto make_key(const std::string_view host, const std::string_view port) const -> memory::string
        {
            memory::string key(mr_);
            key.reserve(host.size() + port.size() + 1);
            key.append(host);
            key.push_back(':');
            key.append(port);
            return key;
        }

        /**
         * @brief 查找或创建请求合并记录
         * @details 若该键对应的请求正在进行中，返回现有记录；
         * 否则创建新的请求记录。键存储在 flight 对象中，确保
         * 哈希表中的 string_view 键指向有效的内存。
         * @param key 查找键
         * @param executor 执行器，用于创建等待定时器
         * @return 请求合并记录的迭代器和是否为新创建的标志
         */
        auto find_or_create(const memory::string &key, const net::any_io_executor &executor)
            -> std::pair<flight_iterator, bool>
        {
            const std::string_view key_view(key);
            if (const auto it = flight_map_.find(key_view); it != flight_map_.end())
            {
                return {it->second, false};
            }

            flights_.emplace_back(key, executor);
            const auto flight_it = std::prev(flights_.end());
            flight_map_.emplace(std::string_view(flight_it->key), flight_it);
            return {flight_it, true};
        }

        /**
         * @brief 标记请求合并记录待清理
         * @details 当请求已完成且无等待者时，标记为待清理状态。
         * 实际删除操作在 flush_cleanup 中执行，避免迭代器失效。
         * @param flight 请求合并记录的迭代器
         */
        static void cleanup_flight(const flight_iterator flight)
        {
            if (flight->ready && flight->waiters == 0)
            {
                flight->pending_cleanup = true;
            }
        }

        /**
         * @brief 执行延迟清理
         * @details 删除所有标记为 pending_cleanup 的 flight 记录。
         * 应在安全时机调用，例如下一次请求开始前。
         * 使用安全的方式遍历和删除，避免迭代器失效。
         */
        void flush_cleanup()
        {
            auto it = flights_.begin();
            while (it != flights_.end())
            {
                if (it->pending_cleanup)
                {
                    flight_map_.erase(it->key);
                    it = flights_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

    private:
        memory::resource_pointer mr_; // 内存资源
        flight_list flights_;         // 请求合并列表
        flight_hash_map flight_map_;  // 请求合并索引
    };
} // namespace psm::resolve::dns::detail
