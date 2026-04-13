/**
 * @file salts.hpp
 * @brief SS2022 Salt 重放保护池
 * @details SIP022 规范要求精确匹配的 salt 重放检测，禁止使用 Bloom filter。
 * 每个 salt 在 TTL 内只能出现一次。该池可跨会话共享（线程安全）。
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <span>
#include <vector>
#include <unordered_map>

namespace psm::protocol::shadowsocks
{
    /**
     * @class salt_pool
     * @brief Salt 重放检测池
     * @details 维护已见 salt 的精确集合，配合 TTL 自动过期清理。
     * 线程安全，可跨多个 relay 会话共享。
     */
    class salt_pool
    {
    public:
        /**
         * @brief 构造 salt 池
         * @param ttl_seconds Salt 条目的生存时间（默认 60 秒）
         */
        explicit salt_pool(std::int64_t ttl_seconds = 60)
            : ttl_(std::chrono::seconds(ttl_seconds))
        {
        }

        /**
         * @brief 检查并插入 salt
         * @param salt Salt 数据
         * @return true 表示首次出现（已插入），false 表示重放
         */
        auto check_and_insert(std::span<const std::uint8_t> salt) -> bool
        {
            std::lock_guard lock(mutex_);
            cleanup_locked();

            const auto key = to_key(salt);
            const auto now = std::chrono::steady_clock::now();

            if (const auto it = entries_.find(key); it != entries_.end())
            {
                // 已存在，检查是否过期
                if (it->second > now)
                {
                    return false; // 重放
                }
                // 已过期，更新
                it->second = now + ttl_;
                return true;
            }

            entries_.emplace(key, now + ttl_);
            return true;
        }

        /**
         * @brief 清理过期条目
         */
        void cleanup()
        {
            std::lock_guard lock(mutex_);
            cleanup_locked();
        }

    private:
        void cleanup_locked()
        {
            const auto now = std::chrono::steady_clock::now();
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                if (it->second <= now)
                {
                    it = entries_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        static auto to_key(std::span<const std::uint8_t> salt) -> std::string
        {
            return {reinterpret_cast<const char *>(salt.data()), salt.size()};
        }

        std::unordered_map<std::string, std::chrono::steady_clock::time_point> entries_;
        std::mutex mutex_;
        std::chrono::seconds ttl_;
    };
} // namespace psm::protocol::shadowsocks
