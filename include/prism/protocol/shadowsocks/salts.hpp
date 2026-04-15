/**
 * @file salts.hpp
 * @brief SS2022 Salt 重放保护池
 * @details SIP022 规范要求精确匹配的 salt 重放检测，禁止使用 Bloom filter。
 * 每个 salt 在 TTL 内只能出现一次。该池为 worker 线程独占，无需锁。
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace psm::protocol::shadowsocks
{
    /**
     * @class salt_pool
     * @brief Salt 重放检测池
     * @details 维护已见 salt 的精确集合，配合 TTL 自动过期清理。
     * 每个 worker 线程持有独立实例（thread_local），无需线程同步。
     */
    class salt_pool
    {
        // 异构查找：允许用 string_view 查找，无需构造 string
        struct string_hash
        {
            using is_transparent = void;
            auto operator()(std::string_view sv) const noexcept -> std::size_t
            {
                // FNV-1a
                std::size_t h = 0xcbf29ce484222325ULL;
                for (char c : sv)
                {
                    h ^= static_cast<std::size_t>(c);
                    h *= 0x100000001b3ULL;
                }
                return h;
            }
        };

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
            // 分摊清理：仅当距上次清理超过 1 秒时才执行
            const auto now = std::chrono::steady_clock::now();
            if (now - last_cleanup_ >= std::chrono::seconds(1))
            {
                cleanup();
                last_cleanup_ = now;
            }

            // 异构查找：直接用 string_view 指向 salt 原始字节，零分配
            const auto key = std::string_view(
                reinterpret_cast<const char *>(salt.data()), salt.size());

            if (const auto it = entries_.find(key); it != entries_.end())
            {
                if (it->second > now)
                {
                    return false; // 重放
                }
                it->second = now + ttl_;
                return true;
            }

            entries_.emplace(std::string(key), now + ttl_);
            return true;
        }

        /**
         * @brief 清理过期条目
         */
        void cleanup()
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

    private:
        std::unordered_map<std::string, std::chrono::steady_clock::time_point,
                           string_hash, std::equal_to<>>
            entries_;
        std::chrono::seconds ttl_;
        std::chrono::steady_clock::time_point last_cleanup_{};
    };
} // namespace psm::protocol::shadowsocks
