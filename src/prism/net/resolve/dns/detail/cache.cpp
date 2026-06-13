#include <prism/net/resolve/dns/detail/cache.hpp>

#include <prism/core/memory/container.hpp>
#include <prism/trace/trace.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

using namespace psm::trace;

namespace
{
    auto resolve_mr(psm::memory::resource_pointer mr) -> psm::memory::resource_pointer
    {
        if (mr)
            return mr;
        return psm::memory::current_resource();
    }
} // namespace

namespace psm::resolve::dns::detail
{

    cache::cache(const cache_options &opts)
        : mr_(resolve_mr(opts.mr)),
          default_ttl_(opts.ttl), max_entries_(opts.max_entries),
          serve_stale_(opts.stale == stale_policy::serve), lru_order_(mr_), entries_(mr_)
    {
    }

    auto cache::make_key(const std::string_view domain, const qtype qt) const
        -> memory::string
    {
        // qtype 数值转为字符串（最大 3 位，如 "65535"）
        const auto num = static_cast<std::uint16_t>(qt);
        const auto num_str = std::to_string(num);

        // 预计算最终长度，一次分配完成
        memory::string key(mr_);
        key.reserve(domain.size() + 1 + num_str.size());
        key.append(domain);
        key.push_back(':');
        key.append(num_str);

        return key;
    }

    auto cache::key_view(const std::string_view domain, const qtype qt,
                              const std::span<char> buffer)
        -> std::string_view
    {
        const auto num = static_cast<std::uint16_t>(qt);
        const auto num_len = std::snprintf(buffer.data() + domain.size() + 1, 6, "%u", num);
        std::memcpy(buffer.data(), domain.data(), domain.size());
        buffer[domain.size()] = ':';
        return std::string_view(buffer.data(), domain.size() + 1 + num_len);
    }

    auto cache::get(const std::string_view domain, const qtype qt)
        -> std::optional<memory::vector<net::ip::address>>
    {
        // 使用栈缓冲区构造查找 key，避免 PMR 分配
        std::array<char, 260> buffer;
        const auto key = key_view(domain, qt, buffer);
        const auto it = entries_.find(key);

        // 未命中
        if (it == entries_.end())
        {
            return std::nullopt;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto &entry = it->second.first; // pair<cache_entry, lru_list::iterator>
        const auto &lru_it = it->second.second;

        // 未过期：直接返回结果，并更新 LRU 顺序（移动到链表头部）
        if (now < entry.expire)
        {
            // LRU 更新：将访问的键移到链表头部
            lru_order_.splice(lru_order_.begin(), lru_order_, lru_it);

            // 正向缓存：返回 IP 列表
            if (!entry.failed)
            {
                return memory::vector<net::ip::address>(entry.ips, mr_);
            }

            // 负缓存命中：返回空 vector
            trace::debug("negative cache hit: {}", domain);
            return memory::vector<net::ip::address>(mr_);
        }

        // 已过期 + serve_stale：返回旧数据（调用方应触发后台刷新）
        if (serve_stale_)
        {
            trace::debug("stale cache hit, refresh needed: {}", domain);
            // LRU 更新
            lru_order_.splice(lru_order_.begin(), lru_order_, lru_it);

            if (!entry.failed)
            {
                return memory::vector<net::ip::address>(entry.ips, mr_);
            }
            return memory::vector<net::ip::address>(mr_);
        }

        // 已过期 + !serve_stale：删除条目并返回未命中
        trace::debug("expired entry removed: {}", domain);
        lru_order_.erase(lru_it); // 同步删除 LRU 链表节点
        entries_.erase(it);
        return std::nullopt;
    }

    void cache::put(const put_input &input)
    {
        const auto now = std::chrono::steady_clock::now();

        // 使用栈缓冲区构造查找 key，避免 PMR string 分配
        std::array<char, 260> buffer;
        const auto key = key_view(input.domain, input.qt, buffer);

        // 检查是否已存在（更新情况）— 单次查找
        if (const auto existing_it = entries_.find(key); existing_it != entries_.end())
        {
            // 更新现有条目，保持 LRU 位置（移到头部）
            const auto &lru_it = existing_it->second.second;
            lru_order_.splice(lru_order_.begin(), lru_order_, lru_it);

            auto &entry = existing_it->second.first;
            entry.ips.assign(input.ips.begin(), input.ips.end());
            entry.ttl = input.ttl_seconds;
            entry.expire = now + std::chrono::seconds(input.ttl_seconds);
            entry.inserted = now;
            entry.failed = false;
            return;
        }

        // 新插入：需要持久化 key（string_view 指向栈缓冲，需要拷贝到 PMR string）
        const auto pmr_key = memory::string(key, mr_);

        // 构建缓存条目
        cache_entry entry(mr_);
        entry.ips.assign(input.ips.begin(), input.ips.end());
        entry.ttl = input.ttl_seconds;
        entry.expire = now + std::chrono::seconds(input.ttl_seconds);
        entry.inserted = now;
        entry.failed = false;

        // 新插入：添加到 LRU 链表头部
        lru_order_.push_front(pmr_key);
        const auto lru_it = lru_order_.begin();

        // 插入缓存表
        entries_.emplace(pmr_key, std::make_pair(std::move(entry), lru_it));

        // LRU 淘汰：条目数超过上限时移除链表尾部（最旧）条目
        while (entries_.size() > max_entries_)
        {
            const auto &oldest_key = lru_order_.back();
            trace::debug("LRU eviction: {} entries, limit {}", entries_.size(), max_entries_);
            entries_.erase(oldest_key); // O(1) 哈希查找
            lru_order_.pop_back();      // O(1) 删除尾部
        }
    }

    void cache::put_negative(const std::string_view domain, const qtype qt, const std::chrono::seconds negative_ttl)
    {
        const auto now = std::chrono::steady_clock::now();

        // 使用栈缓冲区构造查找 key，避免 PMR string 分配
        std::array<char, 260> buffer;
        const auto key = key_view(domain, qt, buffer);

        // 检查是否已存在（更新情况）— 单次查找
        if (const auto existing_it = entries_.find(key); existing_it != entries_.end())
        {
            auto &lru_it = existing_it->second.second;
            lru_order_.splice(lru_order_.begin(), lru_order_, lru_it);

            auto &entry = existing_it->second.first;
            entry.ttl = static_cast<std::uint32_t>(negative_ttl.count());
            entry.expire = now + negative_ttl;
            entry.inserted = now;
            entry.failed = true;
            return;
        }

        // 新插入：需要持久化 key
        const auto pmr_key = memory::string(key, mr_);

        // 构建负缓存条目
        cache_entry entry(mr_);
        entry.ttl = static_cast<std::uint32_t>(negative_ttl.count());
        entry.expire = now + negative_ttl;
        entry.inserted = now;
        entry.failed = true;

        // 新插入：添加到 LRU 链表头部
        lru_order_.push_front(pmr_key);
        const auto lru_it = lru_order_.begin();

        // 插入缓存表
        entries_.emplace(pmr_key, std::make_pair(std::move(entry), lru_it));

        trace::debug("negative cache inserted: {} for {}s", domain, negative_ttl.count());
    }

    void cache::evict_expired()
    {
        const auto now = std::chrono::steady_clock::now();
        auto it = entries_.begin();

        std::size_t evicted = 0;
        while (it != entries_.end())
        {
            if (it->second.first.expire <= now) // pair<cache_entry, lru_list::iterator>
            {
                // 同步删除 LRU 链表节点
                lru_order_.erase(it->second.second);
                it = entries_.erase(it);
                ++evicted;
            }
            else
            {
                ++it;
            }
        }

        if (evicted > 0)
        {
            trace::info("evicted {} expired entries, remaining {}", evicted, entries_.size());
        }
    }

} // namespace psm::resolve::dns::detail
