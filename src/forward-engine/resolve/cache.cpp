#include <algorithm>
#include <string>

#include <forward-engine/resolve/cache.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::resolve
{

    cache::cache(const memory::resource_pointer mr, const std::chrono::seconds ttl,
                 const std::size_t max_entries, const bool serve_stale)
        : mr_(mr ? mr : memory::current_resource()),
          default_ttl_(ttl), max_entries_(max_entries),
          serve_stale_(serve_stale), entries_(mr_)
    {
    }

    auto cache::make_key(const std::string_view domain, const qtype qt) const -> memory::string
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

    auto cache::get(const std::string_view domain, const qtype qt)
        -> std::optional<memory::vector<net::ip::address>>
    {
        // 构造完整的 PMR 键进行查找（transparent_equal 支持 string_view 与 memory::string 比较）
        const auto key = make_key(domain, qt);
        const auto it = entries_.find(std::string_view(key));

        // 未命中
        if (it == entries_.end())
        {
            return std::nullopt;
        }

        const auto now = std::chrono::steady_clock::now();
        auto &entry = it->second;

        // 未过期：直接返回结果
        if (now < entry.expire)
        {
            // 正向缓存：返回 IP 列表
            if (!entry.failed)
            {
                return memory::vector<net::ip::address>(entry.ips, mr_);
            }

            // 负缓存命中：返回空 vector
            trace::debug("[Resolve] negative cache hit: {}", domain);
            return memory::vector<net::ip::address>(mr_);
        }

        // 已过期 + serve_stale：返回旧数据（调用方应触发后台刷新）
        if (serve_stale_)
        {
            trace::debug("[Resolve] stale cache hit, refresh needed: {}", domain);
            if (!entry.failed)
            {
                return memory::vector<net::ip::address>(entry.ips, mr_);
            }
            return memory::vector<net::ip::address>(mr_);
        }

        // 已过期 + !serve_stale：删除条目并返回未命中
        trace::debug("[Resolve] expired entry removed: {}", domain);
        entries_.erase(it);
        return std::nullopt;
    }

    void cache::put(const std::string_view domain, const qtype qt, const memory::vector<net::ip::address> &ips,
                    const uint32_t ttl_seconds)
    {
        const auto now = std::chrono::steady_clock::now();
        const auto key = make_key(domain, qt);

        // 构建缓存条目
        cache_entry entry(mr_);
        entry.ips.assign(ips.begin(), ips.end());
        entry.ttl = ttl_seconds;
        entry.expire = now + std::chrono::seconds(ttl_seconds);
        entry.inserted = now;
        entry.failed = false;

        // 插入或覆盖
        entries_.insert_or_assign(std::move(key), std::move(entry));

        // FIFO 淘汰：条目数超过上限时移除 inserted 最早的条目
        while (entries_.size() > max_entries_)
        {
            auto oldest_it = entries_.begin();
            for (auto it = entries_.begin(); it != entries_.end(); ++it)
            {
                if (it->second.inserted < oldest_it->second.inserted)
                {
                    oldest_it = it;
                }
            }

            trace::debug("[Resolve] FIFO eviction: {} entries, limit {}", entries_.size(), max_entries_);
            entries_.erase(oldest_it);
        }
    }

    void cache::put_negative(const std::string_view domain, const qtype qt, const std::chrono::seconds negative_ttl)
    {
        const auto now = std::chrono::steady_clock::now();
        const auto key = make_key(domain, qt);

        // 构建负缓存条目
        cache_entry entry(mr_);
        entry.ttl = static_cast<uint32_t>(negative_ttl.count());
        entry.expire = now + negative_ttl;
        entry.inserted = now;
        entry.failed = true;

        entries_.insert_or_assign(std::move(key), std::move(entry));

        trace::debug("[Resolve] negative cache inserted: {} for {}s", domain, negative_ttl.count());
    }

    void cache::evict_expired()
    {
        const auto now = std::chrono::steady_clock::now();
        auto it = entries_.begin();

        std::size_t evicted = 0;
        while (it != entries_.end())
        {
            if (it->second.expire <= now)
            {
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
            trace::info("[Resolve] evicted {} expired entries, remaining {}", evicted, entries_.size());
        }
    }

} // namespace ngx::resolve
