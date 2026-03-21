#include <algorithm>
#include <forward-engine/agent/resolve/tcpcache.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::agent::resolve
{
    tcpcache::tcpcache(tcpool &pool, const net::any_io_executor &executor, const memory::resource_pointer mr,
                       const std::chrono::seconds ttl, const std::size_t max_entries, const bool disable_ipv6)
        : pool_(pool), resolver_(executor), mr_(mr ? mr : memory::current_resource()),
          ttl_(ttl), max_entries_(max_entries), lru_order_(mr_), records_(mr_),
          coalescer_(mr_), disable_ipv6_(disable_ipv6)
    {
    }

    auto tcpcache::resolve(std::string_view host, std::string_view port) -> net::awaitable<result>
    {
        coalescer_.flush_cleanup();

        // 禁用 IPv6 时，直接拒绝 IPv6 地址字面量
        if (disable_ipv6_)
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec && addr.is_v6())
            {
                trace::debug("[Resolver] IPv6 disabled, rejected literal: {}", host);
                co_return result{fault::code::host_unreachable, nullptr};
            }
        }

        const lookup_key lookup{host, port};
        const auto now = std::chrono::steady_clock::now();

        // 先去缓存里面找是否有保存的 host 地址
        if (auto cached = co_await async_connect(lookup, now))
        {
            co_return result{fault::code::success, std::move(cached)};
        }

        // 没找到查找或创建一个解析请求记录表
        const auto key = coalescer_.make_key(host, port);
        const auto [flight, is_new] = coalescer_.find_or_create(key, resolver_.get_executor());

        if (!is_new)
        {
            // 不是第一条请求解析的等待解析完成
            if (!flight->ready)
            {
                ++flight->waiters;
                boost::system::error_code ignored;
                co_await flight->timer.async_wait(net::redirect_error(net::use_awaitable, ignored));
                --flight->waiters;
            }

            // 连接缓存
            if (auto cached = co_await async_connect(lookup, std::chrono::steady_clock::now()))
            {
                coalescer::cleanup_flight(flight);
                co_return result{fault::code::success, std::move(cached)};
            }

            // 连接失败
            trace::warn("[Resolver] Resolve {}:{} -> connection failed after DNS wait", host, port);
            coalescer::cleanup_flight(flight);
            co_return result{fault::code::host_unreachable, nullptr};
        }

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        const auto results = co_await resolver_.async_resolve(host, port, token);

        flight->ready = true;
        flight->timer.cancel();

        if (ec || results.empty())
        {
            trace::warn("[Resolver] Resolve {}:{} -> DNS failed: {}", host, port, ec ? ec.message() : "empty results");
            coalescer::cleanup_flight(flight);
            co_return result{fault::code::host_unreachable, nullptr};
        }

        // 构建缓存记录
        record rec{memory::vector<tcp::endpoint>(mr_), std::chrono::steady_clock::now() + ttl_};
        rec.endpoints.reserve(std::distance(results.begin(), results.end()));
        for (const auto &entry : results)
        {
            rec.endpoints.push_back(entry.endpoint());
        }

        // IPv6 过滤
        if (disable_ipv6_)
        {
            const auto before = rec.endpoints.size();
            auto remove_ipv6 = [](const tcp::endpoint &ep)
            {
                return ep.address().is_v6();
            };
            std::erase_if(rec.endpoints, remove_ipv6);
            if (const auto removed = before - rec.endpoints.size(); removed > 0)
            {
                trace::debug("[Resolver] IPv6 disabled, filtered {} endpoints", removed);
            }
        }

        // LRU 插入：添加到列表头部
        lru_order_.push_front(flight->key);
        records_.insert_or_assign(flight->key, std::make_pair(std::move(rec), lru_order_.begin()));

        // LRU 淘汰：从列表尾部删除
        while (records_.size() > max_entries_ && !lru_order_.empty())
        {
            const auto &oldest_key = lru_order_.back();
            records_.erase(oldest_key);
            lru_order_.pop_back();
        }

        // 连接
        if (auto socket = co_await async_connect(lookup, std::chrono::steady_clock::now()))
        {
            coalescer::cleanup_flight(flight);
            co_return result{fault::code::success, std::move(socket)};
        }

        trace::warn("[Resolver] Resolve {}:{} -> all endpoints failed, cached as negative", host, port);
        coalescer::cleanup_flight(flight);
        co_return result{fault::code::bad_gateway, nullptr};
    }

    auto tcpcache::async_connect(const lookup_key &lookup, const std::chrono::steady_clock::time_point now)
        -> net::awaitable<unique_sock>
    {
        const auto it = records_.find(lookup);
        if (it == records_.end())
        {
            co_return nullptr;
        }

        // TTL 过期：利用存储的迭代器直接删除
        if (it->second.first.expire <= now)
        {
            lru_order_.erase(it->second.second);
            records_.erase(it);
            co_return nullptr;
        }

        // 负缓存：直接返回
        if (it->second.first.failed)
        {
            trace::debug("[Resolver] async_connect negative cache hit: {}", lookup.host);
            co_return nullptr;
        }

        // LRU 更新：移动到头部
        lru_order_.splice(lru_order_.begin(), lru_order_, it->second.second);
        it->second.second = lru_order_.begin();

        auto &rec = it->second.first;
        const auto total = rec.endpoints.size();

        // 收集有效的端点（跳过 IPv6）
        memory::vector<tcp::endpoint> valid_endpoints(mr_);
        for (std::size_t i = 0; i < total; ++i)
        {
            const auto idx = (rec.next_index + i) % total;
            const auto &ep = rec.endpoints[idx];
            if (!disable_ipv6_ || !ep.address().is_v6())
            {
                valid_endpoints.push_back(ep);
            }
        }

        if (valid_endpoints.empty())
        {
            rec.failed = true;
            rec.expire = now + std::chrono::seconds(30);
            co_return nullptr;
        }

        // 快速失败：顺序尝试多个端点
        // pool_.acquire_tcp 超时 300ms，最多尝试 3 个，总延迟最多 900ms
        constexpr std::size_t max_attempts = 3;

        const auto attempt_count = (std::min)(valid_endpoints.size(), max_attempts);

        for (std::size_t i = 0; i < attempt_count; ++i)
        {
            const auto &endpoint = valid_endpoints[i];
            trace::debug("[Resolver] async_connect attempt [{}] {}", i + 1, endpoint.address().to_string());

            auto socket = co_await pool_.acquire_tcp(endpoint);
            if (socket && socket->is_open())
            {
                rec.next_index = (rec.next_index + i + 1) % total;
                co_return socket;
            }
        }

        // 所有端点都失败，标记为负缓存
        rec.failed = true;
        rec.expire = now + std::chrono::seconds(30);
        trace::warn("[Resolver] async_connect all endpoints failed, negative cached for 30s: {}", lookup.host);

        co_return nullptr;
    }
} // namespace ngx::agent::resolve
