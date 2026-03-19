#include <forward-engine/agent/resolve/tcpcache.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::agent::resolve
{
    tcpcache::tcpcache(tcpool &pool, const net::any_io_executor &executor, const memory::resource_pointer mr,
                                         const std::chrono::seconds ttl, const std::size_t max_entries)
        : pool_(pool), resolver_(executor), mr_(mr ? mr : memory::current_resource()),
          ttl_(ttl), max_entries_(max_entries), records_(mr_), coalescer_(mr_)
    {
    }

    auto tcpcache::resolve(std::string_view host, std::string_view port) -> net::awaitable<result>
    {
        coalescer_.flush_cleanup();

        const lookup_key lookup{host, port};
        const auto now = std::chrono::steady_clock::now();
        // 先去缓存里面找是否有保存的host地址
        if (auto cached = co_await async_connect(lookup, now))
        {
            co_return result{fault::code::success, std::move(cached)};
        }
        // 没找到查找或创建一个解析请求记录表
        const auto key = coalescer_.make_key(host, port);
        const auto [flight, is_new] = coalescer_.find_or_create(key, resolver_.get_executor());

        if (!is_new)
        {   // 不是第一条请求解析的等待解析完成
            if (!flight->ready)
            {
                ++flight->waiters;
                boost::system::error_code ignored;
                co_await flight->timer.async_wait(net::redirect_error(net::use_awaitable, ignored));
                --flight->waiters;  // 等待完成
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
        {   // 解析失败
            trace::warn("[Resolver] Resolve {}:{} -> DNS failed: {}", host, port, ec ? ec.message() : "empty results");
            coalescer::cleanup_flight(flight);
            co_return result{fault::code::host_unreachable, nullptr};
        }

        const auto insert_time = std::chrono::steady_clock::now();
        record cached{memory::vector<tcp::endpoint>(mr_), insert_time + ttl_, insert_time};
        cached.endpoints.reserve(std::distance(results.begin(), results.end()));
        for (const auto &entry : results)
        {   // 迁移解析出来的host地址列表（IPv4 和 IPv6 都支持）
            cached.endpoints.push_back(entry.endpoint());
        }

        records_.insert_or_assign(flight->key, std::move(cached));
        if (records_.size() > max_entries_)
        {
            // FIFO 淘汰：查找 inserted 最早的条目
            auto oldest = records_.begin();
            for (auto it = std::next(records_.begin()); it != records_.end(); ++it)
            {
                if (it->second.inserted < oldest->second.inserted)
                {
                    oldest = it;
                }
            }
            records_.erase(oldest);
        }
        // 连接
        if (auto socket = co_await async_connect(lookup, std::chrono::steady_clock::now()))
        {
            coalescer::cleanup_flight(flight);
            co_return result{fault::code::success, std::move(socket)};
        }

        trace::warn("[Resolver] Resolve {}:{} -> all endpoints failed, purging cache", host, port);
        if (auto stale = records_.find(lookup); stale != records_.end())
        {
            records_.erase(stale);
        }

        coalescer::cleanup_flight(flight);
        co_return result{fault::code::bad_gateway, nullptr};
    }

    auto tcpcache::async_connect(const lookup_key &lookup, const std::chrono::steady_clock::time_point now)
        -> net::awaitable<unique_sock>
    {
        std::size_t endpoint_index{0};
        bool has_candidate{false};
        while (true)
        {
            const auto it = records_.find(lookup);
            if (it == records_.end())
            {
                break;
            }
            if (it->second.expire <= now)
            {
                records_.erase(it);
                break;
            }
            if (endpoint_index >= it->second.endpoints.size())
            {
                has_candidate = endpoint_index > 0;
                break;
            }

            const auto endpoint = it->second.endpoints[endpoint_index++];
            auto socket = co_await pool_.acquire_tcp(endpoint);
            if (socket && socket->is_open())
            {
                co_return socket;
            }
        }

        if (has_candidate)
        {
            if (const auto stale = records_.find(lookup); stale != records_.end())
            {
                records_.erase(stale);
            }
        }
        co_return nullptr;
    }
} // namespace ngx::agent::resolve
