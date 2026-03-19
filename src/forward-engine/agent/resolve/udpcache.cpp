#include <forward-engine/agent/resolve/udpcache.hpp>

namespace ngx::agent::resolve
{
    udpcache::udpcache(net::any_io_executor executor, const memory::resource_pointer mr,
                                         const std::chrono::seconds ttl, const std::size_t max_entries)
        : executor_(std::move(executor)), resolver_(executor_), mr_(mr ? mr : memory::current_resource()),
          ttl_(ttl), max_entries_(max_entries), records_(mr_), coalescer_(mr_)
    {
    }

    auto udpcache::resolve(const std::string_view host, const std::string_view port) -> net::awaitable<result>
    {
        coalescer_.flush_cleanup();

        const auto now = std::chrono::steady_clock::now();
        const lookup_key lookup{host, port};

        if (const auto hit = records_.find(lookup); hit != records_.end())
        {
            if (hit->second.expire > now)
            {
                co_return result{fault::code::success, hit->second.value};
            }
            records_.erase(hit);
        }

        const auto key = coalescer_.make_key(host, port);
        const auto [flight, is_new] = coalescer_.find_or_create(key, executor_);

        if (!is_new)
        {
            if (!flight->ready)
            {
                ++flight->waiters;
                boost::system::error_code ignored;
                co_await flight->timer.async_wait(net::redirect_error(net::use_awaitable, ignored));
                --flight->waiters;
            }

            const auto after_wait = std::chrono::steady_clock::now();
            if (const auto hit = records_.find(lookup); hit != records_.end() && hit->second.expire > after_wait)
            {
                coalescer::cleanup_flight(flight);
                co_return result{fault::code::success, hit->second.value};
            }

            coalescer::cleanup_flight(flight);
            co_return result{fault::code::host_unreachable, endpoint{}};
        }

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        const auto results = co_await resolver_.async_resolve(host, port, token);

        flight->ready = true;
        flight->timer.cancel();

        if (ec || results.empty())
        {
            coalescer::cleanup_flight(flight);
            co_return result{fault::code::host_unreachable, endpoint{}};
        }

        const endpoint resolved = results.begin()->endpoint();
        const auto insert_time = std::chrono::steady_clock::now();
        records_.insert_or_assign(flight->key, record{resolved, insert_time + ttl_, insert_time});
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

        coalescer::cleanup_flight(flight);
        co_return result{fault::code::success, resolved};
    }
} // namespace ngx::agent::resolve
