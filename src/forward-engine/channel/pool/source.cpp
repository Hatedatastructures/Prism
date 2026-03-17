#include <ranges>
#include <cstdint>
#include <forward-engine/channel/pool/source.hpp>

namespace ngx::channel
{
    void deleter::operator()(tcp::socket *ptr) const
    {
        if (pool)
        {
            if (has_endpoint)
            {
                pool->recycle(ptr, endpoint);
            }
            else
            {
                pool->recycle(ptr);
            }
        }
        else
        {
            delete ptr;
        }
    }

    inline void delete_socket(tcp::socket *s) noexcept
    {
        if (s)
        {
            boost::system::error_code ignore;
            s->close(ignore);
            delete s;
        }
    }

    auto make_endpoint_key(const tcp::endpoint &endpoint) noexcept
        -> endpoint_key
    {
        endpoint_key key;
        key.port = endpoint.port();

        if (const auto address = endpoint.address(); address.is_v4())
        {
            key.family = 4;
            const auto bytes = address.to_v4().to_bytes();
            for (std::size_t i = 0; i < bytes.size(); ++i)
            {
                key.address[i] = bytes[i];
            }
        }
        else if (address.is_v6())
        {
            key.family = 6;
            key.address = address.to_v6().to_bytes();
        }

        return key;
    }

    auto endpoint_hash::operator()(const endpoint_key &key) const noexcept
        -> std::size_t
    {
        std::size_t seed = 0;
        seed ^= std::hash<std::uint16_t>{}(key.port) + 0x9e3779b9U + (seed << 6) + (seed >> 2);
        seed ^= std::hash<std::uint8_t>{}(key.family) + 0x9e3779b9U + (seed << 6) + (seed >> 2);

        for (const auto b : key.address)
        {
            seed = seed * 131u + static_cast<unsigned int>(b);
        }

        return seed;
    }

    auto source::zombie_detection(const tcp::socket *s)
        -> bool
    {
        if (!s || !s->is_open())
        {
            return false;
        }

        boost::system::error_code ec;
        const auto available = s->available(ec);
        if (ec)
        {
            return false;
        }
        return true;
    }

    auto source::acquire_tcp(tcp::endpoint endpoint)
        -> net::awaitable<unique_sock>
    {
        const auto key = make_endpoint_key(endpoint);

        if (const auto it = cache_.find(key); it != cache_.end())
        {
            auto &stack = it->second;

            while (!stack.empty())
            {
                auto [socket, last_used] = stack.back();
                stack.pop_back();

                tcp::socket *s = socket;

                if (auto now = std::chrono::steady_clock::now(); now - last_used > max_idle_time_)
                {
                    delete_socket(s);
                    continue;
                }

                if (zombie_detection(s))
                {
                    co_return unique_sock(s, deleter{this, endpoint, true});
                }

                delete_socket(s);
            }

            if (stack.empty())
            {
                cache_.erase(it);
            }
        }

        auto sock = unique_sock(new tcp::socket(ioc_), deleter{this, endpoint, true});

        boost::system::error_code ec;
        co_await sock->async_connect(endpoint, net::redirect_error(net::use_awaitable, ec));

        if (ec)
        {
            // 显式关闭失败连接，避免走 recycle 逻辑（recycle 会尝试获取 remote_endpoint）
            if (sock && sock->is_open())
            {
                boost::system::error_code ignore;
                sock->close(ignore);
            }
            co_return unique_sock{};
        }

        sock->set_option(tcp::no_delay(true));
        sock->set_option(net::socket_base::receive_buffer_size(266144));
        sock->set_option(net::socket_base::send_buffer_size(266144));

        co_return sock;
    }

    void source::recycle(tcp::socket *s)
    {
        if (!s)
        {
            return;
        }
        if (!s->is_open())
        {
            delete_socket(s);
            return;
        }

        boost::system::error_code ec;
        const auto ep = s->remote_endpoint(ec);
        if (ec)
        {
            delete_socket(s);
            return;
        }
        recycle(s, ep);
    }

    void source::recycle(tcp::socket *s, const tcp::endpoint &endpoint)
    {
        if (!s)
        {
            return;
        }
        if (!s->is_open())
        {
            delete_socket(s);
            return;
        }

        auto &stack = cache_[make_endpoint_key(endpoint)];

        if (stack.size() >= max_cache_endpoint_)
        {
            delete_socket(s);
            return;
        }

        stack.push_back({s, std::chrono::steady_clock::now()});
    }

    void source::clear()
    {
        for (auto &stack : cache_ | std::views::values)
        {
            for (const auto &[socket, last_used] : stack)
            {
                if (socket)
                {
                    boost::system::error_code ignore;
                    socket->close(ignore);
                    delete_socket(socket);
                }
            }
        }
        cache_.clear();
    }
}
