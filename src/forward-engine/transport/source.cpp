#include <ranges>
#include <cstdint>
#include <forward-engine/transport/source.hpp>
#include <forward-engine/abnormal/network.hpp>

namespace ngx::transport
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

    inline auto make_endpoint_key(const tcp::endpoint &endpoint) noexcept
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

        // 尝试轻量级活性检测：检查 socket 是否可读
        boost::system::error_code ec;
        // 检查 socket 是否可读 (非阻塞读取 0 字节)
        // 使用 available() 检查是否有待处理数据（如果连接关闭，可能返回错误）
        const auto available = s->available(ec);
        if (ec)
        {
            // 连接可能已断开
            return false;
        }
        // 如果 available 成功，连接至少处于可读状态。
        // 注意：此方法可能产生 false positive，但连接池会在后续读写时发现错误并销毁连接。
        return true;
    }

    auto source::acquire_tcp(tcp::endpoint endpoint)
        -> net::awaitable<unique_sock>
    {
        const auto endpoint_key = make_endpoint_key(endpoint);

        // 1. 尝试从缓存获取
        if (const auto it = cache_.find(endpoint_key); it != cache_.end())
        {
            auto &stack = it->second;

            // 循环直到找到一个健康的连接，或者栈被掏空
            while (!stack.empty())
            {
                auto [socket, last_used] = stack.back();
                stack.pop_back();

                tcp::socket *s = socket;

                // 检查 A: 是否超时
                if (auto now = std::chrono::steady_clock::now(); now - last_used > max_idle_time_)
                {
                    delete_socket(s); // 太老了，扔掉
                    continue;
                }

                // 检查 B: 是否僵尸
                if (zombie_detection(s))
                {
                    co_return unique_sock(s, deleter{this, endpoint, true});
                }

                delete_socket(s);
            }

            // 如果栈空了，删除 key
            if (stack.empty())
            {
                cache_.erase(it);
            }
        }

        // 2. 缓存没命中（或都是坏的），新建连接
        auto sock = unique_sock(new tcp::socket(ioc_), deleter{this, endpoint, true});

        boost::system::error_code ec;
        // 3. 异步连接
        co_await sock->async_connect(endpoint, net::redirect_error(net::use_awaitable, ec));

        if (ec)
        {
            // 热路径中不抛异常，返回空的 unique_sock 表示连接失败
            // 注意：sock 析构时会自动清理 socket
            co_return unique_sock{};
        }

        // 4. 设置 socket 选项
        // TCP_NODELAY 对于代理至关重要，减少延迟
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
        // 1. 基础健康检查
        if (!s->is_open())
        {
            delete_socket(s);
            return;
        }

        // 2. 尝试获取 endpoint 以归还
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

        // 资源限制保护：单目标过多则丢弃，防止 FD/内存爆炸
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
