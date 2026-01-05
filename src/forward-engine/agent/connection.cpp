#include <ranges>
#include <cstdint>
#include <agent/connection.hpp>

namespace ngx::agent
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

    /**
     * @brief 创建端点键
     * @details 从 `tcp::endpoint` 对象中提取 IP 地址和端口号，构造 `endpoint_key`。
     * @param endpoint 要转换的 TCP 端点
     * @return 对应的 `endpoint_key` 对象
     */
    inline endpoint_key make_endpoint_key(const tcp::endpoint &endpoint) noexcept
    {
        endpoint_key key;
        key.port = endpoint.port();

        const auto address = endpoint.address();
        if (address.is_v4())
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

    std::size_t endpoint_hash::operator()(const endpoint_key &key) const noexcept
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

    /**
     * @brief 僵尸检测
     * @details 检查 TCP 连接是否已断开 (对端关闭了连接)。
     * @param s 要检查的 socket 指针
     * @return true 如果连接已断开 (对端关闭了连接)
     * @return false 如果连接正常 (对端还在发送数据)
     */
    bool source::zombie_detection(tcp::socket *s)
    {
        if (!s || !s->is_open())
        {
            return false;
        }

        boost::system::error_code ec;

        static_cast<void>(s->remote_endpoint(ec));
        if (ec)
        {
            return false;
        }

        return s->is_open();
    }

    /**
     * @brief 获取一个 TCP 连接
     * @details 优先复用缓存中的连接。会自动剔除已断开或超时的僵尸连接。
     * 如果无可用连接，则立即新建并连接。
     */
    net::awaitable<exclusive_connection> source::acquire_tcp(tcp::endpoint endpoint)
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
                    delete s; // 太老了，扔掉
                    continue;
                }

                // 检查 B: 是否僵尸
                if (zombie_detection(s))
                {
                    co_return exclusive_connection(s, deleter{this, endpoint, true});
                }

                delete s;
            }

            // 如果栈空了，删除 key
            if (stack.empty())
            {
                cache_.erase(it);
            }
        }

        // 2. 缓存没命中（或都是坏的），新建连接
        auto sock = exclusive_connection(new tcp::socket(ioc_), deleter{this, endpoint, true});

        boost::system::error_code ec;
        // 3. 异步连接
        co_await sock->async_connect(endpoint, net::redirect_error(net::use_awaitable, ec));

        if (ec)
        {
            throw boost::system::system_error(ec);
        }

        // 4. 设置 socket 选项
        // TCP_NODELAY 对于代理至关重要，减少延迟
        sock->set_option(tcp::no_delay(true));

        co_return sock;
    }

    /**
     * @brief 归还连接（内部接口）
     * @details 由 deleter 析构器自动调用，不要手动调用。
     */
    void source::recycle(tcp::socket *s)
    {
        // 1. 基础健康检查
        if (!s->is_open())
        {
            delete s;
            return;
        }

        // 2. 尝试获取 endpoint 以归类
        try
        {
            // 注意：如果 socket 处于半关闭状态，remote_endpoint 可能会抛出异常
            recycle(s, s->remote_endpoint());
            return;
        }
        catch (...)
        {
            delete s;
        }
    }

    /**
     * @brief 归还连接（外部接口）
     * @details 将连接放回缓存，等待下一次复用。
     * @param s 要归还的 socket 指针
     * @param endpoint 连接的远程端点 (用于归类缓存)
     */
    void source::recycle(tcp::socket *s, const tcp::endpoint &endpoint)
    {
        if (!s->is_open())
        {
            delete s;
            return;
        }

        auto &stack = cache_[make_endpoint_key(endpoint)];

        // 资源限制保护：单目标过多则丢弃，防止 FD/内存爆炸
        if (stack.size() >= max_cache_endpoint_)
        {
            boost::system::error_code ignore;
            s->close(ignore);
            delete s;
            return;
        }

        stack.push_back({s, std::chrono::steady_clock::now()});
    }

    /**
     * @brief 清空所有缓存的连接
     * @details 会关闭所有连接并删除对应的 socket 对象。
     */
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
                    delete socket;
                }
            }
        }
        cache_.clear();
    }

}
