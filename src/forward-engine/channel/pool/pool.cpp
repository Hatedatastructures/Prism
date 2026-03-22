#include <ranges>
#include <cstdint>
#include <memory>
#include <forward-engine/channel/pool/pool.hpp>
#include <forward-engine/channel/health.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::channel
{
    void deleter::operator()(tcp::socket *ptr) const
    {
        if (pool && has_endpoint)
        {
            pool->recycle(ptr, endpoint);
        }
        else
        {
            // 没有端点信息，直接关闭
            if (ptr)
            {
                boost::system::error_code ignore;
                ptr->close(ignore);
                delete ptr;
            }
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
            std::memcpy(key.address.data(), bytes.data(), bytes.size());
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
        // 使用 FNV-1a 变体，一次性处理所有数据
        std::size_t h = 14695981039346656037ULL;
        h ^= key.port;
        h *= 1099511628211ULL;
        h ^= key.family;
        h *= 1099511628211ULL;
        for (const auto b : key.address)
        {
            h ^= b;
            h *= 1099511628211ULL;
        }
        return h;
    }

    auto tcpool::acquire_tcp(tcp::endpoint endpoint)
        -> net::awaitable<unique_sock>
    {
        const auto key = make_endpoint_key(endpoint);

        // 尝试复用缓存的连接
        if (const auto it = cache_.find(key); it != cache_.end())
        {
            auto &stack = it->second;

            while (!stack.empty())
            {
                auto [socket, last_used] = stack.back();
                stack.pop_back();

                // 检查是否过期
                if (std::chrono::steady_clock::now() - last_used > max_idle_time_)
                {
                    delete_socket(socket);
                    continue;
                }

                // 快速健康检测
                if (healthy_fast(*socket))
                {
                    co_return unique_sock(socket, deleter{this, endpoint, true});
                }

                delete_socket(socket);
            }

            if (stack.empty())
            {
                cache_.erase(it);
            }
        }

        // 创建新连接（Windows 上需要 co_spawn + close 方案处理超时）
        // 超时设为 300ms，配合 router 顺序尝试多个端点
        constexpr auto connect_timeout = std::chrono::milliseconds(300);

        // 打包所有状态到一个结构体，只需一次堆分配
        struct connect_state
        {
            tcp::socket socket;
            net::steady_timer timer;
            boost::system::error_code ec;
            bool done{false};

            connect_state(net::io_context &ioc) : socket(ioc), timer(ioc) {}
        };

        auto state = std::make_shared<connect_state>(ioc_);
        state->timer.expires_after(connect_timeout);

        net::co_spawn(ioc_,
            [state, endpoint]() -> net::awaitable<void>
            {
                boost::system::error_code ec;
                co_await state->socket.async_connect(
                    endpoint, net::redirect_error(net::use_awaitable, ec));
                state->ec = ec;
                state->done = true;
                state->timer.cancel();
            },
            net::detached);

        boost::system::error_code timer_ec;
        co_await state->timer.async_wait(net::redirect_error(net::use_awaitable, timer_ec));

        if (!state->done)
        {
            // 超时：强制关闭 socket
            boost::system::error_code ignore;
            state->socket.close(ignore);
            trace::warn("[Pool] connect timed out to {}:{}", endpoint.address().to_string(), endpoint.port());
            co_return unique_sock{};
        }

        if (state->ec)
        {
            trace::warn("[Pool] connect failed: {}", state->ec.message());
            if (state->socket.is_open())
            {
                boost::system::error_code ignore;
                state->socket.close(ignore);
            }
            co_return unique_sock{};
        }

        // 连接成功：设置 socket 选项
        {
            boost::system::error_code opt_ec;
            state->socket.set_option(tcp::no_delay(true), opt_ec);
            state->socket.set_option(tcp::socket::keep_alive(true), opt_ec);
            state->socket.set_option(net::socket_base::receive_buffer_size(266144), opt_ec);
            state->socket.set_option(net::socket_base::send_buffer_size(266144), opt_ec);
        }

        // 转移 socket 所有权：用 move 构造新对象，原 state 析构时自动释放
        auto *raw_sock = new tcp::socket(std::move(state->socket));
        co_return unique_sock(raw_sock, deleter{this, endpoint, true});
    }

    void tcpool::recycle(tcp::socket *s, const tcp::endpoint &endpoint)
    {
        if (!s || !s->is_open())
        {
            delete_socket(s);
            return;
        }

        // IPv6 不缓存
        if (endpoint.address().is_v6())
        {
            trace::debug("[Pool] IPv6 connection not cached");
            delete_socket(s);
            return;
        }

        // 快速健康检测
        if (!healthy_fast(*s))
        {
            delete_socket(s);
            return;
        }

        // 检查缓存容量
        auto &stack = cache_[make_endpoint_key(endpoint)];
        if (stack.size() >= max_cache_endpoint_)
        {
            delete_socket(s);
            return;
        }

        stack.push_back({s, std::chrono::steady_clock::now()});
    }

    void tcpool::clear()
    {
        for (auto &stack : cache_ | std::views::values)
        {
            for (const auto &[socket, last_used] : stack)
            {
                delete_socket(socket);
            }
        }
        cache_.clear();
    }
} // namespace ngx::channel
