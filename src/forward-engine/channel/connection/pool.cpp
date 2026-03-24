#include <ranges>
#include <cstdint>
#include <memory>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <forward-engine/channel/connection/pool.hpp>
#include <forward-engine/channel/health.hpp>
#include <forward-engine/trace.hpp>

namespace ngx::channel
{
    // ── pooled_connection ───────────────────────────────────────────────

    pooled_connection::~pooled_connection()
    {
        reset();
    }

    pooled_connection &pooled_connection::operator=(pooled_connection &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            pool_ = other.pool_;
            socket_ = other.socket_;
            endpoint_ = other.endpoint_;
            other.pool_ = nullptr;
            other.socket_ = nullptr;
        }
        return *this;
    }

    tcp::socket *pooled_connection::release() noexcept
    {
        auto *s = socket_;
        pool_ = nullptr;
        socket_ = nullptr;
        return s;
    }

    void pooled_connection::reset()
    {
        if (socket_)
        {
            if (pool_)
            {
                pool_->recycle(socket_, endpoint_);
            }
            else
            {
                boost::system::error_code ignore;
                socket_->close(ignore);
                delete socket_;
            }
            pool_ = nullptr;
            socket_ = nullptr;
        }
    }

    // ── endpoint_key / endpoint_hash ────────────────────────────────────

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
        // FNV-1a 变体
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

    // ── connection_pool ─────────────────────────────────────────────────

    inline void delete_socket(tcp::socket *s) noexcept
    {
        if (s)
        {
            boost::system::error_code ignore;
            s->close(ignore);
            delete s;
        }
    }

    auto connection_pool::async_acquire(tcp::endpoint endpoint)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        stat_acquires_.fetch_add(1, std::memory_order_relaxed);

        if (!started_)
        {
            trace::debug("[Pool] start() not called, background cleanup is disabled");
        }

        const auto key = make_endpoint_key(endpoint);
        const auto now = std::chrono::steady_clock::now();
        const auto idle_timeout = std::chrono::seconds(config_.max_idle_seconds);

        // 尝试复用缓存的连接
        if (const auto it = cache_.find(key); it != cache_.end())
        {
            auto &stack = it->second;

            while (!stack.empty())
            {
                auto [socket, last_used] = stack.back();
                stack.pop_back();

                // 检查是否过期
                if (now - last_used > idle_timeout)
                {
                    delete_socket(socket);
                    stat_evictions_.fetch_add(1, std::memory_order_relaxed);
                    stat_idle_.fetch_sub(1, std::memory_order_relaxed);
                    continue;
                }

                // 快速健康检测
                if (healthy_fast(*socket))
                {
                    stat_idle_.fetch_sub(1, std::memory_order_relaxed);
                    stat_hits_.fetch_add(1, std::memory_order_relaxed);
                    trace::debug("[Pool] reused {}:{} (idle {}ms)", endpoint.address().to_string(), endpoint.port(),
                                 std::chrono::duration_cast<std::chrono::milliseconds>(now - last_used).count());
                    co_return std::make_pair(fault::code::success, pooled_connection(this, socket, endpoint));
                }

                delete_socket(socket);
                stat_evictions_.fetch_add(1, std::memory_order_relaxed);
                stat_idle_.fetch_sub(1, std::memory_order_relaxed);
            }

            if (stack.empty())
            {
                cache_.erase(it);
                stat_endpoints_.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        // 创建新连接（awaitable_operators || 超时方案）
        using namespace net::experimental::awaitable_operators;

        const auto connect_timeout = std::chrono::milliseconds(config_.connect_timeout_ms);

        auto *sock = new tcp::socket(ioc_);
        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(connect_timeout);

        boost::system::error_code connect_ec;
        boost::system::error_code timer_ec;
        auto connect_token = net::redirect_error(net::use_awaitable, connect_ec);
        auto timer_token = net::redirect_error(net::use_awaitable, timer_ec);

        auto connect_op = sock->async_connect(endpoint, connect_token);
        auto timer_op = timer.async_wait(timer_token);

        const auto result = co_await (std::move(connect_op) || std::move(timer_op));

        if (result.index() == 1)
        { // 超时：timer 先完成，connect 被自动取消
            delete_socket(sock);
            trace::warn("[Pool] connect timed out to {}:{}", endpoint.address().to_string(), endpoint.port());
            co_return std::make_pair(fault::code::timeout, pooled_connection{});
        }

        if (connect_ec)
        { // 连接失败
            delete_socket(sock);
            trace::warn("[Pool] connect failed: {}", connect_ec.message());
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        // 连接成功：设置 socket 选项
        {
            boost::system::error_code opt_ec;
            if (config_.tcp_nodelay)
            {
                sock->set_option(tcp::no_delay(true), opt_ec);
            }
            if (config_.keep_alive)
            {
                sock->set_option(tcp::socket::keep_alive(true), opt_ec);
            }
            if (config_.recv_buffer_size > 0)
            {
                sock->set_option(net::socket_base::receive_buffer_size(config_.recv_buffer_size), opt_ec);
            }
            if (config_.send_buffer_size > 0)
            {
                sock->set_option(net::socket_base::send_buffer_size(config_.send_buffer_size), opt_ec);
            }
        }

        stat_creates_.fetch_add(1, std::memory_order_relaxed);

        trace::debug("[Pool] new connection to {}:{}", endpoint.address().to_string(), endpoint.port());
        co_return std::make_pair(fault::code::success, pooled_connection(this, sock, endpoint));
    }

    void connection_pool::recycle(tcp::socket *s, const tcp::endpoint &endpoint)
    {
        if (!s || !s->is_open())
        {
            delete_socket(s);
            // 无效连接不算驱逐
            return;
        }

        stat_recycles_.fetch_add(1, std::memory_order_relaxed);

        // IPv6 缓存受配置控制
        if (!config_.cache_ipv6 && endpoint.address().is_v6())
        {
            trace::debug("[Pool] IPv6 connection not cached");
            delete_socket(s);
            stat_evictions_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // 快速健康检测
        if (!healthy_fast(*s))
        {
            delete_socket(s);
            stat_evictions_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // 检查缓存容量
        const auto key = make_endpoint_key(endpoint);
        auto [it, inserted] = cache_.try_emplace(key);
        auto &stack = it->second;
        if (inserted)
        {
            stat_endpoints_.fetch_add(1, std::memory_order_relaxed);
        }
        if (stack.size() >= config_.max_cache_per_endpoint)
        {
            delete_socket(s);
            stat_evictions_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        stack.push_back({s, std::chrono::steady_clock::now()});
        stat_idle_.fetch_add(1, std::memory_order_relaxed);
    }

    void connection_pool::start()
    {
        started_ = true;
        if (cleanup_timer_.has_value())
        {
            return; // 已在运行
        }

        cleanup_timer_.emplace(ioc_);

        auto clean_function = [this]() -> net::awaitable<void>
        {
            try
            {
                while (cleanup_timer_.has_value())
                {
                    cleanup_timer_->expires_after(std::chrono::seconds(config_.cleanup_interval_sec));
                    boost::system::error_code ec;
                    auto token = net::redirect_error(net::use_awaitable, ec);
                    co_await cleanup_timer_->async_wait(token);
                    if (ec)
                        break;
                    trace::debug("[Pool] total acquires: {}, total hits: {}, total creates: {}, total evictions: {}, total recycles: {}, total idle: {}",
                                 stat_acquires_.load(std::memory_order_relaxed), stat_hits_.load(std::memory_order_relaxed),
                                 stat_creates_.load(std::memory_order_relaxed), stat_evictions_.load(std::memory_order_relaxed),
                                 stat_recycles_.load(std::memory_order_relaxed), stat_idle_.load(std::memory_order_relaxed));
                    // 执行清理操作
                    cleanup();
                }
            }
            catch (...)
            {
                trace::error("[Pool] cleanup timer error");
            }
        };

        net::co_spawn(ioc_, clean_function, net::detached);
    }

    void connection_pool::cleanup()
    {
        const auto now = std::chrono::steady_clock::now();
        const auto idle_timeout = std::chrono::seconds(config_.max_idle_seconds);

        for (auto it = cache_.begin(); it != cache_.end();)
        {
            auto &stack = it->second;

            // 原地压缩：保留有效项
            std::size_t write = 0;
            for (std::size_t read = 0; read < stack.size(); ++read)
            {
                if (now - stack[read].last_used <= idle_timeout)
                {
                    if (write != read)
                    {
                        stack[write] = std::move(stack[read]);
                    }
                    ++write;
                }
                else
                {
                    delete_socket(stack[read].socket);
                    stat_evictions_.fetch_add(1, std::memory_order_relaxed);
                    stat_idle_.fetch_sub(1, std::memory_order_relaxed);
                }
            }

            if (write == 0)
            {
                stack.clear();
                it = cache_.erase(it);
                stat_endpoints_.fetch_sub(1, std::memory_order_relaxed);
            }
            else
            {
                stack.resize(write);
                ++it;
            }
        }
    }

    auto connection_pool::stats() const -> pool_stats
    {
        pool_stats s;
        s.total_acquires = stat_acquires_.load(std::memory_order_relaxed);
        s.total_hits = stat_hits_.load(std::memory_order_relaxed);
        s.total_creates = stat_creates_.load(std::memory_order_relaxed);
        s.total_recycles = stat_recycles_.load(std::memory_order_relaxed);
        s.total_evictions = stat_evictions_.load(std::memory_order_relaxed);
        s.idle_count = stat_idle_.load(std::memory_order_relaxed);
        s.endpoint_count = stat_endpoints_.load(std::memory_order_relaxed);

        return s;
    }

    void connection_pool::clear()
    {
        // 取消清理定时器
        if (cleanup_timer_.has_value())
        {
            cleanup_timer_->cancel();
            cleanup_timer_.reset();
        }

        for (auto &stack : cache_ | std::views::values)
        {
            for (const auto &[socket, last_used] : stack)
            {
                delete_socket(socket);
            }
        }
        cache_.clear();
        stat_idle_.store(0, std::memory_order_relaxed);
        stat_endpoints_.store(0, std::memory_order_relaxed);
    }
} // namespace ngx::channel
