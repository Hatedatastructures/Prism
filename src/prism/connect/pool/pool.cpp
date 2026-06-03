#include <prism/connect/pool/pool.hpp>

#include <prism/connect/pool/health.hpp>
#include <prism/trace.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <cstdint>
#include <memory>
#include <ranges>

namespace psm::connect
{

    // ── pooled_connection ───────────────────────────────────────────────

    pooled_connection::~pooled_connection() noexcept
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

    auto to_key(const tcp::endpoint &endpoint) noexcept
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
        // 按 8 字节块处理 16 字节 address 数组
        if constexpr (sizeof(std::size_t) >= 8)
        {
            // safe: casting address byte array to uint64_t for hash computation, alignment guaranteed by array<ubyte,16>
            const auto *ptr = reinterpret_cast<const std::uint64_t *>(key.address.data());
            for (std::size_t i = 0; i < key.address.size() / 8; ++i)
            {
                h ^= ptr[i];
                h *= 1099511628211ULL;
            }
        }
        else
        {
            for (const auto b : key.address)
            {
                h ^= b;
                h *= 1099511628211ULL;
            }
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

    auto connection_pool::try_reuse(reuse_opts opts)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        if (const auto it = cache_.find(opts.key); it != cache_.end())
        {
            auto &stack = it->second;

            while (!stack.empty())
            {
                auto [socket, last_used] = stack.back();
                stack.pop_back();

                if (opts.now - last_used > opts.idle_timeout)
                {
                    delete_socket(socket);
                    stat_evictions_ += 1;
                    stat_idle_ -= 1;
                    continue;
                }

                if (healthy_fast(*socket))
                {
                    stat_idle_ -= 1;
                    stat_hits_ += 1;
                    trace::debug("[Pool] reused {}:{} (idle {}ms)", opts.endpoint.address().to_string(), opts.endpoint.port(),
                                 std::chrono::duration_cast<std::chrono::milliseconds>(opts.now - last_used).count());
                    co_return std::make_pair(fault::code::success, pooled_connection(this, socket, opts.endpoint));
                }

                delete_socket(socket);
                stat_evictions_ += 1;
                stat_idle_ -= 1;
            }

            if (stack.empty())
            {
                cache_.erase(it);
                stat_endpoints_ -= 1;
            }
        }

        co_return std::make_pair(fault::code::generic_error, pooled_connection{});
    }

    void connection_pool::apply_opts(tcp::socket &sock) const
    {
        boost::system::error_code opt_ec;
        if (config_.tcp_nodelay)
        {
            sock.set_option(tcp::no_delay(true), opt_ec);
            if (opt_ec)
            {
                trace::warn("[Pool] failed to set TCP_NODELAY: {}", opt_ec.message());
                opt_ec.clear();
            }
        }
        if (config_.keep_alive)
        {
            sock.set_option(tcp::socket::keep_alive(true), opt_ec);
            if (opt_ec)
            {
                trace::warn("[Pool] failed to set SO_KEEPALIVE: {}", opt_ec.message());
                opt_ec.clear();
            }
        }
        if (config_.recv_bufsz > 0)
        {
            sock.set_option(net::socket_base::receive_buffer_size(config_.recv_bufsz), opt_ec);
            if (opt_ec)
            {
                trace::warn("[Pool] failed to set SO_RCVBUF: {}", opt_ec.message());
                opt_ec.clear();
            }
        }
        if (config_.send_bufsz > 0)
        {
            sock.set_option(net::socket_base::send_buffer_size(config_.send_bufsz), opt_ec);
            if (opt_ec)
            {
                trace::warn("[Pool] failed to set SO_SNDBUF: {}", opt_ec.message());
                opt_ec.clear();
            }
        }
    }

    auto connection_pool::async_acquire(tcp::endpoint endpoint)
        -> net::awaitable<std::pair<fault::code, pooled_connection>>
    {
        stat_acquires_ += 1;

        if (!started_)
        {
            trace::debug("[Pool] start() not called, background cleanup is disabled");
        }

        const auto key = to_key(endpoint);
        const auto now = std::chrono::steady_clock::now();
        const auto idle_timeout = std::chrono::seconds(config_.idle_sec);

        auto [reuse_ec, reused] = co_await try_reuse(reuse_opts{key, endpoint, now, idle_timeout});
        if (reuse_ec == fault::code::success)
        {
            co_return std::make_pair(fault::code::success, std::move(reused));
        }

        using net::experimental::awaitable_operators::operator||;

        const auto connect_timeout = std::chrono::milliseconds(config_.conn_timeout);

        auto *sock = new tcp::socket(ioc_);
        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(connect_timeout);

        boost::system::error_code connect_ec;
        boost::system::error_code timer_ec;
        auto connect_token = net::redirect_error(trace::use_prefix_awaitable, connect_ec);
        auto timer_token = net::redirect_error(trace::use_prefix_awaitable, timer_ec);

        auto connect_op = sock->async_connect(endpoint, connect_token);
        auto timer_op = timer.async_wait(timer_token);

        const auto result = co_await (std::move(connect_op) || std::move(timer_op));
        if (result.index() == 1)
        {
            delete_socket(sock);
            trace::warn("[Pool] connect timed out to {}:{}", endpoint.address().to_string(), endpoint.port());
            co_return std::make_pair(fault::code::timeout, pooled_connection{});
        }

        if (connect_ec)
        {
            delete_socket(sock);
            trace::warn("[Pool] connect failed: {}", connect_ec.message());
            co_return std::make_pair(fault::code::bad_gateway, pooled_connection{});
        }

        apply_opts(*sock);

        stat_creates_ += 1;

        trace::debug("[Pool] new connection to {}:{}", endpoint.address().to_string(), endpoint.port());
        co_return std::make_pair(fault::code::success, pooled_connection(this, sock, endpoint));
    }

    void connection_pool::recycle(tcp::socket *s, const tcp::endpoint &endpoint)
    {
        // 无效连接直接销毁，不计入驱逐统计
        if (!s || !s->is_open())
        {
            delete_socket(s);
            return;
        }

        stat_recycles_ += 1;

        // IPv6 连接默认不缓存，受配置控制
        if (!config_.cache_ipv6 && endpoint.address().is_v6())
        {
            trace::debug("[Pool] IPv6 connection not cached");
            delete_socket(s);
            stat_evictions_ += 1;
            return;
        }

        // 快速健康检测，不健康的连接不回收
        if (!healthy_fast(*s))
        {
            delete_socket(s);
            stat_evictions_ += 1;
            return;
        }

        // 检查缓存容量，超过单端点上限则丢弃
        const auto key = to_key(endpoint);
        auto [it, inserted] = cache_.try_emplace(key);
        auto &stack = it->second;
        if (inserted)
        {
            stat_endpoints_ += 1;
        }
        if (stack.size() >= config_.cache_peraddr)
        {
            delete_socket(s);
            stat_evictions_ += 1;
            return;
        }

        // 归还到缓存栈，记录最后使用时间
        stack.push_back({s, std::chrono::steady_clock::now()});
        stat_idle_ += 1;
    }

    void connection_pool::start()
    {
        started_ = true;
        if (cleanup_timer_.has_value())
        {
            return; // 已在运行
        }

        cleanup_timer_.emplace(ioc_);
        shutdown_flag_ = std::make_shared<std::atomic<bool>>(false);

        net::co_spawn(ioc_, cleanup_loop(), net::detached);
    }

    auto connection_pool::cleanup_loop() -> net::awaitable<void>
    {
        try
        {
            while (cleanup_timer_.has_value() && !shutdown_flag_->load(std::memory_order_acquire))
            {
                cleanup_timer_->expires_after(std::chrono::seconds(config_.clean_interval));
                boost::system::error_code ec;
                co_await cleanup_timer_->async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));
                if (ec)
                    break;
                if (shutdown_flag_->load(std::memory_order_acquire))
                    break;
                if (stat_acquires_ != 0)
                {
                    trace::debug("[Pool] total acquires: {}, total hits: {}, "
                                 "total creates: {}, total evictions: {}, "
                                 "total recycles: {}, total idle: {}",
                                 stat_acquires_, stat_hits_,
                                 stat_creates_, stat_evictions_,
                                 stat_recycles_, stat_idle_);
                }
                cleanup();
            }
        }
        catch (...)
        {
            trace::error("[Pool] cleanup timer error");
        }
    }

    void connection_pool::cleanup()
    {
        const auto now = std::chrono::steady_clock::now();
        const auto idle_timeout = std::chrono::seconds(config_.idle_sec);

        // 遍历所有端点的连接缓存
        for (auto it = cache_.begin(); it != cache_.end();)
        {
            auto &stack = it->second;

            // 原地压缩：保留未过期的有效连接，避免额外的内存分配
            std::size_t write = 0;
            for (std::size_t read = 0; read < stack.size(); ++read)
            {
                // 检查连接是否仍在空闲超时时间内
                if (now - stack[read].last_used <= idle_timeout)
                {
                    // 将有效连接前移到写入位置
                    if (write != read)
                    {
                        stack[write] = stack[read];
                    }
                    ++write;
                }
                else
                {
                    // 连接已过期，销毁 socket
                    delete_socket(stack[read].socket);
                    stat_evictions_ += 1;
                    stat_idle_ -= 1;
                }
            }

            // 根据压缩结果更新缓存
            if (write == 0)
            {
                // 该端点所有连接都已过期，清空并移除条目
                stack.clear();
                it = cache_.erase(it);
                stat_endpoints_ -= 1;
            }
            else
            {
                // 缩减栈大小到有效连接数
                stack.resize(write);
                ++it;
            }
        }
    }

    auto connection_pool::stats() const
        -> pool_stats
    {
        pool_stats s;
        s.total_acquires = stat_acquires_;
        s.total_hits = stat_hits_;
        s.total_creates = stat_creates_;
        s.total_recycles = stat_recycles_;
        s.total_evictions = stat_evictions_;
        s.idle_count = stat_idle_;
        s.endpoint_count = stat_endpoints_;

        return s;
    }

    void connection_pool::clear()
    {
        // 先设置退出标志，让清理协程安全退出
        if (shutdown_flag_)
        {
            shutdown_flag_->store(true, std::memory_order_release);
        }

        // 取消清理定时器
        if (cleanup_timer_.has_value())
        {
            cleanup_timer_->cancel();
            cleanup_timer_.reset();
        }

        shutdown_flag_.reset();

        for (auto &stack : cache_ | std::views::values)
        {
            for (const auto &[socket, last_used] : stack)
            {
                delete_socket(socket);
            }
        }
        cache_.clear();
        stat_idle_ = 0;
        stat_endpoints_ = 0;
    }
} // namespace psm::connect
