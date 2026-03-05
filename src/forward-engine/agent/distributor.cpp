#include <forward-engine/agent/distributor.hpp>
#include <abnormal.hpp>
#include <array>
#include <charconv>
#include <string>

namespace ngx::agent
{
    using tcp = boost::asio::ip::tcp;

    distributor::distributor(source &pool, net::io_context &ioc, const memory::resource_pointer mr)
        : pool_(pool), resolver_(ioc), mr_(mr ? mr : memory::current_resource()),
          reverse_map_(mr_), dns_cache_(mr_), flight_map_(mr_)
    {
    }

    void distributor::set_positive_endpoint(const std::string_view host, const std::uint16_t port)
    {
        /**
         * @details 该配置由 `worker` 在初始化阶段注入：
         * - 当 `agent.config.positive` 可用时启用
         * - host 为空或 port 为 0 表示关闭该能力
         *
         * 这里使用 `memory::string` 保存 host，是为了避免外部字符串生命周期问题。
         */
        if (host.empty() || port == 0)
        {
            positive_host_.reset();
            positive_port_ = 0;
            return;
        }

        memory::string host_value(mr_);
        host_value.assign(host);
        positive_host_ = std::move(host_value);
        positive_port_ = port;
    }

    void distributor::add_reverse_route(const std::string_view host, const tcp::endpoint &ep)
    {
        memory::string host_key(mr_);
        host_key.assign(host);
        reverse_map_.insert_or_assign(std::move(host_key), ep);
    }

    auto distributor::try_connect_endpoints(const memory::vector<tcp::endpoint> &endpoints)
        -> net::awaitable<unique_sock>
    {
        for (const auto &endpoint : endpoints)
        {
            auto conn = co_await pool_.acquire_tcp(endpoint);
            if (conn && conn->is_open())
            {
                co_return conn;
            }
        }
        co_return nullptr;
    }

    auto distributor::try_connect_cache(const memory::string &cache_key, const std::chrono::steady_clock::time_point now)
        -> net::awaitable<unique_sock>
    {
        std::size_t endpoint_index{0};
        bool has_candidate{false};
        while (true)
        {
            const auto it = dns_cache_.find(cache_key);
            if (it == dns_cache_.end())
            {
                break;
            }
            if (it->second.expiration_time <= now)
            {
                dns_cache_.erase(cache_key);
                break;
            }
            if (endpoint_index >= it->second.endpoints.size())
            {
                has_candidate = endpoint_index > 0;
                break;
            }

            const auto endpoint = it->second.endpoints[endpoint_index++];
            auto conn = co_await pool_.acquire_tcp(endpoint);
            if (conn && conn->is_open())
            {
                co_return conn;
            }
        }

        if (has_candidate)
        {
            dns_cache_.erase(cache_key);
        }
        co_return nullptr;
    }

    auto distributor::route_positive(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<gist::code, unique_sock>>
    {
        /**
         * @details 通过上游 HTTP 代理建立 `CONNECT` 隧道：
         * 1 解析并连接到上游代理
         * 2 发送 `CONNECT host:port HTTP/1.1`（不带认证头）
         * 3 读取响应头直到 `\\r\\n\\r\\n`，解析状态码，必须为 200
         *
         * @note 这是最小可用实现，用于做“直连失败回退”：
         * - 不解析完整 HTTP 头，仅检查状态行
         * - 响应头读取最多 8192 字节，避免异常响应导致内存膨胀
         */
        if (!positive_host_ || positive_port_ == 0)
        {
            co_return std::make_pair(gist::code::host_unreachable, nullptr);
        }

        boost::system::error_code ec;
        const auto port_string = std::to_string(positive_port_);
        auto token = net::redirect_error(net::use_awaitable, ec);
        const auto endpoints = co_await resolver_.async_resolve((*positive_host_).c_str(), port_string.c_str(), token);
        if (ec || endpoints.empty())
        {
            // 上游代理地址不可解析时，直接视为上游不可达
            co_return std::make_pair(gist::code::host_unreachable, nullptr);
        }

        auto socket_ptr = unique_sock(new tcp::socket(resolver_.get_executor()), transport::deleter{});
        co_await net::async_connect(*socket_ptr, endpoints, token);
        if (ec)
        {
            co_return std::make_pair(gist::code::host_unreachable, nullptr);
        }
        // 设置 TCP_NODELAY 以减少延迟
        socket_ptr->set_option(net::ip::tcp::no_delay(true));

        // 发送 CONNECT 请求
        memory::string connect_request(mr_);
        connect_request.reserve(256);
        connect_request.append("CONNECT ");
        connect_request.append(host.begin(), host.end());
        connect_request.push_back(':');
        connect_request.append(port.begin(), port.end());
        connect_request.append(" HTTP/1.1\r\nHost: ");
        connect_request.append(host.begin(), host.end());
        connect_request.push_back(':');
        connect_request.append(port.begin(), port.end());
        connect_request.append("\r\nProxy-Connection: Keep-Alive\r\n\r\n");

        ec.clear();
        co_await net::async_write(*socket_ptr, net::buffer(connect_request), token);
        if (ec)
        {
            co_return std::make_pair(gist::code::bad_gateway, nullptr);
        }

        memory::string header(mr_);
        header.reserve(1024);

        std::array<char, 1024> read_buf{};
        while (header.find("\r\n\r\n") == std::string::npos && header.size() < 8192)
        {
            ec.clear();
            const auto n = co_await socket_ptr->async_read_some(net::buffer(read_buf), token);
            if (ec || n == 0)
            {
                co_return std::make_pair(gist::code::bad_gateway, nullptr);
            }
            header.append(read_buf.data(), n);
        }

        if (header.find("\r\n\r\n") == std::string::npos)
        {
            co_return std::make_pair(gist::code::bad_gateway, nullptr);
        }

        const auto header_view = std::string_view(header);
        const auto line_end = header_view.find("\r\n");
        const auto status_line = header_view.substr(0, line_end == std::string_view::npos ? header_view.size() : line_end);
        const auto first_space = status_line.find(' ');
        if (first_space == std::string::npos)
        {
            co_return std::make_pair(gist::code::bad_gateway, nullptr);
        }

        const auto second_space = status_line.find(' ', first_space + 1);
        auto string_index = second_space == std::string_view::npos ? std::string_view::npos : second_space - first_space - 1;
        const auto code_str = status_line.substr(first_space + 1, string_index);
        int status_code = 0;
        const auto [ptr, parse_ec] = std::from_chars(code_str.data(), code_str.data() + code_str.size(), status_code);
        static_cast<void>(ptr);
        if (parse_ec != std::errc())
        {
            co_return std::make_pair(gist::code::bad_gateway, nullptr);
        }

        // 检查响应回来的 http CONNECT 报文状态码是否为200
        if (status_code != 200)
        {
            co_return std::make_pair(gist::code::bad_gateway, nullptr);
        }

        co_return std::make_pair(gist::code::success, std::move(socket_ptr));
    }

    auto distributor::route_forward(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<gist::code, unique_sock>>
    {
        // 第一关：黑名单快速拒绝
        if (blacklist_.domain(host))
        {
            co_return std::make_pair(gist::code::blocked, nullptr);
        }

        // 构造 host:port 缓存键（使用 PMR 资源）
        memory::string cache_key(mr_);
        cache_key.reserve(host.size() + 1 + port.size());
        cache_key.append(host);
        cache_key.push_back(':');
        cache_key.append(port);

        // 第二关：常规 DNS 缓存快路径
        if (auto cached_conn = co_await try_connect_cache(cache_key, std::chrono::steady_clock::now()))
        {
            co_return std::make_pair(gist::code::success, std::move(cached_conn));
        }

        // 第三关：若同 key 已有先锋协程在解析，则挂起等待广播
        if (const auto in_flight_it = flight_map_.find(cache_key); in_flight_it != flight_map_.end())
        {
            const auto timer = in_flight_it->second;
            boost::system::error_code ignore_ec;
            co_await timer->async_wait(net::redirect_error(net::use_awaitable, ignore_ec));

            // 被唤醒后再次读取缓存，命中即直接复用
            if (auto cached_conn = co_await try_connect_cache(cache_key, std::chrono::steady_clock::now()))
            {
                co_return std::make_pair(gist::code::success, std::move(cached_conn));
            }
            co_return co_await route_positive(host, port);
        }

        // 第四关：当前协程成为先头，负责真实解析并广播结果
        const auto executor = co_await net::this_coro::executor;
        auto timer = std::make_shared<net::steady_timer>(executor);
        timer->expires_at(std::chrono::steady_clock::time_point::max());
        flight_map_.insert_or_assign(cache_key, timer);

        boost::system::error_code ec;
        const auto results = co_await resolver_.async_resolve(host, port, net::redirect_error(net::use_awaitable, ec));
        flight_map_.erase(cache_key);

        memory::vector<tcp::endpoint> resolved_endpoints(mr_);
        if (!ec && !results.empty())
        {
            resolved_endpoints.reserve(std::distance(results.begin(), results.end()));
            for (const auto &result : results)
            {
                resolved_endpoints.push_back(result.endpoint());
            }

            memory::vector<tcp::endpoint> cached_endpoints(mr_);
            cached_endpoints.reserve(resolved_endpoints.size());
            cached_endpoints.insert(cached_endpoints.end(), resolved_endpoints.begin(), resolved_endpoints.end());
            dns_cache_.insert_or_assign(cache_key, 
                addresses{std::move(cached_endpoints),std::chrono::steady_clock::now() + std::chrono::seconds(30)});
            if (dns_cache_.size() > 10000)
            {
                dns_cache_.erase(dns_cache_.begin());
            }
        }

        timer->cancel();

        // 解析失败或空结果时回退上游代理
        if (ec || resolved_endpoints.empty())
        {
            co_return co_await route_positive(host, port);
        }

        if (auto resolved_conn = co_await try_connect_endpoints(resolved_endpoints))
        {
            co_return std::make_pair(gist::code::success, std::move(resolved_conn));
        }

        co_return co_await route_positive(host, port);
    }

    auto distributor::route_reverse(const std::string_view host)
        -> net::awaitable<std::pair<gist::code, unique_sock>>
    {
        // 1. 查配置表
        if (const auto it = reverse_map_.find(host); it != reverse_map_.end())
        {
            auto conn = co_await pool_.acquire_tcp(it->second);
            if (!conn || !conn->is_open())
            {
                co_return std::make_pair(gist::code::bad_gateway, nullptr);
            }
            co_return std::make_pair(gist::code::success, std::move(conn));
        }
        co_return std::make_pair(gist::code::bad_gateway, nullptr);
    }

    auto distributor::route_direct(const tcp::endpoint ep) const
        -> net::awaitable<std::pair<gist::code, unique_sock>>
    {
        auto conn = co_await pool_.acquire_tcp(ep);
        if (!conn || !conn->is_open())
        {
            co_return std::make_pair(gist::code::bad_gateway, nullptr);
        }
        co_return std::make_pair(gist::code::success, std::move(conn));
    }

}
