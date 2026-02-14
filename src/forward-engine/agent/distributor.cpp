#include <forward-engine/agent/distributor.hpp>
#include <abnormal.hpp>
#include <array>
#include <charconv>
#include <string>

namespace ngx::agent
{
    using tcp = boost::asio::ip::tcp;

    distributor::distributor(source &pool, net::io_context &ioc, const memory::resource_pointer mr)
        : pool_(pool), resolver_(ioc), mr_(mr ? mr : memory::current_resource()), reverse_map_(mr_), dns_cache_(mr_)
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

    void distributor::add_reverse_route(const std::string_view host, const tcp::endpoint& ep)
    {
        memory::string host_key(mr_);
        host_key.assign(host);
        reverse_map_.insert_or_assign(std::move(host_key), ep);
    }

    auto distributor::route_positive(const std::string_view host, const std::string_view port)
        -> net::awaitable<std::pair<gist::code, unique_sock>>
    {
        /**
         * @details 通过上游 HTTP 代理建立 `CONNECT` 隧道：
         * 1) 解析并连接到上游代理
         * 2) 发送 `CONNECT host:port HTTP/1.1`（不带认证头）
         * 3) 读取响应头直到 `\\r\\n\\r\\n`，解析状态码，必须为 200
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
        const auto endpoints = co_await resolver_.async_resolve(
            std::string_view(*positive_host_), std::string_view(port_string),
            net::redirect_error(net::use_awaitable, ec));
        if (ec || endpoints.empty())
        {
            co_return std::make_pair(gist::code::host_unreachable, nullptr);
        }

        auto socket_ptr = unique_sock(new tcp::socket(resolver_.get_executor()), transport::deleter{});
        auto token = net::redirect_error(net::use_awaitable, ec);
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
        const auto code_str = status_line.substr(first_space + 1, second_space == std::string_view::npos ? std::string_view::npos : second_space - first_space - 1);
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
        /**
         * @details 路由优先级：
         * 1) 黑名单拦截（直接返回 `blocked`）
         * 2) 尝试直连：DNS -> 连接池
         * 3) 直连失败则回退：上游正向代理 `CONNECT` 隧道
         *
         * 这样设计的好处是：
         * - 默认走直连，减少不必要的代理跳数
         * - 在 DNS 或建连不可用的环境下，仍可通过上游代理兜底
         */
        // 1. DNS
        if (blacklist_.domain(host))
        {
            co_return std::make_pair(gist::code::blocked, nullptr);
        }
        // DNS 缓存查询
        memory::string cache_key(mr_);
        cache_key.reserve(host.size() + 1 + port.size());
        cache_key.append(host);
        cache_key.push_back(':');
        cache_key.append(port);
        const auto now = std::chrono::steady_clock::now();
        std::optional<tcp::endpoint> cached_endpoint;

        // 1. 尝试查找缓存（避免跨协程挂起持有迭代器）
        if (auto it = dns_cache_.find(cache_key); it != dns_cache_.end() && it->second.expire_at > now)
        {
            const auto &cached = it->second.endpoints;
            if (!cached.empty())
            {
                cached_endpoint = cached.front();
            }
        }

        // 2. 如果缓存命中，尝试建立连接
        if (cached_endpoint)
        {
            auto conn = co_await pool_.acquire_tcp(*cached_endpoint);
            if (conn && conn->is_open())
            {
                co_return std::make_pair(gist::code::success, std::move(conn));
            }
            // 连接失败，清除缓存项（重新查找以避免迭代器失效）
            dns_cache_.erase(cache_key);
        }
        // 缓存未命中或过期，执行解析
        boost::system::error_code ec;
        const auto results = co_await resolver_.async_resolve(host, port, net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            co_return co_await route_positive(host, port);
        }
        if (results.empty())
        {
            co_return co_await route_positive(host, port);
        }
        // 存入缓存，TTL 30 秒
        std::vector<tcp::endpoint> endpoints;
        endpoints.reserve(std::distance(results.begin(), results.end()));
        for (const auto &ep : results)
        {
            endpoints.push_back(ep.endpoint());
        }
        dns_cache_[std::move(cache_key)] = dns_cache_entry{std::move(endpoints), now + std::chrono::seconds(30)};
        // 2. 找池子要连接：失败则回退到正向代理
        auto conn = co_await pool_.acquire_tcp(*results.begin());
        if (!conn || !conn->is_open())
        {
            co_return co_await route_positive(host, port);
        }
        co_return std::make_pair(gist::code::success, std::move(conn));

        co_return std::make_pair(gist::code::bad_gateway, nullptr);
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
