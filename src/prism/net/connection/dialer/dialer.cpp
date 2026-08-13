#include <prism/diagnose/diagnose.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/dialer/racer.hpp>
#include <prism/net/dns/detail/utility.hpp>
#include <prism/net/transport/reliable.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <charconv>

using namespace psm::diagnose;

namespace psm::connect
{

    using dns::detail::parse_port;

    namespace
    {
        /**
         * @struct socket_options
         * @brief 新建 socket 的选项
         */
        struct socket_options
        {
            // 0 = 不设置，使用 Windows 自动调优（自适应 RTT/丢包，避免 64KB 窗口截断带宽）
            std::uint32_t recv_bufsz = 0U; // 接收缓冲区大小（字节）
            std::uint32_t send_bufsz = 0U; // 发送缓冲区大小（字节）
            bool tcp_nodelay = true;       // 是否启用 TCP_NODELAY
            bool keep_alive = true;        // 是否启用 SO_KEEPALIVE
        };

        /**
         * @struct dial_opts
         * @brief 拨号选项（超时 + 日志上下文 + socket 选项）
         */
        struct dial_opts
        {
            std::chrono::milliseconds timeout{300};   // 连接超时（毫秒）
            std::shared_ptr<diagnose::context> trace; // 日志上下文
            socket_options sock;                      // socket 选项
        };

        // 新建 socket 的选项设置
        inline void apply_socket_options(tcp::socket &sock, const socket_options &cfg)
        {
            boost::system::error_code opt_ec;
            if (cfg.tcp_nodelay)
            {
                sock.set_option(tcp::no_delay(true), opt_ec);
                if (opt_ec)
                {
                    opt_ec.clear();
                }
            }
            if (cfg.keep_alive)
            {
                sock.set_option(tcp::socket::keep_alive(true), opt_ec);
                if (opt_ec)
                {
                    opt_ec.clear();
                }
            }
            if (cfg.recv_bufsz > 0)
            {
                sock.set_option(net::socket_base::receive_buffer_size(cfg.recv_bufsz), opt_ec);
                if (opt_ec)
                {
                    opt_ec.clear();
                }
            }
            if (cfg.send_bufsz > 0)
            {
                sock.set_option(net::socket_base::send_buffer_size(cfg.send_bufsz), opt_ec);
                if (opt_ec)
                {
                    opt_ec.clear();
                }
            }
        }

        // 检查目标地址是否为 IPv6 字面量
        [[nodiscard]] inline auto is_ipv6(const std::string_view host) noexcept -> bool
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            return !ec && addr.is_v6();
        }

        // 打开 UDP 套接字（按目标地址选择协议族）
        [[nodiscard]] inline auto open_udp(const net::any_io_executor &executor,
                                           const net::ip::udp::endpoint &target)
            -> std::pair<fault::code, net::ip::udp::socket>
        {
            boost::system::error_code ec;
            net::ip::udp::socket socket(executor);

            auto protocol = net::ip::udp::v4();
            if (target.address().is_v6())
            {
                protocol = net::ip::udp::v6();
            }
            socket.open(protocol, ec);
            if (ec)
            {
                return std::pair{fault::code::io_error, net::ip::udp::socket(executor)};
            }

            return std::pair{fault::code::success, std::move(socket)};
        }
    } // namespace

    dialer::dialer(dialer_options opts)
        : dial_timeout_(opts.dial_timeout), mr_(memory::effective_mr(opts.mr)),
          dns_(std::make_unique<dns::resolver>(opts.ioc, std::move(opts.dns_cfg), mr_)), reverse_map_(mr_),
          executor_(opts.ioc.get_executor())
    {
    }

    void dialer::set_endpoint(const std::string_view host, const std::uint16_t port)
    {
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

    void dialer::add_route(const std::string_view host, const tcp::endpoint &ep)
    {
        memory::string host_key(mr_);
        host_key.assign(host);
        reverse_map_.insert_or_assign(std::move(host_key), ep);
    }

    auto dialer::dial_endpoint(const tcp::endpoint &ep, std::shared_ptr<diagnose::context> trace)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        using net::experimental::awaitable_operators::operator||;

        auto rel = std::make_shared<transport::reliable>(executor_);
        shared_transmission trans = rel;
        auto &sock = rel->native_socket();

        // 显式 open（明确协议族），避免 async_connect 隐式 open 的路径差异
        boost::system::error_code open_ec;
        sock.open(ep.protocol(), open_ec);
        if (open_ec)
        {
            diagnose::warn(trace, "socket open failed: {}", open_ec.message());
            co_return std::make_pair(fault::code::io_error, shared_transmission{});
        }

        const dial_opts opts{dial_timeout_, std::move(trace)};
        net::steady_timer timer(sock.get_executor());
        timer.expires_after(opts.timeout);

        boost::system::error_code connect_ec;
        boost::system::error_code timer_ec;
        auto connect_token = net::redirect_error(net::use_awaitable, connect_ec);
        auto timer_token = net::redirect_error(net::use_awaitable, timer_ec);

        auto connect_op = sock.async_connect(ep, connect_token);
        auto timer_op = timer.async_wait(timer_token);

        const auto result = co_await (std::move(connect_op) || std::move(timer_op));
        if (result.index() == 1)
        {
            diagnose::warn(opts.trace, "connect timed out to {}:{}", ep.address().to_string(), ep.port());
            co_return std::make_pair(fault::code::timeout, shared_transmission{});
        }

        if (connect_ec)
        {
            diagnose::warn(opts.trace, "connect failed: {}", connect_ec.message());
            co_return std::make_pair(fault::code::bad_gateway, shared_transmission{});
        }

        apply_socket_options(sock, opts.sock);

        diagnose::debug(opts.trace, "new connection to {}:{}", ep.address().to_string(), ep.port());
        co_return std::make_pair(fault::code::success, std::move(trans));
    }

    auto dialer::async_reverse(const std::string_view host)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        const auto route = reverse_map_.find(host);
        if (route == reverse_map_.end())
        {
            co_return std::make_pair(fault::code::bad_gateway, shared_transmission{});
        }

        auto [code, conn] = co_await dial_endpoint(route->second, nullptr);
        if (!conn)
        {
            co_return std::make_pair(fault::code::bad_gateway, shared_transmission{});
        }

        co_return std::make_pair(fault::code::success, std::move(conn));
    }

    auto dialer::connect(const target &t, std::shared_ptr<diagnose::context> trace)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>
    {
        // 拒绝 IPv6 地址字面量（仅在禁用 IPv6 时）
        if (ipv6_disabled() && is_ipv6(t.host))
        {
            diagnose::debug(trace, "rejecting IPv6 literal: {}:{}", t.host, t.port);
            co_return std::pair{fault::code::ipv6_disabled, nullptr};
        }

        if (!t.positive)
        {
            // 反向路由：域名 → 预配置的后端地址
            co_return co_await async_reverse(t.host);
        }

        // 正向路由：尝试解析为 IP 字面量，成功则跳过 DNS
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(t.host, ec);
            if (!ec)
            {
                const auto port_num = parse_port(t.port).value_or(0);
                const tcp::endpoint ep(addr, port_num);
                diagnose::debug(trace, "literal address, direct connect: {}", t.host);
                auto [code, conn] = co_await dial_endpoint(ep, trace);
                if (conn)
                {
                    co_return std::make_pair(fault::code::success, std::move(conn));
                }
                co_return std::make_pair(fault::code::bad_gateway, shared_transmission{});
            }
        }

        // DNS 返回多结果，Happy Eyeballs 竞速连接
        auto [resolve_ec, endpoints] = co_await dns().resolve_tcp(t.host, t.port);
        if (fault::failed(resolve_ec) || endpoints.empty())
        {
            diagnose::warn(trace, "DNS resolve {}:{} failed", t.host, t.port);
            co_return std::make_pair(fault::code::host_noreply, shared_transmission{});
        }

        auto conn = co_await race(endpoints, trace);
        if (conn)
        {
            co_return std::make_pair(fault::code::success, std::move(conn));
        }

        co_return std::make_pair(fault::code::bad_gateway, shared_transmission{});
    }

    auto dialer::race(std::span<const tcp::endpoint> endpoints, std::shared_ptr<diagnose::context> trace)
        -> net::awaitable<shared_transmission>
    {
        if (endpoints.empty())
        {
            co_return shared_transmission{};
        }

        address_racer racer([this](const tcp::endpoint &ep) { return dial_endpoint(ep, nullptr); });
        co_return co_await racer.race(endpoints, trace);
    }

    auto dialer::datagram(std::string_view host, std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
    {
        net::ip::udp::endpoint target;
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec)
            {
                if (addr.is_v6() && ipv6_disabled())
                {
                    co_return std::pair{fault::code::host_noreply, net::ip::udp::socket{executor_}};
                }
                const auto port_num = parse_port(port).value_or(0);
                target = net::ip::udp::endpoint(addr, port_num);
            }
            else
            {
                const auto [resolve_ec, resolved] = co_await dns().resolve_udp(host, port);
                if (fault::failed(resolve_ec))
                {
                    co_return std::pair{resolve_ec, net::ip::udp::socket{executor_}};
                }
                target = resolved;
            }
        }

        co_return open_udp(executor_, target);
    }

    auto dialer::resolve_dgram(std::string_view host, std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
    {
        {
            boost::system::error_code ec;
            const auto addr = net::ip::make_address(host, ec);
            if (!ec)
            {
                if (addr.is_v6() && ipv6_disabled())
                {
                    co_return std::make_pair(fault::code::host_noreply, net::ip::udp::endpoint{});
                }
                const auto port_num = parse_port(port).value_or(0);
                co_return std::make_pair(fault::code::success, net::ip::udp::endpoint(addr, port_num));
            }
        }
        co_return co_await dns().resolve_udp(host, port);
    }

} // namespace psm::connect
