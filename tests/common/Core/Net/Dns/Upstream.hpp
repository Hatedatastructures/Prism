/**
 * @file Upstream.hpp
 * @brief DNS 上游查询编排层（UDP / TCP / DoT / DoH 四协议）
 * @details 对齐主项目 net/dns/upstream 分层，只做编排，不做传输：
 *          - 传输细节全部在 Transport.hpp / Doh.hpp（帧编解码、超时、
 *            建连、连接池），本层负责：查询报文构造与 Id 分配、三种策略
 *            （Fallback 顺序 / First 并发首胜 / Fastest 并发选优）、
 *            UDP TC 截断回退 TCP、RCODE 语义、结果聚合
 *          - RCODE 语义与主项目一致：0=成功、3=NXDOMAIN（成功+空 IP，
 *            由上层负缓存）；其余 RCODE 为上游明确拒绝（ProtocolError，
 *            Fallback 模式继续尝试下一上游）
 *          - 连接池：TCP/DoT/DoH 复用建连（Server.KeepAlive=false 关闭），
 *            池中连接可能被对端静默关闭——复用首次失败自动新建重试一次
 * @note 超时用 awaitable_operators 竞速实现（preview 库惯例，同 Dialer）：
 *       查询协程与定时器并行，超时方胜出时查询协程被取消
 */

#pragma once

#include "Answer.hpp"
#include "Config.hpp"
#include "ConnPool.hpp"
#include "Doh.hpp"
#include "Format.hpp"
#include "Transport.hpp"

#include <common/Core/Error.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ssl.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @struct QueryResult
     * @brief 单次上游查询结果
     * @note Response 为热路径扫描摘要（AnswerSet）：MinTtl/Rcode/Truncated
     *       语义与完整报文物化（Message）对齐，字段名保持一致
     */
    struct QueryResult
    {
        AnswerSet Response;                ///< 响应摘要（失败时 Id=0、无记录）
        std::vector<net::ip::address> Ips; ///< 提取的 IP 地址列表
        std::uint64_t RttMs{0};            ///< 往返耗时（毫秒）
        std::string ServerAddr;            ///< 响应来源上游地址
        boost::system::error_code Error;   ///< 错误码（默认成功）
    };

    /**
     * @struct UpstreamOptions
     * @brief 上游查询客户端配置
     * @details 将服务器列表、调度策略、超时和连接池容量收敛为
     *          一个配置对象，避免构造函数参数过多。
     */
    struct UpstreamOptions
    {
        std::vector<Server> Servers; ///< 上游服务器列表
        Mode QueryMode{Mode::Fastest}; ///< 多上游查询策略
        std::chrono::milliseconds DefaultTimeout{4000}; ///< 默认查询超时
        std::size_t MaxConnsPerServer{4}; ///< 每服务器最大闲置连接数
    };

    /**
     * @class Upstream
     * @brief 异步 DNS 查询编排（非线程安全，单 io_context 内使用）
     */
    class Upstream : public std::enable_shared_from_this<Upstream>
    {
    public:
        /**
         * @brief 构造查询客户端
         * @param ex 执行器
         * @param options 上游服务器、策略、超时和连接池配置
         */
        explicit Upstream(net::any_io_executor ex, UpstreamOptions options = {})
            : Ex_(std::move(ex)), Servers_(std::move(options.Servers)),
              Mode_(options.QueryMode), Timeout_(options.DefaultTimeout),
              TcpPool_(options.MaxConnsPerServer, PoolIdleTtl),
              TlsPool_(options.MaxConnsPerServer, PoolIdleTtl),
              DohPool_(options.MaxConnsPerServer, PoolIdleTtl)
        {
        }

        /**
         * @brief 构造查询客户端的简化形式
         * @param ex 执行器
         * @param servers 上游服务器列表
         * @param mode 多上游查询策略
         */
        explicit Upstream(net::any_io_executor ex, std::vector<Server> servers,
                          const Mode mode = Mode::Fastest)
            : Upstream(std::move(ex), UpstreamOptions{std::move(servers), mode})
        {
        }

        /**
         * @brief 替换上游服务器列表
         * @param servers 新列表
         */
        void SetServers(const std::vector<Server> &servers)
        {
            Servers_ = servers;
        }

        /**
         * @brief 设置解析策略
         * @param mode Fallback / First / Fastest
         */
        void SetMode(const Mode mode)
        {
            Mode_ = mode;
        }

        /**
         * @brief 设置默认超时
         * @param ms 毫秒数
         */
        void SetTimeout(const std::chrono::milliseconds ms)
        {
            Timeout_ = ms;
        }

        /**
         * @brief 上游数量
         * @return 当前服务器列表大小
         */
        [[nodiscard]] auto ServerCount() const -> std::size_t
        {
            return Servers_.size();
        }

        /**
         * @brief 闲置连接总数（三池合计，测试/维护用）
         */
        [[nodiscard]] auto IdleConnCount() const -> std::size_t
        {
            return TcpPool_.IdleCount() + TlsPool_.IdleCount() + DohPool_.IdleCount();
        }

        /**
         * @brief 清理全部过期闲置连接（供维护循环周期调用）
         * @return 清理数量
         */
        auto ClearIdleConns() -> std::size_t
        {
            return TcpPool_.ClearExpired() + TlsPool_.ClearExpired() + DohPool_.ClearExpired();
        }

        /**
         * @brief 异步查询域名
         * @details 按当前策略向上游发起查询并聚合结果。id 采用时间戳低位
         *          种子 + 进程内递增计数器，避免并发查询冲突。
         * @param domain 已规范化域名
         * @param qt 查询类型
         * @return 查询结果；无上游或全部失败时 Error 非 success
         */
        [[nodiscard]] auto Resolve(std::string_view domain, const QType qt)
            -> net::awaitable<QueryResult>
        {
            auto query = Message::MakeQuery(domain, qt);
            query.Id = static_cast<std::uint16_t>(
                Seed_ ^ (++Counter_));
            const auto QtNum = static_cast<std::uint16_t>(qt);

            // EDNS0（RFC 6891）：Additional 段宣告接收缓冲 4096；
            // Name 为根、TTL 字段为扩展标志（0，无 DO 位）
            Record opt;
            opt.Name = "";
            opt.Type = QType::Opt;
            opt.RClass = 4096;
            opt.Ttl = 0;
            query.Additional.push_back(std::move(opt));

            if (Servers_.empty())
            {
                QueryResult failed;
                failed.Error = make_error_code(Error::BadAddress);
                co_return failed;
            }
            if (Mode_ == Mode::Fallback)
            {
                co_return co_await ResolveFallback(query, QtNum);
            }
            co_return co_await ResolveConcurrent(query, QtNum);
        }

    private:
        /// 闲置连接存活时长
        static constexpr std::chrono::milliseconds PoolIdleTtl{30000};

        /// 池键：按地址、端口、TLS/HTTP 身份区分可复用连接
        [[nodiscard]] static auto PoolKey(const Server &server) -> std::string
        {
            return server.Address + '|' + std::to_string(server.Port) + '|' + server.Hostname +
                   '|' + server.HttpPath + '|' + (server.SkipCertCheck ? '1' : '0');
        }

        template <PoolableTransport Link>
        struct PooledExchangeRequest
        {
            ConnPool<Link> &Pool;
            std::string Key;
            net::ip::tcp::endpoint Endpoint;
            const Server &ServerConfig;
            std::span<const std::uint8_t> Wire;
        };

        /// 单服务器查询分发
        [[nodiscard]] auto QueryServer(const Server &server, const Message &query,
                                       const std::uint16_t qtNum)
            -> net::awaitable<QueryResult>
        {
            switch (server.Proto)
            {
            case Protocol::Tcp:
                co_return co_await QueryTcp(server, query, qtNum);
            case Protocol::Tls:
                co_return co_await QueryTls(server, query, qtNum);
            case Protocol::Https:
                co_return co_await QueryHttps(server, query, qtNum);
            case Protocol::Udp:
                break;
            }
            co_return co_await QueryUdp(server, query, qtNum);
        }

        /**
         * @brief 带超时执行查询协程
         * @param task 查询协程
         * @param timeout 超时时长
         * @return 成功返回结果；超时返回 Error=Timeout 的占位结果
         */
        [[nodiscard]] auto WithTimeout(net::awaitable<QueryResult> task,
                                       const std::chrono::milliseconds timeout)
            -> net::awaitable<QueryResult>
        {
            using namespace boost::asio::experimental::awaitable_operators;

            net::steady_timer timer(Ex_);
            timer.expires_after(timeout);
            auto outcome = co_await (std::move(task) || timer.async_wait(net::use_awaitable));
            if (outcome.index() == 1)
            {
                QueryResult timedOut;
                timedOut.Error = make_error_code(Error::Timeout);
                co_return timedOut;
            }
            co_return std::move(std::get<0>(outcome));
        }

        /**
         * @brief 解析上游地址为端点（支持域名与 IP 字面量，结果缓存）
         * @param host 上游主机名或 IP
         * @param port 端口
         * @param ec [out] 错误码
         * @return 首个解析端点；失败时 ec 置位
         */
        [[nodiscard]] auto ResolveEndpoint(const std::string &host, const std::uint16_t port,
                                           boost::system::error_code &ec)
            -> net::awaitable<net::ip::basic_endpoint<net::ip::tcp>>
        {
            const auto CacheKey = host + ':' + std::to_string(port);
            if (const auto It = EndpointCache_.find(CacheKey); It != EndpointCache_.end())
            {
                co_return It->second;
            }
            net::ip::tcp::resolver resolver(Ex_);
            auto results = co_await resolver.async_resolve(
                host, std::to_string(port), net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return net::ip::tcp::endpoint{};
            }
            const auto Ep = results.begin()->endpoint();
            EndpointCache_.emplace(CacheKey, Ep);
            co_return Ep;
        }

        /// 单帧收发（Send → Receive，任何一步失败即终止）
        template <typename Link>
        static auto ExchangeOnce(Link &link, std::span<const std::uint8_t> wire)
            -> net::awaitable<EcResult<std::vector<std::uint8_t>>>
        {
            if (auto ec = co_await link.Send(wire))
            {
                co_return std::unexpected(ec);
            }
            co_return co_await link.Receive();
        }

        /**
         * @brief 池化交换：优先复用空闲连接，复用失败（对端已关）新建重试一次
         * @param makeLink 新建连接工厂（返回 EcResult，建连失败携带错误码）
         */
        template <PoolableTransport Link, typename Factory>
        auto ExchangePooled(PooledExchangeRequest<Link> request, Factory makeLink)
            -> net::awaitable<EcResult<std::vector<std::uint8_t>>>
        {
            if (request.ServerConfig.KeepAlive)
            {
                auto lease = request.Pool.Acquire(request.Key);
                if (lease.Conn)
                {
                    if (auto result = co_await ExchangeOnce(*lease.Conn, request.Wire))
                    {
                        request.Pool.Release(request.Key, lease.Conn);
                        co_return result;
                    }
                    // 复用失败：对端可能已按自身策略关闭 keep-alive 连接，
                    // 连接随 lease 离开作用域丢弃，落新建重试
                }
            }
            auto fresh = co_await makeLink(request.Endpoint, request.ServerConfig);
            if (!fresh)
            {
                co_return std::unexpected(fresh.error());
            }
            auto result = co_await ExchangeOnce(**fresh, request.Wire);
            if (result && request.ServerConfig.KeepAlive)
            {
                request.Pool.Release(request.Key, *fresh);
            }
            co_return result;
        }

        /// 构造已建连的 TCP 传输（工厂用）
        [[nodiscard]] auto MakeTcp(const net::ip::tcp::endpoint &ep, const Server &server)
            -> net::awaitable<EcResult<std::shared_ptr<TcpTransport>>>
        {
            auto link = std::make_shared<TcpTransport>(Ex_, TimeoutFor(server));
            if (auto ec = co_await link->Connect(ep, server))
            {
                co_return std::unexpected(ec);
            }
            co_return link;
        }

        /// 构造已建连的 DoT 传输（工厂用）
        [[nodiscard]] auto MakeTls(const net::ip::tcp::endpoint &ep, const Server &server)
            -> net::awaitable<EcResult<std::shared_ptr<TlsTransport>>>
        {
            auto link = std::make_shared<TlsTransport>(Ex_, TimeoutFor(server), GetSslContext(server));
            if (auto ec = co_await link->Connect(ep, server))
            {
                co_return std::unexpected(ec);
            }
            co_return link;
        }

        /// 构造已建连的 DoH 传输（工厂用）
        [[nodiscard]] auto MakeDoh(const net::ip::tcp::endpoint &ep, const Server &server)
            -> net::awaitable<EcResult<std::shared_ptr<DohTransport>>>
        {
            const auto HostHeader = !server.Hostname.empty() ? server.Hostname : server.Address;
            DohOptions options;
            options.Executor = Ex_;
            options.Timeout = TimeoutFor(server);
            options.Context = GetSslContext(server);
            options.HttpPath = server.HttpPath;
            options.HostHeader = HostHeader;
            auto link = std::make_shared<DohTransport>(std::move(options));
            if (auto ec = co_await link->Connect(ep, server))
            {
                co_return std::unexpected(ec);
            }
            co_return link;
        }

        /**
         * @brief UDP 查询（TC 截断自动回退 TCP）
         */
        [[nodiscard]] auto QueryUdp(const Server &server, const Message &query,
                                    const std::uint16_t qtNum)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                const net::ip::udp::endpoint UdpEp(ep.address(), server.Port);
                UdpTransport udp(Ex_, TimeoutFor(server));
                ec = co_await udp.Connect(UdpEp, server);
                if (!ec)
                {
                    if (auto sendEc = co_await udp.Send(wire))
                    {
                        ec = sendEc;
                    }
                    else if (auto received = co_await udp.Receive())
                    {
                        auto scan = CheckScan(*received, query.Id, qtNum);
                        if (scan)
                        {
                            if (scan->Truncated)
                            {
                                // TC 截断：响应不完整，回退 TCP 重查
                                co_return co_await QueryTcp(server, query, qtNum);
                            }
                            co_return BuildCheckedResult(*scan, server.Address, Start);
                        }
                        ec = make_error_code(Error::BadMessage);
                    }
                    else
                    {
                        ec = received.error();
                    }
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
        }

        /**
         * @brief TCP 查询（2 字节长度前缀帧，连接池复用）
         */
        [[nodiscard]] auto QueryTcp(const Server &server, const Message &query,
                                    const std::uint16_t qtNum)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                auto received = co_await ExchangePooled(
                    PooledExchangeRequest<TcpTransport>{TcpPool_, PoolKey(server), ep, server, wire},
                    [&](const net::ip::tcp::endpoint &end, const Server &srv)
                    { return MakeTcp(end, srv); });
                if (!received)
                {
                    ec = received.error();
                }
                else if (auto scan = CheckScan(*received, query.Id, qtNum))
                {
                    co_return BuildCheckedResult(*scan, server.Address, Start);
                }
                else
                {
                    ec = make_error_code(Error::BadMessage);
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
        }

        /**
         * @brief DoT 查询（TLS 承载 TCP 帧，连接池复用）
         */
        [[nodiscard]] auto QueryTls(const Server &server, const Message &query,
                                    const std::uint16_t qtNum)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                auto received = co_await ExchangePooled(
                    PooledExchangeRequest<TlsTransport>{TlsPool_, PoolKey(server), ep, server, wire},
                    [&](const net::ip::tcp::endpoint &end, const Server &srv)
                    { return MakeTls(end, srv); });
                if (!received)
                {
                    ec = received.error();
                }
                else if (auto scan = CheckScan(*received, query.Id, qtNum))
                {
                    co_return BuildCheckedResult(*scan, server.Address, Start);
                }
                else
                {
                    ec = make_error_code(Error::BadMessage);
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
        }

        /**
         * @brief DoH 查询（HTTP/1.1 POST，RFC 8484，连接池复用）
         */
        [[nodiscard]] auto QueryHttps(const Server &server, const Message &query,
                                      const std::uint16_t qtNum)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                auto received = co_await ExchangePooled(
                    PooledExchangeRequest<DohTransport>{DohPool_, PoolKey(server), ep, server, wire},
                    [&](const net::ip::tcp::endpoint &end, const Server &srv)
                    { return MakeDoh(end, srv); });
                if (!received)
                {
                    ec = received.error();
                }
                else if (auto scan = CheckScan(*received, query.Id, qtNum))
                {
                    co_return BuildCheckedResult(*scan, server.Address, Start);
                }
                else
                {
                    ec = make_error_code(Error::BadMessage);
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
        }

        /// 热路径扫描并校验报文 Id（Id 不匹配视为坏报文）
        [[nodiscard]] static auto CheckScan(std::span<const std::uint8_t> wire,
                                            const std::uint16_t id, const std::uint16_t qtNum)
            -> std::optional<AnswerSet>
        {
            auto scan = ScanAnswers(wire, qtNum);
            if (scan && scan->Id != id)
            {
                scan.reset();
            }
            return scan;
        }

        /**
         * @brief 取或建 TLS 上下文（按 主机名+验证策略 缓存）
         * @param server 目标服务器
         * @return 共享 ssl context
         */
        [[nodiscard]] auto GetSslContext(const Server &server) -> std::shared_ptr<ssl::context>
        {
            const auto Key = server.Hostname + '|' + (server.SkipCertCheck ? '0' : '1');
            if (const auto it = SslCtxs_.find(Key); it != SslCtxs_.end())
            {
                return it->second;
            }
            auto ctx = std::make_shared<ssl::context>(ssl::context::tls_client);
            if (!server.SkipCertCheck)
            {
                ctx->set_default_verify_paths();
                ctx->set_verify_mode(ssl::verify_peer);
            }
            else
            {
                ctx->set_verify_mode(ssl::verify_none);
            }
            return SslCtxs_.emplace(Key, std::move(ctx)).first->second;
        }

        /// 构造结果（RCODE 语义：0/3 之外为上游拒绝）
        [[nodiscard]] static auto BuildCheckedResult(const AnswerSet &scan, const std::string &addr,
                                                     std::chrono::steady_clock::time_point start)
            -> QueryResult
        {
            QueryResult out;
            out.Response = scan;
            out.ServerAddr = addr;
            out.RttMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start)
                    .count());
            if (scan.Rcode != 0 && scan.Rcode != 3)
            {
                // SERVFAIL 等明确拒绝：不当作"无记录的空应答"，
                // Fallback 模式据此继续尝试下一上游
                out.Error = make_error_code(Error::ProtocolError);
                return out;
            }
            out.Ips.assign(scan.Ips.begin(), scan.Ips.end());
            return out;
        }

        /// 构造失败结果
        [[nodiscard]] static auto FailResult(const std::string &addr, boost::system::error_code ec)
            -> QueryResult
        {
            QueryResult out;
            out.ServerAddr = addr;
            out.Error = ec;
            return out;
        }

        /**
         * @brief 顺序尝试所有上游（Fallback 策略）
         * @return 首个成功结果；全部失败返回最后一个错误
         */
        [[nodiscard]] auto ResolveFallback(const Message &query, const std::uint16_t qtNum)
            -> net::awaitable<QueryResult>
        {
            QueryResult last;
            for (const auto &server : Servers_)
            {
                auto result =
                    co_await WithTimeout(QueryServer(server, query, qtNum), TimeoutFor(server));
                last = std::move(result);
                // 终止条件：有 IP 的成功响应，或 NXDOMAIN（Rcode=3 的权威空应答）——
                // 二者均为终态，不再重试其余上游；成功但零应答
                // （NOERROR + 空，即"无记录"）视为不满足，继续尝试下一上游
                if (!last.Error && (!last.Ips.empty() || last.Response.Rcode == 3))
                {
                    co_return last;
                }
            }
            if (!last.Error)
            {
                last.Error = make_error_code(Error::BadAddress);
            }
            co_return last;
        }

        /**
         * @brief 并发查询所有上游（First / Fastest 策略）
         * @details completion_signal 定时器信号驱动：worker 完成后 cancel
         *          唤醒主协程，First 收获首个成功即返回，Fastest 等全部完成
         *          后选 RTT 最低者。结构与主项目 resolve_concurrent 一致。
         */
        [[nodiscard]] auto ResolveConcurrent(const Message &query, const std::uint16_t qtNum)
            -> net::awaitable<QueryResult>
        {
            const auto Total = Servers_.size();
            auto results = std::make_shared<std::vector<QueryResult>>(Total);
            auto completed = std::make_shared<std::atomic<std::size_t>>(0);
            auto wake = std::make_shared<net::steady_timer>(Ex_);
            wake->expires_at(net::steady_timer::time_point::max());

            for (std::size_t i = 0; i < Total; ++i)
            {
                const auto server = Servers_[i]; // 按值捕获：与 Servers_ 生命周期解耦
                // 优先共享所有权延长生命周期（Resolver 场景）；非 shared 拥有
                // （如测试中的栈对象）时以空删除器降级，生命周期由调用方保证
                std::shared_ptr<Upstream> self;
                try
                {
                    self = shared_from_this();
                }
                catch (const std::bad_weak_ptr &)
                {
                    self = std::shared_ptr<Upstream>(this, [](Upstream *) {});
                }
                auto task = [self, server, query, qtNum, results, i, completed, wake]()
                    -> net::awaitable<void>
                {
                    try
                    {
                        (*results)[i] = co_await self->WithTimeout(
                            self->QueryServer(server, query, qtNum), self->TimeoutFor(server));
                    }
                    catch (...)
                    {
                        // 兜底：传输层意外异常不冒泡（等待方只读共享结果槽），
                        // 折算为该上游的失败结果（与 Resolver leader 路径对称）
                        QueryResult failed;
                        failed.ServerAddr = server.Address;
                        failed.Error = make_error_code(Error::IoError);
                        (*results)[i] = std::move(failed);
                    }
                    completed->fetch_add(1);
                    wake->cancel();
                };
                net::co_spawn(Ex_, std::move(task), net::detached);
            }

            const auto IsSuccess = [](const QueryResult &r)
            { return !r.Error && !r.Ips.empty(); };

            while (true)
            {
                boost::system::error_code waitEc;
                co_await wake->async_wait(net::redirect_error(net::use_awaitable, waitEc));
                if (waitEc == net::error::operation_aborted)
                {
                    wake->expires_at(net::steady_timer::time_point::max());
                }

                // First：首个成功即返回
                if (Mode_ == Mode::First)
                {
                    for (auto &r : *results)
                    {
                        if (IsSuccess(r))
                        {
                            co_return std::move(r);
                        }
                    }
                }
                if (completed->load() >= Total)
                {
                    break;
                }
            }
            co_return SelectBest(*results);
        }

        /**
         * @brief 从全部完成的结果中选优（Fastest 取最低 RTT）
         * @param results 全部上游结果
         * @return 最优成功结果；全败返回首个错误结果
         */
        [[nodiscard]] static auto SelectBest(std::vector<QueryResult> &results) -> QueryResult
        {
            QueryResult *best = nullptr;
            for (auto &r : results)
            {
                if (!r.Error && !r.Ips.empty() && (!best || r.RttMs < best->RttMs))
                {
                    best = &r;
                }
            }
            if (best)
            {
                return std::move(*best);
            }
            if (!results.empty())
            {
                return std::move(results.front());
            }
            QueryResult failed;
            failed.Error = make_error_code(Error::BadAddress);
            return failed;
        }

        /// 服务器独立超时优先，否则用默认值
        [[nodiscard]] auto TimeoutFor(const Server &server) const -> std::chrono::milliseconds
        {
            return server.TimeoutMs > 0 ? std::chrono::milliseconds(server.TimeoutMs) : Timeout_;
        }

        net::any_io_executor Ex_;
        std::vector<Server> Servers_;
        Mode Mode_;
        std::chrono::milliseconds Timeout_{4000};
        std::map<std::string, std::shared_ptr<ssl::context>> SslCtxs_; ///< TLS 上下文缓存
        std::unordered_map<std::string, net::ip::tcp::endpoint> EndpointCache_; ///< 上游端点解析缓存（host:port）
        ConnPool<TcpTransport> TcpPool_;   ///< TCP 帧连接池
        ConnPool<TlsTransport> TlsPool_;   ///< DoT 连接池
        ConnPool<DohTransport> DohPool_;   ///< DoH 连接池
        std::uint64_t Seed_{static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count())}; ///< id 种子
        std::uint16_t Counter_{0};                                         ///< id 递增计数器
    };

} // namespace Preview::Network::Dns
