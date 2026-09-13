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
#include "Detail/Exchange.hpp"
#include "Detail/Fallback.hpp"
#include "Format.hpp"
#include "Types.hpp"
#include "Transport.hpp"

#include <preview/Foundation/Error.hpp>

#include <boost/asio.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
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

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;

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
        explicit Upstream(Net::any_io_executor Executor, UpstreamOptions Options = {})
            : Ex_(std::move(Executor)), Servers_(std::move(Options.Servers)),
              Mode_(Options.QueryMode), Timeout_(Options.DefaultTimeout),
              TcpPool_(Options.MaxConnsPerServer, PoolIdleTtl),
              TlsPool_(Options.MaxConnsPerServer, PoolIdleTtl),
              DohPool_(Options.MaxConnsPerServer, PoolIdleTtl)
        {
        }

        /**
         * @brief 构造查询客户端的简化形式
         * @param ex 执行器
         * @param servers 上游服务器列表
         * @param mode 多上游查询策略
         */
        explicit Upstream(Net::any_io_executor Executor, std::vector<Server> Servers,
                          const Mode QueryMode = Mode::Fastest)
            : Upstream(std::move(Executor), UpstreamOptions{std::move(Servers), QueryMode})
        {
        }

        /**
         * @brief 替换上游服务器列表
         * @param servers 新列表
         */
        void SetServers(const std::vector<Server> &Servers)
        {
            Servers_ = Servers;
        }

        /**
         * @brief 设置解析策略
         * @param mode Fallback / First / Fastest
         */
        void SetMode(const Mode QueryMode)
        {
            Mode_ = QueryMode;
        }

        /**
         * @brief 设置默认超时
         * @param ms 毫秒数
         */
        void SetTimeout(const std::chrono::milliseconds Timeout)
        {
            Timeout_ = Timeout;
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
            -> Net::awaitable<QueryResult>
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
            if (Servers_.size() == 1)
            {
                const auto &ServerConfig = Servers_.front();
                co_return co_await WithTimeout(
                    QueryServer(ServerConfig, query, QtNum), TimeoutFor(ServerConfig));
            }
            std::shared_ptr<Upstream> Owner;
            try
            {
                Owner = shared_from_this();
            }
            catch (const std::bad_weak_ptr &)
            {
                QueryResult failed;
                failed.Error = make_error_code(Error::NotSupported);
                co_return failed;
            }
            co_return co_await ResolveConcurrent(query, QtNum, std::move(Owner));
        }

    private:
        /// 闲置连接存活时长
        static constexpr std::chrono::milliseconds PoolIdleTtl{30000};

        /// 池键：按地址、端口、TLS/HTTP 身份区分可复用连接
        [[nodiscard]] static auto PoolKey(const Server &server) -> std::string
        {
            std::string Key = server.Address + '|' + std::to_string(server.Port) + '|' + server.Hostname +
                              '|' + server.HttpPath + '|';
            if (server.SkipCertCheck)
            {
                Key += '1';
            }
            else
            {
                Key += '0';
            }
            return Key;
        }

        /// 单服务器查询分发
        [[nodiscard]] auto QueryServer(const Server &server, const Message &query,
                                       const std::uint16_t qtNum)
            -> Net::awaitable<QueryResult>
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
        [[nodiscard]] auto WithTimeout(Net::awaitable<QueryResult> task,
                                       const std::chrono::milliseconds timeout)
            -> Net::awaitable<QueryResult>
        {
            using Net::experimental::awaitable_operators::operator||;

            Net::steady_timer timer(Ex_);
            timer.expires_after(timeout);
            auto outcome = co_await (std::move(task) || timer.async_wait(Net::use_awaitable));
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
            -> Net::awaitable<Net::ip::basic_endpoint<Net::ip::tcp>>
        {
            const auto CacheKey = host + ':' + std::to_string(port);
            if (const auto It = EndpointCache_.find(CacheKey); It != EndpointCache_.end())
            {
                co_return It->second;
            }
            Net::ip::tcp::resolver resolver(Ex_);
            auto results = co_await resolver.async_resolve(
                host, std::to_string(port), Net::redirect_error(Net::use_awaitable, ec));
            if (ec)
            {
                co_return Net::ip::tcp::endpoint{};
            }
            const auto Ep = results.begin()->endpoint();
            EndpointCache_.emplace(CacheKey, Ep);
            co_return Ep;
        }

        /// 构造已建连的 TCP 传输（工厂用）
        [[nodiscard]] auto MakeTcp(const Net::ip::tcp::endpoint &ep, const Server &server)
            -> Net::awaitable<EcResult<std::shared_ptr<TcpTransport>>>
        {
            auto link = std::make_shared<TcpTransport>(Ex_, TimeoutFor(server));
            if (auto ec = co_await link->Connect(ep, server))
            {
                co_return std::unexpected(ec);
            }
            co_return link;
        }

        /// 构造已建连的 DoT 传输（工厂用）
        [[nodiscard]] auto MakeTls(const Net::ip::tcp::endpoint &ep, const Server &server)
            -> Net::awaitable<EcResult<std::shared_ptr<TlsTransport>>>
        {
            auto link = std::make_shared<TlsTransport>(Ex_, TimeoutFor(server), GetSslContext(server));
            if (auto ec = co_await link->Connect(ep, server))
            {
                co_return std::unexpected(ec);
            }
            co_return link;
        }

        /// 构造已建连的 DoH 传输（工厂用）
        [[nodiscard]] auto MakeDoh(const Net::ip::tcp::endpoint &ep, const Server &server)
            -> Net::awaitable<EcResult<std::shared_ptr<DohTransport>>>
        {
            std::string HostHeader = server.Address;
            if (!server.Hostname.empty())
            {
                HostHeader = server.Hostname;
            }
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
            -> Net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                const Net::ip::udp::endpoint UdpEp(ep.address(), server.Port);
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
                             co_return Detail::BuildCheckedResult(*scan, server.Address, Start);
                        }
                        ec = make_error_code(Error::BadMessage);
                    }
                    else
                    {
                        ec = received.error();
                    }
                }
            }
            if (!ec)
            {
                ec = make_error_code(Error::IoError);
            }
            co_return Detail::FailResult(server.Address, ec);
        }

        /**
         * @brief TCP 查询（2 字节长度前缀帧，连接池复用）
         */
        [[nodiscard]] auto QueryTcp(const Server &server, const Message &query,
                                    const std::uint16_t qtNum)
            -> Net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                auto received = co_await Detail::ExchangePooled(
                    Detail::PooledExchangeRequest<TcpTransport>{TcpPool_, PoolKey(server), ep, server, wire},
                    [&](const Net::ip::tcp::endpoint &end, const Server &srv)
                    { return MakeTcp(end, srv); });
                if (!received)
                {
                    ec = received.error();
                }
                else if (auto scan = CheckScan(*received, query.Id, qtNum))
                {
                    co_return Detail::BuildCheckedResult(*scan, server.Address, Start);
                }
                else
                {
                    ec = make_error_code(Error::BadMessage);
                }
            }
            if (!ec)
            {
                ec = make_error_code(Error::IoError);
            }
            co_return Detail::FailResult(server.Address, ec);
        }

        /**
         * @brief DoT 查询（TLS 承载 TCP 帧，连接池复用）
         */
        [[nodiscard]] auto QueryTls(const Server &server, const Message &query,
                                    const std::uint16_t qtNum)
            -> Net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                auto received = co_await Detail::ExchangePooled(
                    Detail::PooledExchangeRequest<TlsTransport>{TlsPool_, PoolKey(server), ep, server, wire},
                    [&](const Net::ip::tcp::endpoint &end, const Server &srv)
                    { return MakeTls(end, srv); });
                if (!received)
                {
                    ec = received.error();
                }
                else if (auto scan = CheckScan(*received, query.Id, qtNum))
                {
                    co_return Detail::BuildCheckedResult(*scan, server.Address, Start);
                }
                else
                {
                    ec = make_error_code(Error::BadMessage);
                }
            }
            if (!ec)
            {
                ec = make_error_code(Error::IoError);
            }
            co_return Detail::FailResult(server.Address, ec);
        }

        /**
         * @brief DoH 查询（HTTP/1.1 POST，RFC 8484，连接池复用）
         */
        [[nodiscard]] auto QueryHttps(const Server &server, const Message &query,
                                      const std::uint16_t qtNum)
            -> Net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto wire = query.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                auto received = co_await Detail::ExchangePooled(
                    Detail::PooledExchangeRequest<DohTransport>{DohPool_, PoolKey(server), ep, server, wire},
                    [&](const Net::ip::tcp::endpoint &end, const Server &srv)
                    { return MakeDoh(end, srv); });
                if (!received)
                {
                    ec = received.error();
                }
                else if (auto scan = CheckScan(*received, query.Id, qtNum))
                {
                    co_return Detail::BuildCheckedResult(*scan, server.Address, Start);
                }
                else
                {
                    ec = make_error_code(Error::BadMessage);
                }
            }
            if (!ec)
            {
                ec = make_error_code(Error::IoError);
            }
            co_return Detail::FailResult(server.Address, ec);
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
        [[nodiscard]] auto GetSslContext(const Server &server) -> std::shared_ptr<Ssl::context>
        {
            std::string Key = server.Hostname + '|';
            if (server.SkipCertCheck)
            {
                Key += '0';
            }
            else
            {
                Key += '1';
            }
            if (const auto it = SslCtxs_.find(Key); it != SslCtxs_.end())
            {
                return it->second;
            }
            auto ctx = std::make_shared<Ssl::context>(Ssl::context::tls_client);
            if (!server.SkipCertCheck)
            {
                ctx->set_default_verify_paths();
                ctx->set_verify_mode(Ssl::verify_peer);
            }
            else
            {
                ctx->set_verify_mode(Ssl::verify_none);
            }
            return SslCtxs_.emplace(Key, std::move(ctx)).first->second;
        }

        /**
         * @brief 顺序尝试所有上游（Fallback 策略）
         * @return 首个成功结果；全部失败返回最后一个错误
         */
        [[nodiscard]] auto ResolveFallback(const Message &query, const std::uint16_t qtNum)
            -> Net::awaitable<QueryResult>
        {
            co_return co_await Detail::ResolveFallback(
                Servers_, query, qtNum,
                [this](const Server &server, const Message &message, const std::uint16_t type)
                    -> Net::awaitable<QueryResult>
                { co_return co_await QueryServer(server, message, type); },
                [this](Net::awaitable<QueryResult> task, const Server &server)
                    -> Net::awaitable<QueryResult>
                { co_return co_await WithTimeout(std::move(task), TimeoutFor(server)); });
        }

        /**
         * @brief 并发查询所有上游（First / Fastest 策略）
         * @details 完成通道与计数器驱动：worker 完成后发送通知并递增计数，
         *          等待方收到通知后重检计数，First 收获首个成功即返回，
         *          Fastest 等全部完成后选 RTT 最低者。
         */
        [[nodiscard]] auto ResolveConcurrent(const Message &query, const std::uint16_t qtNum,
                                             std::shared_ptr<Upstream> Owner)
            -> Net::awaitable<QueryResult>
        {
            const auto Total = Servers_.size();
            auto results = std::make_shared<std::vector<QueryResult>>(Total);
            auto completed = std::make_shared<std::atomic<std::size_t>>(0);
            using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;
            auto completion = std::make_shared<CompletionChannel>(Ex_, 1);
            auto cancels = std::make_shared<std::vector<std::shared_ptr<Net::cancellation_signal>>>();
            cancels->reserve(Total);

            for (std::size_t i = 0; i < Total; ++i)
            {
                const auto server = Servers_[i]; // 按值捕获：与 Servers_ 生命周期解耦
                auto cancel = std::make_shared<Net::cancellation_signal>();
                cancels->push_back(cancel);
                auto task = [Owner, server, query, qtNum, results, i, completed, completion]()
                    -> Net::awaitable<void>
                {
                    try
                    {
                        (*results)[i] = co_await Owner->WithTimeout(
                            Owner->QueryServer(server, query, qtNum), Owner->TimeoutFor(server));
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
                    (void)completion->try_send(boost::system::error_code{});
                };
                Net::co_spawn(Ex_, std::move(task),
                              Net::bind_cancellation_slot(cancel->slot(), Net::detached));
            }

            const auto IsSuccess = [](const QueryResult &r)
            { return !r.Error && !r.Ips.empty(); };

            const auto WaitForAll = [&]() -> Net::awaitable<void>
            {
                while (completed->load() < Total)
                {
                    boost::system::error_code WaitError;
                    co_await completion->async_receive(Net::redirect_error(Net::use_awaitable, WaitError));
                }
                co_return;
            };

            while (true)
            {
                boost::system::error_code waitEc;
                co_await completion->async_receive(Net::redirect_error(Net::use_awaitable, waitEc));

                // First：首个成功即返回
                if (Mode_ == Mode::First)
                {
                    for (auto &r : *results)
                    {
                        if (IsSuccess(r))
                        {
                            for (const auto &Signal : *cancels)
                            {
                                Signal->emit(Net::cancellation_type::all);
                            }
                            co_await WaitForAll();
                            co_return std::move(r);
                        }
                    }
                }
                if (completed->load() >= Total)
                {
                    break;
                }
            }
            co_return Detail::SelectBest(*results);
        }

        /// 服务器独立超时优先，否则用默认值
        [[nodiscard]] auto TimeoutFor(const Server &server) const -> std::chrono::milliseconds
        {
            if (server.TimeoutMs > 0)
            {
                return std::chrono::milliseconds(server.TimeoutMs);
            }
            return Timeout_;
        }

        Net::any_io_executor Ex_;
        std::vector<Server> Servers_;
        Mode Mode_;
        std::chrono::milliseconds Timeout_{4000};
        std::map<std::string, std::shared_ptr<Ssl::context>> SslCtxs_; ///< TLS 上下文缓存
        std::unordered_map<std::string, Net::ip::tcp::endpoint> EndpointCache_; ///< 上游端点解析缓存（host:port）
        ConnPool<TcpTransport> TcpPool_;   ///< TCP 帧连接池
        ConnPool<TlsTransport> TlsPool_;   ///< DoT 连接池
        ConnPool<DohTransport> DohPool_;   ///< DoH 连接池
        std::uint64_t Seed_{static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count())}; ///< id 种子
        std::uint16_t Counter_{0};                                         ///< id 递增计数器
    };

} // namespace Preview::Network::Dns
