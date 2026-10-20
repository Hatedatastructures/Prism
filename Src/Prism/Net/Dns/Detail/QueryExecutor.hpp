/**
 * @file QueryExecutor.hpp
 * @brief DNS 单上游传输查询、绝对 deadline 与超时竞速 owner
 * @details 持有端点解析器、TCP/DoT/DoH 连接池和 TLS 上下文，负责一个上游
 *          的 UDP、TCP、DoT 或 DoH 查询。多上游调度、查询报文 ID 和 EDNS0
 *          由 Upstream 负责。
 *          每次尝试在入口创建一个绝对 AttemptDeadline：端点解析、建连、
 *          收发以及 DoH 分块读写全部消费同一个时刻，超时由本 owner 竞速
 *          取消并返回明确的 Timeout。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Net/Dns/Answer.hpp>
#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Net/Dns/ConnPool.hpp>
#include <Prism/Net/Dns/Doh.hpp>
#include <Prism/Net/Dns/Detail/Deadline.hpp>
#include <Prism/Net/Dns/Detail/Exchange.hpp>
#include <Prism/Net/Dns/Detail/Fallback.hpp>
#include <Prism/Net/Dns/Detail/TcpTransport.hpp>
#include <Prism/Net/Dns/Detail/TlsTransport.hpp>
#include <Prism/Net/Dns/Detail/Wire.hpp>
#include <Prism/Net/Dns/Detail/UdpTransport.hpp>
#include <Prism/Net/Dns/Format.hpp>
#include <Prism/Net/Dns/Transport.hpp>
#include <Prism/Net/Dns/UpstreamTypes.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ssl.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace Prism::Network::Dns::Detail
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;

    /** @brief 单 executor 内解析并缓存 DNS 上游 TCP 端点。 */
    class EndpointResolver final
    {
    public:
        explicit EndpointResolver(Net::any_io_executor Executor)
            : Ex_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Resolve(const std::string_view Host, const std::uint16_t Port,
                                   boost::system::error_code &Error)
            -> Net::awaitable<Net::ip::tcp::endpoint>;

    private:
        Net::any_io_executor Ex_;
        std::unordered_map<std::string, Net::ip::tcp::endpoint> EndpointCache_;
    };

    /**
     * @struct QueryExecutorOptions
     * @brief 单上游传输查询 owner 的冻结预算：连接池上限与默认超时
     */
    struct QueryExecutorOptions
    {
        std::size_t MaxConnsPerServer{4};               ///< 每服务器最大闲置连接数（0 = 禁用池）
        std::size_t MaxIdleConnsPerPool{64};            ///< 每个协议连接池的闲置连接总数上限
        std::chrono::milliseconds DefaultTimeout{4000}; ///< 默认查询超时
    };

    /// DNS 连接池闲置连接存活时长
    inline constexpr std::chrono::milliseconds PoolIdleTtl{30000};

    /**
     * @brief 从 owner 预算生成单个协议连接池预算
     * @param Options owner 冻结预算
     * @param IdleTtl 闲置存活时长
     * @return 连接池预算
     */
    [[nodiscard]] inline auto MakePoolOptions(const QueryExecutorOptions &Options,
                                              const std::chrono::milliseconds IdleTtl)
        -> ConnPoolOptions
    {
        ConnPoolOptions PoolOptions;
        PoolOptions.MaxPerServer = Options.MaxConnsPerServer;
        PoolOptions.MaxTotal = Options.MaxIdleConnsPerPool;
        PoolOptions.IdleTtl = IdleTtl;
        return PoolOptions;
    }

    /**
     * @class QueryExecutor
     * @brief 一个 DNS 上游的传输查询 owner
     * @note 非线程安全，所有操作应在同一 io_context 内执行。
     */
    class QueryExecutor
    {
    public:
        explicit QueryExecutor(Net::any_io_executor Executor, const QueryExecutorOptions Options)
            : Ex_(std::move(Executor)), Endpoint_(Ex_), Timeout_(Options.DefaultTimeout),
              TcpPool_(MakePoolOptions(Options, PoolIdleTtl)),
              TlsPool_(MakePoolOptions(Options, PoolIdleTtl)),
              DohPool_(MakePoolOptions(Options, PoolIdleTtl)),
              Pool_(Prism::Memory::BytePoolOptions{.BlockCount = 4})
        {
        }

        /**
         * @brief 更新默认查询超时
         * @param Timeout 新的默认超时时长
         */
        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void
        {
            Timeout_ = Timeout;
        }

        /**
         * @brief 计算上游本次查询的有效超时
         * @param ServerConfig 上游配置
         * @return Server 独立超时优先，否则返回默认超时
         */
        [[nodiscard]] auto TimeoutFor(const Server &ServerConfig) const -> std::chrono::milliseconds
        {
            if (ServerConfig.TimeoutMs > 0)
            {
                return std::chrono::milliseconds(ServerConfig.TimeoutMs);
            }
            return Timeout_;
        }

        /**
         * @brief 闲置连接总数
         * @return TCP、DoT、DoH 三个连接池中的闲置连接数总和
         */
        [[nodiscard]] auto IdleConnCount() const -> std::size_t
        {
            return TcpPool_.IdleCount() + TlsPool_.IdleCount() + DohPool_.IdleCount();
        }

        /**
         * @brief 清理全部过期闲置连接
         * @return 清理数量
         */
        auto ClearIdleConns() -> std::size_t
        {
            return TcpPool_.ClearExpired() + TlsPool_.ClearExpired() + DohPool_.ClearExpired();
        }

        /**
         * @brief 执行一个上游的 DNS 查询
         * @param ServerConfig 上游服务器配置
         * @param Wire 已编码查询报文（只借用到本次尝试完成）
         * @param Identity 当前 query 拥有身份；ID、type、class 与 wire 同源
         * @return 经过报文校验和 RCODE 处理的查询结果
         * @details 解析、建连与收发共享一个绝对 deadline；超时竞速取消尝试
         *          后返回 Error=Timeout，外部取消不会被伪装成超时。
         */
        [[nodiscard]] auto Query(const Server &ServerConfig, const std::span<const std::uint8_t> Wire,
                                 const QueryIdentity &Identity) -> Net::awaitable<QueryResult>
        {
            const auto Deadline = AttemptDeadline::FromBudget(TimeoutFor(ServerConfig));
            co_return co_await RaceDeadline(
                QueryAttempt(AttemptRequest{ServerConfig, Wire, Identity, Deadline}), Deadline);
        }

    private:
        [[nodiscard]] static auto PoolKey(const Server &ServerConfig) -> std::string
        {
            std::string Key = ServerConfig.Address + '|' + std::to_string(ServerConfig.Port) + '|' +
                              ServerConfig.Hostname + '|' + ServerConfig.HttpPath + '|';
            if (ServerConfig.SkipCertCheck)
            {
                Key += '1';
            }
            else
            {
                Key += '0';
            }
            return Key;
        }

        /**
         * @brief 以绝对 deadline 对一次尝试做超时竞速
         * @param Task 尝试协程（解析、建连、收发）
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 尝试结果；到期取消尝试并返回 Error=Timeout 的占位结果
         */
        [[nodiscard]] auto RaceDeadline(Net::awaitable<QueryResult> Task,
                                        const AttemptDeadline Deadline)
            -> Net::awaitable<QueryResult>
        {
            using Net::experimental::awaitable_operators::operator||;

            Net::steady_timer Timer(Ex_);
            Timer.expires_at(Deadline.At());
            auto Outcome = co_await (std::move(Task) || Timer.async_wait(Net::use_awaitable));
            if (Outcome.index() == 1)
            {
                QueryResult TimedOut;
                TimedOut.Error = Prism::Fault::Failure{Prism::Fault::Code::Timeout, {}};
                co_return TimedOut;
            }
            co_return std::move(std::get<0>(Outcome));
        }

        /**
         * @brief 按上游协议分派一次尝试
         * @param Request 借用输入与共享绝对 deadline
         * @return 查询结果
         */
        [[nodiscard]] auto QueryAttempt(AttemptRequest Request) -> Net::awaitable<QueryResult>
        {
            switch (Request.ServerConfig.Proto)
            {
            case Protocol::Tcp:
                co_return co_await QueryTcp(Request);
            case Protocol::Tls:
                co_return co_await QueryTls(Request);
            case Protocol::Https:
                co_return co_await QueryHttps(Request);
            case Protocol::Udp:
                break;
            }
            co_return co_await QueryUdp(Request);
        }

        /**
         * @brief 构造已建连的 TCP 传输
         * @param EndpointValue 已解析的 TCP 端点
         * @param ServerValue 上游配置
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 已连接的 TCP 传输或错误
         */
        [[nodiscard]] auto MakeTcp(const Net::ip::tcp::endpoint &EndpointValue, const Server &ServerValue,
                                   const AttemptDeadline Deadline)
            -> Net::awaitable<EcResult<std::shared_ptr<TcpTransport>>>
        {
            auto Link = std::make_shared<TcpTransport>(Ex_);
            if (auto ErrorCode = co_await Link->Connect(EndpointValue, ServerValue, Deadline))
            {
                Link->Close();
                co_return std::unexpected(ErrorCode);
            }
            co_return Link;
        }

        /**
         * @brief 构造已建连的 DoT 传输
         * @param EndpointValue 已解析的 TCP 端点
         * @param ServerValue 上游配置
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 已连接的 TLS 传输或错误
         */
        [[nodiscard]] auto MakeTls(const Net::ip::tcp::endpoint &EndpointValue, const Server &ServerValue,
                                   const AttemptDeadline Deadline)
            -> Net::awaitable<EcResult<std::shared_ptr<TlsTransport>>>
        {
            auto Link = std::make_shared<TlsTransport>(Ex_, GetSslContext(ServerValue));
            if (auto ErrorCode = co_await Link->Connect(EndpointValue, ServerValue, Deadline))
            {
                Link->Close();
                co_return std::unexpected(ErrorCode);
            }
            co_return Link;
        }

        /**
         * @brief 构造已建连的 DoH 传输
         * @param EndpointValue 已解析的 TCP 端点
         * @param ServerValue 上游配置
         * @param Deadline 本次尝试的绝对截止时刻
         * @return 已连接的 DoH 传输或错误
         */
        [[nodiscard]] auto MakeDoh(const Net::ip::tcp::endpoint &EndpointValue, const Server &ServerValue,
                                   const AttemptDeadline Deadline)
            -> Net::awaitable<EcResult<std::shared_ptr<DohTransport>>>
        {
            DohOptions Options;
            Options.Executor = Ex_;
            Options.Context = GetSslContext(ServerValue);
            Options.HttpPath = ServerValue.HttpPath;
            if (ServerValue.Hostname.empty())
            {
                Options.HostHeader = ServerValue.Address;
            }
            else
            {
                Options.HostHeader = ServerValue.Hostname;
            }
            auto Link = std::make_shared<DohTransport>(std::move(Options));
            if (auto ErrorCode = co_await Link->Connect(EndpointValue, ServerValue, Deadline))
            {
                Link->Close();
                co_return std::unexpected(ErrorCode);
            }
            co_return Link;
        }

        /**
         * @brief UDP 查询，TC 截断时回退 TCP（同一 deadline 内）
         * @param Request 借用输入与共享绝对 deadline
         * @return 查询结果
         */
        [[nodiscard]] auto QueryUdp(const AttemptRequest &Request) -> Net::awaitable<QueryResult>
        {
            const auto &ServerConfig = Request.ServerConfig;
            const auto Start = std::chrono::steady_clock::now();
            boost::system::error_code ErrorCode;
            auto EndpointValue = co_await Endpoint_.Resolve(ServerConfig.Address, ServerConfig.Port,
                                                            ErrorCode);
            if (!ErrorCode)
            {
                const Net::ip::udp::endpoint UdpEndpoint(EndpointValue.address(), ServerConfig.Port);
                UdpTransport Udp(Ex_);
                ErrorCode = co_await Udp.Connect(UdpEndpoint, ServerConfig, Request.Deadline);
                if (!ErrorCode)
                {
                    if (auto SendError = co_await Udp.Send(Request.Wire, Request.Deadline))
                    {
                        ErrorCode = SendError;
                    }
                    else if (auto Received = co_await Udp.Receive(Request.Deadline))
                    {
                        auto Scan = CheckScan(*Received, Request.Identity);
                        if (Scan)
                        {
                            if (Scan->Truncated)
                            {
                                co_return co_await QueryTcp(Request);
                            }
                            co_return BuildCheckedResult(std::move(*Scan), ServerConfig.Address, Start);
                        }
                        ErrorCode = make_error_code(Error::BadMessage);
                    }
                    else
                    {
                        ErrorCode = Received.error();
                    }
                }
            }
            if (!ErrorCode)
            {
                ErrorCode = make_error_code(Error::IoError);
            }
            co_return FailResult(ServerConfig.Address, ErrorCode);
        }

        /**
         * @brief TCP 查询，使用两字节长度前缀和连接池
         * @param Request 借用输入与共享绝对 deadline
         * @return 查询结果
         */
        [[nodiscard]] auto QueryTcp(const AttemptRequest &Request) -> Net::awaitable<QueryResult>
        {
            const auto &ServerConfig = Request.ServerConfig;
            const auto Start = std::chrono::steady_clock::now();
            boost::system::error_code ErrorCode;
            auto EndpointValue = co_await Endpoint_.Resolve(ServerConfig.Address, ServerConfig.Port,
                                                            ErrorCode);
            if (!ErrorCode)
            {
                auto Received = co_await ExchangePooled(
                    PooledExchangeRequest<TcpTransport>{TcpPool_, PoolKey(ServerConfig),
                                                        EndpointValue, ServerConfig, Request.Wire,
                                                        CheckedAnswerRequest{Request.Identity, Pool_},
                                                        Request.Deadline},
                    [&](const Net::ip::tcp::endpoint &EndpointValue2, const Server &ServerValue)
                    { return MakeTcp(EndpointValue2, ServerValue, Request.Deadline); });
                if (!Received)
                {
                    ErrorCode = Received.error();
                }
                else
                {
                    co_return BuildCheckedResult(std::move(*Received), ServerConfig.Address, Start);
                }
            }
            if (!ErrorCode)
            {
                ErrorCode = make_error_code(Error::IoError);
            }
            co_return FailResult(ServerConfig.Address, ErrorCode);
        }

        /**
         * @brief DoT 查询，使用 TLS 承载 TCP 帧和连接池
         * @param Request 借用输入与共享绝对 deadline
         * @return 查询结果
         */
        [[nodiscard]] auto QueryTls(const AttemptRequest &Request) -> Net::awaitable<QueryResult>
        {
            const auto &ServerConfig = Request.ServerConfig;
            const auto Start = std::chrono::steady_clock::now();
            boost::system::error_code ErrorCode;
            auto EndpointValue = co_await Endpoint_.Resolve(ServerConfig.Address, ServerConfig.Port,
                                                            ErrorCode);
            if (!ErrorCode)
            {
                auto Received = co_await ExchangePooled(
                    PooledExchangeRequest<TlsTransport>{TlsPool_, PoolKey(ServerConfig),
                                                        EndpointValue, ServerConfig, Request.Wire,
                                                        CheckedAnswerRequest{Request.Identity, Pool_},
                                                        Request.Deadline},
                    [&](const Net::ip::tcp::endpoint &EndpointValue2, const Server &ServerValue)
                    { return MakeTls(EndpointValue2, ServerValue, Request.Deadline); });
                if (!Received)
                {
                    ErrorCode = Received.error();
                }
                else
                {
                    co_return BuildCheckedResult(std::move(*Received), ServerConfig.Address, Start);
                }
            }
            if (!ErrorCode)
            {
                ErrorCode = make_error_code(Error::IoError);
            }
            co_return FailResult(ServerConfig.Address, ErrorCode);
        }

        /**
         * @brief DoH 查询，使用 HTTP POST 和连接池
         * @param Request 借用输入与共享绝对 deadline
         * @return 查询结果
         */
        [[nodiscard]] auto QueryHttps(const AttemptRequest &Request) -> Net::awaitable<QueryResult>
        {
            const auto &ServerConfig = Request.ServerConfig;
            const auto Start = std::chrono::steady_clock::now();
            boost::system::error_code ErrorCode;
            auto EndpointValue = co_await Endpoint_.Resolve(ServerConfig.Address, ServerConfig.Port,
                                                            ErrorCode);
            if (!ErrorCode)
            {
                auto Received = co_await ExchangePooled(
                    PooledExchangeRequest<DohTransport>{DohPool_, PoolKey(ServerConfig),
                                                        EndpointValue, ServerConfig, Request.Wire,
                                                        CheckedAnswerRequest{Request.Identity, Pool_},
                                                        Request.Deadline},
                    [&](const Net::ip::tcp::endpoint &EndpointValue2, const Server &ServerValue)
                    { return MakeDoh(EndpointValue2, ServerValue, Request.Deadline); });
                if (!Received)
                {
                    ErrorCode = Received.error();
                }
                else
                {
                    co_return BuildCheckedResult(std::move(*Received), ServerConfig.Address, Start);
                }
            }
            if (!ErrorCode)
            {
                ErrorCode = make_error_code(Error::IoError);
            }
            co_return FailResult(ServerConfig.Address, ErrorCode);
        }

        /**
         * @brief 校验应答属于完整当前问题
         * @param Wire 应答字节；只借用到同步返回，不保存引用
         * @param Identity 当前 query 拥有身份；ID、QR/opcode、完整 question、type/class 同次校验
         * @return 成功返回独占地址块；畸形或不关联返回 ProtocolError，池额度不足返回 ResourceUnavailable
         * @details 不取消 I/O、不关闭载体；真实网络错误由传输 owner 原样返回。
         */
        [[nodiscard]] auto CheckScan(const std::span<const std::uint8_t> Wire,
                                     const QueryIdentity &Identity)
            -> std::expected<AnswerSet, Fault::Failure>
        {
            return CheckAnswers(Wire, CheckedAnswerRequest{Identity, Pool_});
        }

        /**
         * @brief 获取或创建 TLS 上下文
         * @param ServerConfig 目标服务器配置
         * @return 共享 TLS 上下文
         */
        [[nodiscard]] auto GetSslContext(const Server &ServerConfig) -> std::shared_ptr<Ssl::context>
        {
            std::string Key = ServerConfig.Hostname + '|';
            if (ServerConfig.SkipCertCheck)
            {
                Key += '0';
            }
            else
            {
                Key += '1';
            }
            if (const auto It = SslCtxs_.find(Key); It != SslCtxs_.end())
            {
                return It->second;
            }

            auto Context = std::make_shared<Ssl::context>(Ssl::context::tls_client);
            if (!ServerConfig.SkipCertCheck)
            {
                Context->set_default_verify_paths();
                Context->set_verify_mode(Ssl::verify_peer);
            }
            else
            {
                Context->set_verify_mode(Ssl::verify_none);
            }
            return SslCtxs_.emplace(Key, std::move(Context)).first->second;
        }

        Net::any_io_executor Ex_;
        EndpointResolver Endpoint_;
        std::chrono::milliseconds Timeout_;
        std::map<std::string, std::shared_ptr<Ssl::context>> SslCtxs_;
        ConnPool<TcpTransport> TcpPool_;
        ConnPool<TlsTransport> TlsPool_;
        ConnPool<DohTransport> DohPool_;
        Prism::Memory::BytePool Pool_;
    };

} // namespace Prism::Network::Dns::Detail
