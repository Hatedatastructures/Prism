/**
 * @file Upstream.hpp
 * @brief DNS 上游查询层（UDP / TCP / DoT / DoH 四传输）
 * @details 对齐主项目 net/dns/upstream 分层：
 *          - 四种传输：UDP（标准查询，TC 截断回退 TCP）、TCP（2 字节长度
 *            前缀帧）、DoT（TLS 承载 TCP 帧，端口 853）、DoH（HTTPS POST
 *            application/dns-message，RFC 8484，端口 443）
 *          - 三种策略：Fallback 顺序尝试、First 并发取首个成功、
 *            Fastest 并发取 RTT 最低成功
 *          - 编排结构与主项目一致：resolve_fallback 顺序循环；
 *            resolve_concurrent 用 completion_signal 定时器唤醒主协程，
 *            避免轮询；select_best_result 选优
 * @note 超时用 awaitable_operators 竞速实现（preview 库惯例，同 Dialer）：
 *       查询协程与定时器并行，超时方胜出时查询协程被取消
 */

#pragma once

#include "Config.hpp"
#include "Format.hpp"

#include <common/Core/Error.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ssl.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    namespace net = boost::asio;
    namespace ssl = net::ssl;

    /**
     * @struct QueryResult
     * @brief 单次上游查询结果
     */
    struct QueryResult
    {
        Message Response;                            ///< 响应报文（失败时为空）
        std::vector<net::ip::address> Ips;           ///< 提取的 IP 地址列表
        std::uint64_t RttMs{0};                      ///< 往返耗时（毫秒）
        std::string ServerAddr;                      ///< 响应来源上游地址
        boost::system::error_code Error;                       ///< 错误码（默认成功）
    };

    /**
     * @class Upstream
     * @brief 异步 DNS 查询客户端（非线程安全，单 io_context 内使用）
     */
    class Upstream
    {
    public:
        /**
         * @brief 构造查询客户端
         * @param ex 执行器
         * @param servers 上游服务器列表
         * @param mode 解析策略
         * @param defaultTimeout 默认超时（毫秒），Server 未单独配置时生效
         */
        explicit Upstream(net::any_io_executor ex, std::vector<Server> servers = {},
                          const Mode mode = Mode::Fastest,
                          const std::chrono::milliseconds defaultTimeout = std::chrono::milliseconds{4000})
            : Ex_(std::move(ex)), Servers_(std::move(servers)), Mode_(mode), Timeout_(defaultTimeout)
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

            if (Servers_.empty())
            {
                QueryResult failed;
                failed.Error = make_error_code(Error::BadAddress);
                co_return failed;
            }
            if (Mode_ == Mode::Fallback)
            {
                co_return co_await ResolveFallback(domain, query);
            }
            co_return co_await ResolveConcurrent(query);
        }

    private:
        /// 单服务器查询分发
        [[nodiscard]] auto QueryServer(const Server &server, const Message &query)
            -> net::awaitable<QueryResult>
        {
            switch (server.Proto)
            {
            case Protocol::Tcp:
                co_return co_await QueryTcp(server, query);
            case Protocol::Tls:
                co_return co_await QueryTls(server, query);
            case Protocol::Https:
                co_return co_await QueryHttps(server, query);
            case Protocol::Udp:
                break;
            }
            co_return co_await QueryUdp(server, query);
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
         * @brief 解析上游地址为端点（支持域名与 IP 字面量）
         * @param host 上游主机名或 IP
         * @param port 端口
         * @param ec [out] 错误码
         * @return 首个解析端点；失败时 ec 置位
         */
        [[nodiscard]] auto ResolveEndpoint(const std::string &host, const std::uint16_t port,
                                           boost::system::error_code &ec)
            -> net::awaitable<net::ip::basic_endpoint<net::ip::tcp>>
        {
            net::ip::tcp::resolver resolver(Ex_);
            auto results = co_await resolver.async_resolve(
                host, std::to_string(port), net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return net::ip::tcp::endpoint{};
            }
            co_return results.begin()->endpoint();
        }

        /**
         * @brief UDP 查询（TC 截断自动回退 TCP）
         */
        [[nodiscard]] auto QueryUdp(const Server &server, const Message &query)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto msg = query;
            auto wire = msg.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                // TCP 解析结果转 UDP 端点（地址与端口一致）
                const net::ip::udp::endpoint UdpEp(ep.address(), server.Port);
                net::ip::udp::socket sock(Ex_, UdpEp.protocol());
                sock.connect(UdpEp, ec);
                if (!ec)
                {
                    co_await sock.async_send(net::buffer(wire),
                                             net::redirect_error(net::use_awaitable, ec));
                    if (!ec)
                    {
                        std::array<std::uint8_t, 4096> buf{};
                        const auto n =
                            co_await sock.async_receive(net::buffer(buf),
                                                        net::redirect_error(net::use_awaitable, ec));
                        if (!ec)
                        {
                            auto resp = Message::Unpack(std::span(buf.data(), n));
                            if (resp && resp->Id == msg.Id)
                            {
                                // TC 截断：响应不完整，回退 TCP 重查
                                if (resp->Tc)
                                {
                                    co_return co_await QueryTcp(server, query);
                                }
                                co_return BuildResult(*resp, server.Address, Start);
                            }
                            ec = make_error_code(Error::BadMessage);
                        }
                    }
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
        }

        /**
         * @brief TCP 查询（2 字节长度前缀帧）
         */
        [[nodiscard]] auto QueryTcp(const Server &server, const Message &query)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto msg = query;
            auto frame = PackTcp(msg);

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                net::ip::tcp::socket sock(Ex_);
                co_await sock.async_connect(ep, net::redirect_error(net::use_awaitable, ec));
                if (!ec)
                {
                    co_await net::async_write(sock, net::buffer(frame),
                                              net::redirect_error(net::use_awaitable, ec));
                    if (!ec)
                    {
                        std::array<std::uint8_t, 2> lenBuf{};
                        co_await net::async_read(sock, net::buffer(lenBuf),
                                                 net::redirect_error(net::use_awaitable, ec));
                        if (!ec)
                        {
                            const auto Len = static_cast<std::size_t>((lenBuf[0] << 8) | lenBuf[1]);
                            std::vector<std::uint8_t> body(Len);
                            co_await net::async_read(sock, net::buffer(body),
                                                     net::redirect_error(net::use_awaitable, ec));
                            if (!ec)
                            {
                                auto resp = Message::Unpack(body);
                                if (resp && resp->Id == msg.Id)
                                {
                                    co_return BuildResult(*resp, server.Address, Start);
                                }
                                ec = make_error_code(Error::BadMessage);
                            }
                        }
                    }
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
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

        /**
         * @brief TLS 连接握手（SNI + 证书校验）
         * @param stream TLS 流
         * @param server 目标服务器
         * @param ec [out] 错误码
         */
        auto HandshakeTls(ssl::stream<net::ip::tcp::socket> &stream, const Server &server,
                          boost::system::error_code &ec) -> net::awaitable<void>
        {
            const auto sniName = !server.Hostname.empty() ? server.Hostname : server.Address;
            if (!server.SkipCertCheck)
            {
                // SNI 与证书主机名校验共用同一名称
                SSL_set_tlsext_host_name(stream.native_handle(), sniName.c_str());
                stream.set_verify_callback(ssl::host_name_verification(sniName), ec);
                if (ec)
                {
                    co_return;
                }
            }
            co_await stream.async_handshake(ssl::stream_base::client,
                                            net::redirect_error(net::use_awaitable, ec));
        }

        /**
         * @brief DoT 查询（TLS 承载 TCP 帧，默认端口 853）
         */
        [[nodiscard]] auto QueryTls(const Server &server, const Message &query)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto msg = query;
            auto frame = PackTcp(msg);

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                ssl::stream<net::ip::tcp::socket> stream(Ex_, *GetSslContext(server));
                stream.lowest_layer().connect(ep, ec);
                if (!ec)
                {
                    co_await HandshakeTls(stream, server, ec);
                    if (!ec)
                    {
                        co_await net::async_write(stream, net::buffer(frame),
                                                  net::redirect_error(net::use_awaitable, ec));
                        if (!ec)
                        {
                            auto resp = co_await ReadTcpFrame(stream, ec);
                            if (!ec)
                            {
                                if (resp && resp->Id == msg.Id)
                                {
                                    co_return BuildResult(*resp, server.Address, Start);
                                }
                                ec = make_error_code(Error::BadMessage);
                            }
                        }
                    }
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
        }

        /**
         * @brief 从 TLS 流异步读取一个 TCP 帧（2 字节前缀 + 报文体）
         */
        [[nodiscard]] auto ReadTcpFrame(ssl::stream<net::ip::tcp::socket> &stream,
                                        boost::system::error_code &ec)
            -> net::awaitable<std::optional<Message>>
        {
            std::array<std::uint8_t, 2> lenBuf{};
            co_await net::async_read(stream, net::buffer(lenBuf),
                                     net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return std::nullopt;
            }
            std::vector<std::uint8_t> body(
                static_cast<std::size_t>((lenBuf[0] << 8) | lenBuf[1]));
            if (!body.empty())
            {
                co_await net::async_read(stream, net::buffer(body),
                                         net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return std::nullopt;
                }
            }
            co_return Message::Unpack(body);
        }

        /**
         * @brief DoH 查询（HTTP/1.1 POST，RFC 8484）
         * @details 手写 HTTP 头（Content-Type: application/dns-message，
         *          Connection: close），读取至 \r\n\r\n 后按 Content-Length
         *          收满报文体，对齐主项目 upstream.cpp 的 DoH 编解码。
         */
        [[nodiscard]] auto QueryHttps(const Server &server, const Message &query)
            -> net::awaitable<QueryResult>
        {
            const auto Start = std::chrono::steady_clock::now();
            auto msg = query;
            auto wire = msg.Pack();

            boost::system::error_code ec;
            auto ep = co_await ResolveEndpoint(server.Address, server.Port, ec);
            if (!ec)
            {
                ssl::stream<net::ip::tcp::socket> stream(Ex_, *GetSslContext(server));
                stream.lowest_layer().connect(ep, ec);
                if (!ec)
                {
                    co_await HandshakeTls(stream, server, ec);
                    if (!ec)
                    {
                        const auto hostHeader =
                            !server.Hostname.empty() ? server.Hostname : server.Address;
                        std::string request;
                        request += "POST ";
                        request += server.HttpPath;
                        request += " HTTP/1.1\r\nHost: ";
                        request += hostHeader;
                        request += "\r\nContent-Type: application/dns-message\r\nContent-Length: ";
                        request += std::to_string(wire.size());
                        request += "\r\nConnection: close\r\n\r\n";

                        co_await net::async_write(stream, net::buffer(request),
                                                  net::redirect_error(net::use_awaitable, ec));
                        if (!ec)
                        {
                            co_await net::async_write(stream, net::buffer(wire),
                                                      net::redirect_error(net::use_awaitable, ec));
                            if (!ec)
                            {
                                auto resp = co_await ReadDohResponse(stream, ec);
                                if (!ec)
                                {
                                    if (resp && resp->Id == msg.Id)
                                    {
                                        co_return BuildResult(*resp, server.Address, Start);
                                    }
                                    ec = make_error_code(Error::BadMessage);
                                }
                            }
                        }
                    }
                }
            }
            co_return FailResult(server.Address, ec ? ec : make_error_code(Error::IoError));
        }

        /**
         * @brief 读取 DoH HTTP 响应并提取 DNS 报文体
         * @details 逐段读入直到出现 \r\n\r\n（头结束），从头部解析
         *          Content-Length，再读满剩余报文体
         */
        [[nodiscard]] auto ReadDohResponse(ssl::stream<net::ip::tcp::socket> &stream,
                                           boost::system::error_code &ec)
            -> net::awaitable<std::optional<Message>>
        {
            constexpr std::string_view Delim = "\r\n\r\n";
            std::string raw;
            raw.resize(Delim.size());
            std::size_t got = 0;

            while (true)
            {
                std::array<std::uint8_t, 2048> buf{};
                const auto n = co_await stream.async_read_some(net::buffer(buf),
                                                               net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return std::nullopt;
                }
                raw.append(reinterpret_cast<const char *>(buf.data()), n);
                if ((got += n) < Delim.size())
                {
                    continue;
                }
                if (raw.find(Delim) != std::string::npos)
                {
                    break;
                }
            }

            // 解析 Content-Length（兼容大小写两种头形式）
            std::size_t contentLength = 0;
            auto pos = raw.find("Content-Length:");
            if (pos == std::string::npos)
            {
                pos = raw.find("content-length:");
            }
            if (pos != std::string::npos)
            {
                contentLength = static_cast<std::size_t>(std::strtoull(raw.c_str() + pos + 15, nullptr, 10));
            }
            if (contentLength == 0)
            {
                ec = make_error_code(Error::BadMessage);
                co_return std::nullopt;
            }

            const auto HeaderEnd = raw.find(Delim) + Delim.size();
            std::string body = raw.substr(HeaderEnd);
            while (body.size() < contentLength)
            {
                std::array<std::uint8_t, 2048> buf{};
                const auto n = co_await stream.async_read_some(net::buffer(buf),
                                                               net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return std::nullopt;
                }
                body.append(reinterpret_cast<const char *>(buf.data()), n);
            }
            body.resize(contentLength);

            std::span<const std::uint8_t> spanBody(reinterpret_cast<const std::uint8_t *>(body.data()),
                                                   body.size());
            co_return Message::Unpack(spanBody);
        }

        /// 构造成功结果（含 RTT 与 IP 提取）
        [[nodiscard]] static auto BuildResult(const Message &resp, const std::string &addr,
                                              std::chrono::steady_clock::time_point start)
            -> QueryResult
        {
            QueryResult out;
            out.Response = resp;
            out.Ips = resp.ExtractIps();
            out.ServerAddr = addr;
            out.RttMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start)
                    .count());
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
        [[nodiscard]] auto ResolveFallback(std::string_view domain, const Message &query)
            -> net::awaitable<QueryResult>
        {
            QueryResult last;
            for (const auto &server : Servers_)
            {
                auto result = co_await WithTimeout(QueryServer(server, query), TimeoutFor(server));
                last = std::move(result);
                if (!last.Error && !last.Ips.empty())
                {
                    co_return last;
                }
            }
            (void)domain;
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
        [[nodiscard]] auto ResolveConcurrent(const Message &query) -> net::awaitable<QueryResult>
        {
            const auto Total = Servers_.size();
            auto results = std::make_shared<std::vector<QueryResult>>(Total);
            auto completed = std::make_shared<std::atomic<std::size_t>>(0);
            auto wake = std::make_shared<net::steady_timer>(Ex_);
            wake->expires_at(net::steady_timer::time_point::max());

            for (std::size_t i = 0; i < Total; ++i)
            {
                const auto &server = Servers_[i];
                auto task = [this, &server, query, results, i, completed, wake]()
                    -> net::awaitable<void>
                {
                    (*results)[i] =
                        co_await WithTimeout(QueryServer(server, query), TimeoutFor(server));
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
        std::uint64_t Seed_{static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count())}; ///< id 种子
        std::uint16_t Counter_{0};                                         ///< id 递增计数器
    };

} // namespace Preview::Network::Dns
