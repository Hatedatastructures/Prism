/**
 * @file DnsTransportTest.cpp
 * @brief DNS 传输层测试（连接池 + DoT/DoH 路径 + RCODE 语义）
 * @details 覆盖：
 *          - TCP 连接池复用（同服务器多查询单连接）、KeepAlive=false 退回
 *            每查询新建、池容量淘汰（MaxConnsPerServer=1）
 *          - DoT 池化复用（MockTlsServer 单连接限制反证复用生效）
 *          - DoH 正常应答（Responder 工厂构造 HTTP 200）与状态码拒绝
 *          - 复用连接被对端关闭后的一次新建重试（OneShot 服务器）
 *          - SERVFAIL（Rcode=2）为错误且 Fallback 继续下一上游
 * @note 全部走 127.0.0.1 回环，无外部网络依赖
 */

#include <Prism/Net/Dns/Format.hpp>
#include <Prism/Net/Dns/Transport.hpp>
#include <Prism/Net/Dns/Upstream.hpp>
#include "DnsServerTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    using Prism::Network::Dns::Message;
    using Prism::Network::Dns::Mode;
    using Prism::Network::Dns::Protocol;
    using Prism::Network::Dns::QType;
    using Prism::Network::Dns::QueryResult;
    using Prism::Network::Dns::Server;
    using Prism::Network::Dns::Upstream;
    using Prism::Network::Dns::UpstreamOptions;

    using Net::ip::tcp;
    using Net::ip::udp;

    auto PutTransportU16(std::vector<std::uint8_t> &Output, const std::uint16_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    auto PutU32(std::vector<std::uint8_t> &Output, const std::uint32_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 24));
        Output.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    /// 定位查询报文问题段结束偏移（QNAME + QTYPE + QCLASS）
    auto QuestionEnd(std::span<const std::uint8_t> Query) -> std::size_t
    {
        std::size_t Offset = 12;
        while (Offset < Query.size() && Query[Offset] != 0)
        {
            Offset += static_cast<std::size_t>(Query[Offset]) + 1;
        }
        return Offset + 5;
    }

    /// 构造应答（回显问题段 + 固定 A 记录 1.2.3.4 / 可配 Rcode）
    auto BuildResponse(std::span<const std::uint8_t> Query, const std::uint8_t Rcode = 0)
        -> std::vector<std::uint8_t>
    {
        const auto QEnd = QuestionEnd(Query);
        if (QEnd > Query.size())
        {
            return {};
        }
        const bool Full = Rcode == 0;
        std::vector<std::uint8_t> Output;
        PutTransportU16(Output, static_cast<std::uint16_t>((Query[0] << 8) | Query[1]));
        PutTransportU16(Output, 0x8180u | Rcode);
        PutTransportU16(Output, 1);
        std::uint16_t AnswerCount = 0;
        if (Full)
        {
            AnswerCount = 1;
        }
        PutTransportU16(Output, AnswerCount);
        PutTransportU16(Output, 0);
        PutTransportU16(Output, 0);
        Output.insert(Output.end(), Query.begin() + 12,
                      Query.begin() + static_cast<std::ptrdiff_t>(QEnd));
        if (Full)
        {
            PutTransportU16(Output, 0xC00Cu);
            PutTransportU16(Output, 1);
            PutTransportU16(Output, 1);
            PutU32(Output, 60);
            PutTransportU16(Output, 4);
            Output.insert(Output.end(), {1, 2, 3, 4});
        }
        return Output;
    }

    /** @brief 复制完整 query question 并构造 QR=1 的合法 NOERROR/NODATA 应答。 */
    [[nodiscard]] auto BuildNoDataResponse(const std::span<const std::uint8_t> Query)
        -> std::vector<std::uint8_t>
    {
        if (Query.size() < 12 || Query[4] != 0 || Query[5] != 1)
        {
            return {};
        }
        const auto QuestionEndOffset = QuestionEnd(Query);
        if (QuestionEndOffset > Query.size())
        {
            return {};
        }
        std::vector<std::uint8_t> Response;
        Response.reserve(QuestionEndOffset);
        PutTransportU16(Response, static_cast<std::uint16_t>((Query[0] << 8) | Query[1]));
        const auto QueryFlags = static_cast<std::uint16_t>((Query[2] << 8) | Query[3]);
        PutTransportU16(Response, static_cast<std::uint16_t>((QueryFlags & 0x7900u) | 0x8080u));
        PutTransportU16(Response, 1);
        PutTransportU16(Response, 0);
        PutTransportU16(Response, 0);
        PutTransportU16(Response, 0);
        Response.insert(Response.end(), Query.begin() + 12,
                        Query.begin() + static_cast<std::ptrdiff_t>(QuestionEndOffset));
        return Response;
    }

    using TransportDnsTlsResponder =
        std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)>;

    /** @brief 累积 DoT 帧并以完整 DNS NODATA wire 回答每个 query。 */
    struct TransportDotDnsAnswerResponder final
    {
        std::shared_ptr<std::vector<std::uint8_t>> Pending;

        auto operator()(const std::byte *Data, const std::size_t Length)
            -> std::optional<std::vector<std::byte>>
        {
            if (Length == 0)
            {
                return std::nullopt;
            }
            const auto *Input = reinterpret_cast<const std::uint8_t *>(Data);
            Pending->insert(Pending->end(), Input, Input + Length);
            std::vector<std::byte> Output;
            std::size_t Consumed = 0;
            while (Pending->size() - Consumed >= 2)
            {
                const auto FrameBytes = static_cast<std::size_t>(
                    (static_cast<std::uint16_t>((*Pending)[Consumed]) << 8) |
                    (*Pending)[Consumed + 1]);
                if (FrameBytes < 12)
                {
                    Pending->clear();
                    return std::nullopt;
                }
                if (Pending->size() - Consumed - 2 < FrameBytes)
                {
                    break;
                }
                const auto Query = std::span<const std::uint8_t>(
                    Pending->data() + Consumed + 2, FrameBytes);
                const auto Response = BuildNoDataResponse(Query);
                if (Response.empty() || Response.size() > 0xFFFFu)
                {
                    Pending->clear();
                    return std::nullopt;
                }
                Output.push_back(static_cast<std::byte>(Response.size() >> 8));
                Output.push_back(static_cast<std::byte>(Response.size() & 0xFFu));
                for (const auto Byte : Response)
                {
                    Output.push_back(static_cast<std::byte>(Byte));
                }
                Consumed += FrameBytes + 2;
            }
            if (Consumed != 0)
            {
                Pending->erase(Pending->begin(), Pending->begin() + static_cast<std::ptrdiff_t>(Consumed));
            }
            if (Output.empty())
            {
                return std::nullopt;
            }
            return Output;
        }
    };

    [[nodiscard]] auto MakeTransportDotDnsAnswerResponder() -> TransportDnsTlsResponder
    {
        return TransportDnsTlsResponder(
            TransportDotDnsAnswerResponder{std::make_shared<std::vector<std::uint8_t>>()});
    }

    /** @brief 保留 TLS helper 的 HTTP 请求累积，并把 body 变为 DNS NODATA 应答。 */
    struct TransportDohDnsAnswerResponder final
    {
        TransportDnsTlsResponder EchoResponder;
        std::string StatusLine;

        auto operator()(const std::byte *Data, const std::size_t Length)
            -> std::optional<std::vector<std::byte>>
        {
            auto EchoReply = EchoResponder(Data, Length);
            if (!EchoReply)
            {
                return std::nullopt;
            }
            const auto *ReplyText = reinterpret_cast<const char *>(EchoReply->data());
            const auto ReplyTextSize = EchoReply->size();
            const auto HeaderEnd = std::string_view(ReplyText, ReplyTextSize).find("\r\n\r\n");
            if (HeaderEnd == std::string_view::npos)
            {
                return std::vector<std::byte>{};
            }
            const auto BodyStart = HeaderEnd + 4;
            const auto BodyBytes = ReplyTextSize - BodyStart;
            const auto Query = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(EchoReply->data() + BodyStart), BodyBytes);
            const auto DnsResponse = BuildNoDataResponse(Query);
            if (DnsResponse.empty())
            {
                return std::vector<std::byte>{};
            }
            auto Headers = StatusLine + "\r\nContent-Type: application/dns-message\r\nContent-Length: ";
            Headers += std::to_string(DnsResponse.size());
            Headers += "\r\n\r\n";
            std::vector<std::byte> Output;
            Output.reserve(Headers.size() + DnsResponse.size());
            for (const auto Character : Headers)
            {
                Output.push_back(static_cast<std::byte>(Character));
            }
            for (const auto Byte : DnsResponse)
            {
                Output.push_back(static_cast<std::byte>(Byte));
            }
            return Output;
        }
    };

    [[nodiscard]] auto MakeTransportDohDnsAnswerResponder(const std::string_view StatusLine)
        -> TransportDnsTlsResponder
    {
        auto EchoResponder = Prism::Testing::Tls::MakeDohResponder(StatusLine);
        return TransportDnsTlsResponder(
            TransportDohDnsAnswerResponder{std::move(EchoResponder), std::string(StatusLine)});
    }

    /**
     * @class FrameTcpServer
     * @brief 计连接数的帧式 TCP DNS 服务器（Loop = 常驻 / OneShot = 一问即断）
     */
    class FrameTcpServer : public std::enable_shared_from_this<FrameTcpServer>
    {
    public:
        enum class Mode
        {
            Loop,    ///< 一连接服务多次查询
            OneShot, ///< 一连接只答一次后关闭（模拟对端关闭 keep-alive 连接）
        };

        FrameTcpServer(Net::io_context &Ioc, const Mode ServerMode = Mode::Loop)
            : Ex_(Ioc.get_executor()), Tasks_(Ex_), Mode_(ServerMode),
              Acceptor_(Ioc, tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Acceptor_.local_endpoint().port();
            auto Self = shared_from_this();
            Tasks_.Spawn(Self, Self->AcceptLoop());
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Port_;
        }

        [[nodiscard]] auto ConnCount() const -> std::size_t
        {
            return ConnCount_;
        }

        [[nodiscard]] auto MakeConfig() const -> Server
        {
            Server ServerConfig;
            ServerConfig.Address = "127.0.0.1";
            ServerConfig.Port = Port_;
            ServerConfig.Proto = Protocol::Tcp;
            ServerConfig.TimeoutMs = 2000;
            return ServerConfig;
        }

        auto Close() -> void
        {
            boost::system::error_code ErrorCode;
            Acceptor_.close(ErrorCode);
            for (auto &Connection : Conns_)
            {
                Connection->close(ErrorCode);
            }
        }

        /** @brief 等待 accept 循环和所有已接受 TCP 连接循环完成。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            co_await Tasks_.Drain();
        }

    private:
        auto AcceptLoop() -> Net::awaitable<void>
        {
            auto Self = shared_from_this();
            for (;;)
            {
                boost::system::error_code ErrorCode;
                auto Socket = std::make_shared<tcp::socket>(
                    co_await Acceptor_.async_accept(Net::redirect_error(Net::use_awaitable, ErrorCode)));
                if (ErrorCode)
                {
                    co_return;
                }
                ++ConnCount_;
                Conns_.push_back(Socket);
                Tasks_.Spawn(Self, Self->ConnLoop(Socket));
            }
        }

        auto ConnLoop(std::shared_ptr<tcp::socket> Socket) -> Net::awaitable<void>
        {
            for (;;)
            {
                std::array<std::uint8_t, 2> LengthBuffer{};
                boost::system::error_code ErrorCode;
                co_await Net::async_read(*Socket, Net::buffer(LengthBuffer),
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    CloseConnection(Socket);
                    co_return;
                }
                const auto Len = static_cast<std::size_t>((LengthBuffer[0] << 8) | LengthBuffer[1]);
                std::vector<std::uint8_t> Body(Len);
                co_await Net::async_read(*Socket, Net::buffer(Body),
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    CloseConnection(Socket);
                    co_return;
                }
                auto Response = BuildResponse(Body);
                std::vector<std::uint8_t> Frame;
                PutTransportU16(Frame, static_cast<std::uint16_t>(Response.size()));
                Frame.insert(Frame.end(), Response.begin(), Response.end());
                co_await Net::async_write(*Socket, Net::buffer(Frame),
                                          Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode || Mode_ == Mode::OneShot)
                {
                    CloseConnection(Socket);
                    co_return; // OneShot：应答后立即关闭，制造"池中连接已死"
                }
            }
        }

        auto CloseConnection(const std::shared_ptr<tcp::socket> &Socket) -> void
        {
            boost::system::error_code ErrorCode;
            Socket->close(ErrorCode);
        }

        Net::any_io_executor Ex_;
        DnsServerTaskGroup Tasks_;
        Mode Mode_;
        tcp::acceptor Acceptor_;
        std::vector<std::shared_ptr<tcp::socket>> Conns_;
        std::uint16_t Port_{0};
        std::size_t ConnCount_{0};
    };

    /**
     * @class RawUdpServer
     * @brief 可配 Rcode 的 UDP DNS 服务器（SERVFAIL/Fallback 语义测试用）
     */
    class RawUdpServer : public std::enable_shared_from_this<RawUdpServer>
    {
    public:
        RawUdpServer(Net::io_context &Ioc, const std::uint8_t Rcode)
            : Ex_(Ioc.get_executor()), Tasks_(Ex_), Rcode_(Rcode),
              Udp_(Ioc, udp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Udp_.local_endpoint().port();
            auto Self = shared_from_this();
            Tasks_.Spawn(Self, Self->Loop());
        }

        [[nodiscard]] auto MakeConfig() const -> Server
        {
            Server ServerConfig;
            ServerConfig.Address = "127.0.0.1";
            ServerConfig.Port = Port_;
            ServerConfig.TimeoutMs = 2000;
            return ServerConfig;
        }

        auto Close() -> void
        {
            boost::system::error_code ErrorCode;
            Udp_.close(ErrorCode);
        }

        /** @brief 等待 UDP 收发循环真实退栈。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            co_await Tasks_.Drain();
        }

    private:
        auto Loop() -> Net::awaitable<void>
        {
            std::vector<std::uint8_t> Buffer(4096);
            udp::endpoint Sender;
            for (;;)
            {
                boost::system::error_code ErrorCode;
                const auto Count = co_await Udp_.async_receive_from(
                    Net::buffer(Buffer), Sender, Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode || Count < 12)
                {
                    co_return;
                }
                auto Response = BuildResponse({Buffer.data(), Count}, Rcode_);
                if (Response.empty())
                {
                    continue;
                }
                co_await Udp_.async_send_to(Net::buffer(Response), Sender,
                                            Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
        }

        Net::any_io_executor Ex_;
        DnsServerTaskGroup Tasks_;
        std::uint8_t Rcode_;
        udp::socket Udp_;
        std::uint16_t Port_{0};
    };

    /** @brief 两个并发 TCP 查询的连接池容量测试状态。 */
    class PoolCapacityScenario final
    {
    public:
        PoolCapacityScenario(Net::io_context &IoContext,
                             std::shared_ptr<FrameTcpServer> ServerValue,
                             std::shared_ptr<Upstream> UpstreamValue)
            : Executor_(IoContext.get_executor()), Server(std::move(ServerValue)),
              Client(std::move(UpstreamValue)), QueryCompleted(Executor_, 1)
        {
        }

        auto RecordCompletion(std::exception_ptr Error, QueryResult) -> void
        {
            if (Error && !Failure)
            {
                Failure = std::move(Error);
            }
            if (--RemainingQueries == 0)
            {
                (void)QueryCompleted.try_send(boost::system::error_code{});
            }
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<FrameTcpServer> Server;
        std::shared_ptr<Upstream> Client;
        Net::experimental::channel<void(boost::system::error_code)> QueryCompleted;
        std::exception_ptr Failure;
        std::size_t IdleConnectionCount{0};
        int RemainingQueries{2};
    };

    auto RunPoolCapacityQueries(std::shared_ptr<PoolCapacityScenario> Scenario)
        -> Net::awaitable<void>
    {
        auto CompletionHandler = [Scenario](std::exception_ptr Error, QueryResult Value)
        {
            Scenario->RecordCompletion(std::move(Error), std::move(Value));
        };
        Net::co_spawn(Scenario->Executor_,
                      Scenario->Client->Resolve("a.example.com", QType::A), CompletionHandler);
        Net::co_spawn(Scenario->Executor_,
                      Scenario->Client->Resolve("b.example.com", QType::A), CompletionHandler);
        (void)co_await Scenario->QueryCompleted.async_receive(Net::use_awaitable);
        Scenario->IdleConnectionCount = Scenario->Client->IdleConnCount();
        Scenario->Client.reset();
        Scenario->Server->Close();
        co_await Scenario->Server->Drain();
    }

} // namespace

TEST(DnsTransport, TestTcpPoolReusesConnection)
{
    // 同一服务器连续查询共享一条 TCP 连接（keep-alive 默认开启）
Net::io_context IoContext;
    auto ServerOwner = std::make_shared<FrameTcpServer>(IoContext, FrameTcpServer::Mode::Loop);
    ServerOwner->Start();

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerOwner->MakeConfig()}});
    QueryResult FirstResult;
    QueryResult SecondResult;
    std::size_t IdleConnectionCount = 0;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                FirstResult = co_await UpstreamOwner->Resolve("one.example.com", QType::A);
                SecondResult = co_await UpstreamOwner->Resolve("two.example.com", QType::A);
                IdleConnectionCount = UpstreamOwner->IdleConnCount();
                UpstreamOwner.reset();
                ServerOwner->Close();
                co_await ServerOwner->Drain();
            });

    EXPECT_TRUE(FirstResult.Error.Succeeded());
    EXPECT_TRUE(SecondResult.Error.Succeeded());
    EXPECT_EQ(ServerOwner->ConnCount(), 1u); // 两次查询仅一条连接
    EXPECT_EQ(IdleConnectionCount, 1u);  // 用毕归还池中
}

TEST(DnsTransport, RejectsOversizedTcpFrameBeforeLengthEncoding)
{
    const std::vector<std::uint8_t> Maximum(Prism::Network::Dns::Detail::MaxFrameBytes, 0xA5);
    const std::vector<std::uint8_t> Oversized(Prism::Network::Dns::Detail::MaxFrameBytes + 1, 0xA5);

    const auto MaxFrame = Prism::Network::Dns::Detail::MakeTcpFrame(Maximum);
    ASSERT_TRUE(MaxFrame.has_value());
    EXPECT_EQ(MaxFrame->size(), Maximum.size() + 2);

    const auto OversizedFrame = Prism::Network::Dns::Detail::MakeTcpFrame(Oversized);
    ASSERT_FALSE(OversizedFrame.has_value());
    EXPECT_EQ(OversizedFrame.error(),
              boost::system::errc::make_error_code(boost::system::errc::message_size));
}

TEST(DnsTransport, TestKeepAliveOffDisablesPool)
{
    // KeepAlive=false：每查询新建连接，不入池
Net::io_context IoContext;
    auto ServerOwner = std::make_shared<FrameTcpServer>(IoContext, FrameTcpServer::Mode::Loop);
    ServerOwner->Start();

    auto ServerConfig = ServerOwner->MakeConfig();
    ServerConfig.KeepAlive = false;
    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    std::size_t IdleConnectionCount = 0;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                (void)co_await UpstreamOwner->Resolve("one.example.com", QType::A);
                (void)co_await UpstreamOwner->Resolve("two.example.com", QType::A);
                IdleConnectionCount = UpstreamOwner->IdleConnCount();
                UpstreamOwner.reset();
                ServerOwner->Close();
                co_await ServerOwner->Drain();
            });

    EXPECT_EQ(ServerOwner->ConnCount(), 2u);
    EXPECT_EQ(IdleConnectionCount, 0u);
}

TEST(DnsTransport, TestPoolCapacityEviction)
{
    // MaxConnsPerServer=1：并发两查询各建一连接，归还后仅保留 1 条闲置
Net::io_context IoContext;
    auto ServerOwner = std::make_shared<FrameTcpServer>(IoContext, FrameTcpServer::Mode::Loop);
    ServerOwner->Start();

    UpstreamOptions Options;
    Options.Servers = {ServerOwner->MakeConfig()};
    Options.QueryMode = Mode::Fastest;
    Options.DefaultTimeout = std::chrono::milliseconds{4000};
    Options.MaxConnsPerServer = 1;
    auto UpstreamOwner = std::make_shared<Upstream>(IoContext.get_executor(), std::move(Options));
    auto Scenario = std::make_shared<PoolCapacityScenario>(
        IoContext, ServerOwner, std::move(UpstreamOwner));
    RunCoro(IoContext, RunPoolCapacityQueries(Scenario));
    if (Scenario->Failure)
    {
        std::rethrow_exception(Scenario->Failure);
    }

    EXPECT_EQ(ServerOwner->ConnCount(), 2u); // 并发期各建一条
    EXPECT_EQ(Scenario->IdleConnectionCount, 1u);  // 容量 1 → 只留一条
}

TEST(DnsTransport, TestStalePoolConnRetriedOnce)
{
    // OneShot 服务器：首次查询后关闭连接；第二次查询从池中取到"已死"连接，
    // 复用失败自动新建重试一次并最终成功
Net::io_context IoContext;
    auto ServerOwner = std::make_shared<FrameTcpServer>(IoContext, FrameTcpServer::Mode::OneShot);
    ServerOwner->Start();

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerOwner->MakeConfig()}});
    QueryResult FirstResult;
    QueryResult SecondResult;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                FirstResult = co_await UpstreamOwner->Resolve("one.example.com", QType::A);
                SecondResult = co_await UpstreamOwner->Resolve("two.example.com", QType::A);
                UpstreamOwner.reset();
                ServerOwner->Close();
                co_await ServerOwner->Drain();
            });

    EXPECT_TRUE(FirstResult.Error.Succeeded());
    EXPECT_TRUE(SecondResult.Error.Succeeded());
    EXPECT_EQ(ServerOwner->ConnCount(), 2u); // 死连接复用失败 → 新建第二条
}

TEST(DnsTransport, TestTlsPoolReuse)
{
    // MockTlsServer 限制 MaxConnections=1：若第二次查询未复用连接，
    // 服务器已退出 accept → 必失败；DNS-aware responder 返回合法 NODATA，
    // 两查询均成功即证明池化复用。
Net::io_context IoContext;
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1, MakeTransportDotDnsAnswerResponder());
    const auto Port = TlsServer->Port();
    TlsServer->Start();

    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = Port;
    ServerConfig.Proto = Protocol::Tls;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;
    ServerConfig.TimeoutMs = 2000;

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult FirstResult;
    QueryResult SecondResult;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                FirstResult = co_await UpstreamOwner->Resolve("one.example.com", QType::A);
                SecondResult = co_await UpstreamOwner->Resolve("two.example.com", QType::A);
                UpstreamOwner.reset();
                TlsServer->Close();
                co_await TlsServer->Drain();
            });

    EXPECT_TRUE(FirstResult.Error.Succeeded());
    EXPECT_TRUE(SecondResult.Error.Succeeded());
}

TEST(DnsTransport, TestDohStatus200WithResponder)
{
    // Responder 工厂回真实 HTTP 200 + 合法 DNS NODATA 应答体：状态码校验、
    // Content-Length 头区解析、报文体收满和 query 身份校验全链路。
Net::io_context IoContext;
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 2, MakeTransportDohDnsAnswerResponder("HTTP/1.1 200 OK"));
    const auto Port = TlsServer->Port();
    TlsServer->Start();

    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = Port;
    ServerConfig.Proto = Protocol::Https;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;
    ServerConfig.TimeoutMs = 2000;

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult Result;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("doh.example.com", QType::A);
                UpstreamOwner.reset();
                TlsServer->Close();
                co_await TlsServer->Drain();
            });

    // 应答保留 query ID/question、设置 QR=1、Rcode=0 且无地址 → 成功 + 空 IP。
    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsTransport, TestDohStatusRejection)
{
    // HTTP 404 → BadMessage，不当作有效应答
Net::io_context IoContext;
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1,
        Prism::Testing::Tls::MakeDohResponder("HTTP/1.1 404 Not Found"));
    const auto Port = TlsServer->Port();
    TlsServer->Start();

    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = Port;
    ServerConfig.Proto = Protocol::Https;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;
    ServerConfig.TimeoutMs = 2000;

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult Result;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("doh.example.com", QType::A);
                UpstreamOwner.reset();
                TlsServer->Close();
                co_await TlsServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Failed());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsTransport, TestServfailFallsThroughInFallbackMode)
{
    // SERVFAIL（Rcode=2）为明确拒绝：Fallback 跳过它继续下一个上游
Net::io_context IoContext;
    auto ServfailServer = std::make_shared<RawUdpServer>(IoContext, 2);
    auto GoodServer = std::make_shared<RawUdpServer>(IoContext, 0);
    ServfailServer->Start();
    GoodServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {ServfailServer->MakeConfig(), GoodServer->MakeConfig()},
                                .QueryMode = Mode::Fallback});
    QueryResult Result;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("sf.example.com", QType::A);
                ServfailServer->Close();
                GoodServer->Close();
                co_await ServfailServer->Drain();
                co_await GoodServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    ASSERT_EQ(Result.Response.Ips.Size(), 1u);
    EXPECT_EQ(Result.Response.Ips[0], Net::ip::make_address_v4("1.2.3.4"));
}

TEST(DnsTransport, TestServfailAloneIsError)
{
    // 单 SERVFAIL 上游：结果为错误（不冒充"成功+空"进负缓存语义）
Net::io_context IoContext;
    auto ServfailServer = std::make_shared<RawUdpServer>(IoContext, 2);
    ServfailServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {ServfailServer->MakeConfig()}, .QueryMode = Mode::Fallback});
    QueryResult Result;
    RunCoro(IoContext,
[&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("sf.example.com", QType::A);
                ServfailServer->Close();
                co_await ServfailServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Failed());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}
