/**
 * @file DnsUpstreamProtocolTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "DnsUpstreamTestSupport.hpp"

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Net/Dns/ConnPool.hpp>
#include <Prism/Net/Dns/Detail/TlsTransport.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace
{
    using RequestObservedChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief DoT 查询在途场景及由测试持有的结果槽。 */
    struct DotQueryScenario final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Upstream> UpstreamOwner;
        std::shared_ptr<DnsTlsTestServer> TlsServer;
        std::shared_ptr<RequestObservedChannel> RequestObserved;
        std::shared_ptr<RequestObservedChannel> QueryCompleted;
        QueryResult *Result;
        std::exception_ptr *Failure;
        bool *RequestSeen;
    };

    auto WaitForObservedRequest(std::shared_ptr<RequestObservedChannel> Observed)
        -> Net::awaitable<bool>
    {
        (void)co_await Observed->async_receive(Net::use_awaitable);
        co_return true;
    }

    auto WaitForRequestWatchdog(Net::steady_timer &Timer) -> Net::awaitable<bool>
    {
        co_await Timer.async_wait(Net::use_awaitable);
        co_return false;
    }

    auto WaitForRequestObserved(
        const DotQueryScenario &Scenario,
        const std::chrono::milliseconds Timeout) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        Net::steady_timer Timer(Scenario.Executor);
        Timer.expires_after(Timeout);
        const auto Outcome = co_await (
            WaitForObservedRequest(Scenario.RequestObserved) || WaitForRequestWatchdog(Timer));
        co_return Outcome.index() == 0U;
    }

    /** @brief 等待 DoT 查询的完整帧到达后收束其 deadline 结果与服务端任务。 */
    auto RunDotTimeoutScenario(DotQueryScenario Scenario) -> Net::awaitable<void>
    {
        auto Cancellation = std::make_shared<Net::cancellation_signal>();
        Net::co_spawn(
            Scenario.Executor,
            Scenario.UpstreamOwner->Resolve("dot-timeout.example.com", QType::A),
            Net::bind_cancellation_slot(
                Cancellation->slot(),
                [Scenario](std::exception_ptr Failure, QueryResult Value)
                {
                    *Scenario.Failure = std::move(Failure);
                    *Scenario.Result = std::move(Value);
                    (void)Scenario.QueryCompleted->try_send(boost::system::error_code{});
                }));
        const auto RequestSeen = co_await WaitForRequestObserved(
            Scenario, std::chrono::seconds(1));
        *Scenario.RequestSeen = RequestSeen;
        if (!RequestSeen)
        {
            Cancellation->emit(Net::cancellation_type::all);
        }
        (void)co_await Scenario.QueryCompleted->async_receive(Net::use_awaitable);
        Scenario.UpstreamOwner.reset();
        Scenario.TlsServer->Close();
        co_await Scenario.TlsServer->Drain();
    }

    /** @brief 等待完整 DoT 查询帧到达后取消读取并收束连接任务。 */
    struct DotCancellationScenario final
    {
        DotQueryScenario Query;
        std::shared_ptr<Net::cancellation_signal> Cancellation;
    };

    auto RunDotCancellationScenario(DotCancellationScenario Scenario)
        -> Net::awaitable<void>
    {
        auto Query = std::move(Scenario.Query);
        Net::co_spawn(
            Query.Executor,
            Query.UpstreamOwner->Resolve("dot-cancel.example.com", QType::A),
            Net::bind_cancellation_slot(
                Scenario.Cancellation->slot(),
                [Query](std::exception_ptr Failure, QueryResult Value)
                {
                    *Query.Failure = std::move(Failure);
                    *Query.Result = std::move(Value);
                    (void)Query.QueryCompleted->try_send(boost::system::error_code{});
                }));
        const auto RequestSeen = co_await WaitForRequestObserved(
            Query, std::chrono::seconds(4));
        *Query.RequestSeen = RequestSeen;
        Scenario.Cancellation->emit(Net::cancellation_type::all);
        (void)co_await Query.QueryCompleted->async_receive(Net::use_awaitable);
        Query.UpstreamOwner.reset();
        Query.TlsServer->Close();
        co_await Query.TlsServer->Drain();
    }

    /** @brief 收到完整 DoT 查询帧后通知测试，并保持 TLS 连接静默。 */
    struct SilentDotResponder final
    {
        std::shared_ptr<RequestObservedChannel> RequestObserved;
        std::vector<std::byte> Pending;
        bool Signaled{false};

        auto operator()(const std::byte *Data, const std::size_t Length)
            -> std::optional<std::vector<std::byte>>
        {
            if (Length != 0 && !Signaled)
            {
                Pending.insert(Pending.end(), Data, Data + Length);
                if (Pending.size() >= 2)
                {
                    const auto FrameBytes =
                        (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Pending[0])) << 8) |
                        std::to_integer<std::uint8_t>(Pending[1]);
                    if (FrameBytes >= 12 && Pending.size() >= FrameBytes + 2)
                    {
                        Signaled = true;
                        (void)RequestObserved->try_send(boost::system::error_code{});
                    }
                }
            }
            return std::nullopt;
        }
    };

    class ScriptedAsyncReadStream final
    {
    public:
        using executor_type = Net::any_io_executor;

        ScriptedAsyncReadStream(
            executor_type Executor,
            std::vector<std::uint8_t> Input,
            boost::system::error_code Failure)
            : Executor_(std::move(Executor)), Input_(std::move(Input)), Failure_(Failure)
        {
        }

        [[nodiscard]] auto get_executor() const noexcept -> executor_type
        {
            return Executor_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        template <typename Buffers, typename Token>
        auto async_read_some(const Buffers &Output, Token &&Handler)
        {
            return Net::async_initiate<Token,
                void(boost::system::error_code, std::size_t)>(
                [this, Output](auto Completion) mutable
                {
                    ++ReadCalls_;
                    const auto Count = Net::buffer_copy(Output, Net::buffer(Input_));
                    Net::post(Executor_,
                        [Completion = std::move(Completion), Failure = Failure_, Count]() mutable
                        { Completion(Failure, Count); });
                }, Handler);
        }

    private:
        executor_type Executor_;
        std::vector<std::uint8_t> Input_;
        boost::system::error_code Failure_;
        std::size_t ReadCalls_{0};
    };

    struct TerminalPoolLink final
    {
        bool Open{true};
        std::size_t CloseCalls{0};

        auto Send(std::span<const std::uint8_t>, Prism::Network::Dns::Detail::AttemptDeadline) -> int
        {
            return 0;
        }

        auto Receive(Prism::Network::Dns::Detail::AttemptDeadline) -> int
        {
            return 0;
        }

        auto Connect(const Net::ip::tcp::endpoint &, const Server &,
                     Prism::Network::Dns::Detail::AttemptDeadline) -> int
        {
            return 0;
        }

        auto Close() -> void
        {
            ++CloseCalls;
            Open = false;
        }

        [[nodiscard]] auto IsOpen() const -> bool
        {
            return Open;
        }
    };

    struct DnsFrameReadOutcome final
    {
        std::vector<std::uint8_t> Body;
        boost::system::error_code Failure;
        std::size_t ReadCalls{0};
    };

    struct CompleteBodyTerminalRequest final
    {
        ScriptedAsyncReadStream &Stream;
        std::shared_ptr<TerminalPoolLink> Link;
        const std::vector<std::uint8_t> &Expected;
        DnsFrameReadOutcome *Outcome;
    };

    auto RunCompleteBodyTerminalRead(CompleteBodyTerminalRequest Request)
        -> Net::awaitable<void>
    {
        std::vector<std::uint8_t> Body(Request.Expected.size());
        boost::system::error_code ErrorCode;
        const auto Bytes = co_await Net::async_read(
            Request.Stream, Net::buffer(Body),
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        auto Result = Prism::Network::Dns::Detail::FinishDnsFrameBody(
            {std::move(Body), Bytes, ErrorCode},
            [Link = Request.Link] { Link->Close(); });
        if (Result)
        {
            Request.Outcome->Body = std::move(*Result);
        }
        else
        {
            Request.Outcome->Failure = Result.error();
        }
        Request.Outcome->ReadCalls = Request.Stream.ReadCalls();
        co_return;
    }

    struct PartialFrameReadOutcome final
    {
        Prism::Network::Dns::Detail::ExactReadOutcome Header;
        boost::system::error_code BodyFailure;
        std::size_t HeaderReadCalls{0};
        std::size_t BodyReadCalls{0};
    };

    struct PartialFrameTerminalRequest final
    {
        ScriptedAsyncReadStream &HeaderStream;
        ScriptedAsyncReadStream &BodyStream;
        std::size_t BodySize;
        PartialFrameReadOutcome *Outcome;
    };

    auto RunPartialFrameTerminalRead(PartialFrameTerminalRequest Request)
        -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 2> Header{};
        boost::system::error_code HeaderError;
        const auto HeaderBytes = co_await Net::async_read(
            Request.HeaderStream, Net::buffer(Header),
            Net::redirect_error(Net::use_awaitable, HeaderError));
        Request.Outcome->Header = Prism::Network::Dns::Detail::ClassifyExactRead(
            {HeaderBytes, HeaderError}, Header.size());
        Request.Outcome->HeaderReadCalls = Request.HeaderStream.ReadCalls();

        if (Request.Outcome->Header.State !=
            Prism::Network::Dns::Detail::ExactReadState::Complete)
        {
            Request.Outcome->BodyReadCalls = Request.BodyStream.ReadCalls();
            co_return;
        }

        std::vector<std::uint8_t> Body(Request.BodySize);
        boost::system::error_code BodyError;
        const auto BodyBytes = co_await Net::async_read(
            Request.BodyStream, Net::buffer(Body),
            Net::redirect_error(Net::use_awaitable, BodyError));
        auto BodyResult = Prism::Network::Dns::Detail::FinishDnsFrameBody(
            {std::move(Body), BodyBytes, BodyError}, [] {});
        if (!BodyResult)
        {
            Request.Outcome->BodyFailure = BodyResult.error();
        }
        Request.Outcome->BodyReadCalls = Request.BodyStream.ReadCalls();
        co_return;
    }

    struct HeaderTerminalGateOutcome final
    {
        Prism::Network::Dns::Detail::ExactReadOutcome Header;
        std::size_t HeaderReadCalls{0};
        std::size_t BodyReadCalls{0};
    };

    struct HeaderTerminalGateRequest final
    {
        ScriptedAsyncReadStream &HeaderStream;
        ScriptedAsyncReadStream &BodyStream;
        HeaderTerminalGateOutcome *Outcome;
    };

    auto RunHeaderTerminalGate(HeaderTerminalGateRequest Request)
        -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 2> Header{};
        boost::system::error_code HeaderError;
        const auto HeaderBytes = co_await Net::async_read(
            Request.HeaderStream, Net::buffer(Header),
            Net::redirect_error(Net::use_awaitable, HeaderError));
        Request.Outcome->Header = Prism::Network::Dns::Detail::ClassifyExactRead(
            {HeaderBytes, HeaderError}, Header.size());
        if (Request.Outcome->Header.State ==
            Prism::Network::Dns::Detail::ExactReadState::Complete)
        {
            std::array<std::uint8_t, 4> Body{};
            boost::system::error_code BodyError;
            (void)co_await Net::async_read(
                Request.BodyStream, Net::buffer(Body),
                Net::redirect_error(Net::use_awaitable, BodyError));
        }
        Request.Outcome->HeaderReadCalls = Request.HeaderStream.ReadCalls();
        Request.Outcome->BodyReadCalls = Request.BodyStream.ReadCalls();
        co_return;
    }
} // namespace

TEST(DnsUpstream, TestTimeoutOnSilentServer)
{
Net::io_context IoContext;
    auto SilentServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Silent);
    SilentServer->Start();

    Server ServerConfig = SilentServer->MakeConfig();
    ServerConfig.TimeoutMs = 300;
    Upstream UpstreamOwner(IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("silent.com", QType::A);
                SilentServer->Close();
                co_await SilentServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Failed());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, TestAllServersFail)
{
Net::io_context IoContext;
    auto FirstServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::EmptyAnswer);
    auto SecondServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Silent);
    FirstServer->Start();
    SecondServer->Start();

    Server SecondServerConfig = SecondServer->MakeConfig();
    SecondServerConfig.TimeoutMs = 200;
    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {FirstServer->MakeConfig(), SecondServerConfig},
                                .QueryMode = Prism::Network::Dns::Mode::Fallback});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("none.com", QType::A);
                FirstServer->Close();
                SecondServer->Close();
                co_await FirstServer->Drain();
                co_await SecondServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Failed());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, TestNxDomainReturnsSuccessEmpty)
{
    // NXDOMAIN 是"成功+空"：无错误码、空 IP（由上层负缓存），而非错误
Net::io_context IoContext;
    auto DnsServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::NxDomain);
    DnsServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(), UpstreamOptions{.Servers = {DnsServer->MakeConfig()}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("nx.example.com", QType::A);
                DnsServer->Close();
                co_await DnsServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
    EXPECT_EQ(Result.Response.Rcode, 3u);
}

TEST(DnsUpstream, TestFallbackNxDomainStopsAtFirst)
{
    // 1.3 修复验证：首个上游回 NXDOMAIN 即终态，不再重试第二个上游
Net::io_context IoContext;
    auto NxDomainServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::NxDomain);
    auto GoodServer = std::make_shared<FakeDnsServer>(IoContext, FakeDnsServer::Behavior::Answer);
    NxDomainServer->Start();
    GoodServer->Start();

    Upstream UpstreamOwner(IoContext.get_executor(),
                UpstreamOptions{.Servers = {NxDomainServer->MakeConfig(), GoodServer->MakeConfig()},
                                .QueryMode = Prism::Network::Dns::Mode::Fallback});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner.Resolve("nx.example.com", QType::A);
                NxDomainServer->Close();
                GoodServer->Close();
                co_await NxDomainServer->Drain();
                co_await GoodServer->Drain();
            });

    // 应答来源是首个（NXDOMAIN）服务器而非被"跳过"到第二个
    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
    EXPECT_EQ(Result.ServerAddr, NxDomainServer->Addr());
}

TEST(DnsUpstream, TestDotHandshakeAndFrameRead)
{
    // DoT 路径覆盖（此前零覆盖）：TLS 握手 HandshakeTls + 帧读取 ReadTcpFrame。
    // responder 解析长度帧并返回 QR=1、ID/question 匹配的合法 NODATA 应答；
    // 保留原来的无错误与空 IP 断言，同时覆盖 DoT 的成功校验路径。
Net::io_context IoContext;
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1, MakeDotDnsAnswerResponder());
    const auto Port = TlsServer->Port();
    TlsServer->Start();

    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = Port;
    ServerConfig.Proto = Prism::Network::Dns::Protocol::Tls;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;

    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    QueryResult Result;
    RunCoro(IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await UpstreamOwner->Resolve("dot.example.com", QType::A);
                UpstreamOwner.reset();
                TlsServer->Close();
                co_await TlsServer->Drain();
            });

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, DotReceiveDeadlineMapsToTimeout)
{
    Net::io_context IoContext;
    auto RequestObserved = std::make_shared<RequestObservedChannel>(IoContext, 1);
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1, SilentDotResponder{RequestObserved});
    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = TlsServer->Port();
    ServerConfig.Proto = Prism::Network::Dns::Protocol::Tls;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;
    ServerConfig.TimeoutMs = 500;
    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    auto QueryCompleted = std::make_shared<RequestObservedChannel>(IoContext, 1);
    QueryResult Result;
    std::exception_ptr QueryFailure;
    bool RequestSeen = false;
    TlsServer->Start();

    RunCoro(IoContext, RunDotTimeoutScenario(DotQueryScenario{
                  IoContext.get_executor(), UpstreamOwner, TlsServer, RequestObserved,
                  QueryCompleted, &Result, &QueryFailure, &RequestSeen}));

    EXPECT_FALSE(QueryFailure);
    EXPECT_TRUE(RequestSeen);
    EXPECT_EQ(Result.Error.Code, Prism::Fault::Code::Timeout);
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, DotReceiveCancellationMapsToCanceled)
{
    Net::io_context IoContext;
    auto RequestObserved = std::make_shared<RequestObservedChannel>(IoContext, 1);
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1, SilentDotResponder{RequestObserved});
    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = TlsServer->Port();
    ServerConfig.Proto = Prism::Network::Dns::Protocol::Tls;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;
    ServerConfig.TimeoutMs = 5000;
    auto UpstreamOwner = std::make_shared<Upstream>(
        IoContext.get_executor(), UpstreamOptions{.Servers = {ServerConfig}});
    auto QueryCompleted = std::make_shared<RequestObservedChannel>(IoContext, 1);
    auto Cancellation = std::make_shared<Net::cancellation_signal>();
    QueryResult Result;
    std::exception_ptr QueryFailure;
    bool RequestSeen = false;
    TlsServer->Start();

    RunCoro(IoContext,
            RunDotCancellationScenario(DotCancellationScenario{
                DotQueryScenario{IoContext.get_executor(), UpstreamOwner, TlsServer,
                                 RequestObserved, QueryCompleted, &Result, &QueryFailure,
                                 &RequestSeen},
                Cancellation}));

    EXPECT_FALSE(QueryFailure);
    EXPECT_TRUE(RequestSeen);
    EXPECT_EQ(Result.Error.Code, Prism::Fault::Code::Canceled);
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

TEST(DnsUpstream, DotCompleteBodyWithNativeTerminalIsAcceptedAndNotPooled)
{
    Net::io_context IoContext;
    const std::vector<std::uint8_t> Query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'd', 'o', 't', 0x00, 0x00, 0x01, 0x00, 0x01};
    const auto Expected = BuildDnsNoDataResponse(Query);
    const auto Reset = Net::error::make_error_code(Net::error::connection_reset);
    ScriptedAsyncReadStream Stream(IoContext.get_executor(), Expected, Reset);
    auto Link = std::make_shared<TerminalPoolLink>();
    Prism::Network::Dns::ConnPool<TerminalPoolLink> Pool;
    DnsFrameReadOutcome Outcome;

    RunCoro(IoContext, RunCompleteBodyTerminalRead(
        CompleteBodyTerminalRequest{Stream, Link, Expected, &Outcome}));
    Pool.Release("dot.example", Link);
    const auto Reacquired = Pool.Acquire("dot.example");

    EXPECT_FALSE(Expected.empty());
    EXPECT_EQ(Outcome.Body, Expected);
    EXPECT_FALSE(Outcome.Failure);
    EXPECT_EQ(Outcome.ReadCalls, 1U);
    EXPECT_EQ(Link->CloseCalls, 1U);
    EXPECT_FALSE(Link->IsOpen());
    EXPECT_EQ(Pool.IdleCount(), 0U);
    EXPECT_FALSE(Reacquired.Conn);
}

TEST(DnsUpstream, DotCompleteBodyDoesNotConsumeCancellationOrDeadline)
{
    const std::vector<std::uint8_t> Query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'd', 'o', 't', 0x00, 0x00, 0x01, 0x00, 0x01};
    const auto Payload = BuildDnsNoDataResponse(Query);
    std::size_t RetireCount = 0;
    const auto Retire = [&RetireCount] { ++RetireCount; };
    const auto Canceled = Net::error::operation_aborted;
    const auto CanceledResult = Prism::Network::Dns::Detail::FinishDnsFrameBody(
        {Payload, Payload.size(), Canceled}, Retire);
    const auto Timeout = Prism::make_error_code(Prism::Error::Timeout);
    const auto TimeoutResult = Prism::Network::Dns::Detail::FinishDnsFrameBody(
        {Payload, Payload.size(), Timeout}, Retire);

    EXPECT_FALSE(Payload.empty());
    ASSERT_FALSE(CanceledResult);
    EXPECT_EQ(CanceledResult.error(), Canceled);
    ASSERT_FALSE(TimeoutResult);
    EXPECT_EQ(TimeoutResult.error(), Timeout);
    EXPECT_EQ(RetireCount, 0U);
}

TEST(DnsUpstream, DotPartialHeaderAndBodyWithNativeTerminalRemainFailures)
{
    Net::io_context IoContext;
    const auto Reset = Net::error::make_error_code(Net::error::connection_reset);
    ScriptedAsyncReadStream HeaderStream(
        IoContext.get_executor(), {0x00}, Reset);
    ScriptedAsyncReadStream BodyStream(
        IoContext.get_executor(), {0x12, 0x34}, Reset);
    PartialFrameReadOutcome Outcome;

    RunCoro(IoContext, RunPartialFrameTerminalRead(
        PartialFrameTerminalRequest{HeaderStream, BodyStream, 4U, &Outcome}));

    EXPECT_EQ(Outcome.Header.State,
        Prism::Network::Dns::Detail::ExactReadState::Failed);
    EXPECT_EQ(Outcome.Header.Failure, Reset);
    EXPECT_EQ(Outcome.HeaderReadCalls, 1U);
    EXPECT_FALSE(Outcome.BodyFailure);
    EXPECT_EQ(Outcome.BodyReadCalls, 0U);

    Net::io_context BodyIoContext;
    ScriptedAsyncReadStream CompleteHeaderStream(
        BodyIoContext.get_executor(), {0x00, 0x04}, {});
    ScriptedAsyncReadStream PartialBodyStream(
        BodyIoContext.get_executor(), {0x12, 0x34}, Reset);
    PartialFrameReadOutcome BodyOutcome;
    RunCoro(BodyIoContext, RunPartialFrameTerminalRead(
        PartialFrameTerminalRequest{
            CompleteHeaderStream, PartialBodyStream, 4U, &BodyOutcome}));

    EXPECT_EQ(BodyOutcome.Header.State,
        Prism::Network::Dns::Detail::ExactReadState::Complete);
    EXPECT_EQ(BodyOutcome.HeaderReadCalls, 1U);
    EXPECT_EQ(BodyOutcome.BodyFailure, Reset);
    EXPECT_EQ(BodyOutcome.BodyReadCalls, 1U);
}

TEST(DnsUpstream, DotCompleteHeaderWithNativeTerminalDoesNotReadBody)
{
    Net::io_context IoContext;
    const auto Reset = Net::error::make_error_code(Net::error::connection_reset);
    ScriptedAsyncReadStream HeaderStream(
        IoContext.get_executor(), {0x00, 0x04}, Reset);
    ScriptedAsyncReadStream BodyStream(
        IoContext.get_executor(), {0x12, 0x34, 0x56, 0x78}, {});
    HeaderTerminalGateOutcome Outcome;

    RunCoro(IoContext, RunHeaderTerminalGate(
        HeaderTerminalGateRequest{HeaderStream, BodyStream, &Outcome}));

    EXPECT_EQ(Outcome.Header.State,
        Prism::Network::Dns::Detail::ExactReadState::CompleteWithTerminal);
    EXPECT_EQ(Outcome.Header.Failure, Reset);
    EXPECT_EQ(Outcome.HeaderReadCalls, 1U);
    EXPECT_EQ(Outcome.BodyReadCalls, 0U);
}

TEST(DnsUpstream, TestDohHandshakeAndHttpRead)
{
    // DoH 路径覆盖（此前零覆盖）：TLS 握手 + HTTP 响应解析
    // （状态码校验、Content-Length 头区解析、\r\n\r\n 扫描、报文体收满）。
    // responder 将 HTTP POST 中的 query 转为 QR=1、ID/question 匹配的合法 NODATA answer。
Net::io_context IoContext;
    auto TlsServer = std::make_shared<DnsTlsTestServer>(
        IoContext, 1, MakeDohDnsAnswerResponder("HTTP/1.1 200 OK"));
    const auto Port = TlsServer->Port();
    TlsServer->Start();

    Prism::Network::Dns::Server ServerConfig;
    ServerConfig.Address = "127.0.0.1";
    ServerConfig.Port = Port;
    ServerConfig.Proto = Prism::Network::Dns::Protocol::Https;
    ServerConfig.Hostname = "127.0.0.1";
    ServerConfig.SkipCertCheck = true;
    ServerConfig.HttpPath = "/dns-query";

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

    EXPECT_TRUE(Result.Error.Succeeded());
    EXPECT_TRUE(Result.Response.Ips.Empty());
}

