/**
 * @file TrafficMiddlewareTest.cpp
 * @brief 流量统计聚合测试（T4-4）
 * @details 覆盖：
 *          - 按 identity 聚合 up/down
 *          - 未知 identity / 零流量返回 0
 *          - 多会话累计（同一 identity 汇总）
 *          - 会话编排集成：relay 结束点 → 聚合器收到
 */

#include <gtest/gtest.h>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <thread>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Foundation/Memory/BytePoolOptions.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/Statistics.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    auto SpawnAndSignal(Net::any_io_executor Executor, Net::awaitable<void> Task)
        -> std::shared_ptr<CompletionChannel>
    {
        auto Done = std::make_shared<CompletionChannel>(Executor, 1);
        Net::co_spawn(Executor, std::move(Task),
                      [Done](std::exception_ptr Failure)
                      {
                          boost::system::error_code ErrorCode;
                          if (Failure)
                          {
                              ErrorCode = boost::system::errc::make_error_code(
                                  boost::system::errc::io_error);
                          }
                          Done->try_send(ErrorCode);
                      });
        return Done;
    }

    auto SpawnAndSignal(Net::any_io_executor Executor,
                        Net::awaitable<Preview::Fault::Failure> Task)
        -> std::shared_ptr<CompletionChannel>
    {
        auto Done = std::make_shared<CompletionChannel>(Executor, 1);
        Net::co_spawn(Executor, std::move(Task),
                      [Done](std::exception_ptr Failure, Preview::Fault::Failure)
                      {
                          boost::system::error_code ErrorCode;
                          if (Failure)
                          {
                              ErrorCode = boost::system::errc::make_error_code(
                                  boost::system::errc::io_error);
                          }
                          Done->try_send(ErrorCode);
                      });
        return Done;
    }

    /// 回显上游
    auto echo_upstream(SharedTransmission client_side) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        while (true)
        {
            const auto Read = co_await client_side->ReadSome(std::span<std::byte>(buf));
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                break;
            }
            const auto Written = co_await client_side->WriteSome(
                std::span<const std::byte>(buf.data(), Read.Bytes));
            if (Written.Failure.Failed())
            {
                break;
            }
        }
        const auto Closed = client_side->Close();
        EXPECT_TRUE(Closed);
    }

    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    auto make_pair_shared(Net::io_context &ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(a)),
                std::make_shared<MemoryStream>(std::move(b))};
    }

    /**
     * @brief 完成集成测试的认证和 typed stream data-plane 装配。
     */
    auto RunSessionAcceptOutcome(
        Preview::SharedAuthenticator Authenticator,
        Preview::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
        [[maybe_unused]] auto Metadata = std::move(Input.Metadata);
        Plane.Target.Route = Preview::Network::RouteKind::Forward;
        auto Credential = Preview::Account::Credential::Password("pw");
        auto Authentication = Authenticator->Authenticate(Preview::AuthenticationRequest{
            .Identity = "alice", .Credential = Credential.View(), .Rate = {}});
        if (!Authentication)
        {
            co_return std::unexpected(Authentication.error());
        }
        Plane.AccountId = Authentication->AccountId();
        Plane.Identity = std::string(Authentication->Identity());
        Plane.DisplayIdentity = std::string(Authentication->DisplayIdentity());
        Plane.AccountLease = std::move(*Authentication);
        Plane.ProtocolAuthenticated = true;
        co_return Plane;
    }

    /**
     * @brief 驱动真实 Session relay、echo upstream、空闲等待和四端点关闭。
     */
    struct TrafficSessionRequest final
    {
        Net::io_context &Io;
        Preview::Runtime::Session &Session;
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Inbound;
        std::shared_ptr<MemoryStream> Upstream;
        std::shared_ptr<MemoryStream> Outbound;
    };

    auto RunTrafficSessionIntegration(TrafficSessionRequest Request)
        -> Net::awaitable<void>
    {
        auto SessionDone = SpawnAndSignal(Request.Io.get_executor(), Request.Session.Run(Request.Inbound));
        auto EchoDone = SpawnAndSignal(Request.Io.get_executor(), echo_upstream(Request.Upstream));

        const auto Payload = socks5_greeting();
        const auto Written = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        EXPECT_FALSE(Written.Failure.Failed());
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Request.Client->ReadSome(std::span<std::byte>(Buffer));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Payload);

        Net::steady_timer Timer(Request.Io);
        Timer.expires_after(std::chrono::milliseconds(300));
        co_await Timer.async_wait(Net::use_awaitable);
        const auto ClientClosed = Request.Client->Close();
        const auto InboundClosed = Request.Inbound->Close();
        const auto UpstreamClosed = Request.Upstream->Close();
        const auto OutboundClosed = Request.Outbound->Close();
        EXPECT_TRUE(ClientClosed);
        EXPECT_TRUE(InboundClosed);
        EXPECT_TRUE(UpstreamClosed);
        EXPECT_TRUE(OutboundClosed);
        boost::system::error_code SessionError;
        boost::system::error_code EchoError;
        co_await SessionDone->async_receive(
            Net::redirect_error(Net::use_awaitable, SessionError));
        co_await EchoDone->async_receive(
            Net::redirect_error(Net::use_awaitable, EchoError));
        EXPECT_FALSE(SessionError);
        EXPECT_FALSE(EchoError);
    }

    TEST(TrafficCounter, AggregateByNumericAccount)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
            .Workers = 1, .MaxCounterEntries = 256}, ControlIo.get_executor());
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{1}, .Up = 10, .Down = 20});
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{1}, .Up = 5, .Down = 7});
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{2}, .Up = 100, .Down = 1});
        counter.Flush();

        const auto a = counter.Value(Preview::Statistics::Scope::Account, 1);
        EXPECT_EQ(a.UpBytes, 15);
        EXPECT_EQ(a.DownBytes, 27);
        const auto b = counter.Value(Preview::Statistics::Scope::Account, 2);
        EXPECT_EQ(b.UpBytes, 100);
        EXPECT_EQ(b.DownBytes, 1);
        EXPECT_EQ(counter.Accepted(), 3U);
        EXPECT_EQ(counter.ConsumedObservations(), 3U);
    }

    TEST(TrafficCounter, AcceptsMultipleNumericAccountsWithinCounterCapacity)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
            .Workers = 1, .MaxCounterEntries = 32}, ControlIo.get_executor());
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{1}, .Up = 10, .Down = 20});
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{2}, .Up = 30, .Down = 40});
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{1}, .Up = 1, .Down = 2});
        counter.Flush();

        EXPECT_EQ(counter.Value(Preview::Statistics::Scope::Account, 1).UpBytes, 11u);
        EXPECT_EQ(counter.Value(Preview::Statistics::Scope::Account, 2).UpBytes, 30u);
        EXPECT_EQ(counter.Dropped(), 0U);
    }

    TEST(TrafficCounter, UnknownNumericAccountIsZero)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
            .Workers = 1, .MaxCounterEntries = 256}, ControlIo.get_executor());
        const auto e = counter.Value(Preview::Statistics::Scope::Account, 99);
        EXPECT_EQ(e.UpBytes, 0);
        EXPECT_EQ(e.DownBytes, 0);
        EXPECT_EQ(counter.Accepted(), 0U);
    }

    TEST(TrafficCounter, NumericAccountAggregationUsesAccountId)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
            .Workers = 1, .MaxCounterEntries = 256}, ControlIo.get_executor());
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{1}, .Up = 3, .Down = 4});
        counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{0},
                        .Account = Preview::AccountId{1}, .Up = 2, .Down = 1});
        counter.Flush();
        const auto e = counter.Value(Preview::Statistics::Scope::Account, 1);
        EXPECT_EQ(e.UpBytes, 5);
        EXPECT_EQ(e.DownBytes, 5);
    }

    TEST(TrafficCounter, SessionPipelineIntegration)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        auto CounterOwner = std::make_shared<Preview::Runtime::TrafficCounter>(
            Preview::Runtime::TrafficCounter::Options{
                .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1},
                .Workers = 1, .MaxCounterEntries = 256}, ioc.get_executor());
        auto& counter = *CounterOwner;
        Preview::Runtime::SessionOptions opts;
        auto Control = std::make_shared<Preview::Runtime::SessionControl>();
        Control->SetIdentity(Preview::Lifecycle::TaskIdentity{
            .TaskId = Preview::TaskId{1}, .SessionId = Preview::SessionId{1},
            .WorkerId = Preview::WorkerId{1}, .Generation = Preview::GenerationId{1}});
        opts.Control = Control;
        auto Authenticator = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Preview::Account::Credential::Password("pw"), "alice", "alice", {}})->Authenticator;
        opts.Services->Traffic = CounterOwner;
        opts.Services->Bytes = std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{.BlockCount = 8U});
        opts.Services->RelayIdleTimeout = std::chrono::milliseconds(50);
        opts.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
            [Authenticator](Preview::Contract::StreamAcceptInput Input)
            {
                return RunSessionAcceptOutcome(std::move(Authenticator), std::move(Input));
            });
        opts.Services->Dial = [outbound_s](const Preview::Network::Target &)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            co_return outbound_s;
        };
        Preview::Runtime::Session Session(opts);

        RunCoro(ioc, RunTrafficSessionIntegration(
            TrafficSessionRequest{ioc, Session, client_s, inbound_s, upstream_s, outbound_s}));

        counter.Flush();
        const auto a = counter.Value(Preview::Statistics::Scope::Session, 1);
        EXPECT_GE(a.UpBytes, socks5_greeting().size()); // 上行：首包
        EXPECT_GE(a.DownBytes, socks5_greeting().size()); // 下行：回显
        EXPECT_GE(counter.Accepted(), 3U);
        EXPECT_EQ(a.Events, 1U);
    }

    TEST(TrafficCounter, ScopedNumericBytesHaveOneControlOwner)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter Counter({
            .Process = Preview::ProcessId{9}, .Generation = Preview::GenerationId{3}, .Workers = 2},
            ControlIo.get_executor());
        Counter.Report({.Generation = Preview::GenerationId{3}, .Worker = Preview::WorkerId{2},
            .Session = Preview::SessionId{23}, .Stream = Preview::StreamId{31},
            .Task = Preview::TaskId{47}, .Account = Preview::AccountId{11}, .Up = 37, .Down = 41});
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 0U);
        Counter.Flush();
        const std::array Owners{
            std::pair{Preview::Statistics::Scope::Process, 9U},
            std::pair{Preview::Statistics::Scope::Worker, 2U},
            std::pair{Preview::Statistics::Scope::Account, 11U},
            std::pair{Preview::Statistics::Scope::Session, 23U},
            std::pair{Preview::Statistics::Scope::Task, 47U}};
        for (const auto &[Scope, Id] : Owners)
        {
            const auto Value = Counter.Value(Scope, Id);
            EXPECT_EQ(Value.UpBytes, 37U);
            EXPECT_EQ(Value.DownBytes, 41U);
            EXPECT_EQ(Value.Events, 1U);
        }
        EXPECT_EQ(Counter.StreamValue(Preview::SessionId{23}, Preview::StreamId{31}).UpBytes, 37U);
        EXPECT_EQ(Counter.StreamValue(Preview::SessionId{23}, Preview::StreamId{31}).Events, 1U);
        const auto Snapshot = Counter.Value(Preview::Statistics::Scope::Account, 11);
        Counter.Report({.Generation = Preview::GenerationId{3}, .Account = Preview::AccountId{11}, .Up = 13});
        Counter.Flush();
        EXPECT_EQ(Snapshot.UpBytes, 37U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 50U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Worker, 1).UpBytes, 0U);
    }

    TEST(TrafficCounter, QueueFullDropsBelongToTheirActualWorker)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter Counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1}, .Workers = 2},
            ControlIo.get_executor());
        for (std::size_t Index = 0; Index < 1025U; ++Index)
            Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
                .Account = Preview::AccountId{11}, .Up = 3, .Down = 5});
        Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{2},
            .Account = Preview::AccountId{12}, .Up = 7, .Down = 11});
        EXPECT_EQ(Counter.Accepted(), 1025U);
        EXPECT_EQ(Counter.Dropped(), 1U);
        EXPECT_EQ(Counter.Dropped(Preview::WorkerId{1}), 1U);
        EXPECT_EQ(Counter.Dropped(Preview::WorkerId{2}), 0U);
        Counter.Flush();
        EXPECT_EQ(Counter.ConsumedObservations(), 1025U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 3072U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 12).DownBytes, 11U);
        Counter.Flush();
        EXPECT_EQ(Counter.ConsumedObservations(), 1025U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).Events, 1024U);
        Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
            .Account = Preview::AccountId{11}, .Up = 13});
        Counter.Flush();
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 3085U);
    }

    TEST(TrafficCounter, SameWireStreamIdInDifferentRootsHasDistinctTraffic)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter Counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1}, .Workers = 1},
            ControlIo.get_executor());
        Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
            .Session = Preview::SessionId{23}, .Stream = Preview::StreamId{1},
            .Account = Preview::AccountId{11}, .Up = 37, .Down = 41});
        Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
            .Session = Preview::SessionId{24}, .Stream = Preview::StreamId{1},
            .Account = Preview::AccountId{11}, .Up = 13, .Down = 17});
        Counter.Flush();
        EXPECT_EQ(Counter.StreamValue(Preview::SessionId{23}, Preview::StreamId{1}).UpBytes, 37U);
        EXPECT_EQ(Counter.StreamValue(Preview::SessionId{24}, Preview::StreamId{1}).DownBytes, 17U);
        EXPECT_EQ(Counter.StreamValue(Preview::SessionId{25}, Preview::StreamId{1}).Events, 0U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 50U);
    }

    TEST(TrafficCounter, SharedWorkerQueueSupportsRealConcurrentProducersWithoutLoss)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter Counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1}, .Workers = 1},
            ControlIo.get_executor());
        std::array<std::thread, 4> Producers;
        for (std::size_t Producer = 0; Producer < Producers.size(); ++Producer)
        {
            Producers[Producer] = std::thread([&Counter, Producer]
            {
                for (std::size_t Index = 0; Index < 200U; ++Index)
                    Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
                        .Account = Preview::AccountId{Producer + 1U}, .Up = 3, .Down = 5});
            });
        }
        for (auto &Producer : Producers) Producer.join();
        EXPECT_EQ(Counter.Accepted(), 800U);
        EXPECT_EQ(Counter.Dropped(), 0U);
        Counter.Finish();
        EXPECT_EQ(Counter.ConsumedObservations(), 800U);
        for (std::uint64_t Account = 1; Account <= 4U; ++Account)
        {
            EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, Account).UpBytes, 600U);
            EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, Account).DownBytes, 1000U);
            EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, Account).Events, 200U);
        }
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Worker, 1).UpBytes, 2400U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Process, 1).DownBytes, 4000U);
    }

    TEST(TrafficCounter, CapacityFailureRejectsWholeEventAndCountsItOnce)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter Counter({.Process = Preview::ProcessId{1},
            .Generation = Preview::GenerationId{1}, .Workers = 1, .MaxCounterEntries = 8},
            ControlIo.get_executor());
        Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
            .Account = Preview::AccountId{11}, .Up = 37, .Down = 41});
        Counter.Flush();
        EXPECT_EQ(Counter.Accepted(), 1U);
        EXPECT_EQ(Counter.ConsumedObservations(), 1U);
        EXPECT_EQ(Counter.Dropped(), 0U);
        EXPECT_EQ(Counter.AggregationFailures(), 1U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Process, 1).UpBytes, 0U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Worker, 1).DownBytes, 0U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).Events, 0U);
        Counter.Flush();
        EXPECT_EQ(Counter.AggregationFailures(), 1U);
        Counter.Report({.Generation = Preview::GenerationId{1}, .Account = Preview::AccountId{11},
            .Up = 13, .Down = 17});
        Counter.Flush();
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 13U);
        EXPECT_EQ(Counter.AggregationFailures(), 1U);
    }

    TEST(TrafficCounter, StaleEpochAndUnassignedWorkerCannotPolluteCounters)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter Counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{3}, .Workers = 1},
            ControlIo.get_executor());
        Counter.Report({.Generation = Preview::GenerationId{2}, .Worker = Preview::WorkerId{1},
            .Account = Preview::AccountId{11}, .Up = 37});
        Counter.Report({.Generation = Preview::GenerationId{3}, .Worker = Preview::WorkerId{2},
            .Account = Preview::AccountId{11}, .Up = 41});
        Counter.Flush();
        EXPECT_EQ(Counter.Accepted(), 0U);
        EXPECT_EQ(Counter.ConsumedObservations(), 0U);
        EXPECT_EQ(Counter.Dropped(), 2U);
        EXPECT_EQ(Counter.Dropped(Preview::WorkerId{1}), 1U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 0U);
    }

    TEST(TrafficCounter, FinishIsFinalExactlyOnceAndLateReportsAreObservableDrops)
    {
        Net::io_context ControlIo;
        Preview::Runtime::TrafficCounter Counter({
            .Process = Preview::ProcessId{1}, .Generation = Preview::GenerationId{1}, .Workers = 1},
            ControlIo.get_executor());
        Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
            .Account = Preview::AccountId{11}, .Up = 37, .Down = 41});
        Counter.Finish();
        Counter.Finish();
        Counter.Report({.Generation = Preview::GenerationId{1}, .Worker = Preview::WorkerId{1},
            .Account = Preview::AccountId{11}, .Up = 13, .Down = 17});
        Counter.Finish();
        EXPECT_TRUE(Counter.IsSealed());
        EXPECT_EQ(Counter.Accepted(), 1U);
        EXPECT_EQ(Counter.ConsumedObservations(), 1U);
        EXPECT_EQ(Counter.Dropped(), 1U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).UpBytes, 37U);
        EXPECT_EQ(Counter.Value(Preview::Statistics::Scope::Account, 11).Events, 1U);
    }

} // namespace
