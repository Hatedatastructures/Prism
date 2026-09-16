/**
 * @file TimeoutRelayTest.cpp
 * @brief 管线超时/背压测试（T4-5 / D9）
 * @details 覆盖：
 *          - 空闲超时关闭隧道（可配 + Context.timeout 优先）
 *          - 持续活动不关闭
 *          - 0 = 禁用超时
 *          - 背压：写失败（对端关闭）→ 隧道立即终止
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Middleware/Pipeline.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct RelayCompletionState
    {
        explicit RelayCompletionState(Net::any_io_executor Executor)
            : Done(std::make_shared<CompletionChannel>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<CompletionChannel> Done;
        std::exception_ptr Failure;
        std::exception_ptr DirectionFailure;
        Preview::Fault::Code Result{Preview::Fault::Code::Success};
    };

    struct RelayStartRequest
    {
        std::shared_ptr<RelayCompletionState> State;
        Preview::SharedTransmission Inbound;
        Preview::SharedTransmission Outbound;
        std::chrono::milliseconds IdleTimeout{};
        std::chrono::milliseconds ContextTimeout{};
    };

    struct RelayWaitRequest
    {
        std::shared_ptr<RelayCompletionState> State;
        std::vector<Preview::SharedTransmission> CloseTargets;
    };

    auto StartRelay(RelayStartRequest Request) -> void
    {
        const auto Executor = Request.Inbound->Executor();
        const auto State = Request.State;
        auto RelayCoroutine = [Request = std::move(Request)]() mutable -> Net::awaitable<void>
        {
            Preview::Middleware::Context Context;
            Context.Inbound = Request.Inbound;
            Context.Outbound = Request.Outbound;
            Context.timeout = Request.ContextTimeout;
            Preview::Middleware::Builtin::RelayMiddleware Relay(nullptr, Request.IdleTimeout);
            auto Temporary = Context.Inbound;
            Request.State->Result = co_await Relay.Handle(Temporary, Context);
            Request.State->DirectionFailure = Relay.LastDirectionError();
        };
        auto Completion = [State](std::exception_ptr Failure)
        {
            State->Failure = std::move(Failure);
            (void)State->Done->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, std::move(RelayCoroutine), std::move(Completion));
    }

    auto WaitForRelay(RelayWaitRequest Request) -> Net::awaitable<bool>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        auto Completion = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                                    Watchdog.async_wait(Net::use_awaitable));
        if (Completion.index() == 0U)
        {
            co_return true;
        }

        for (const auto &Transport : Request.CloseTargets)
        {
            if (Transport)
            {
                Transport->Cancel();
                Transport->Close();
            }
        }
        Watchdog.expires_after(std::chrono::seconds(1));
        auto Grace = co_await (Request.State->Done->async_receive(Net::use_awaitable) ||
                               Watchdog.async_wait(Net::use_awaitable));
        co_return Grace.index() == 0U;
    }

    auto RunCoroutine(Net::io_context &IoContext, auto CoroutineValue)
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(CoroutineValue), [&](std::exception_ptr e) { Exception = e; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakePairShared(Net::io_context &IoContext)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [Input, Output] = MakeMemoryPair(IoContext.get_executor());
        return {std::make_shared<MemoryStream>(std::move(Input)),
                std::make_shared<MemoryStream>(std::move(Output))};
    }

    TEST(TimeoutRelay, IdleTimeoutClosesTunnel)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);
        auto State = std::make_shared<RelayCompletionState>(IoContext.get_executor());
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     StartRelay({State, RelayInput, RelayOutput,
                                 std::chrono::milliseconds(50), {}});
                     const auto Completed = co_await WaitForRelay(
                         {State, {InputA, OutputPeer, RelayInput, RelayOutput}});
                     EXPECT_TRUE(Completed);
                     EXPECT_FALSE(State->Failure);
                     EXPECT_EQ(State->Result, Preview::Fault::Code::Timeout);
                 });
    }

    TEST(TimeoutRelay, NoTimeoutWhenActive)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        auto State = std::make_shared<RelayCompletionState>(IoContext.get_executor());
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     StartRelay({State, RelayInput, RelayOutput,
                                 std::chrono::milliseconds(100), {}});

                     // 立即首包（Relay 启动后马上有活动，避免初始超时窗口）
                     const std::string FirstMessage = "FirstMessage";
                     std::error_code WriteError;
                     co_await InputA->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(FirstMessage.data()),
                                                    FirstMessage.size()),
                         WriteError);
                     std::array<std::byte, 64> Buffer{};
                     std::error_code ReadError;
                     const auto InitialCount = co_await OutputPeer->async_read_some(std::span<std::byte>(Buffer), ReadError);
                     EXPECT_GT(InitialCount, 0);

                     // 持续活动（每 20ms 发一次，共 160ms > 超时 100ms）
                     for (int Index = 0; Index < 8; ++Index)
                     {
                         const std::string Message = "keepalive-" + std::to_string(Index);
                         co_await InputA->async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(Message.data()),
                                                        Message.size()),
                             WriteError);
                         const auto Count = co_await OutputPeer->async_read_some(std::span<std::byte>(Buffer), ReadError);
                         EXPECT_GT(Count, 0);
                         Net::steady_timer Timer(IoContext);
                         Timer.expires_after(std::chrono::milliseconds(20));
                         co_await Timer.async_wait(Net::use_awaitable);
                     }
                      InputA->Close();
                      OutputPeer->Close();
                      const auto Completed = co_await WaitForRelay(
                          {State, {InputA, OutputPeer, RelayInput, RelayOutput}});
                      EXPECT_TRUE(Completed);
                      EXPECT_FALSE(State->Failure);
                      EXPECT_EQ(State->Result, Preview::Fault::Code::Success);
                  });
    }

    TEST(TimeoutRelay, ZeroDisablesTimeout)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        auto State = std::make_shared<RelayCompletionState>(IoContext.get_executor());
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     StartRelay({State, RelayInput, RelayOutput,
                                 std::chrono::milliseconds(0), {}});
                     // 等 200ms（若超时未禁用，已关闭）
                     Net::steady_timer Timer(IoContext);
                     Timer.expires_after(std::chrono::milliseconds(200));
                     co_await Timer.async_wait(Net::use_awaitable);
                      EXPECT_TRUE(RelayInput->IsOpen());
                      InputA->Close(); // 显式关闭入站发送方向
                      OutputPeer->Close(); // 显式关闭出站发送方向
                      const auto Completed = co_await WaitForRelay(
                          {State, {InputA, OutputPeer, RelayInput, RelayOutput}});
                      EXPECT_TRUE(Completed);
                      EXPECT_FALSE(State->Failure);
                  });
    }

    TEST(TimeoutRelay, ContextTimeoutTakesPriority)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        auto State = std::make_shared<RelayCompletionState>(IoContext.get_executor());
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     StartRelay({State, RelayInput, RelayOutput,
                                 std::chrono::seconds(300),
                                 std::chrono::milliseconds(40)});
                     const auto Completed = co_await WaitForRelay(
                         {State, {InputA, OutputPeer, RelayInput, RelayOutput}});
                     EXPECT_TRUE(Completed);
                     EXPECT_FALSE(State->Failure);
                     EXPECT_EQ(State->Result, Preview::Fault::Code::Timeout);
                  });
    }

    TEST(TimeoutRelay, WriteFailureTerminatesTunnel)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        auto State = std::make_shared<RelayCompletionState>(IoContext.get_executor());
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     StartRelay({State, RelayInput, RelayOutput,
                                 std::chrono::milliseconds(0), {}});

                     // 关闭 Outbound 对端（OutputPeer）→ Relay 写 RelayOutput 失败 → 隧道终止
                     OutputPeer->Close();
                     const std::string Message = "to-dead-peer";
                     std::error_code WriteError;
                     co_await InputA->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Message.data()),
                                                    Message.size()),
                         WriteError);
                      const auto Completed = co_await WaitForRelay(
                          {State, {InputA, OutputPeer, RelayInput, RelayOutput}});
                      EXPECT_TRUE(Completed);
                      EXPECT_FALSE(State->Failure);
                      EXPECT_EQ(State->Result, Preview::Fault::Code::IoError);
                  });
    }

    TEST(TimeoutRelay, WriteFailureReturnsIoError)
    {
        Net::io_context IoContext;
        auto Inbound = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        auto Outbound = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Outbound->FailNextWrite = true;
        Preview::Fault::Code Result = Preview::Fault::Code::Success;

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     Net::post(IoContext, [Inbound]
                               { Inbound->InjectRead({0x01U, 0x02U, 0x03U}); });
                     Preview::Middleware::Context Context;
                     Context.Inbound = Inbound;
                     Context.Outbound = Outbound;
                     Preview::Middleware::Builtin::RelayMiddleware Relay(
                         nullptr, std::chrono::milliseconds(0));
                     auto Input = Context.Inbound;
                     Result = co_await Relay.Handle(Input, Context);
                 });

        EXPECT_EQ(Result, Preview::Fault::Code::IoError);
        EXPECT_TRUE(Inbound->IsClosed());
        EXPECT_TRUE(Outbound->IsClosed());
    }

    TEST(TimeoutRelay, PartialReadWithErrorIsNotCleanHalfClose)
    {
        Net::io_context IoContext;
        auto Inbound = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        auto Outbound = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Inbound->ToRead = {0x01U, 0x02U, 0x03U};
        Inbound->ReadErrorBytes = 3;
        Inbound->SetReadError(std::make_error_code(std::errc::timed_out));
        Outbound->EofOnDrain = true;
        Preview::Fault::Code Result = Preview::Fault::Code::Success;

        RunCoroutine(IoContext,
                     [&]() -> Net::awaitable<void>
                     {
                         Preview::Middleware::Context Context;
                         Context.Inbound = Inbound;
                         Context.Outbound = Outbound;
                         Preview::Middleware::Builtin::RelayMiddleware Relay(
                             nullptr, std::chrono::milliseconds(0));
                         auto Input = Context.Inbound;
                         Result = co_await Relay.Handle(Input, Context);
                     });

        EXPECT_EQ(Result, Preview::Fault::Code::Timeout);
        EXPECT_EQ(Outbound->Written, (std::vector<std::uint8_t>{0x01U, 0x02U, 0x03U}));
        EXPECT_TRUE(Inbound->IsClosed());
        EXPECT_TRUE(Outbound->IsClosed());
    }

    TEST(TimeoutRelay, PartialWriteWithErrorClosesRelay)
    {
        Net::io_context IoContext;
        auto Inbound = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        auto Outbound = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Inbound->ToRead = {0x11U, 0x12U, 0x13U};
        Inbound->EofOnDrain = true;
        Outbound->WriteErrorBytes = 3;
        Outbound->SetWriteError(std::make_error_code(std::errc::timed_out));
        Preview::Fault::Code Result = Preview::Fault::Code::Success;

        RunCoroutine(IoContext,
                     [&]() -> Net::awaitable<void>
                     {
                         Preview::Middleware::Context Context;
                         Context.Inbound = Inbound;
                         Context.Outbound = Outbound;
                         Preview::Middleware::Builtin::RelayMiddleware Relay(
                             nullptr, std::chrono::milliseconds(0));
                         auto Input = Context.Inbound;
                         Result = co_await Relay.Handle(Input, Context);
                     });

        EXPECT_EQ(Result, Preview::Fault::Code::Timeout);
        EXPECT_EQ(Outbound->Written, (std::vector<std::uint8_t>{0x11U, 0x12U, 0x13U}));
        EXPECT_TRUE(Inbound->IsClosed());
        EXPECT_TRUE(Outbound->IsClosed());
    }

    TEST(TimeoutRelay, ConcurrentBidirectionalTransfer)
    {
        Net::io_context IoContext;
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto [Outbound, Server] = MakePairShared(IoContext);
        auto State = std::make_shared<RelayCompletionState>(IoContext.get_executor());

        auto TestCoroutine = [&]()
            -> Net::awaitable<void>
        {
            StartRelay({State, Inbound, Outbound, std::chrono::milliseconds(0), {}});

            const std::string Uplink = "Uplink payload with Input different length";
            const std::string Downlink = "Downlink";
            std::error_code write_ec;
            co_await Client->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Uplink.data()),
                                           Uplink.size()),
                write_ec);
            co_await Server->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Downlink.data()),
                                           Downlink.size()),
                write_ec);
            EXPECT_FALSE(write_ec);

            std::string ReceivedUplink(Uplink.size(), '\0');
            std::string ReceivedDownlink(Downlink.size(), '\0');
            std::error_code ReadEc;
            const auto uplink_n = co_await Server->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(ReceivedUplink.data()),
                                     ReceivedUplink.size()),
                ReadEc);
            EXPECT_FALSE(ReadEc);
            EXPECT_EQ(uplink_n, Uplink.size());
            EXPECT_EQ(ReceivedUplink, Uplink);

            const auto downlink_n = co_await Client->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(ReceivedDownlink.data()),
                                     ReceivedDownlink.size()),
                ReadEc);
            EXPECT_FALSE(ReadEc);
            EXPECT_EQ(downlink_n, Downlink.size());
            EXPECT_EQ(ReceivedDownlink, Downlink);

            Client->Close();
            Server->Close();
            const auto Completed = co_await WaitForRelay(
                {State, {Client, Server, Inbound, Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
        };

        RunCoroutine(IoContext, std::move(TestCoroutine));
    }

    TEST(TimeoutRelay, HalfCloseKeepsReverseDirection)
    {
        Net::io_context IoContext;
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto [Outbound, Server] = MakePairShared(IoContext);
        auto State = std::make_shared<RelayCompletionState>(IoContext.get_executor());

        auto TestCoroutine = [&]()
            -> Net::awaitable<void>
        {
            StartRelay({State, Inbound, Outbound, std::chrono::milliseconds(0), {}});

            const std::string Request = "Request before half Close";
            const std::string response = "response after half Close";
            std::error_code ErrorCode;
            co_await Client->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.data()),
                                           Request.size()),
                ErrorCode);
            Client->Shutdown();

            std::string received_request(Request.size(), '\0');
            const auto RequestCount = co_await Server->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(received_request.data()),
                                     received_request.size()),
                ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(RequestCount, Request.size());
            EXPECT_EQ(received_request, Request);

            co_await Server->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(response.data()),
                                           response.size()),
                ErrorCode);
            Server->Shutdown();

            std::string received_response(response.size(), '\0');
            const auto ResponseCount = co_await Client->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(received_response.data()),
                                     received_response.size()),
                ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(ResponseCount, response.size());
            EXPECT_EQ(received_response, response);

            std::array<std::byte, 1> eof_buffer{};
            const auto eof_n = co_await Client->async_read_some(eof_buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(eof_n, 0U);

            const auto Completed = co_await WaitForRelay(
                {State, {Client, Server, Inbound, Outbound}});
            EXPECT_TRUE(Completed);
            EXPECT_FALSE(State->Failure);
            EXPECT_FALSE(State->DirectionFailure);
        };

        RunCoroutine(IoContext, std::move(TestCoroutine));
    }

} // namespace
