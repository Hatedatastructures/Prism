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
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>

#include <preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

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

        // Relay 结束标志
        bool RelayDone = false;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     Net::co_spawn(
                         IoContext.get_executor(),
                         [&]() -> Net::awaitable<void>
                         {
                             Preview::Middleware::Context Context;
                             Context.Inbound = RelayInput;
                             Context.Outbound = RelayOutput;
                             Preview::Middleware::Builtin::RelayMiddleware Relay(nullptr,
                                                                                  std::chrono::milliseconds(50));
                             auto Temporary = Context.Inbound;
                             co_await Relay.Handle(Temporary, Context);
                             RelayDone = true;
                         },
                         Net::detached);
                     // 50ms 空闲超时必须在兜底关闭前生效（10ms 步进有界轮询，200ms 截止）
                     for (int Index = 0; Index < 20 && !RelayDone; ++Index)
                     {
                         Net::steady_timer PollTimer(IoContext);
                         PollTimer.expires_after(std::chrono::milliseconds(10));
                         co_await PollTimer.async_wait(Net::use_awaitable);
                     }
                     EXPECT_TRUE(RelayDone); // 超时机制失效时此处失败，而非被兜底掩蔽
                     InputA->Close();
                 });
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, NoTimeoutWhenActive)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        bool RelayDone = false;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     Net::co_spawn(
                         IoContext.get_executor(),
                         [&]() -> Net::awaitable<void>
                         {
                             Preview::Middleware::Context Context;
                             Context.Inbound = RelayInput;
                             Context.Outbound = RelayOutput;
                             Preview::Middleware::Builtin::RelayMiddleware Relay(nullptr,
                                                                                  std::chrono::milliseconds(100));
                             auto Temporary = Context.Inbound;
                             co_await Relay.Handle(Temporary, Context);
                             RelayDone = true;
                         },
                         Net::detached);

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
                     EXPECT_FALSE(RelayDone); // 活动期间不关闭
                     InputA->Close();
                     OutputPeer->Close();
                     // 给 Relay 收尾时间
                     Net::steady_timer EndTimer(IoContext);
                     EndTimer.expires_after(std::chrono::milliseconds(100));
                     co_await EndTimer.async_wait(Net::use_awaitable);
                 });
        // 结束后 Relay 才关闭
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, ZeroDisablesTimeout)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        bool RelayDone = false;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     Net::co_spawn(
                         IoContext.get_executor(),
                         [&]() -> Net::awaitable<void>
                         {
                             Preview::Middleware::Context Context;
                             Context.Inbound = RelayInput;
                             Context.Outbound = RelayOutput;
                             Preview::Middleware::Builtin::RelayMiddleware Relay(nullptr,
                                                                                  std::chrono::milliseconds(0));
                             auto Temporary = Context.Inbound;
                             co_await Relay.Handle(Temporary, Context);
                             RelayDone = true;
                         },
                         Net::detached);
                     // 等 200ms（若超时未禁用，已关闭）
                     Net::steady_timer Timer(IoContext);
                     Timer.expires_after(std::chrono::milliseconds(200));
                     co_await Timer.async_wait(Net::use_awaitable);
                     EXPECT_FALSE(RelayDone); // 0 = 禁用 → 未关闭
                     InputA->Close(); // 显式关闭入站发送方向
                     OutputPeer->Close(); // 显式关闭出站发送方向
                     Net::steady_timer EndTimer(IoContext);
                     EndTimer.expires_after(std::chrono::milliseconds(50));
                     co_await EndTimer.async_wait(Net::use_awaitable);
                 });
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, ContextTimeoutTakesPriority)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        bool RelayDone = false;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     Net::co_spawn(
                         IoContext.get_executor(),
                         [&]() -> Net::awaitable<void>
                         {
                             Preview::Middleware::Context Context;
                             Context.Inbound = RelayInput;
                             Context.Outbound = RelayOutput;
                             Context.timeout = std::chrono::milliseconds(40); // Context 优先（构造为 300s）
                             Preview::Middleware::Builtin::RelayMiddleware Relay(
                                 nullptr, std::chrono::seconds(300));
                             auto Temporary = Context.Inbound;
                             co_await Relay.Handle(Temporary, Context);
                             RelayDone = true;
                         },
                         Net::detached);
                     // Context.timeout(40ms) 必须先于兜底关闭生效（10ms 步进有界轮询，200ms 截止）
                     for (int Index = 0; Index < 20 && !RelayDone; ++Index)
                     {
                         Net::steady_timer PollTimer(IoContext);
                         PollTimer.expires_after(std::chrono::milliseconds(10));
                         co_await PollTimer.async_wait(Net::use_awaitable);
                     }
                     EXPECT_TRUE(RelayDone); // Context.timeout 未优先生效时此处失败，而非被兜底掩蔽
                     InputA->Close();
                 });
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, WriteFailureTerminatesTunnel)
    {
        Net::io_context IoContext;
        auto [InputA, RelayInput] = MakePairShared(IoContext);
        auto [RelayOutput, OutputPeer] = MakePairShared(IoContext);

        bool RelayDone = false;
        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     Net::co_spawn(
                         IoContext.get_executor(),
                         [&]() -> Net::awaitable<void>
                         {
                             Preview::Middleware::Context Context;
                             Context.Inbound = RelayInput;
                             Context.Outbound = RelayOutput;
                             Preview::Middleware::Builtin::RelayMiddleware Relay(
                                 nullptr, std::chrono::milliseconds(0));
                             auto Temporary = Context.Inbound;
                             co_await Relay.Handle(Temporary, Context);
                             RelayDone = true;
                         },
                         Net::detached);

                     // 关闭 Outbound 对端（OutputPeer）→ Relay 写 RelayOutput 失败 → 隧道终止
                     OutputPeer->Close();
                     const std::string Message = "to-dead-peer";
                     std::error_code WriteError;
                     co_await InputA->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Message.data()),
                                                    Message.size()),
                         WriteError);
                     // 写失败必须在兜底关闭前终止隧道（10ms 步进有界轮询，200ms 截止）
                     for (int Index = 0; Index < 20 && !RelayDone; ++Index)
                     {
                         Net::steady_timer PollTimer(IoContext);
                         PollTimer.expires_after(std::chrono::milliseconds(10));
                         co_await PollTimer.async_wait(Net::use_awaitable);
                     }
                     EXPECT_TRUE(RelayDone); // 写失败未终止时此处失败，而非被兜底掩蔽
                     InputA->Close();
                 });
        EXPECT_TRUE(RelayDone);
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

    TEST(TimeoutRelay, ConcurrentBidirectionalTransfer)
    {
        Net::io_context IoContext;
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto [Outbound, Server] = MakePairShared(IoContext);
        bool RelayDone = false;
        std::exception_ptr RelayException;

        auto TestCoroutine = [&]()
            -> Net::awaitable<void>
        {
            auto AsyncRelay = [Inbound, Outbound]()
                -> Net::awaitable<void>
            {
                Preview::Middleware::Context Context;
                Context.Inbound = Inbound;
                Context.Outbound = Outbound;
                Preview::Middleware::Builtin::RelayMiddleware Relay(
                    nullptr, std::chrono::milliseconds(0));
                auto Temporary = Context.Inbound;
                co_await Relay.Handle(Temporary, Context);
            };
            auto OnError = [&RelayDone, &RelayException](const std::exception_ptr &Exception)
            {
                RelayException = Exception;
                RelayDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), std::move(AsyncRelay), std::move(OnError));

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
            Net::steady_timer CompletionTimer(IoContext);
            CompletionTimer.expires_after(std::chrono::milliseconds(20));
            co_await CompletionTimer.async_wait(Net::use_awaitable);
        };

        Net::co_spawn(IoContext, std::move(TestCoroutine), [&](const std::exception_ptr &Exception)
                      {
                          if (Exception)
                          {
                              RelayException = Exception;
                          }
                          IoContext.stop();
                      });
        IoContext.run();
        ASSERT_FALSE(RelayException);
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, HalfCloseKeepsReverseDirection)
    {
        Net::io_context IoContext;
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto [Outbound, Server] = MakePairShared(IoContext);
        bool RelayDone = false;
        std::exception_ptr RelayException;
        std::exception_ptr DirectionException;

        auto TestCoroutine = [&]()
            -> Net::awaitable<void>
        {
            auto AsyncRelay = [Inbound, Outbound, &DirectionException]()
                -> Net::awaitable<void>
            {
                Preview::Middleware::Context Context;
                Context.Inbound = Inbound;
                Context.Outbound = Outbound;
                Preview::Middleware::Builtin::RelayMiddleware Relay(
                    nullptr, std::chrono::milliseconds(0));
                auto Temporary = Context.Inbound;
                co_await Relay.Handle(Temporary, Context);
                DirectionException = Relay.LastDirectionError();
            };
            auto OnError = [&RelayDone, &RelayException](const std::exception_ptr &Exception)
            {
                RelayException = Exception;
                RelayDone = true;
            };
            Net::co_spawn(IoContext.get_executor(), std::move(AsyncRelay), std::move(OnError));

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

            Net::steady_timer CompletionTimer(IoContext);
            CompletionTimer.expires_after(std::chrono::milliseconds(20));
            co_await CompletionTimer.async_wait(Net::use_awaitable);

            // 正常半关闭路径：两个方向协程均无异常残留
            // （置于收尾等待之后，确保 Relay.Handle 已返回并落盘诊断状态）
            EXPECT_FALSE(DirectionException);
        };

        Net::co_spawn(IoContext, std::move(TestCoroutine), [&](const std::exception_ptr &Exception)
                      {
                          if (Exception)
                          {
                              RelayException = Exception;
                          }
                          IoContext.stop();
                      });
        IoContext.run();
        ASSERT_FALSE(RelayException);
        EXPECT_TRUE(RelayDone);
    }

} // namespace
