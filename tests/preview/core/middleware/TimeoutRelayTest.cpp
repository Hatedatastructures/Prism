/**
 * @file TimeoutRelayTest.cpp
 * @brief 管线超时/背压测试（T4-5 / D9）
 * @details 覆盖：
 *          - 空闲超时关闭隧道（可配 + ctx.timeout 优先）
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

    namespace net = boost::asio;
    using namespace Preview;

    auto run_coro(net::io_context &ioc, auto coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(a)),
                std::make_shared<MemoryStream>(std::move(b))};
    }

    TEST(TimeoutRelay, IdleTimeoutClosesTunnel)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        // relay 结束标志
        bool RelayDone = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Preview::Middleware::Context ctx;
                             ctx.Inbound = a2;
                             ctx.Outbound = b1;
                             Preview::Middleware::Builtin::RelayMiddleware relay(nullptr,
                                                                                  std::chrono::milliseconds(50));
                             auto tmp = ctx.Inbound;
                             co_await relay.Handle(tmp, ctx);
                             RelayDone = true;
                         },
                         net::detached);
                     // 50ms 空闲超时必须在兜底关闭前生效（10ms 步进有界轮询，200ms 截止）
                     for (int i = 0; i < 20 && !RelayDone; ++i)
                     {
                         net::steady_timer poll_t(ioc);
                         poll_t.expires_after(std::chrono::milliseconds(10));
                         co_await poll_t.async_wait(net::use_awaitable);
                     }
                     EXPECT_TRUE(RelayDone); // 超时机制失效时此处失败，而非被兜底掩蔽
                     a1->Close();
                 });
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, NoTimeoutWhenActive)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool RelayDone = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Preview::Middleware::Context ctx;
                             ctx.Inbound = a2;
                             ctx.Outbound = b1;
                             Preview::Middleware::Builtin::RelayMiddleware relay(nullptr,
                                                                                  std::chrono::milliseconds(100));
                             auto tmp = ctx.Inbound;
                             co_await relay.Handle(tmp, ctx);
                             RelayDone = true;
                         },
                         net::detached);

                     // 立即首包（relay 启动后马上有活动，避免初始超时窗口）
                     const std::string first = "first";
                     std::error_code wec;
                     co_await a1->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(first.data()),
                                                    first.size()),
                         wec);
                     std::array<std::byte, 64> buf{};
                     std::error_code rec;
                     const auto n0 = co_await b2->async_read_some(std::span<std::byte>(buf), rec);
                     EXPECT_GT(n0, 0);

                     // 持续活动（每 20ms 发一次，共 160ms > 超时 100ms）
                     for (int i = 0; i < 8; ++i)
                     {
                         const std::string msg = "keepalive-" + std::to_string(i);
                         co_await a1->async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()),
                                                        msg.size()),
                             wec);
                         const auto n = co_await b2->async_read_some(std::span<std::byte>(buf), rec);
                         EXPECT_GT(n, 0);
                         net::steady_timer t(ioc);
                         t.expires_after(std::chrono::milliseconds(20));
                         co_await t.async_wait(net::use_awaitable);
                     }
                     EXPECT_FALSE(RelayDone); // 活动期间不关闭
                     a1->Close();
                     b2->Close();
                     // 给 relay 收尾时间
                     net::steady_timer t2(ioc);
                     t2.expires_after(std::chrono::milliseconds(100));
                     co_await t2.async_wait(net::use_awaitable);
                 });
        // 结束后 relay 才关闭
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, ZeroDisablesTimeout)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool RelayDone = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Preview::Middleware::Context ctx;
                             ctx.Inbound = a2;
                             ctx.Outbound = b1;
                             Preview::Middleware::Builtin::RelayMiddleware relay(nullptr,
                                                                                  std::chrono::milliseconds(0));
                             auto tmp = ctx.Inbound;
                             co_await relay.Handle(tmp, ctx);
                             RelayDone = true;
                         },
                         net::detached);
                     // 等 200ms（若超时未禁用，已关闭）
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(200));
                     co_await t.async_wait(net::use_awaitable);
                     EXPECT_FALSE(RelayDone); // 0 = 禁用 → 未关闭
                     a1->Close(); // 显式关闭入站发送方向
                     b2->Close(); // 显式关闭出站发送方向
                     net::steady_timer t2(ioc);
                     t2.expires_after(std::chrono::milliseconds(50));
                     co_await t2.async_wait(net::use_awaitable);
                 });
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, ContextTimeoutTakesPriority)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool RelayDone = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Preview::Middleware::Context ctx;
                             ctx.Inbound = a2;
                             ctx.Outbound = b1;
                             ctx.timeout = std::chrono::milliseconds(40); // ctx 优先（构造为 300s）
                             Preview::Middleware::Builtin::RelayMiddleware relay(
                                 nullptr, std::chrono::seconds(300));
                             auto tmp = ctx.Inbound;
                             co_await relay.Handle(tmp, ctx);
                             RelayDone = true;
                         },
                         net::detached);
                     // ctx.timeout(40ms) 必须先于兜底关闭生效（10ms 步进有界轮询，200ms 截止）
                     for (int i = 0; i < 20 && !RelayDone; ++i)
                     {
                         net::steady_timer poll_t(ioc);
                         poll_t.expires_after(std::chrono::milliseconds(10));
                         co_await poll_t.async_wait(net::use_awaitable);
                     }
                     EXPECT_TRUE(RelayDone); // ctx.timeout 未优先生效时此处失败，而非被兜底掩蔽
                     a1->Close();
                 });
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, WriteFailureTerminatesTunnel)
    {
        net::io_context ioc;
        auto [a1, a2] = make_pair_shared(ioc);
        auto [b1, b2] = make_pair_shared(ioc);

        bool RelayDone = false;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void>
                         {
                             Preview::Middleware::Context ctx;
                             ctx.Inbound = a2;
                             ctx.Outbound = b1;
                             Preview::Middleware::Builtin::RelayMiddleware relay(
                                 nullptr, std::chrono::milliseconds(0));
                             auto tmp = ctx.Inbound;
                             co_await relay.Handle(tmp, ctx);
                             RelayDone = true;
                         },
                         net::detached);

                     // 关闭 Outbound 对端（b2）→ relay 写 b1 失败 → 隧道终止
                     b2->Close();
                     const std::string msg = "to-dead-peer";
                     std::error_code wec;
                     co_await a1->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(msg.data()),
                                                    msg.size()),
                         wec);
                     // 写失败必须在兜底关闭前终止隧道（10ms 步进有界轮询，200ms 截止）
                     for (int i = 0; i < 20 && !RelayDone; ++i)
                     {
                         net::steady_timer poll_t(ioc);
                         poll_t.expires_after(std::chrono::milliseconds(10));
                         co_await poll_t.async_wait(net::use_awaitable);
                     }
                     EXPECT_TRUE(RelayDone); // 写失败未终止时此处失败，而非被兜底掩蔽
                     a1->Close();
                 });
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, WriteFailureReturnsIoError)
    {
        net::io_context ioc;
        auto Inbound = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        auto Outbound = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        Outbound->FailNextWrite = true;
        Preview::Fault::Code Result = Preview::Fault::Code::Success;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::post(ioc, [Inbound]
                               { Inbound->InjectRead({0x01U, 0x02U, 0x03U}); });
                     Preview::Middleware::Context ctx;
                     ctx.Inbound = Inbound;
                     ctx.Outbound = Outbound;
                     Preview::Middleware::Builtin::RelayMiddleware relay(
                         nullptr, std::chrono::milliseconds(0));
                     auto Input = ctx.Inbound;
                     Result = co_await relay.Handle(Input, ctx);
                 });

        EXPECT_EQ(Result, Preview::Fault::Code::IoError);
        EXPECT_TRUE(Inbound->IsClosed());
        EXPECT_TRUE(Outbound->IsClosed());
    }

    TEST(TimeoutRelay, ConcurrentBidirectionalTransfer)
    {
        net::io_context ioc;
        auto [Client, Inbound] = make_pair_shared(ioc);
        auto [Outbound, Server] = make_pair_shared(ioc);
        bool RelayDone = false;
        std::exception_ptr relay_ep;

        auto test = [&]()
            -> net::awaitable<void>
        {
            auto async_relay = [Inbound, Outbound]()
                -> net::awaitable<void>
            {
                Preview::Middleware::Context ctx;
                ctx.Inbound = Inbound;
                ctx.Outbound = Outbound;
                Preview::Middleware::Builtin::RelayMiddleware relay(
                    nullptr, std::chrono::milliseconds(0));
                auto tmp = ctx.Inbound;
                co_await relay.Handle(tmp, ctx);
            };
            auto on_error = [&RelayDone, &relay_ep](const std::exception_ptr &ep)
            {
                relay_ep = ep;
                RelayDone = true;
            };
            net::co_spawn(ioc.get_executor(), std::move(async_relay), std::move(on_error));

            const std::string uplink = "uplink payload with a different length";
            const std::string downlink = "downlink";
            std::error_code write_ec;
            co_await Client->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(uplink.data()),
                                           uplink.size()),
                write_ec);
            co_await Server->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(downlink.data()),
                                           downlink.size()),
                write_ec);
            EXPECT_FALSE(write_ec);

            std::string received_uplink(uplink.size(), '\0');
            std::string received_downlink(downlink.size(), '\0');
            std::error_code ReadEc;
            const auto uplink_n = co_await Server->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(received_uplink.data()),
                                     received_uplink.size()),
                ReadEc);
            EXPECT_FALSE(ReadEc);
            EXPECT_EQ(uplink_n, uplink.size());
            EXPECT_EQ(received_uplink, uplink);

            const auto downlink_n = co_await Client->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(received_downlink.data()),
                                     received_downlink.size()),
                ReadEc);
            EXPECT_FALSE(ReadEc);
            EXPECT_EQ(downlink_n, downlink.size());
            EXPECT_EQ(received_downlink, downlink);

            Client->Close();
            Server->Close();
            net::steady_timer done_wait(ioc);
            done_wait.expires_after(std::chrono::milliseconds(20));
            co_await done_wait.async_wait(net::use_awaitable);
        };

        net::co_spawn(ioc, std::move(test), [&](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              relay_ep = ep;
                          }
                          ioc.stop();
                      });
        ioc.run();
        ASSERT_FALSE(relay_ep);
        EXPECT_TRUE(RelayDone);
    }

    TEST(TimeoutRelay, HalfCloseKeepsReverseDirection)
    {
        net::io_context ioc;
        auto [Client, Inbound] = make_pair_shared(ioc);
        auto [Outbound, Server] = make_pair_shared(ioc);
        bool RelayDone = false;
        std::exception_ptr relay_ep;
        std::exception_ptr direction_ep;

        auto test = [&]()
            -> net::awaitable<void>
        {
            auto async_relay = [Inbound, Outbound, &direction_ep]()
                -> net::awaitable<void>
            {
                Preview::Middleware::Context ctx;
                ctx.Inbound = Inbound;
                ctx.Outbound = Outbound;
                Preview::Middleware::Builtin::RelayMiddleware relay(
                    nullptr, std::chrono::milliseconds(0));
                auto tmp = ctx.Inbound;
                co_await relay.Handle(tmp, ctx);
                direction_ep = relay.LastDirectionError();
            };
            auto on_error = [&RelayDone, &relay_ep](const std::exception_ptr &ep)
            {
                relay_ep = ep;
                RelayDone = true;
            };
            net::co_spawn(ioc.get_executor(), std::move(async_relay), std::move(on_error));

            const std::string Request = "Request before half Close";
            const std::string response = "response after half Close";
            std::error_code ec;
            co_await Client->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.data()),
                                           Request.size()),
                ec);
            Client->Shutdown();

            std::string received_request(Request.size(), '\0');
            const auto request_n = co_await Server->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(received_request.data()),
                                     received_request.size()),
                ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(request_n, Request.size());
            EXPECT_EQ(received_request, Request);

            co_await Server->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(response.data()),
                                           response.size()),
                ec);
            Server->Shutdown();

            std::string received_response(response.size(), '\0');
            const auto response_n = co_await Client->AsyncRead(
                std::span<std::byte>(reinterpret_cast<std::byte *>(received_response.data()),
                                     received_response.size()),
                ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(response_n, response.size());
            EXPECT_EQ(received_response, response);

            std::array<std::byte, 1> eof_buffer{};
            const auto eof_n = co_await Client->async_read_some(eof_buffer, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(eof_n, 0U);

            net::steady_timer done_wait(ioc);
            done_wait.expires_after(std::chrono::milliseconds(20));
            co_await done_wait.async_wait(net::use_awaitable);

            // 正常半关闭路径：两个方向协程均无异常残留
            // （置于收尾等待之后，确保 relay.Handle 已返回并落盘诊断状态）
            EXPECT_FALSE(direction_ep);
        };

        net::co_spawn(ioc, std::move(test), [&](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              relay_ep = ep;
                          }
                          ioc.stop();
                      });
        ioc.run();
        ASSERT_FALSE(relay_ep);
        EXPECT_TRUE(RelayDone);
    }

} // namespace
