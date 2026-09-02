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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>

#include <preview/Foundation/Authenticator.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Runtime/Statistics.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace Preview;

    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    using CompletionChannel = net::experimental::channel<void(boost::system::error_code)>;

    auto SpawnAndSignal(net::any_io_executor Executor, net::awaitable<void> Task)
        -> std::shared_ptr<CompletionChannel>
    {
        auto Done = std::make_shared<CompletionChannel>(Executor, 1);
        net::co_spawn(Executor, std::move(Task),
                      [Done](std::exception_ptr Failure)
                      {
                          Done->try_send(Failure ? boost::system::errc::make_error_code(
                                                        boost::system::errc::io_error)
                                                  : boost::system::error_code{});
                      });
        return Done;
    }

    auto SpawnAndSignal(net::any_io_executor Executor,
                        net::awaitable<Preview::Fault::Code> Task)
        -> std::shared_ptr<CompletionChannel>
    {
        auto Done = std::make_shared<CompletionChannel>(Executor, 1);
        net::co_spawn(Executor, std::move(Task),
                      [Done](std::exception_ptr Failure, Preview::Fault::Code)
                      {
                          Done->try_send(Failure ? boost::system::errc::make_error_code(
                                                        boost::system::errc::io_error)
                                                  : boost::system::error_code{});
                      });
        return Done;
    }

    /// 回显上游
    auto echo_upstream(SharedTransmission client_side) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        while (true)
        {
            const auto n = co_await client_side->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                break;
            }
            co_await client_side->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
            if (ec)
            {
                break;
            }
        }
        client_side->Close();
    }

    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(a)),
                std::make_shared<MemoryStream>(std::move(b))};
    }

    TEST(TrafficCounter, AggregateByIdentity)
    {
        Preview::Runtime::TrafficCounter counter;
        counter.Report("alice", 10, 20);
        counter.Report("alice", 5, 7);
        counter.Report("bob", 100, 1);

        auto a = counter.Total("alice");
        EXPECT_EQ(a.Up, 15);
        EXPECT_EQ(a.Down, 27);
        auto b = counter.Total("bob");
        EXPECT_EQ(b.Up, 100);
        EXPECT_EQ(b.Down, 1);
        EXPECT_EQ(counter.IdentityCount(), 2);

        auto g = counter.GrandTotal();
        EXPECT_EQ(g.Up, 115);
        EXPECT_EQ(g.Down, 28);
    }

    TEST(TrafficCounter, UnknownIdentityZero)
    {
        Preview::Runtime::TrafficCounter counter;
        auto e = counter.Total("nobody");
        EXPECT_EQ(e.Up, 0);
        EXPECT_EQ(e.Down, 0);
        EXPECT_EQ(counter.IdentityCount(), 0);
    }

    TEST(TrafficCounter, EmptyIdentityAggregates)
    {
        Preview::Runtime::TrafficCounter counter;
        counter.Report("", 3, 4);
        counter.Report("", 2, 1);
        auto e = counter.Total("");
        EXPECT_EQ(e.Up, 5);
        EXPECT_EQ(e.Down, 5);
        EXPECT_EQ(counter.IdentityCount(), 1);
    }

    TEST(TrafficCounter, SessionPipelineIntegration)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        Preview::Runtime::TrafficCounter counter;
        Preview::Runtime::SessionOptions opts;
        opts.Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "pw");
        opts.traffic = &counter;
        opts.RelayIdleTimeout = std::chrono::milliseconds(50);
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> net::awaitable<Preview::Fault::Code>
        {
            ctx.Target.positive = true;
            ctx.RawIdentity = "alice";
            ctx.RawSecret = "pw";
            co_return Preview::Fault::Code::Success;
        };
        opts.Dial = [outbound_s](const Preview::Network::Target &) -> net::awaitable<
            std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::Success, outbound_s};
        };
        Preview::Runtime::Session Session(opts);

        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto session_done = SpawnAndSignal(ioc.get_executor(), Session.Run(inbound_s));
                     auto echo_done = SpawnAndSignal(ioc.get_executor(), echo_upstream(upstream_s));

                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     std::array<std::byte, 64> buf{};
                     std::error_code sec;
                     const auto n = co_await client_s->async_read_some(std::span<std::byte>(buf), sec);
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), payload);

                     // 空闲超时 → relay 结束 → 上报
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(300));
                     co_await t.async_wait(net::use_awaitable);
                     client_s->Close();
                     inbound_s->Close();
                     upstream_s->Close();
                     outbound_s->Close();
                     boost::system::error_code session_ec;
                     boost::system::error_code echo_ec;
                     co_await session_done->async_receive(
                         net::redirect_error(net::use_awaitable, session_ec));
                     co_await echo_done->async_receive(
                         net::redirect_error(net::use_awaitable, echo_ec));
                     EXPECT_FALSE(session_ec);
                     EXPECT_FALSE(echo_ec);
                 });

        auto a = counter.Total("alice");
        EXPECT_GE(a.Up, socks5_greeting().size()); // 上行：首包
        EXPECT_GE(a.Down, socks5_greeting().size()); // 下行：回显
        EXPECT_EQ(counter.IdentityCount(), 1);
    }

} // namespace
