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
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>

#include <common/Core/Authenticator.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Runtime/Statistics.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transmission.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace Preview;

    using psm::testing::RunCoro; // 公共样板（见 <common/RuntimeTestHelpers.hpp>）

    /// 回显上游
    auto echo_upstream(SharedTransmission client_side) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        while (true)
        {
            const auto n = co_await client_side->AsyncReadSome(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                break;
            }
            co_await client_side->AsyncWriteSome(std::span<const std::byte>(buf.data(), n), ec);
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
        EXPECT_EQ(a.up, 15);
        EXPECT_EQ(a.down, 27);
        auto b = counter.Total("bob");
        EXPECT_EQ(b.up, 100);
        EXPECT_EQ(b.down, 1);
        EXPECT_EQ(counter.IdentityCount(), 2);

        auto g = counter.GrandTotal();
        EXPECT_EQ(g.up, 115);
        EXPECT_EQ(g.down, 28);
    }

    TEST(TrafficCounter, UnknownIdentityZero)
    {
        Preview::Runtime::TrafficCounter counter;
        auto e = counter.Total("nobody");
        EXPECT_EQ(e.up, 0);
        EXPECT_EQ(e.down, 0);
        EXPECT_EQ(counter.IdentityCount(), 0);
    }

    TEST(TrafficCounter, EmptyIdentityAggregates)
    {
        Preview::Runtime::TrafficCounter counter;
        counter.Report("", 3, 4);
        counter.Report("", 2, 1);
        auto e = counter.Total("");
        EXPECT_EQ(e.up, 5);
        EXPECT_EQ(e.down, 5);
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
            co_return Preview::Fault::Code::success;
        };
        opts.Dial = [outbound_s](const Preview::Network::Target &) -> net::awaitable<
            std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::success, outbound_s};
        };
        Preview::Runtime::Session Session(opts);

        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await Session.Run(inbound_s); },
                         net::detached);
                     net::co_spawn(
                         ioc.get_executor(),
                         [&]() -> net::awaitable<void> { co_await echo_upstream(upstream_s); },
                         net::detached);

                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->AsyncWriteSome(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     std::array<std::byte, 64> buf{};
                     std::error_code sec;
                     const auto n = co_await client_s->AsyncReadSome(std::span<std::byte>(buf), sec);
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), payload);

                     // 空闲超时 → relay 结束 → 上报
                     net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(300));
                     co_await t.async_wait(net::use_awaitable);
                     client_s->Close();
                 });

        auto a = counter.Total("alice");
        EXPECT_GE(a.up, socks5_greeting().size()); // 上行：首包
        EXPECT_GE(a.down, socks5_greeting().size()); // 下行：回显
        EXPECT_EQ(counter.IdentityCount(), 1);
    }

} // namespace
