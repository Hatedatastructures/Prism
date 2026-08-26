/**
 * @file CoreModulesCoverage.cpp
 * @brief core 传输装饰器/中间件/辅助模块覆盖测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Recognition/ProbeDefense.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transport/Pad.hpp>
#include <common/Core/Transport/Preview.hpp>
#include <common/Core/Transport/Snapshot.hpp>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(CoreModules, AddressHashBasic)
    {
        const auto v4a = Preview::Recognition::AddressHash::FromV4(0x7F000001);
        const auto v4b = Preview::Recognition::AddressHash::FromV4(0x7F000001);
        const auto v4c = Preview::Recognition::AddressHash::FromV4(0x7F000002);
        EXPECT_EQ(v4a, v4b);
        EXPECT_NE(v4a, v4c);

        const std::array<std::byte, 16> ip6{};
        EXPECT_EQ(Preview::Recognition::AddressHash::FromV6(ip6),
                  Preview::Recognition::AddressHash::FromV6(ip6));
    }

    TEST(CoreModules, PadRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Preview::Transport::PadConfig cfg;
        cfg.PadTargets = "64";
        cfg.StopAfter = 2;
        auto pad = std::make_shared<Preview::Transport::PadTransport>(
            std::make_shared<MemoryStream>(std::move(b)), cfg);
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            EXPECT_TRUE(cfg.Enabled());

            auto sink = [&]() -> net::awaitable<void>
            {
                std::array<std::byte, 512> buf{};
                std::error_code ec;
                const auto n = co_await pad->async_read_some(buf, ec);
                EXPECT_GT(n, 0u);
            };
            net::co_spawn(ioc.get_executor(), sink(), net::detached);

            const std::string Data = "pad-roundtrip-Data";
            std::error_code ec;
            co_await a.async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size()), ec);
            EXPECT_FALSE(ec);
        });
    }

    TEST(CoreModules, PadDisabledPassthrough)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Preview::Transport::PadConfig cfg;
        cfg.PadTargets = "";
        auto pad = std::make_shared<Preview::Transport::PadTransport>(
            std::make_shared<MemoryStream>(std::move(b)), cfg);
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            EXPECT_FALSE(cfg.Enabled());

            auto sink = [&]() -> net::awaitable<void>
            {
                std::array<std::byte, 128> buf{};
                std::error_code ec;
                const auto n = co_await pad->async_read_some(buf, ec);
                EXPECT_EQ(n, 5u);
            };
            net::co_spawn(ioc.get_executor(), sink(), net::detached);

            const std::string Data = "hello";
            std::error_code ec;
            co_await a.async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size()), ec);
        });
    }

    TEST(CoreModules, PreviewPreread)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            const std::string head = "preread";
            auto PrereadTx = std::make_shared<Preview::Transport::PreviewTransport>(
                std::make_shared<MemoryStream>(std::move(b)),
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(head.data()), head.size()));

            std::array<std::byte, 16> buf{};
            std::error_code ec;
            const auto n = co_await PrereadTx->async_read_some(buf, ec);
            EXPECT_EQ(n, 7u);
        });
    }

    TEST(CoreModules, SnapshotRead)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto snap = std::make_shared<Preview::Transport::Snapshot>(
                std::make_shared<MemoryStream>(std::move(b)));
            const std::string Data = "snap";
            std::error_code ec;
            co_await a.async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size()), ec);

            std::array<std::byte, 16> buf{};
            const auto n = co_await snap->async_read_some(buf, ec);
            EXPECT_EQ(n, 4u);
        });
    }

    TEST(CoreModules, MiddlewareContextBasics)
    {
        Preview::Middleware::Context ctx;
        EXPECT_EQ(ctx.detected, 0u);
        EXPECT_EQ(ctx.BufferSize, 16384u);
        ctx.identity = "alice";
        EXPECT_EQ(ctx.identity, "alice");
    }

} // namespace
