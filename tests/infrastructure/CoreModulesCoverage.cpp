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

#include <common/core/middleware/context.hpp>
#include <common/core/rate/counter.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transport/pad.hpp>
#include <common/core/transport/preview.hpp>
#include <common/core/transport/snapshot.hpp>

namespace
{
    using namespace psmtest;
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
        const auto v4a = psmtest::rate::address_hash::from_v4(0x7F000001);
        const auto v4b = psmtest::rate::address_hash::from_v4(0x7F000001);
        const auto v4c = psmtest::rate::address_hash::from_v4(0x7F000002);
        EXPECT_EQ(v4a, v4b);
        EXPECT_NE(v4a, v4c);

        const std::array<std::byte, 16> ip6{};
        EXPECT_EQ(psmtest::rate::address_hash::from_v6(ip6),
                  psmtest::rate::address_hash::from_v6(ip6));
    }

    TEST(CoreModules, PadRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        psmtest::transport::pad_config cfg;
        cfg.pad_targets = "64";
        cfg.stop_after = 2;
        auto pad = std::make_shared<psmtest::transport::pad_transport>(
            std::make_shared<memory_stream>(std::move(b)), cfg);
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            EXPECT_TRUE(cfg.enabled());

            auto sink = [&]() -> net::awaitable<void>
            {
                std::array<std::byte, 512> buf{};
                std::error_code ec;
                const auto n = co_await pad->async_read_some(buf, ec);
                EXPECT_GT(n, 0u);
            };
            net::co_spawn(ioc.get_executor(), sink(), net::detached);

            const std::string data = "pad-roundtrip-data";
            std::error_code ec;
            co_await a.async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(data.data()), data.size()), ec);
            EXPECT_FALSE(ec);
        });
    }

    TEST(CoreModules, PadDisabledPassthrough)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        psmtest::transport::pad_config cfg;
        cfg.pad_targets = "";
        auto pad = std::make_shared<psmtest::transport::pad_transport>(
            std::make_shared<memory_stream>(std::move(b)), cfg);
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            EXPECT_FALSE(cfg.enabled());

            auto sink = [&]() -> net::awaitable<void>
            {
                std::array<std::byte, 128> buf{};
                std::error_code ec;
                const auto n = co_await pad->async_read_some(buf, ec);
                EXPECT_EQ(n, 5u);
            };
            net::co_spawn(ioc.get_executor(), sink(), net::detached);

            const std::string data = "hello";
            std::error_code ec;
            co_await a.async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(data.data()), data.size()), ec);
        });
    }

    TEST(CoreModules, PreviewPreread)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            const std::string head = "preread";
            auto preview = std::make_shared<psmtest::transport::preview>(
                std::make_shared<memory_stream>(std::move(b)),
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(head.data()), head.size()));

            std::array<std::byte, 16> buf{};
            std::error_code ec;
            const auto n = co_await preview->async_read_some(buf, ec);
            EXPECT_EQ(n, 7u);
        });
    }

    TEST(CoreModules, SnapshotRead)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto snap = std::make_shared<psmtest::transport::snapshot>(
                std::make_shared<memory_stream>(std::move(b)));
            const std::string data = "snap";
            std::error_code ec;
            co_await a.async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(data.data()), data.size()), ec);

            std::array<std::byte, 16> buf{};
            const auto n = co_await snap->async_read_some(buf, ec);
            EXPECT_EQ(n, 4u);
        });
    }

    TEST(CoreModules, MiddlewareContextBasics)
    {
        psmtest::middleware::context ctx;
        EXPECT_EQ(ctx.detected, 0u);
        EXPECT_EQ(ctx.buffer_size, 16384u);
        ctx.identity = "alice";
        EXPECT_EQ(ctx.identity, "alice");
    }

} // namespace
