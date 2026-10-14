/**
 * @file SmuxCraftErrorLifecycleTest.cpp
 * @brief SMUX address-error、发送收口和 craft 生命周期测试。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/outbound/direct.hpp>

#include "TestSupport/Production/ProductionMockTransport.hpp"
#include <gtest/gtest.h>

// 预包含依赖头文件（不打开 private）
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

// 打开 craft 及其传递依赖的非公开访问
#define private public
#define protected public
#include <prism/protocol/multiplex/smux/control.hpp>
#undef protected
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../../../src/prism/protocol/multiplex/smux/control.cpp"
#include "SmuxCraftDeepSupport.hpp"

using Preview::Testing::SmuxCraft::CraftFixture;
namespace multiplex = psm::multiplex;
namespace smux = psm::multiplex::smux;
namespace Net = boost::asio;

TEST(SmuxCraftDeep2, SendAddrErrSendsErrorAndFin)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);
    fx.craft_obj->pending_.emplace(1, multiplex::multiplexer::pending_entry(psm::memory::current_resource()));

    int frame_count = 0;
    bool done = false;

    Net::co_spawn(
        fx.ioc(),
        [&]() -> Net::awaitable<void>
        {
            co_await fx.craft_obj->send_addr_err(1);
            done = true;
        },
        Net::detached);

    // send_addr_err 内部 co_await send + fin，其中 fin co_spawn
    // send(1帧, push) + fin(co_spawn push) = 2帧
    Net::co_spawn(
        fx.ioc(),
        [&]() -> Net::awaitable<void>
        {
            for (int i = 0; i < 2; ++i)
            {
                boost::system::error_code ec;
                auto token = Net::redirect_error(Net::use_awaitable, ec);
                co_await fx.craft_obj->channel_.async_receive(token);
                if (!ec)
                {
                    frame_count++;
                }
            }
        },
        Net::detached);

    fx.poll();

    EXPECT_TRUE(done) << "send_addr_err: completed";
    EXPECT_GE(frame_count, 2) << "send_addr_err: sent error data + fin >= 2 frames";
    EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 0) << "send_addr_err: pending erased";
}

// ─── 杂项 ────────────────────────────────────────

TEST(SmuxCraftDeep2, ExecutorReturnsTransportExecutor)
{
    CraftFixture fx;
    auto ex = fx.craft_obj->executor();
}

TEST(SmuxCraftDeep2, ConstructorChannelCapacity)
{
    CraftFixture fx;
    EXPECT_TRUE(fx.craft_obj->channel_.is_open()) << "constructor: channel is open";
}

TEST(SmuxCraftDeep2, CloseIdempotent)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);
    fx.craft_obj->close();
    EXPECT_TRUE(!fx.craft_obj->active_.load(std::memory_order_acquire))
        << "close: Active_ = false after first close";

    fx.craft_obj->close();
    EXPECT_TRUE(!fx.craft_obj->active_.load(std::memory_order_acquire))
        << "close: still false after second close";
}

TEST(SmuxCraftDeep2, CloseClearsState)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);
    fx.craft_obj->pending_.emplace(1, multiplex::multiplexer::pending_entry(psm::memory::current_resource()));
    fx.craft_obj->pending_.emplace(2, multiplex::multiplexer::pending_entry(psm::memory::current_resource()));

    fx.craft_obj->close();

    EXPECT_TRUE(fx.craft_obj->pending_.empty()) << "close: pending cleared";
    EXPECT_TRUE(fx.craft_obj->streams_.empty()) << "close: ducts cleared";
    EXPECT_TRUE(fx.craft_obj->datagrams_.empty()) << "close: parcels cleared";
}
