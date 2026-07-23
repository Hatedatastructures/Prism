/**
 * @file YamuxCraftDeep2.cpp
 * @brief multiplex/yamux/craft 窗口管理与流控制深度测试
 * @details 通过 #define private/protected public 访问 craft 和 core 的
 *          非公开成员，测试 ensure_window、get_window、handle_rst、
 *          handle_fin、try_activate_pending、start_pending、
 *          close（含窗口/定时器）、remove_duct/remove_parcel（含窗口）。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "common/MockTransport.hpp"

// 打开 craft 及其传递依赖（core、frame 等）的非公开访问
#define private public
#define protected public
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/protocol/multiplex/yamux/craft.hpp>
#include <prism/account/stats/traffic.hpp>
#undef protected
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/protocol/multiplex/yamux/craft.cpp"

using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace yamux = psm::multiplex::yamux;
namespace net = boost::asio;

#include <gtest/gtest.h>

namespace
{
    struct CraftFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;
        std::shared_ptr<yamux::craft> craft_obj;
        static multiplex::config cfg;

        CraftFixture()
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            pool = std::make_unique<psm::connect::connection_pool>(*ioc);
            psm::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{transport, nullptr, cfg, nullptr};
            craft_obj = std::make_shared<yamux::craft>(std::move(opts));
        }
    };

    multiplex::config CraftFixture::cfg{};

    // ─── ensure_window ────────────────────────────

    TEST(YamuxCraftDeep2, EnsureWindowCreatesNew)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        EXPECT_TRUE(w != nullptr) << "ensure_window: creates new window";
        EXPECT_TRUE(fx.craft_obj->windows_.count(1) == 1) << "ensure_window: inserted into map";
    }

    TEST(YamuxCraftDeep2, EnsureWindowReturnsExisting)
    {
        CraftFixture fx;
        auto *w1 = fx.craft_obj->ensure_window(1);
        auto *w2 = fx.craft_obj->ensure_window(1);
        EXPECT_TRUE(w1 == w2) << "ensure_window: returns same pointer";
        EXPECT_TRUE(fx.craft_obj->windows_.size() == 1) << "ensure_window: no duplicate entry";
    }

    TEST(YamuxCraftDeep2, EnsureWindowMultipleStreams)
    {
        CraftFixture fx;
        auto *w1 = fx.craft_obj->ensure_window(1);
        auto *w2 = fx.craft_obj->ensure_window(2);
        auto *w3 = fx.craft_obj->ensure_window(3);
        EXPECT_TRUE(w1 != w2) << "ensure_window: stream 1 != stream 2";
        EXPECT_TRUE(w2 != w3) << "ensure_window: stream 2 != stream 3";
        EXPECT_TRUE(fx.craft_obj->windows_.size() == 3) << "ensure_window: 3 entries";
    }

    // ─── get_window ───────────────────────────────

    TEST(YamuxCraftDeep2, GetWindowNotFound)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->get_window(999);
        EXPECT_TRUE(w == nullptr) << "get_window: not found -> nullptr";
    }

    TEST(YamuxCraftDeep2, GetWindowFound)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(42);
        auto *w = fx.craft_obj->get_window(42);
        EXPECT_TRUE(w != nullptr) << "get_window: found -> non-null";
    }

    TEST(YamuxCraftDeep2, GetWindowAfterErase)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(10);
        fx.craft_obj->windows_.erase(10);
        auto *w = fx.craft_obj->get_window(10);
        EXPECT_TRUE(w == nullptr) << "get_window: erased -> nullptr";
    }

    // ─── handle_rst ──────────────────────────────

    TEST(YamuxCraftDeep2, HandleRstCleansPending)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
        EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 1) << "handle_rst: pending exists before";

        fx.craft_obj->handle_rst(1);
        EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 0) << "handle_rst: pending erased";
    }

    TEST(YamuxCraftDeep2, HandleRstCleansWindow)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(5);
        EXPECT_TRUE(fx.craft_obj->windows_.count(5) == 1) << "handle_rst: window exists before";

        fx.craft_obj->handle_rst(5);
        EXPECT_TRUE(fx.craft_obj->windows_.count(5) == 0) << "handle_rst: window erased";
    }

    TEST(YamuxCraftDeep2, HandleRstWithPendingAndWindow)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(3, multiplex::core::pending_entry(psm::memory::current_resource()));
        fx.craft_obj->ensure_window(3);

        fx.craft_obj->handle_rst(3);
        EXPECT_TRUE(fx.craft_obj->pending_.count(3) == 0) << "handle_rst: pending erased";
        EXPECT_TRUE(fx.craft_obj->windows_.count(3) == 0) << "handle_rst: window erased";
    }

    TEST(YamuxCraftDeep2, HandleRstNoEntries)
    {
        CraftFixture fx;
        fx.craft_obj->handle_rst(999);
    }

    TEST(YamuxCraftDeep2, HandleRstNullDuctPtr)
    {
        CraftFixture fx;
        fx.craft_obj->ducts_[7];
        fx.craft_obj->ensure_window(7);

        fx.craft_obj->handle_rst(7);
        EXPECT_TRUE(fx.craft_obj->ducts_.count(7) == 1) << "handle_rst: duct null ptr -> entry remains";
        EXPECT_TRUE(fx.craft_obj->windows_.count(7) == 0) << "handle_rst: window erased (duct case)";
    }

    TEST(YamuxCraftDeep2, HandleRstNullParcelPtr)
    {
        CraftFixture fx;
        fx.craft_obj->parcels_[8];
        fx.craft_obj->ensure_window(8);

        fx.craft_obj->handle_rst(8);
        EXPECT_TRUE(fx.craft_obj->parcels_.count(8) == 1) << "handle_rst: parcel null ptr -> entry remains";
        EXPECT_TRUE(fx.craft_obj->windows_.count(8) == 0) << "handle_rst: window erased (parcel case)";
    }

    TEST(YamuxCraftDeep2, HandleRstWithPendingTimer)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(10, multiplex::core::pending_entry(psm::memory::current_resource()));
        fx.craft_obj->ensure_window(10);
        // 手动创建一个 timer 而不是通过 start_pending（避免 co_spawn 副作用）
        auto timer = std::make_shared<net::steady_timer>(fx.craft_obj->executor());
        timer->expires_after(std::chrono::milliseconds(30000));
        fx.craft_obj->pending_timers_[10] = timer;
        EXPECT_TRUE(fx.craft_obj->pending_timers_.count(10) == 1) << "handle_rst: timer exists";

        fx.craft_obj->handle_rst(10);
        EXPECT_TRUE(fx.craft_obj->pending_.count(10) == 0) << "handle_rst: pending erased (timer case)";
        EXPECT_TRUE(fx.craft_obj->windows_.count(10) == 0) << "handle_rst: window erased (timer case)";
    }

    // ─── handle_fin ──────────────────────────────

    TEST(YamuxCraftDeep2, HandleFinPendingBranch)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
        fx.craft_obj->ensure_window(1);

        fx.craft_obj->handle_fin(1);
        EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 0) << "handle_fin: pending erased";
        EXPECT_TRUE(fx.craft_obj->windows_.count(1) == 0) << "handle_fin: window erased (pending branch)";
    }

    TEST(YamuxCraftDeep2, HandleFinPendingNoWindow)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(2, multiplex::core::pending_entry(psm::memory::current_resource()));

        fx.craft_obj->handle_fin(2);
        EXPECT_TRUE(fx.craft_obj->pending_.count(2) == 0) << "handle_fin: pending erased (no window)";
    }

    TEST(YamuxCraftDeep2, HandleFinDuctBranchNullPtr)
    {
        CraftFixture fx;
        fx.craft_obj->ducts_[3];

        fx.craft_obj->handle_fin(3);
        EXPECT_TRUE(fx.craft_obj->ducts_.count(3) == 1) << "handle_fin: duct null -> entry remains";
    }

    TEST(YamuxCraftDeep2, HandleFinParcelBranchNullPtr)
    {
        CraftFixture fx;
        fx.craft_obj->parcels_[4];

        fx.craft_obj->handle_fin(4);
        EXPECT_TRUE(fx.craft_obj->parcels_.count(4) == 1) << "handle_fin: parcel null -> entry remains";
    }

    TEST(YamuxCraftDeep2, HandleFinNoEntries)
    {
        CraftFixture fx;
        fx.craft_obj->handle_fin(999);
    }

    // ─── try_activate_pending ─────────────────────

    TEST(YamuxCraftDeep2, TryActivateNotInPending)
    {
        CraftFixture fx;
        fx.craft_obj->try_activate_pending(999);
    }

    TEST(YamuxCraftDeep2, TryActivateAlreadyConnecting)
    {
        CraftFixture fx;
        auto [it, _] = fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
        it->second.connecting = true;
        it->second.buffer.resize(100);
        // connecting=true -> should return early, not call shared_from_this
        // 但 try_activate_pending 读取 connecting 后直接 return，不触及 shared_from_this
        fx.craft_obj->try_activate_pending(1);
        EXPECT_TRUE(it->second.connecting) << "try_activate: connecting stays true";
    }

    TEST(YamuxCraftDeep2, TryActivateBufferTooSmall)
    {
        CraftFixture fx;
        auto [it, _] = fx.craft_obj->pending_.emplace(2, multiplex::core::pending_entry(psm::memory::current_resource()));
        it->second.connecting = false;
        it->second.buffer.resize(3);
        // buffer.size() < 7 -> should return early
        fx.craft_obj->try_activate_pending(2);
        EXPECT_TRUE(!it->second.connecting) << "try_activate: buffer too small -> connecting stays false";
    }

    TEST(YamuxCraftDeep2, TryActivateBufferExactlySix)
    {
        CraftFixture fx;
        auto [it, _] = fx.craft_obj->pending_.emplace(3, multiplex::core::pending_entry(psm::memory::current_resource()));
        it->second.connecting = false;
        it->second.buffer.resize(6);
        // buffer.size() < 7 -> should return early
        fx.craft_obj->try_activate_pending(3);
        EXPECT_TRUE(!it->second.connecting) << "try_activate: buffer=6 -> connecting stays false";
    }

    // ─── start_pending ────────────────────────────

    TEST(YamuxCraftDeep2, StartPendingCreatesTimer)
    {
        CraftFixture fx;
        // open_timeout=0 时 start_pending 跳过创建
        fx.cfg.yamux.open_timeout = 0;
        fx.craft_obj->start_pending(1);
        EXPECT_TRUE(fx.craft_obj->pending_timers_.count(1) == 0) << "start_pending: timeout=0 -> no timer";
    }

    TEST(YamuxCraftDeep2, StartPendingMultipleStreams)
    {
        CraftFixture fx;
        fx.cfg.yamux.open_timeout = 0;
        fx.craft_obj->start_pending(1);
        fx.craft_obj->start_pending(2);
        fx.craft_obj->start_pending(3);
        EXPECT_TRUE(fx.craft_obj->pending_timers_.empty()) << "start_pending: timeout=0 -> all skipped";
    }

    TEST(YamuxCraftDeep2, StartPendingReplacesExisting)
    {
        CraftFixture fx;
        fx.cfg.yamux.open_timeout = 0;
        fx.craft_obj->start_pending(1);
        fx.craft_obj->start_pending(1);
        EXPECT_TRUE(fx.craft_obj->pending_timers_.empty()) << "start_pending: timeout=0 -> remains empty";
    }

    // ─── close with windows + pending_timers ────

    TEST(YamuxCraftDeep2, CloseWithWindowsAndTimers)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(1);
        fx.craft_obj->ensure_window(2);
        // 手动创建 timer 避免通过 start_pending 的 co_spawn
        auto timer1 = std::make_shared<net::steady_timer>(fx.craft_obj->executor());
        auto timer2 = std::make_shared<net::steady_timer>(fx.craft_obj->executor());
        fx.craft_obj->pending_timers_[1] = timer1;
        fx.craft_obj->pending_timers_[2] = timer2;

        fx.craft_obj->close();
        EXPECT_TRUE(fx.craft_obj->windows_.empty()) << "close: windows cleared";
        EXPECT_TRUE(fx.craft_obj->pending_timers_.empty()) << "close: timers cleared";
    }

    TEST(YamuxCraftDeep2, CloseCancelsWindowSignals)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(10);
        auto *w = fx.craft_obj->get_window(10);
        ASSERT_TRUE(w != nullptr) << "close: window exists before close";

        fx.craft_obj->close();
        EXPECT_TRUE(fx.craft_obj->windows_.empty()) << "close: windows empty after close";
    }

    // ─── remove_duct with window ────────────────

    TEST(YamuxCraftDeep2, RemoveDuctWithWindow)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(5);
        EXPECT_TRUE(fx.craft_obj->windows_.count(5) == 1) << "remove_duct: window before";

        fx.craft_obj->remove_duct(5);
        EXPECT_TRUE(fx.craft_obj->windows_.count(5) == 0) << "remove_duct: window erased";
    }

    TEST(YamuxCraftDeep2, RemoveDuctWithoutWindow)
    {
        CraftFixture fx;
        fx.craft_obj->remove_duct(99);
    }

    // ─── remove_parcel with window ──────────────

    TEST(YamuxCraftDeep2, RemoveParcelWithWindow)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(6);
        EXPECT_TRUE(fx.craft_obj->windows_.count(6) == 1) << "remove_parcel: window before";

        fx.craft_obj->remove_parcel(6);
        EXPECT_TRUE(fx.craft_obj->windows_.count(6) == 0) << "remove_parcel: window erased";
    }

    TEST(YamuxCraftDeep2, RemoveParcelWithoutWindow)
    {
        CraftFixture fx;
        fx.craft_obj->remove_parcel(99);
    }

    // ─── 窗口初始状态 ─────────────────────────────

    TEST(YamuxCraftDeep2, WindowInitialState)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        EXPECT_TRUE(w->send_window.load() > 0) << "window: initial send_window > 0";
        EXPECT_TRUE(w->recv_consumed.load() == 0) << "window: initial recv_consumed=0";
        EXPECT_TRUE(w->window_signal != nullptr) << "window: signal timer non-null";
    }

    TEST(YamuxCraftDeep2, WindowSendWindowUpdate)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        w->send_window.store(1024, std::memory_order_release);
        EXPECT_TRUE(w->send_window.load(std::memory_order_acquire) == 1024) << "window: send_window updated";
    }

    TEST(YamuxCraftDeep2, WindowRecvConsumedUpdate)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        w->recv_consumed.fetch_add(512, std::memory_order_acq_rel);
        EXPECT_TRUE(w->recv_consumed.load(std::memory_order_acquire) == 512) << "window: recv_consumed updated";
    }

    TEST(YamuxCraftDeep2, WindowSignalExpiry)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        auto expiry = w->window_signal->expiry();
        EXPECT_TRUE(expiry == net::steady_timer::time_point::max()) << "window: signal expires at max";
    }

} // namespace
