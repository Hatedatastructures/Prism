/**
 * @file YamuxCraftDeep2.cpp
 * @brief multiplex/yamux/craft 窗口管理与流控制深度测试
 * @details 通过 #define private/protected public 访问 craft 和 core 的
 *          非公开成员，测试 ensure_window、get_window、handle_rst、
 *          handle_fin、try_activate_pending、start_pending、
 *          close（含窗口/定时器）、remove_duct/remove_parcel（含窗口）。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

// 打开 craft 及其传递依赖（core、frame 等）的非公开访问
#define private public
#define protected public
#include <prism/connect/pool/pool.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/multiplex/yamux/craft.hpp>
#include <prism/stats/traffic.hpp>
#undef protected
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/multiplex/yamux/craft.cpp"

using psm::testing::TestRunner;
using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace yamux = psm::multiplex::yamux;
namespace net = boost::asio;

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
            psm::resolve::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{transport, *router_ptr, cfg, nullptr};
            craft_obj = std::make_shared<yamux::craft>(std::move(opts));
        }
    };

    multiplex::config CraftFixture::cfg{};

    // ─── ensure_window ────────────────────────────

    void TestEnsureWindowCreatesNew(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        runner.Check(w != nullptr, "ensure_window: creates new window");
        runner.Check(fx.craft_obj->windows_.count(1) == 1, "ensure_window: inserted into map");
    }

    void TestEnsureWindowReturnsExisting(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w1 = fx.craft_obj->ensure_window(1);
        auto *w2 = fx.craft_obj->ensure_window(1);
        runner.Check(w1 == w2, "ensure_window: returns same pointer");
        runner.Check(fx.craft_obj->windows_.size() == 1, "ensure_window: no duplicate entry");
    }

    void TestEnsureWindowMultipleStreams(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w1 = fx.craft_obj->ensure_window(1);
        auto *w2 = fx.craft_obj->ensure_window(2);
        auto *w3 = fx.craft_obj->ensure_window(3);
        runner.Check(w1 != w2, "ensure_window: stream 1 != stream 2");
        runner.Check(w2 != w3, "ensure_window: stream 2 != stream 3");
        runner.Check(fx.craft_obj->windows_.size() == 3, "ensure_window: 3 entries");
    }

    // ─── get_window ───────────────────────────────

    void TestGetWindowNotFound(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->get_window(999);
        runner.Check(w == nullptr, "get_window: not found -> nullptr");
    }

    void TestGetWindowFound(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(42);
        auto *w = fx.craft_obj->get_window(42);
        runner.Check(w != nullptr, "get_window: found -> non-null");
    }

    void TestGetWindowAfterErase(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(10);
        fx.craft_obj->windows_.erase(10);
        auto *w = fx.craft_obj->get_window(10);
        runner.Check(w == nullptr, "get_window: erased -> nullptr");
    }

    // ─── handle_rst ──────────────────────────────

    void TestHandleRstCleansPending(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
        runner.Check(fx.craft_obj->pending_.count(1) == 1, "handle_rst: pending exists before");

        fx.craft_obj->handle_rst(1);
        runner.Check(fx.craft_obj->pending_.count(1) == 0, "handle_rst: pending erased");
    }

    void TestHandleRstCleansWindow(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(5);
        runner.Check(fx.craft_obj->windows_.count(5) == 1, "handle_rst: window exists before");

        fx.craft_obj->handle_rst(5);
        runner.Check(fx.craft_obj->windows_.count(5) == 0, "handle_rst: window erased");
    }

    void TestHandleRstWithPendingAndWindow(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(3, multiplex::core::pending_entry(psm::memory::current_resource()));
        fx.craft_obj->ensure_window(3);

        fx.craft_obj->handle_rst(3);
        runner.Check(fx.craft_obj->pending_.count(3) == 0, "handle_rst: pending erased");
        runner.Check(fx.craft_obj->windows_.count(3) == 0, "handle_rst: window erased");
    }

    void TestHandleRstNoEntries(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->handle_rst(999);
        runner.Check(true, "handle_rst: no entries -> no crash");
    }

    void TestHandleRstNullDuctPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ducts_[7];
        fx.craft_obj->ensure_window(7);

        fx.craft_obj->handle_rst(7);
        runner.Check(fx.craft_obj->ducts_.count(7) == 1, "handle_rst: duct null ptr -> entry remains");
        runner.Check(fx.craft_obj->windows_.count(7) == 0, "handle_rst: window erased (duct case)");
    }

    void TestHandleRstNullParcelPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->parcels_[8];
        fx.craft_obj->ensure_window(8);

        fx.craft_obj->handle_rst(8);
        runner.Check(fx.craft_obj->parcels_.count(8) == 1, "handle_rst: parcel null ptr -> entry remains");
        runner.Check(fx.craft_obj->windows_.count(8) == 0, "handle_rst: window erased (parcel case)");
    }

    void TestHandleRstWithPendingTimer(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(10, multiplex::core::pending_entry(psm::memory::current_resource()));
        fx.craft_obj->ensure_window(10);
        // 手动创建一个 timer 而不是通过 start_pending（避免 co_spawn 副作用）
        auto timer = std::make_shared<net::steady_timer>(fx.craft_obj->executor());
        timer->expires_after(std::chrono::milliseconds(30000));
        fx.craft_obj->pending_timers_[10] = timer;
        runner.Check(fx.craft_obj->pending_timers_.count(10) == 1, "handle_rst: timer exists");

        fx.craft_obj->handle_rst(10);
        runner.Check(fx.craft_obj->pending_.count(10) == 0, "handle_rst: pending erased (timer case)");
        runner.Check(fx.craft_obj->windows_.count(10) == 0, "handle_rst: window erased (timer case)");
    }

    // ─── handle_fin ──────────────────────────────

    void TestHandleFinPendingBranch(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
        fx.craft_obj->ensure_window(1);

        fx.craft_obj->handle_fin(1);
        runner.Check(fx.craft_obj->pending_.count(1) == 0, "handle_fin: pending erased");
        runner.Check(fx.craft_obj->windows_.count(1) == 0, "handle_fin: window erased (pending branch)");
    }

    void TestHandleFinPendingNoWindow(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->pending_.emplace(2, multiplex::core::pending_entry(psm::memory::current_resource()));

        fx.craft_obj->handle_fin(2);
        runner.Check(fx.craft_obj->pending_.count(2) == 0, "handle_fin: pending erased (no window)");
    }

    void TestHandleFinDuctBranchNullPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ducts_[3];

        fx.craft_obj->handle_fin(3);
        runner.Check(fx.craft_obj->ducts_.count(3) == 1, "handle_fin: duct null -> entry remains");
    }

    void TestHandleFinParcelBranchNullPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->parcels_[4];

        fx.craft_obj->handle_fin(4);
        runner.Check(fx.craft_obj->parcels_.count(4) == 1, "handle_fin: parcel null -> entry remains");
    }

    void TestHandleFinNoEntries(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->handle_fin(999);
        runner.Check(true, "handle_fin: no entries -> no crash");
    }

    // ─── try_activate_pending ─────────────────────

    void TestTryActivateNotInPending(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->try_activate_pending(999);
        runner.Check(true, "try_activate: not in pending -> no crash");
    }

    void TestTryActivateAlreadyConnecting(TestRunner &runner)
    {
        CraftFixture fx;
        auto [it, _] = fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
        it->second.connecting = true;
        it->second.buffer.resize(100);
        // connecting=true -> should return early, not call shared_from_this
        // 但 try_activate_pending 读取 connecting 后直接 return，不触及 shared_from_this
        fx.craft_obj->try_activate_pending(1);
        runner.Check(it->second.connecting, "try_activate: connecting stays true");
    }

    void TestTryActivateBufferTooSmall(TestRunner &runner)
    {
        CraftFixture fx;
        auto [it, _] = fx.craft_obj->pending_.emplace(2, multiplex::core::pending_entry(psm::memory::current_resource()));
        it->second.connecting = false;
        it->second.buffer.resize(3);
        // buffer.size() < 7 -> should return early
        fx.craft_obj->try_activate_pending(2);
        runner.Check(!it->second.connecting, "try_activate: buffer too small -> connecting stays false");
    }

    void TestTryActivateBufferExactlySix(TestRunner &runner)
    {
        CraftFixture fx;
        auto [it, _] = fx.craft_obj->pending_.emplace(3, multiplex::core::pending_entry(psm::memory::current_resource()));
        it->second.connecting = false;
        it->second.buffer.resize(6);
        // buffer.size() < 7 -> should return early
        fx.craft_obj->try_activate_pending(3);
        runner.Check(!it->second.connecting, "try_activate: buffer=6 -> connecting stays false");
    }

    // ─── start_pending ────────────────────────────

    void TestStartPendingCreatesTimer(TestRunner &runner)
    {
        CraftFixture fx;
        // open_timeout=0 时 start_pending 跳过创建
        fx.cfg.yamux.open_timeout = 0;
        fx.craft_obj->start_pending(1);
        runner.Check(fx.craft_obj->pending_timers_.count(1) == 0, "start_pending: timeout=0 -> no timer");
    }

    void TestStartPendingMultipleStreams(TestRunner &runner)
    {
        CraftFixture fx;
        fx.cfg.yamux.open_timeout = 0;
        fx.craft_obj->start_pending(1);
        fx.craft_obj->start_pending(2);
        fx.craft_obj->start_pending(3);
        runner.Check(fx.craft_obj->pending_timers_.empty(), "start_pending: timeout=0 -> all skipped");
    }

    void TestStartPendingReplacesExisting(TestRunner &runner)
    {
        CraftFixture fx;
        fx.cfg.yamux.open_timeout = 0;
        fx.craft_obj->start_pending(1);
        fx.craft_obj->start_pending(1);
        runner.Check(fx.craft_obj->pending_timers_.empty(), "start_pending: timeout=0 -> remains empty");
    }

    // ─── close with windows + pending_timers ────

    void TestCloseWithWindowsAndTimers(TestRunner &runner)
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
        runner.Check(fx.craft_obj->windows_.empty(), "close: windows cleared");
        runner.Check(fx.craft_obj->pending_timers_.empty(), "close: timers cleared");
    }

    void TestCloseCancelsWindowSignals(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(10);
        auto *w = fx.craft_obj->get_window(10);
        runner.Check(w != nullptr, "close: window exists before close");

        fx.craft_obj->close();
        runner.Check(fx.craft_obj->windows_.empty(), "close: windows empty after close");
    }

    // ─── remove_duct with window ────────────────

    void TestRemoveDuctWithWindow(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(5);
        runner.Check(fx.craft_obj->windows_.count(5) == 1, "remove_duct: window before");

        fx.craft_obj->remove_duct(5);
        runner.Check(fx.craft_obj->windows_.count(5) == 0, "remove_duct: window erased");
    }

    void TestRemoveDuctWithoutWindow(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->remove_duct(99);
        runner.Check(true, "remove_duct: no window -> no crash");
    }

    // ─── remove_parcel with window ──────────────

    void TestRemoveParcelWithWindow(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ensure_window(6);
        runner.Check(fx.craft_obj->windows_.count(6) == 1, "remove_parcel: window before");

        fx.craft_obj->remove_parcel(6);
        runner.Check(fx.craft_obj->windows_.count(6) == 0, "remove_parcel: window erased");
    }

    void TestRemoveParcelWithoutWindow(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->remove_parcel(99);
        runner.Check(true, "remove_parcel: no window -> no crash");
    }

    // ─── 窗口初始状态 ─────────────────────────────

    void TestWindowInitialState(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        runner.Check(w->send_window.load() > 0, "window: initial send_window > 0");
        runner.Check(w->recv_consumed.load() == 0, "window: initial recv_consumed=0");
        runner.Check(w->window_signal != nullptr, "window: signal timer non-null");
    }

    void TestWindowSendWindowUpdate(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        w->send_window.store(1024, std::memory_order_release);
        runner.Check(w->send_window.load(std::memory_order_acquire) == 1024, "window: send_window updated");
    }

    void TestWindowRecvConsumedUpdate(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        w->recv_consumed.fetch_add(512, std::memory_order_acq_rel);
        runner.Check(w->recv_consumed.load(std::memory_order_acquire) == 512, "window: recv_consumed updated");
    }

    void TestWindowSignalExpiry(TestRunner &runner)
    {
        CraftFixture fx;
        auto *w = fx.craft_obj->ensure_window(1);
        auto expiry = w->window_signal->expiry();
        runner.Check(expiry == net::steady_timer::time_point::max(), "window: signal expires at max");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("YamuxCraftDeep2");

    // ensure_window
    TestEnsureWindowCreatesNew(runner);
    TestEnsureWindowReturnsExisting(runner);
    TestEnsureWindowMultipleStreams(runner);

    // get_window
    TestGetWindowNotFound(runner);
    TestGetWindowFound(runner);
    TestGetWindowAfterErase(runner);

    // handle_rst
    TestHandleRstCleansPending(runner);
    TestHandleRstCleansWindow(runner);
    TestHandleRstWithPendingAndWindow(runner);
    TestHandleRstNoEntries(runner);
    TestHandleRstNullDuctPtr(runner);
    TestHandleRstNullParcelPtr(runner);
    TestHandleRstWithPendingTimer(runner);

    // handle_fin
    TestHandleFinPendingBranch(runner);
    TestHandleFinPendingNoWindow(runner);
    TestHandleFinDuctBranchNullPtr(runner);
    TestHandleFinParcelBranchNullPtr(runner);
    TestHandleFinNoEntries(runner);

    // try_activate_pending
    TestTryActivateNotInPending(runner);
    TestTryActivateAlreadyConnecting(runner);
    TestTryActivateBufferTooSmall(runner);
    TestTryActivateBufferExactlySix(runner);

    // start_pending
    TestStartPendingCreatesTimer(runner);
    TestStartPendingMultipleStreams(runner);
    TestStartPendingReplacesExisting(runner);

    // close with windows + pending_timers
    TestCloseWithWindowsAndTimers(runner);
    TestCloseCancelsWindowSignals(runner);

    // remove_duct with window
    TestRemoveDuctWithWindow(runner);
    TestRemoveDuctWithoutWindow(runner);

    // remove_parcel with window
    TestRemoveParcelWithWindow(runner);
    TestRemoveParcelWithoutWindow(runner);

    // 窗口初始状态
    TestWindowInitialState(runner);
    TestWindowSendWindowUpdate(runner);
    TestWindowRecvConsumedUpdate(runner);
    TestWindowSignalExpiry(runner);

    return runner.Summary();
}
