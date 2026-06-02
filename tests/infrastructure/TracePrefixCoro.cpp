/**
 * @file TracePrefixCoro.cpp
 * @brief trace::scope_guard / active_prefix 多协程竞争综合测试
 * @details 覆盖以下场景：
 *
 * 1. 裸 scope_guard 同层交错污染（基线）
 * 2. protected_step 修复方案验证
 * 3. co_spawn 独立协程残留 active_prefix
 * 4. 调用者 co_return 提前结束，子协程仍持有悬垂 active_prefix
 * 5. 多层嵌套 co_spawn（模拟 AnyTLS 模式）
 * 6. mux 多流并发 dispatch 模式
 * 7. racer 竞速模式
 * 8. scope_guard 析构后 active_prefix 恢复
 * 9. 高压力综合场景
 */

#include <prism/trace/context.hpp>
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio.hpp>

namespace net = boost::asio;

namespace
{

    // ============================================================
    // 日志收集器
    // ============================================================

    struct log_entry
    {
        std::uint64_t expected_sid;
        std::uint64_t actual_sid;
        int step;
        const char *scenario;
    };

    std::vector<log_entry> g_log;
    std::mutex g_log_mutex;

    void record_log(std::uint64_t expected, std::uint64_t actual,
                    int step, const char *scenario = "default")
    {
        std::lock_guard lock(g_log_mutex);
        g_log.push_back({expected, actual, step, scenario});
    }

    void clear_log() { g_log.clear(); }

    auto count_corruptions_for(const char *scenario) -> int
    {
        int n = 0;
        for (const auto &e : g_log)
            if (e.expected_sid != e.actual_sid && std::strcmp(e.scenario, scenario) == 0)
                ++n;
        return n;
    }

    // ============================================================
    // 场景 1: 裸 scope_guard 同层交错（基线）
    // ============================================================

    auto bugged_session_coro(psm::trace::session_prefix &pfx, int yield_count)
        -> net::awaitable<void>
    {
        psm::trace::scope_guard guard(pfx);
        for (int i = 0; i < yield_count; ++i)
        {
            auto *cur = psm::trace::active_prefix;
            record_log(pfx.session_id, cur ? cur->session_id : 0, i * 2, "bugged");

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);

            cur = psm::trace::active_prefix;
            record_log(pfx.session_id, cur ? cur->session_id : 0, i * 2 + 1, "bugged");
        }
    }

    // ============================================================
    // 场景 2: protected_step 修复
    // ============================================================

    auto protected_step(psm::trace::session_prefix &pfx)
        -> net::awaitable<void>
    {
        psm::trace::active_prefix = &pfx;
        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(std::chrono::milliseconds(1));
        co_await timer.async_wait(net::use_awaitable);
        psm::trace::active_prefix = &pfx;
    }

    auto fixed_session_coro(psm::trace::session_prefix &pfx, int yield_count)
        -> net::awaitable<void>
    {
        psm::trace::scope_guard guard(pfx);
        for (int i = 0; i < yield_count; ++i)
        {
            auto *cur = psm::trace::active_prefix;
            record_log(pfx.session_id, cur ? cur->session_id : 0, i * 2, "fixed");

            co_await protected_step(pfx);

            cur = psm::trace::active_prefix;
            record_log(pfx.session_id, cur ? cur->session_id : 0, i * 2 + 1, "fixed");
        }
    }

    // ============================================================
    // 场景 3: co_spawn 独立协程残留 active_prefix
    //   模拟 duct/parcel/anytls 模式
    // ============================================================

    auto orphan_coro(int checks, std::shared_ptr<std::atomic<int>> done_counter)
        -> net::awaitable<void>
    {
        for (int i = 0; i < checks; ++i)
        {
            auto *cur = psm::trace::active_prefix;
            record_log(0, cur ? cur->session_id : 0, i, "orphan");

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
        }
        done_counter->fetch_add(1);
    }

    auto parent_coro(psm::trace::session_prefix &pfx, int child_count,
                     std::shared_ptr<std::atomic<int>> done_counter)
        -> net::awaitable<void>
    {
        psm::trace::scope_guard guard(pfx);
        auto ex = co_await net::this_coro::executor;

        for (int i = 0; i < child_count; ++i)
            net::co_spawn(ex, orphan_coro(3, done_counter), net::detached);

        for (int i = 0; i < 3; ++i)
        {
            record_log(pfx.session_id,
                       psm::trace::active_prefix ? psm::trace::active_prefix->session_id : 0,
                       i, "parent");

            net::steady_timer timer(ex);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
        }
    }

    // ============================================================
    // 场景 4: 调用者 co_return 提前结束，子协程仍持有 active_prefix
    //   模拟 trojan/vless mux 模式
    // ============================================================

    auto mux_start_and_return(psm::trace::session_prefix &mux_pfx,
                              std::shared_ptr<std::atomic<int>> mux_checks)
        -> net::awaitable<void>
    {
        // 按指针捕获 mux_pfx，因为调用者可能在 detached 协程运行期间析构
        auto *pfx_ptr = &mux_pfx;
        auto run_wrapper = [pfx_ptr, mux_checks]() -> net::awaitable<void>
        {
            psm::trace::scope_guard guard(*pfx_ptr);
            for (int i = 0; i < 4; ++i)
            {
                mux_checks->fetch_add(1);
                record_log(pfx_ptr->session_id,
                           psm::trace::active_prefix ? psm::trace::active_prefix->session_id : 0,
                           i, "mux_run");

                net::steady_timer timer(co_await net::this_coro::executor);
                timer.expires_after(std::chrono::milliseconds(2));
                co_await timer.async_wait(net::use_awaitable);
            }
        };

        auto ex = co_await net::this_coro::executor;
        net::co_spawn(ex, run_wrapper(), net::detached);
    }

    auto session_then_mux(psm::trace::session_prefix &session_pfx,
                          psm::trace::session_prefix &mux_pfx,
                          std::shared_ptr<std::atomic<int>> mux_checks)
        -> net::awaitable<void>
    {
        // session_pfx 和 mux_pfx 的生命周期由测试函数的 vector 保证
        psm::trace::scope_guard session_guard(session_pfx);
        record_log(session_pfx.session_id,
                   psm::trace::active_prefix ? psm::trace::active_prefix->session_id : 0,
                   0, "session_pre_mux");

        co_await mux_start_and_return(mux_pfx, mux_checks);
    }

    // ============================================================
    // 场景 5: 多层嵌套 co_spawn（模拟 AnyTLS 模式）
    // ============================================================

    auto innermost_coro(std::uint64_t caller_sid, int checks,
                        std::shared_ptr<std::atomic<int>> done)
        -> net::awaitable<void>
    {
        for (int i = 0; i < checks; ++i)
        {
            auto *cur = psm::trace::active_prefix;
            record_log(caller_sid, cur ? cur->session_id : 0, i, "innermost");

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
        }
        done->fetch_add(1);
    }

    auto middle_coro(psm::trace::session_prefix &pfx,
                     std::shared_ptr<std::atomic<int>> done)
        -> net::awaitable<void>
    {
        psm::trace::scope_guard guard(pfx);

        auto ex = co_await net::this_coro::executor;
        net::co_spawn(ex, innermost_coro(pfx.session_id, 3, done), net::detached);

        for (int i = 0; i < 3; ++i)
        {
            record_log(pfx.session_id,
                       psm::trace::active_prefix ? psm::trace::active_prefix->session_id : 0,
                       i, "middle");

            net::steady_timer timer(ex);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
        }
    }

    auto outer_handshake(psm::trace::session_prefix &outer_pfx,
                         psm::trace::session_prefix &middle_pfx,
                         std::shared_ptr<std::atomic<int>> done)
        -> net::awaitable<void>
    {
        psm::trace::scope_guard guard(outer_pfx);
        co_await middle_coro(middle_pfx, done);
    }

    // ============================================================
    // 场景 6: mux 多流 dispatch（yamux 模式）
    // ============================================================

    auto dispatch_coro(psm::trace::session_prefix &stream_pfx,
                       std::uint64_t stream_id,
                       std::shared_ptr<std::atomic<int>> done)
        -> net::awaitable<void>
    {
        psm::trace::active_prefix = nullptr;
        psm::trace::scope_guard guard(stream_pfx);

        record_log(stream_id,
                   psm::trace::active_prefix ? psm::trace::active_prefix->session_id : 0,
                   0, "dispatch");

        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(std::chrono::milliseconds(1));
        co_await timer.async_wait(net::use_awaitable);

        record_log(stream_id,
                   psm::trace::active_prefix ? psm::trace::active_prefix->session_id : 0,
                   1, "dispatch");

        done->fetch_add(1);
    }

    auto frame_loop_coro(psm::trace::session_prefix &mux_pfx,
                         std::vector<psm::trace::session_prefix> &stream_pfxs,
                         std::shared_ptr<std::atomic<int>> done)
        -> net::awaitable<void>
    {
        psm::trace::scope_guard guard(mux_pfx);
        auto ex = co_await net::this_coro::executor;

        for (size_t i = 0; i < stream_pfxs.size(); ++i)
        {
            net::co_spawn(ex,
                dispatch_coro(stream_pfxs[i], stream_pfxs[i].session_id, done),
                net::detached);

            net::steady_timer timer(ex);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
        }
    }

    // ============================================================
    // 场景 7: racer 竞速模式
    // ============================================================

    auto race_endpoint(std::uint64_t endpoint_id,
                       std::shared_ptr<std::atomic<bool>> winner,
                       std::shared_ptr<std::atomic<int>> done)
        -> net::awaitable<void>
    {
        psm::trace::active_prefix = nullptr;

        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(std::chrono::milliseconds(1 + static_cast<int>(endpoint_id)));
        co_await timer.async_wait(net::use_awaitable);

        auto *cur = psm::trace::active_prefix;
        record_log(0, cur ? cur->session_id : 0,
                   static_cast<int>(endpoint_id),
                   winner->exchange(true) ? "racer_loser" : "racer_winner");

        done->fetch_add(1);
    }

    auto racer_main(psm::trace::session_prefix &session_pfx, int endpoint_count,
                    std::shared_ptr<std::atomic<bool>> winner,
                    std::shared_ptr<std::atomic<int>> done)
        -> net::awaitable<void>
    {
        psm::trace::scope_guard guard(session_pfx);
        auto ex = co_await net::this_coro::executor;

        for (int i = 0; i < endpoint_count; ++i)
            net::co_spawn(ex, race_endpoint(i, winner, done), net::detached);

        // 等待所有竞速完成
        auto pending = std::make_shared<std::atomic<int>>(endpoint_count);
        for (int attempt = 0; attempt < endpoint_count * 3; ++attempt)
        {
            if (done->load() >= endpoint_count)
                break;
            net::steady_timer timer(ex);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
        }
    }

    // ============================================================
    // 场景 8: scope_guard 析构后 active_prefix 恢复
    // ============================================================

    auto short_lived_session_coro(std::shared_ptr<std::atomic<int>> phase)
        -> net::awaitable<void>
    {
        auto short_pfx = std::make_unique<psm::trace::session_prefix>();
        short_pfx->session_id = 999;
        {
            psm::trace::scope_guard guard(*short_pfx);
            record_log(999,
                       psm::trace::active_prefix ? psm::trace::active_prefix->session_id : 0,
                       0, "short_lived");
        }
        phase->store(1);

        net::steady_timer timer(co_await net::this_coro::executor);
        timer.expires_after(std::chrono::milliseconds(1));
        co_await timer.async_wait(net::use_awaitable);
    }

    auto observer_coro(std::shared_ptr<std::atomic<int>> phase)
        -> net::awaitable<void>
    {
        for (int i = 0; i < 50; ++i)
        {
            if (phase->load() >= 1)
                break;
            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
        }

        auto *cur = psm::trace::active_prefix;
        record_log(0, cur ? cur->session_id : 0, 0, "observer");
    }

    // ============================================================
    // 常量
    // ============================================================

    constexpr int coro_count = 8;
    constexpr int yields = 4;

} // namespace

// ============================================================
// 测试 1: 裸 scope_guard — 基线
// ============================================================

TEST(ScopedPrefix, BuggedScopeGuard_ShowsCorruption)
{
    clear_log();
    net::io_context ioc;

    std::array<psm::trace::session_prefix, coro_count> pfx{};
    for (int i = 0; i < coro_count; ++i)
        pfx[i].session_id = 100 + i;

    for (int i = 0; i < coro_count; ++i)
        net::co_spawn(ioc, bugged_session_coro(pfx[i], yields), net::detached);

    ioc.run();
    const auto bad = count_corruptions_for("bugged");

    EXPECT_GT(bad, 0) << "裸 scope_guard 在 " << coro_count
                      << " 协程交错时未产生前缀污染";
    std::printf("[Bugged] 总日志: %zu, 污染: %d\n", g_log.size(), bad);
}

// ============================================================
// 测试 2: protected_step 修复
// ============================================================

TEST(ScopedPrefix, ProtectedStep_NoCorruption)
{
    clear_log();
    net::io_context ioc;

    std::array<psm::trace::session_prefix, coro_count> pfx{};
    for (int i = 0; i < coro_count; ++i)
        pfx[i].session_id = 200 + i;

    for (int i = 0; i < coro_count; ++i)
        net::co_spawn(ioc, fixed_session_coro(pfx[i], yields), net::detached);

    ioc.run();
    const auto bad = count_corruptions_for("fixed");

    EXPECT_EQ(bad, 0) << "protected_step 仍有 " << bad << " 次污染";
    std::printf("[Fixed] 总日志: %zu, 污染: %d\n", g_log.size(), bad);
}

// ============================================================
// 测试 3: co_spawn 残留
// ============================================================

TEST(ScopedPrefix, CoSpawnOrphan_ResidualPrefix)
{
    clear_log();
    net::io_context ioc;

    constexpr int parents = 4;
    constexpr int children_per_parent = 3;
    constexpr int total_children = parents * children_per_parent;
    auto done = std::make_shared<std::atomic<int>>(0);

    std::array<psm::trace::session_prefix, parents> pfx{};
    for (int i = 0; i < parents; ++i)
        pfx[i].session_id = 300 + i;

    for (int i = 0; i < parents; ++i)
        net::co_spawn(ioc, parent_coro(pfx[i], children_per_parent, done), net::detached);

    ioc.run();

    const auto residual = count_corruptions_for("orphan");
    std::printf("[Orphan] 总日志: %zu, 残留非零: %d, done=%d/%d\n",
                g_log.size(), residual, done->load(), total_children);

    EXPECT_EQ(done->load(), total_children);
}

// ============================================================
// 测试 4: session co_return 后 mux 仍运行
// ============================================================

TEST(ScopedPrefix, SessionReturn_MuxStillRunning)
{
    clear_log();
    net::io_context ioc;

    constexpr int sessions = 4;
    std::vector<psm::trace::session_prefix> session_pfx(sessions);
    std::vector<psm::trace::session_prefix> mux_pfx(sessions);
    std::vector<std::shared_ptr<std::atomic<int>>> mux_checks(sessions);

    for (int i = 0; i < sessions; ++i)
    {
        session_pfx[i].session_id = 400 + i;
        mux_pfx[i].session_id = 500 + i;
        mux_checks[i] = std::make_shared<std::atomic<int>>(0);
    }

    for (int i = 0; i < sessions; ++i)
    {
        net::co_spawn(ioc,
            session_then_mux(session_pfx[i], mux_pfx[i], mux_checks[i]),
            net::detached);
    }

    ioc.run();

    int total_mux_checks = 0;
    for (int i = 0; i < sessions; ++i)
        total_mux_checks += mux_checks[i]->load();

    const auto mux_bad = count_corruptions_for("mux_run");
    std::printf("[Session+Mux] mux污染=%d, mux_checks=%d\n", mux_bad, total_mux_checks);
}

// ============================================================
// 测试 5: 多层嵌套 co_spawn (AnyTLS 模式)
// ============================================================

TEST(ScopedPrefix, NestedCoSpawn_AnyTlsMode)
{
    clear_log();
    net::io_context ioc;

    constexpr int depth = 4;
    std::vector<psm::trace::session_prefix> outer_pfx(depth);
    std::vector<psm::trace::session_prefix> middle_pfx(depth);
    auto done = std::make_shared<std::atomic<int>>(0);

    for (int i = 0; i < depth; ++i)
    {
        outer_pfx[i].session_id = 600 + i;
        middle_pfx[i].session_id = 700 + i;
    }

    for (int i = 0; i < depth; ++i)
    {
        net::co_spawn(ioc,
            outer_handshake(outer_pfx[i], middle_pfx[i], done),
            net::detached);
    }

    ioc.run();

    const auto middle_bad = count_corruptions_for("middle");
    const auto inner_bad = count_corruptions_for("innermost");

    std::printf("[Nested] middle污染=%d, innermost污染=%d, done=%d/%d\n",
                middle_bad, inner_bad, done->load(), depth);
}

// ============================================================
// 测试 6: mux 多流 dispatch
// ============================================================

TEST(ScopedPrefix, MuxDispatch_YamuxMode)
{
    clear_log();
    net::io_context ioc;

    constexpr int streams = 8;
    psm::trace::session_prefix mux_pfx{};
    mux_pfx.session_id = 800;
    std::vector<psm::trace::session_prefix> stream_pfx(streams);
    auto done = std::make_shared<std::atomic<int>>(0);

    for (int i = 0; i < streams; ++i)
        stream_pfx[i].session_id = 810 + i;

    net::co_spawn(ioc,
        frame_loop_coro(mux_pfx, stream_pfx, done),
        net::detached);

    ioc.run();

    const auto bad = count_corruptions_for("dispatch");
    std::printf("[Dispatch] 总日志: %zu, dispatch污染=%d, done=%d/%d\n",
                g_log.size(), bad, done->load(), streams);

    EXPECT_EQ(bad, 0) << "dispatch 模式出现 " << bad << " 次污染";
    EXPECT_EQ(done->load(), streams);
}

// ============================================================
// 测试 7: racer 竞速模式
// ============================================================

TEST(ScopedPrefix, RacerMode)
{
    clear_log();
    net::io_context ioc;

    constexpr int endpoints = 6;
    psm::trace::session_prefix session_pfx{};
    session_pfx.session_id = 900;

    auto winner = std::make_shared<std::atomic<bool>>(false);
    auto done = std::make_shared<std::atomic<int>>(0);

    net::co_spawn(ioc,
        racer_main(session_pfx, endpoints, winner, done),
        net::detached);

    ioc.run();

    const auto racer_bad = count_corruptions_for("racer_winner") +
                           count_corruptions_for("racer_loser");
    std::printf("[Racer] done=%d/%d, racer污染=%d\n",
                done->load(), endpoints, racer_bad);

    EXPECT_EQ(racer_bad, 0) << "racer 模式出现 " << racer_bad << " 次残留";
    EXPECT_EQ(done->load(), endpoints);
}

// ============================================================
// 测试 8: scope_guard 析构后恢复
// ============================================================

TEST(ScopedPrefix, ScopeGuardDestruct_RestoresPrefix)
{
    clear_log();
    net::io_context ioc;

    auto phase = std::make_shared<std::atomic<int>>(0);
    psm::trace::session_prefix global_pfx{};
    global_pfx.session_id = 9999;

    {
        psm::trace::scope_guard global_guard(global_pfx);

        net::co_spawn(ioc, short_lived_session_coro(phase), net::detached);
        net::co_spawn(ioc, observer_coro(phase), net::detached);

        ioc.run();
    }

    const auto obs_entries = std::count_if(g_log.begin(), g_log.end(),
        [](const log_entry &e)
        { return std::strcmp(e.scenario, "observer") == 0; });

    EXPECT_GT(obs_entries, 0) << "observer 未产生日志";
    std::printf("[ScopeRestore] phase=%d, 日志条数=%zu\n",
                phase->load(), g_log.size());
}

// ============================================================
// 测试 9: 高压力综合
// ============================================================

TEST(ScopedPrefix, HighStress_AllModes)
{
    clear_log();
    net::io_context ioc;

    constexpr int stress_coros = 32;
    constexpr int stress_yields = 8;

    std::vector<psm::trace::session_prefix> pfx(stress_coros);
    for (int i = 0; i < stress_coros; ++i)
        pfx[i].session_id = 1000 + i;

    for (int i = 0; i < stress_coros / 2; ++i)
        net::co_spawn(ioc, fixed_session_coro(pfx[i], stress_yields), net::detached);

    for (int i = stress_coros / 2; i < stress_coros; ++i)
        net::co_spawn(ioc, bugged_session_coro(pfx[i], stress_yields), net::detached);

    ioc.run();

    const auto fixed_bad = count_corruptions_for("fixed");
    const auto bugged_bad = count_corruptions_for("bugged");

    std::printf("[HighStress] 总日志: %zu, fixed污染=%d, bugged污染=%d\n",
                g_log.size(), fixed_bad, bugged_bad);

    EXPECT_EQ(fixed_bad, 0) << "fixed 模式出现 " << fixed_bad << " 次污染";
    EXPECT_GT(bugged_bad, 0) << "bugged 模式未产生污染";
}
