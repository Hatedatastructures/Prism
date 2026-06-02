/**
 * @file StealthExecutorDeep2.cpp
 * @brief scheme_executor 私有同步方法深度测试
 * @details 通过 #define private public + #include 源文件访问：
 *          pass_through、ensure_snapshot、try_rewind、find_scheme。
 *          覆盖 executor.cpp 未覆盖的行 52-56, 66, 75, 78-82, 235。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>

#include "common/MockTransport.hpp"

// ── 关键：在 connect/util.hpp 等传递依赖之前，先以 private=open 包含 snapshot + executor ──
// 这样 snapshot.hpp 的 #pragma once 会确保 private 成员对外开放
#define private public
#include <prism/transport/snapshot.hpp>
#include <prism/stealth/executor.hpp>
#undef private

#include <prism/stealth/facade/native.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>

#include "../../src/prism/stealth/executor.cpp"

namespace
{
    namespace stealth = psm::stealth;
    namespace transport = psm::transport;
    using psm::connect::as;

    // ─── find_scheme ─────────────────────────────────

    TEST(StealthExecutorDeep2, FindSchemeRegistered)
    {
        stealth::scheme_registry registry;
        registry.add(std::make_shared<psm::stealth::native::native>());

        stealth::scheme_executor exec(registry);
        auto found = exec.find_scheme("native");
        EXPECT_TRUE(found != nullptr) << "find_scheme: native found";
        EXPECT_TRUE(found->name() == std::string_view("native")) << "find_scheme: name matches";
    }

    TEST(StealthExecutorDeep2, FindSchemeNotRegistered)
    {
        stealth::scheme_registry registry;
        stealth::scheme_executor exec(registry);
        auto found = exec.find_scheme("nonexistent");
        EXPECT_TRUE(found == nullptr) << "find_scheme: nonexistent returns nullptr";
    }

    TEST(StealthExecutorDeep2, FindSchemeMultiple)
    {
        stealth::scheme_registry registry;
        registry.add(std::make_shared<psm::stealth::native::native>());
        registry.add(std::make_shared<psm::stealth::reality::scheme>());

        stealth::scheme_executor exec(registry);
        auto native = exec.find_scheme("native");
        auto reality = exec.find_scheme("reality");
        auto bad = exec.find_scheme("foo");
        EXPECT_TRUE(native != nullptr) << "find_scheme multi: native found";
        EXPECT_TRUE(reality != nullptr) << "find_scheme multi: reality found";
        EXPECT_TRUE(bad == nullptr) << "find_scheme multi: foo not found";
    }

    // ─── pass_through ────────────────────────────────

    TEST(StealthExecutorDeep2, PassThroughWithTransport)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = mock;

        stealth::scheme_executor::pass_through(ctx, res);
        EXPECT_TRUE(ctx.inbound == mock) << "pass_through: sets transport";
    }

    TEST(StealthExecutorDeep2, PassThroughNoTransport)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = nullptr;

        stealth::scheme_executor::pass_through(ctx, res);
        EXPECT_TRUE(ctx.inbound == nullptr) << "pass_through: null transport keeps null";
    }

    TEST(StealthExecutorDeep2, PassThroughWithPrereadAndTransport)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = mock;
        res.preread = psm::memory::vector<std::byte>();
        res.preread.push_back(std::byte{0x01});
        res.preread.push_back(std::byte{0x02});

        stealth::scheme_executor::pass_through(ctx, res);
        EXPECT_TRUE(ctx.inbound != mock) << "pass_through: wraps with preview";
        EXPECT_TRUE(ctx.inbound != nullptr) << "pass_through: not null after wrap";
        auto *pv = dynamic_cast<transport::preview *>(ctx.inbound.get());
        EXPECT_TRUE(pv != nullptr) << "pass_through: is preview";
    }

    TEST(StealthExecutorDeep2, PassThroughEmptyPreread)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = mock;
        stealth::scheme_executor::pass_through(ctx, res);
        EXPECT_TRUE(ctx.inbound == mock) << "pass_through: empty preread no wrap";
    }

    TEST(StealthExecutorDeep2, PassThroughPrereadNoTransport)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = nullptr;
        res.preread.push_back(std::byte{0xAA});

        stealth::scheme_executor::pass_through(ctx, res);
        EXPECT_TRUE(ctx.inbound == nullptr) << "pass_through: preread but no transport stays null";
    }

    // ─── ensure_snapshot ─────────────────────────────

    TEST(StealthExecutorDeep2, EnsureSnapshotNull)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;
        stealth::scheme_executor::ensure_snapshot(ctx);
        EXPECT_TRUE(ctx.inbound == nullptr) << "ensure_snapshot: null stays null";
    }

    TEST(StealthExecutorDeep2, EnsureSnapshotAlreadySnapshot)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        auto snap = std::make_shared<transport::snapshot>(mock);
        stealth::handshake_context ctx;
        ctx.inbound = snap;

        stealth::scheme_executor::ensure_snapshot(ctx);
        EXPECT_TRUE(ctx.inbound == snap) << "ensure_snapshot: already snapshot unchanged";
    }

    TEST(StealthExecutorDeep2, EnsureSnapshotNotSnapshot)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = mock;

        stealth::scheme_executor::ensure_snapshot(ctx);
        EXPECT_TRUE(ctx.inbound != mock) << "ensure_snapshot: wraps non-snapshot";
        auto *snap = dynamic_cast<transport::snapshot *>(ctx.inbound.get());
        EXPECT_TRUE(snap != nullptr) << "ensure_snapshot: result is snapshot";
    }

    // ─── try_rewind ──────────────────────────────────

    TEST(StealthExecutorDeep2, TryRewindPolluted)
    {
        stealth::handshake_context ctx;
        ctx.inbound = std::make_shared<psm::testing::MockTransport>();
        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::polluted);
        EXPECT_TRUE(result == false) << "try_rewind: polluted returns false";
    }

    TEST(StealthExecutorDeep2, TryRewindNullInbound)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;
        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        EXPECT_TRUE(result == false) << "try_rewind: null inbound returns false";
    }

    TEST(StealthExecutorDeep2, TryRewindNotSnapshot)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = mock;

        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        EXPECT_TRUE(result == false) << "try_rewind: non-snapshot returns false";
    }

    TEST(StealthExecutorDeep2, TryRewindSnapshotCannotRewind)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        auto snap = std::make_shared<transport::snapshot>(mock);
        // wrote_ 已通过 #define private public 开放（snapshot.hpp 首次包含时生效）
        snap->wrote_ = true;
        stealth::handshake_context ctx;
        ctx.inbound = snap;

        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        EXPECT_TRUE(result == false) << "try_rewind: snapshot wrote_ returns false";
    }

    TEST(StealthExecutorDeep2, TryRewindSnapshotSuccess)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        auto snap = std::make_shared<transport::snapshot>(mock);
        stealth::handshake_context ctx;
        ctx.inbound = snap;

        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        EXPECT_TRUE(result == true) << "try_rewind: clean snapshot returns true";
    }

} // namespace
