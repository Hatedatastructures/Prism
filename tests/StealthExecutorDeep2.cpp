/**
 * @file StealthExecutorDeep2.cpp
 * @brief scheme_executor 私有同步方法深度测试
 * @details 通过 #define private public + #include 源文件访问：
 *          pass_through、ensure_snapshot、try_rewind、find_scheme。
 *          覆盖 executor.cpp 未覆盖的行 52-56, 66, 75, 78-82, 235。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

// ── 关键：在 connect/util.hpp 等传递依赖之前，先以 private=open 包含 snapshot + executor ──
// 这样 snapshot.hpp 的 #pragma once 会确保 private 成员对外开放
#define private public
#include <prism/transport/snapshot.hpp>
#include <prism/stealth/executor.hpp>
#undef private

#include <prism/stealth/facade/native.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>

#include "../src/prism/stealth/executor.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace stealth = psm::stealth;
    namespace transport = psm::transport;
    using psm::connect::as;

    // ─── find_scheme ─────────────────────────────────

    void TestFindSchemeRegistered(TestRunner &runner)
    {
        stealth::scheme_registry registry;
        registry.add(std::make_shared<psm::stealth::native::native>());

        stealth::scheme_executor exec(registry);
        auto found = exec.find_scheme("native");
        runner.Check(found != nullptr, "find_scheme: native found");
        runner.Check(found->name() == std::string_view("native"), "find_scheme: name matches");
    }

    void TestFindSchemeNotRegistered(TestRunner &runner)
    {
        stealth::scheme_registry registry;
        stealth::scheme_executor exec(registry);
        auto found = exec.find_scheme("nonexistent");
        runner.Check(found == nullptr, "find_scheme: nonexistent returns nullptr");
    }

    void TestFindSchemeMultiple(TestRunner &runner)
    {
        stealth::scheme_registry registry;
        registry.add(std::make_shared<psm::stealth::native::native>());
        registry.add(std::make_shared<psm::stealth::reality::scheme>());

        stealth::scheme_executor exec(registry);
        auto native = exec.find_scheme("native");
        auto reality = exec.find_scheme("reality");
        auto bad = exec.find_scheme("foo");
        runner.Check(native != nullptr, "find_scheme multi: native found");
        runner.Check(reality != nullptr, "find_scheme multi: reality found");
        runner.Check(bad == nullptr, "find_scheme multi: foo not found");
    }

    // ─── pass_through ────────────────────────────────

    void TestPassThroughWithTransport(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = mock;

        stealth::scheme_executor::pass_through(ctx, res);
        runner.Check(ctx.inbound == mock, "pass_through: sets transport");
    }

    void TestPassThroughNoTransport(TestRunner &runner)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = nullptr;

        stealth::scheme_executor::pass_through(ctx, res);
        runner.Check(ctx.inbound == nullptr, "pass_through: null transport keeps null");
    }

    void TestPassThroughWithPrereadAndTransport(TestRunner &runner)
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
        runner.Check(ctx.inbound != mock, "pass_through: wraps with preview");
        runner.Check(ctx.inbound != nullptr, "pass_through: not null after wrap");
        auto *pv = dynamic_cast<transport::preview *>(ctx.inbound.get());
        runner.Check(pv != nullptr, "pass_through: is preview");
    }

    void TestPassThroughEmptyPreread(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = mock;
        stealth::scheme_executor::pass_through(ctx, res);
        runner.Check(ctx.inbound == mock, "pass_through: empty preread no wrap");
    }

    void TestPassThroughPrereadNoTransport(TestRunner &runner)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;

        stealth::handshake_result res;
        res.transport = nullptr;
        res.preread.push_back(std::byte{0xAA});

        stealth::scheme_executor::pass_through(ctx, res);
        runner.Check(ctx.inbound == nullptr, "pass_through: preread but no transport stays null");
    }

    // ─── ensure_snapshot ─────────────────────────────

    void TestEnsureSnapshotNull(TestRunner &runner)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;
        stealth::scheme_executor::ensure_snapshot(ctx);
        runner.Check(ctx.inbound == nullptr, "ensure_snapshot: null stays null");
    }

    void TestEnsureSnapshotAlreadySnapshot(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        auto snap = std::make_shared<transport::snapshot>(mock);
        stealth::handshake_context ctx;
        ctx.inbound = snap;

        stealth::scheme_executor::ensure_snapshot(ctx);
        runner.Check(ctx.inbound == snap, "ensure_snapshot: already snapshot unchanged");
    }

    void TestEnsureSnapshotNotSnapshot(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = mock;

        stealth::scheme_executor::ensure_snapshot(ctx);
        runner.Check(ctx.inbound != mock, "ensure_snapshot: wraps non-snapshot");
        auto *snap = dynamic_cast<transport::snapshot *>(ctx.inbound.get());
        runner.Check(snap != nullptr, "ensure_snapshot: result is snapshot");
    }

    // ─── try_rewind ──────────────────────────────────

    void TestTryRewindPolluted(TestRunner &runner)
    {
        stealth::handshake_context ctx;
        ctx.inbound = std::make_shared<psm::testing::MockTransport>();
        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::polluted);
        runner.Check(result == false, "try_rewind: polluted returns false");
    }

    void TestTryRewindNullInbound(TestRunner &runner)
    {
        stealth::handshake_context ctx;
        ctx.inbound = nullptr;
        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        runner.Check(result == false, "try_rewind: null inbound returns false");
    }

    void TestTryRewindNotSnapshot(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        stealth::handshake_context ctx;
        ctx.inbound = mock;

        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        runner.Check(result == false, "try_rewind: non-snapshot returns false");
    }

    void TestTryRewindSnapshotCannotRewind(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        auto snap = std::make_shared<transport::snapshot>(mock);
        // wrote_ 已通过 #define private public 开放（snapshot.hpp 首次包含时生效）
        snap->wrote_ = true;
        stealth::handshake_context ctx;
        ctx.inbound = snap;

        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        runner.Check(result == false, "try_rewind: snapshot wrote_ returns false");
    }

    void TestTryRewindSnapshotSuccess(TestRunner &runner)
    {
        auto mock = std::make_shared<psm::testing::MockTransport>();
        auto snap = std::make_shared<transport::snapshot>(mock);
        stealth::handshake_context ctx;
        ctx.inbound = snap;

        auto result = stealth::scheme_executor::try_rewind(ctx, stealth::rewind_mode::clean);
        runner.Check(result == true, "try_rewind: clean snapshot returns true");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("StealthExecutorDeep2");

    TestFindSchemeRegistered(runner);
    TestFindSchemeNotRegistered(runner);
    TestFindSchemeMultiple(runner);

    TestPassThroughWithTransport(runner);
    TestPassThroughNoTransport(runner);
    TestPassThroughWithPrereadAndTransport(runner);
    TestPassThroughEmptyPreread(runner);
    TestPassThroughPrereadNoTransport(runner);

    TestEnsureSnapshotNull(runner);
    TestEnsureSnapshotAlreadySnapshot(runner);
    TestEnsureSnapshotNotSnapshot(runner);

    TestTryRewindPolluted(runner);
    TestTryRewindNullInbound(runner);
    TestTryRewindNotSnapshot(runner);
    TestTryRewindSnapshotCannotRewind(runner);
    TestTryRewindSnapshotSuccess(runner);

    return runner.Summary();
}
