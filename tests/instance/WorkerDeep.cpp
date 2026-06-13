/**
 * @file WorkerDeep.cpp
 * @brief Worker 生命周期深度测试
 * @details 通过包含源文件测试 worker 构造、反向路由注册、
 * 正向端点设置、run/stop 生命周期、负载快照等行为。
 */

#include <gtest/gtest.h>

// Deep test: 包含源文件以访问内部状态
// 注意：不能与其他包含 worker.cpp 的测试编译到同一可执行文件
#define private public
#include "../../src/prism/instance/worker/worker.cpp"
#undef private

#include <prism/account/directory.hpp>
#include <prism/config/config.hpp>
#include <prism/core/core.hpp>
#include <prism/account/stats/runtime.hpp>
#include <prism/account/stats/traffic.hpp>

#include <chrono>
#include <memory>
#include <thread>

namespace
{
    using namespace psm::instance::worker;
} // anonymous namespace

// ── 构造：最小配置 ──

TEST(WorkerDeep, ConstructMinimal)
{
    psm::config cfg;
    auto acct = std::make_shared<psm::account::directory>();

    worker w(cfg, acct);

    // 空 cert/key → null SSL context
    EXPECT_EQ(w.ssl_ctx_, nullptr);

    // outbound_direct 已创建
    EXPECT_NE(w.outbound_direct_, nullptr);

    // server config 已存储
    EXPECT_NE(w.server_ctx_.cfg.load(), nullptr);

    // worker context 指向内部 traffic_state
    EXPECT_EQ(w.worker_ctx_.traffic, &w.traffic_);

    // 初始负载快照全零
    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u);
    EXPECT_EQ(snap.pending_handoffs, 0u);
    EXPECT_EQ(snap.lag_us, 0u);
}

// ── 构造：有效反向路由 ──

TEST(WorkerDeep, ConstructWithValidReverseRoute)
{
    psm::config cfg;
    cfg.instance.reverse_map["example.com"] = psm::instance::endpoint{
        psm::memory::string("192.168.1.1"), 8080};

    auto acct = std::make_shared<psm::account::directory>();
    worker w(cfg, acct);
    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u) << "valid reverse route: worker constructible";
}

// ── 构造：无效反向路由（端口为 0）──

TEST(WorkerDeep, ConstructWithZeroPortReverseRoute)
{
    psm::config cfg;
    cfg.instance.reverse_map["bad.com"] = psm::instance::endpoint{
        psm::memory::string("10.0.0.1"), 0};

    auto acct = std::make_shared<psm::account::directory>();
    worker w(cfg, acct);
    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u) << "zero port route: worker constructible";
}

// ── 构造：无效反向路由（非法地址）──

TEST(WorkerDeep, ConstructWithInvalidAddressReverseRoute)
{
    psm::config cfg;
    cfg.instance.reverse_map["bad.com"] = psm::instance::endpoint{
        psm::memory::string("not-an-ip!!!"), 443};

    auto acct = std::make_shared<psm::account::directory>();
    worker w(cfg, acct);
    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u) << "invalid address route: worker constructible";
}
// ── 构造：正向代理端点 ──

TEST(WorkerDeep, ConstructWithPositiveEndpoint)
{
    psm::config cfg;
    cfg.instance.positive = psm::instance::endpoint{
        psm::memory::string("proxy.example.com"), 3128};

    auto acct = std::make_shared<psm::account::directory>();
    worker w(cfg, acct);
    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u) << "positive endpoint: worker constructible";
}

// ── 构造：正向端点空主机名 ──

TEST(WorkerDeep, ConstructWithEmptyPositiveHost)
{
    psm::config cfg;
    cfg.instance.positive = psm::instance::endpoint{
        psm::memory::string(""), 3128};

    auto acct = std::make_shared<psm::account::directory>();
    worker w(cfg, acct);
    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u) << "empty positive host: worker constructible";
}

TEST(WorkerDeep, LoadSnapshotInitial)
{
    psm::config cfg;
    auto acct = std::make_shared<psm::account::directory>();
    worker w(cfg, acct);

    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u);
    EXPECT_EQ(snap.pending_handoffs, 0u);
}

// ── run + stop 生命周期 ──

TEST(WorkerDeep, RunStopLifecycle)
{
    psm::config cfg;
    auto acct = std::make_shared<psm::account::directory>();
    auto w = std::make_unique<worker>(cfg, acct);

    std::atomic<bool> started{false};
    std::thread t([&]() {
        started = true;
        w->run();
    });

    // 等待线程启动
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(started);

    w->stop();
    t.join();

    w.reset();
}

// ── 析构取消注册 traffic_state ──

TEST(WorkerDeep, DestructorUnregistersTraffic)
{
    {
        psm::config cfg;
        auto acct = std::make_shared<psm::account::directory>();
        worker w(cfg, acct);
        // 构造时 register_instance 被调用
    }
    // 析构时 unregister_instance 被调用

    // 实例已移除，aggregate 应安全
    auto snap = psm::stats::traffic::traffic_state::aggregate();
    EXPECT_EQ(snap.total_connections, 0u);
}

// ── stop 在 run 之前调用 ──

TEST(WorkerDeep, StopBeforeRun)
{
    psm::config cfg;
    auto acct = std::make_shared<psm::account::directory>();
    worker w(cfg, acct);

    // stop() 在 run() 之前调用不应崩溃
    w.stop();
    auto snap = w.load_snapshot();
    EXPECT_EQ(snap.active_sessions, 0u) << "stop before run: worker idle";
}
