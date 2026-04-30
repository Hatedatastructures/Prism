/**
 * @file AccountDirectory.cpp
 * @brief Account Directory 单元测试
 * @details 测试账户目录的 upsert、连接限制、lease RAII、多凭据别名等核心逻辑。
 */

#include <prism/agent/account/directory.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include "common/TestRunner.hpp"

#ifdef WIN32
#include <windows.h>
#endif

namespace account = psm::agent::account;

/// 辅助函数：将 lease 转为 bool（因为 explicit operator bool 不能隐式转换）
static auto IsValid(const account::lease &l) -> bool
{
    return static_cast<bool>(l);
}

/**
 * @brief 测试基本 upsert + find
 */
void TestBasicUpsertFind(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestBasicUpsertFind ===");

    account::directory dir;

    // 未注册 -> find 返回 nullptr
    runner.Check(!dir.find("unknown"), "basic: unregistered credential returns null");

    // 注册 -> find 返回有效 entry
    dir.upsert("cred1", 5);
    auto entry = dir.find("cred1");
    runner.Check(entry != nullptr, "basic: registered credential found");
    runner.Check(entry && entry->max_connections == 5, "basic: correct max_connections");
    runner.Check(entry && entry->active_connections.load() == 0, "basic: initial active is 0");
}

/**
 * @brief 测试 upsert 更新
 */
void TestUpsertUpdate(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestUpsertUpdate ===");

    account::directory dir;
    dir.upsert("cred1", 3);

    // 更新 max_connections
    dir.upsert("cred1", 10);
    auto entry = dir.find("cred1");
    runner.Check(entry && entry->max_connections == 10, "update: max_connections updated to 10");
}

/**
 * @brief 测试连接限制 + lease RAII
 */
void TestConnectionLimit(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestConnectionLimit ===");

    account::directory dir;
    dir.upsert("limited", 2);

    auto entry = dir.find("limited");

    // 第一个 lease
    {
        auto lease1 = account::try_acquire(dir, "limited");
        runner.Check(IsValid(lease1), "limit: first lease succeeds");
        runner.Check(entry && entry->active_connections.load() == 1, "limit: active = 1");
    }

    // lease1 析构，active 应递减
    runner.Check(entry && entry->active_connections.load() == 0, "limit: active = 0 after release");

    // 获取两个 lease
    {
        auto lease1 = account::try_acquire(dir, "limited");
        auto lease2 = account::try_acquire(dir, "limited");
        runner.Check(IsValid(lease1) && IsValid(lease2), "limit: two leases succeed");
        runner.Check(entry && entry->active_connections.load() == 2, "limit: active = 2");

        // 第三个应失败
        auto lease3 = account::try_acquire(dir, "limited");
        runner.Check(!IsValid(lease3), "limit: third lease fails (limit=2)");
    }

    // 全部释放后 active 归零
    runner.Check(entry && entry->active_connections.load() == 0, "limit: active = 0 after all released");
}

/**
 * @brief 测试不存在的凭据
 */
void TestNonexistentCredential(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestNonexistentCredential ===");

    account::directory dir;

    auto lease = account::try_acquire(dir, "nonexistent");
    runner.Check(!IsValid(lease), "nonexistent: lease fails for unregistered credential");

    runner.Check(!account::contains(dir, "nonexistent"), "nonexistent: contains returns false");
}

/**
 * @brief 测试 max_connections=0 表示无限制
 */
void TestUnlimitedConnections(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestUnlimitedConnections ===");

    account::directory dir;
    dir.upsert("unlimited", 0); // 0 = 无限制

    // 应该能获取任意数量的 lease
    psm::memory::vector<account::lease> leases(psm::memory::current_resource());
    for (int i = 0; i < 100; ++i)
    {
        auto lease = account::try_acquire(dir, "unlimited");
        runner.Check(IsValid(lease), "unlimited: lease succeeds");
        if (IsValid(lease))
        {
            leases.push_back(std::move(lease));
        }
    }

    auto entry = dir.find("unlimited");
    runner.Check(entry && entry->active_connections.load() == 100, "unlimited: 100 active connections");
}

/**
 * @brief 测试 contains
 */
void TestContains(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestContains ===");

    account::directory dir;
    dir.upsert("existing");

    runner.Check(account::contains(dir, "existing"), "contains: registered credential found");
    runner.Check(!account::contains(dir, "missing"), "contains: unregistered credential not found");
}

/**
 * @brief 测试 clear
 */
void TestClear(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestClear ===");

    account::directory dir;
    dir.upsert("a");
    dir.upsert("b");
    dir.upsert("c");

    runner.Check(account::contains(dir, "a"), "clear: a exists before clear");
    dir.clear();
    runner.Check(!account::contains(dir, "a"), "clear: a gone after clear");
    runner.Check(!account::contains(dir, "b"), "clear: b gone after clear");
    runner.Check(!account::contains(dir, "c"), "clear: c gone after clear");
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    psm::testing::TestRunner runner("AccountDirectory");
    runner.LogInfo("Starting AccountDirectory tests...");

    TestBasicUpsertFind(runner);
    TestUpsertUpdate(runner);
    TestConnectionLimit(runner);
    TestNonexistentCredential(runner);
    TestUnlimitedConnections(runner);
    TestContains(runner);
    TestClear(runner);

    return runner.Summary();
}
