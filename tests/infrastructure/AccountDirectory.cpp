/**
 * @file AccountDirectory.cpp
 * @brief Account Directory 单元测试
 * @details 测试账户目录的 upsert、连接限制、lease RAII、多凭据别名等核心逻辑。
 */

#include <prism/account/directory.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

namespace account = psm::account;

/// 辅助函数：将 lease 转为 bool（因为 explicit operator bool 不能隐式转换）
static auto IsValid(const account::lease &l) -> bool
{
    return static_cast<bool>(l);
}

namespace
{
    TEST(AccountDirectory, BasicUpsertFind)
    {
        account::directory dir;

        // 未注册 -> find 返回 nullptr
        EXPECT_TRUE(!dir.find("unknown")) << "basic: unregistered credential returns null";

        // 注册 -> find 返回有效 entry
        dir.upsert("cred1", 5);
        auto entry = dir.find("cred1");
        ASSERT_TRUE(entry != nullptr) << "basic: registered credential found";
        EXPECT_TRUE(entry->max_connections == 5) << "basic: correct max_connections";
        EXPECT_TRUE(entry->active_connections.load() == 0) << "basic: initial active is 0";
    }

    TEST(AccountDirectory, UpsertUpdate)
    {
        account::directory dir;
        dir.upsert("cred1", 3);

        // 更新 max_connections
        dir.upsert("cred1", 10);
        auto entry = dir.find("cred1");
        ASSERT_TRUE(entry) << "update: entry exists";
        EXPECT_TRUE(entry->max_connections == 10) << "update: max_connections updated to 10";
    }

    TEST(AccountDirectory, ConnectionLimit)
    {
        account::directory dir;
        dir.upsert("limited", 2);

        auto entry = dir.find("limited");

        // 第一个 lease
        {
            auto lease1 = account::try_acquire(dir, "limited");
            EXPECT_TRUE(IsValid(lease1)) << "limit: first lease succeeds";
            EXPECT_TRUE(entry && entry->active_connections.load() == 1) << "limit: active = 1";
        }

        // lease1 析构，active 应递减
        EXPECT_TRUE(entry && entry->active_connections.load() == 0) << "limit: active = 0 after release";

        // 获取两个 lease
        {
            auto lease1 = account::try_acquire(dir, "limited");
            auto lease2 = account::try_acquire(dir, "limited");
            EXPECT_TRUE(IsValid(lease1) && IsValid(lease2)) << "limit: two leases succeed";
            EXPECT_TRUE(entry && entry->active_connections.load() == 2) << "limit: active = 2";

            // 第三个应失败
            auto lease3 = account::try_acquire(dir, "limited");
            EXPECT_TRUE(!IsValid(lease3)) << "limit: third lease fails (limit=2)";
        }

        // 全部释放后 active 归零
        EXPECT_TRUE(entry && entry->active_connections.load() == 0) << "limit: active = 0 after all released";
    }

    TEST(AccountDirectory, NonexistentCredential)
    {
        account::directory dir;

        auto lease = account::try_acquire(dir, "nonexistent");
        EXPECT_TRUE(!IsValid(lease)) << "nonexistent: lease fails for unregistered credential";

        EXPECT_TRUE(!account::contains(dir, "nonexistent")) << "nonexistent: contains returns false";
    }

    TEST(AccountDirectory, UnlimitedConnections)
    {
        account::directory dir;
        dir.upsert("unlimited", 0); // 0 = 无限制

        // 应该能获取任意数量的 lease
        psm::memory::vector<account::lease> leases(psm::memory::current_resource());
        for (int i = 0; i < 100; ++i)
        {
            auto lease = account::try_acquire(dir, "unlimited");
            ASSERT_TRUE(IsValid(lease)) << "unlimited: lease succeeds";
            leases.push_back(std::move(lease));
        }

        auto entry = dir.find("unlimited");
        EXPECT_TRUE(entry && entry->active_connections.load() == 100) << "unlimited: 100 active connections";
    }

    TEST(AccountDirectory, Contains)
    {
        account::directory dir;
        dir.upsert("existing");

        EXPECT_TRUE(account::contains(dir, "existing")) << "contains: registered credential found";
        EXPECT_TRUE(!account::contains(dir, "missing")) << "contains: unregistered credential not found";
    }

    TEST(AccountDirectory, Clear)
    {
        account::directory dir;
        dir.upsert("a");
        dir.upsert("b");
        dir.upsert("c");

        EXPECT_TRUE(account::contains(dir, "a")) << "clear: a exists before clear";
        dir.clear();
        EXPECT_TRUE(!account::contains(dir, "a")) << "clear: a gone after clear";
        EXPECT_TRUE(!account::contains(dir, "b")) << "clear: b gone after clear";
        EXPECT_TRUE(!account::contains(dir, "c")) << "clear: c gone after clear";
    }
} // namespace
