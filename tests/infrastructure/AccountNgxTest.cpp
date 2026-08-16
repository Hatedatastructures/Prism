/**
 * @file AccountNgxTest.cpp
 * @brief 账户目录测试（T5-3 O3）
 * @details 覆盖：
 *          - cow_map：set/find/update/remove/snapshot/clear
 *          - directory：upsert/insert/remove/find/for_each/clear
 *          - lease：RAII 释放 / move 语义 / 空判
 *          - try_acquire：无限制 / 限制 / 禁用 / 过期 / 多协议共享配额
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <common/core/account/cow_map.hpp>
#include <common/core/account/directory.hpp>

namespace
{

    TEST(AccountCowMap, SetFindUpdate)
    {
        psmtest::account::cow_map<std::string, int> m;
        m.set("a", 1);
        m.set("b", 2);

        int v = 0;
        EXPECT_TRUE(m.find("a", v));
        EXPECT_EQ(v, 1);
        EXPECT_TRUE(m.find("b", v));
        EXPECT_EQ(v, 2);
        EXPECT_FALSE(m.find("c", v));
        EXPECT_EQ(m.size(), 2);

        // 更新
        m.set("a", 10);
        EXPECT_TRUE(m.find("a", v));
        EXPECT_EQ(v, 10);
        EXPECT_EQ(m.size(), 2);
    }

    TEST(AccountCowMap, RemoveAndClear)
    {
        psmtest::account::cow_map<std::string, int> m;
        m.set("a", 1);
        m.set("b", 2);
        EXPECT_TRUE(m.remove("a"));
        EXPECT_FALSE(m.remove("a"));
        EXPECT_EQ(m.size(), 1);

        m.clear();
        EXPECT_EQ(m.size(), 0);
        int v = 0;
        EXPECT_FALSE(m.find("b", v));
    }

    TEST(AccountCowMap, SnapshotIsolation)
    {
        psmtest::account::cow_map<std::string, int> m;
        m.set("a", 1);

        auto snap1 = m.snapshot(); // 旧快照
        m.set("b", 2);             // 写时复制：旧快照不受影响
        EXPECT_EQ(snap1->size(), 1);
        EXPECT_EQ(m.size(), 2);
    }

    TEST(AccountDirectory, UpsertFindRemove)
    {
        psmtest::account::directory dir;
        EXPECT_FALSE(dir.contains("alice"));

        dir.upsert("alice", 5);
        EXPECT_TRUE(dir.contains("alice"));
        auto e = dir.find("alice");
        ASSERT_NE(e, nullptr);
        EXPECT_EQ(e->max_connections(), 5);
        EXPECT_FALSE(e->disabled());

        EXPECT_TRUE(dir.remove("alice"));
        EXPECT_FALSE(dir.contains("alice"));
        EXPECT_EQ(dir.size(), 0);
    }

    TEST(AccountDirectory, ForEachSnapshot)
    {
        psmtest::account::directory dir;
        dir.upsert("a", 1);
        dir.upsert("b", 2);
        dir.upsert("c", 3);

        std::vector<std::string> creds;
        dir.for_each([&](std::string_view c, const psmtest::account::shared_entry &)
                     { creds.emplace_back(c); });
        EXPECT_EQ(creds.size(), 3);
        EXPECT_EQ(dir.size(), 3);

        dir.clear();
        EXPECT_EQ(dir.size(), 0);
    }

    TEST(AccountLease, RaiiRelease)
    {
        psmtest::account::directory dir;
        dir.upsert("alice", 2);

        {
            auto l1 = psmtest::account::try_acquire(dir, "alice");
            auto l2 = psmtest::account::try_acquire(dir, "alice");
            EXPECT_TRUE(l1);
            EXPECT_TRUE(l2);
            auto e = dir.find("alice");
            EXPECT_EQ(e->active(), 2);
            // 第三个被拒（超限）
            EXPECT_FALSE(psmtest::account::try_acquire(dir, "alice"));
        } // l1/l2 析构 → 释放
        auto e = dir.find("alice");
        EXPECT_EQ(e->active(), 0);

        // 释放后可再获取
        EXPECT_TRUE(psmtest::account::try_acquire(dir, "alice"));
    }

    TEST(AccountLease, MoveSemantics)
    {
        psmtest::account::directory dir;
        dir.upsert("bob", 1);

        auto l1 = psmtest::account::try_acquire(dir, "bob");
        EXPECT_TRUE(l1);
        auto l2 = std::move(l1);
        EXPECT_FALSE(l1); // 移动后空
        EXPECT_TRUE(l2);
        auto e = dir.find("bob");
        EXPECT_EQ(e->active(), 1);
    }

    TEST(AccountLease, UnlimitedConnections)
    {
        psmtest::account::directory dir;
        dir.upsert("carol", 0); // 0 = 无限制

        std::vector<psmtest::account::lease> leases;
        for (int i = 0; i < 100; ++i)
        {
            auto l = psmtest::account::try_acquire(dir, "carol");
            ASSERT_TRUE(l);
            leases.push_back(std::move(l));
        }
        auto e = dir.find("carol");
        EXPECT_EQ(e->active(), 100);
    }

    TEST(AccountLease, DisabledRejected)
    {
        psmtest::account::directory dir;
        dir.upsert("dave", 5, true); // 禁用

        EXPECT_FALSE(psmtest::account::try_acquire(dir, "dave"));
        // 未知账户
        EXPECT_FALSE(psmtest::account::try_acquire(dir, "nobody"));
    }

    TEST(AccountLease, ExpiredRejected)
    {
        psmtest::account::directory dir;
        dir.upsert("eve", 5, false, 1000); // 1000ms 过期

        EXPECT_TRUE(psmtest::account::try_acquire(dir, "eve", 500));  // 未过期
        EXPECT_FALSE(psmtest::account::try_acquire(dir, "eve", 1000)); // 过期
        EXPECT_TRUE(psmtest::account::try_acquire(dir, "eve", 0));     // 不校验
    }

    TEST(AccountLease, SharedEntrySharedQuota)
    {
        psmtest::account::directory dir;
        // 两凭证共享同一 entry → 配额共享
        auto shared = std::make_shared<psmtest::account::entry>(1);
        dir.insert("tcp", shared);
        dir.insert("udp", shared);

        EXPECT_TRUE(psmtest::account::try_acquire(dir, "tcp")); // 临时租约：持有一瞬
        auto l_tcp = psmtest::account::try_acquire(dir, "tcp");
        ASSERT_TRUE(l_tcp);
        EXPECT_FALSE(psmtest::account::try_acquire(dir, "udp")); // 共享上限 1
        auto e = dir.find("tcp");
        EXPECT_EQ(e->active(), 1);
    }

} // namespace
