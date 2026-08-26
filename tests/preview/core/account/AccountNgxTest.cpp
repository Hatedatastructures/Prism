/**
 * @file AccountNgxTest.cpp
 * @brief 账户目录测试（T5-3 O3）
 * @details 覆盖：
 *          - CowMap：set/Find/Update/Remove/Snapshot/Clear
 *          - Directory：Upsert/Insert/Remove/Find/ForEach/Clear
 *          - Lease：RAII 释放 / move 语义 / 空判
 *          - TryAcquire：无限制 / 限制 / 禁用 / 过期 / 多协议共享配额
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <common/Core/Memory/CowMap.hpp>
#include <common/Core/Account/Directory.hpp>

namespace
{

    TEST(AccountCowMap, SetFindUpdate)
    {
        Preview::Memory::CowMap<std::string, int> m;
        m.Set("a", 1);
        m.Set("b", 2);

        int v = 0;
        EXPECT_TRUE(m.Find("a", v));
        EXPECT_EQ(v, 1);
        EXPECT_TRUE(m.Find("b", v));
        EXPECT_EQ(v, 2);
        EXPECT_FALSE(m.Find("c", v));
        EXPECT_EQ(m.Size(), 2);

        // 更新
        m.Set("a", 10);
        EXPECT_TRUE(m.Find("a", v));
        EXPECT_EQ(v, 10);
        EXPECT_EQ(m.Size(), 2);
    }

    TEST(AccountCowMap, RemoveAndClear)
    {
        Preview::Memory::CowMap<std::string, int> m;
        m.Set("a", 1);
        m.Set("b", 2);
        EXPECT_TRUE(m.Remove("a"));
        EXPECT_FALSE(m.Remove("a"));
        EXPECT_EQ(m.Size(), 1);

        m.Clear();
        EXPECT_EQ(m.Size(), 0);
        int v = 0;
        EXPECT_FALSE(m.Find("b", v));
    }

    TEST(AccountCowMap, SnapshotIsolation)
    {
        Preview::Memory::CowMap<std::string, int> m;
        m.Set("a", 1);

        auto snap1 = m.Snapshot(); // 旧快照
        m.Set("b", 2);             // 写时复制：旧快照不受影响
        EXPECT_EQ(snap1->size(), 1);
        EXPECT_EQ(m.Size(), 2);
    }

    TEST(AccountDirectory, UpsertFindRemove)
    {
        Preview::Account::Directory dir;
        EXPECT_FALSE(dir.Contains("alice"));

        dir.Upsert("alice", 5);
        EXPECT_TRUE(dir.Contains("alice"));
        auto e = dir.Find("alice");
        ASSERT_NE(e, nullptr);
        EXPECT_EQ(e->MaxConnections(), 5);
        EXPECT_FALSE(e->Disabled());

        EXPECT_TRUE(dir.Remove("alice"));
        EXPECT_FALSE(dir.Contains("alice"));
        EXPECT_EQ(dir.Size(), 0);
    }

    TEST(AccountDirectory, ForEachSnapshot)
    {
        Preview::Account::Directory dir;
        dir.Upsert("a", 1);
        dir.Upsert("b", 2);
        dir.Upsert("c", 3);

        std::vector<std::string> creds;
        dir.ForEach([&](std::string_view c, const Preview::Account::SharedEntry &)
                     { creds.emplace_back(c); });
        EXPECT_EQ(creds.size(), 3);
        EXPECT_EQ(dir.Size(), 3);

        dir.Clear();
        EXPECT_EQ(dir.Size(), 0);
    }

    TEST(AccountLease, RaiiRelease)
    {
        Preview::Account::Directory dir;
        dir.Upsert("alice", 2);

        {
            auto l1 = Preview::Account::TryAcquire(dir, "alice");
            auto l2 = Preview::Account::TryAcquire(dir, "alice");
            EXPECT_TRUE(l1);
            EXPECT_TRUE(l2);
            auto e = dir.Find("alice");
            EXPECT_EQ(e->Active(), 2);
            // 第三个被拒（超限）
            EXPECT_FALSE(Preview::Account::TryAcquire(dir, "alice"));
        } // l1/l2 析构 → 释放
        auto e = dir.Find("alice");
        EXPECT_EQ(e->Active(), 0);

        // 释放后可再获取
        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "alice"));
    }

    TEST(AccountLease, MoveSemantics)
    {
        Preview::Account::Directory dir;
        dir.Upsert("bob", 1);

        auto l1 = Preview::Account::TryAcquire(dir, "bob");
        EXPECT_TRUE(l1);
        auto l2 = std::move(l1);
        EXPECT_FALSE(l1); // 移动后空
        EXPECT_TRUE(l2);
        auto e = dir.Find("bob");
        EXPECT_EQ(e->Active(), 1);
    }

    TEST(AccountLease, UnlimitedConnections)
    {
        Preview::Account::Directory dir;
        dir.Upsert("carol", 0); // 0 = 无限制

        std::vector<Preview::Account::Lease> leases;
        for (int i = 0; i < 100; ++i)
        {
            auto l = Preview::Account::TryAcquire(dir, "carol");
            ASSERT_TRUE(l);
            leases.push_back(std::move(l));
        }
        auto e = dir.Find("carol");
        EXPECT_EQ(e->Active(), 100);
    }

    TEST(AccountLease, DisabledRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("dave", 5, true); // 禁用

        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "dave"));
        // 未知账户
        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "nobody"));
    }

    TEST(AccountLease, ExpiredRejected)
    {
        Preview::Account::Directory dir;
        dir.Upsert("eve", 5, false, 1000); // 1000ms 过期

        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "eve", 500));  // 未过期
        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "eve", 1000)); // 过期
        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "eve", 0));     // 不校验
    }

    TEST(AccountLease, SharedEntrySharedQuota)
    {
        Preview::Account::Directory dir;
        // 两凭证共享同一 Entry → 配额共享
        auto shared = std::make_shared<Preview::Account::Entry>(1);
        dir.Insert("Tcp", shared);
        dir.Insert("udp", shared);

        EXPECT_TRUE(Preview::Account::TryAcquire(dir, "Tcp")); // 临时租约：持有一瞬
        auto l_tcp = Preview::Account::TryAcquire(dir, "Tcp");
        ASSERT_TRUE(l_tcp);
        EXPECT_FALSE(Preview::Account::TryAcquire(dir, "udp")); // 共享上限 1
        auto e = dir.Find("Tcp");
        EXPECT_EQ(e->Active(), 1);
    }

} // namespace
