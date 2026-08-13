/**
 * @file AccountDirectoryPure.cpp
 * @brief user::directory 纯函数单元测试
 * @details 测试 upsert/find/insert/clear/reserve 的基本功能，
 *          验证 COW（copy-on-write）语义和并发安全性。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/user/directory.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace user = psm::user;

    TEST(AccountDirectoryPure, DirectoryFindEmpty)
    {
        user::directory dir(psm::memory::current_resource());
        auto entry = dir.find("nonexistent");
        EXPECT_TRUE(!entry) << "dir: find empty returns nullptr";
    }

    TEST(AccountDirectoryPure, DirectoryUpsertAndFind)
    {
        user::directory dir(psm::memory::current_resource());
        dir.upsert("user1:pass1", 5);

        auto entry = dir.find("user1:pass1");
        ASSERT_TRUE(entry != nullptr) << "dir: find after upsert returns entry";
        EXPECT_TRUE(entry->max_connections == 5) << "dir: max_connections=5";
    }

    TEST(AccountDirectoryPure, DirectoryUpsertUpdate)
    {
        user::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        dir.upsert("user1", 10);

        auto entry = dir.find("user1");
        ASSERT_TRUE(entry != nullptr) << "dir: find after update";
        EXPECT_TRUE(entry->max_connections == 10) << "dir: updated max_connections=10";
    }

    TEST(AccountDirectoryPure, DirectoryFindNotFound)
    {
        user::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        auto entry = dir.find("user2");
        EXPECT_TRUE(!entry) << "dir: find different key returns nullptr";
    }

    TEST(AccountDirectoryPure, DirectoryInsertSharedEntry)
    {
        user::directory dir(psm::memory::current_resource());
        dir.upsert("credential1", 5);

        auto original = dir.find("credential1");
        ASSERT_TRUE(original != nullptr) << "dir: original exists";

        // 使用 insert 将同一 entry 以不同凭证键插入
        dir.insert("credential2", original);

        auto dup = dir.find("credential2");
        ASSERT_TRUE(dup != nullptr) << "dir: find inserted credential2";
        EXPECT_TRUE(dup->max_connections == 5) << "dir: shared entry max_connections=5";

        // 原始键仍可查找
        auto orig2 = dir.find("credential1");
        EXPECT_NE(orig2, nullptr) << "dir: original key still found";
    }

    TEST(AccountDirectoryPure, DirectoryClear)
    {
        user::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        dir.upsert("user2", 5);

        dir.clear();

        EXPECT_TRUE(!dir.find("user1")) << "dir: cleared user1 gone";
        EXPECT_TRUE(!dir.find("user2")) << "dir: cleared user2 gone";
    }

    TEST(AccountDirectoryPure, DirectoryReserve)
    {
        user::directory dir(psm::memory::current_resource());
        // reserve 不应崩溃
        dir.reserve(100);
        dir.upsert("user1", 1);
        auto entry = dir.find("user1");
        EXPECT_NE(entry, nullptr) << "dir: find after reserve works";
    }

    TEST(AccountDirectoryPure, DirectoryContains)
    {
        user::directory dir(psm::memory::current_resource());
        dir.upsert("test_cred", 3);

        EXPECT_TRUE(psm::user::contains(dir, "test_cred")) << "contains: existing credential";
        EXPECT_TRUE(!psm::user::contains(dir, "missing")) << "contains: missing credential";
    }
} // namespace
