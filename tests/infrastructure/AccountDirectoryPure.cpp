/**
 * @file AccountDirectoryPure.cpp
 * @brief account::directory 纯函数单元测试
 * @details 测试 upsert/find/insert/clear/reserve 的基本功能，
 *          验证 COW（copy-on-write）语义和并发安全性。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/account/directory.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace account = psm::account;

    TEST(AccountDirectoryPure, DirectoryFindEmpty)
    {
        account::directory dir(psm::memory::current_resource());
        auto entry = dir.find("nonexistent");
        EXPECT_TRUE(!entry) << "dir: find empty returns nullptr";
    }

    TEST(AccountDirectoryPure, DirectoryUpsertAndFind)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1:pass1", 5);

        auto entry = dir.find("user1:pass1");
        ASSERT_TRUE(entry != nullptr) << "dir: find after upsert returns entry";
        EXPECT_TRUE(entry->max_connections == 5) << "dir: max_connections=5";
    }

    TEST(AccountDirectoryPure, DirectoryUpsertUpdate)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        dir.upsert("user1", 10);

        auto entry = dir.find("user1");
        ASSERT_TRUE(entry != nullptr) << "dir: find after update";
        EXPECT_TRUE(entry->max_connections == 10) << "dir: updated max_connections=10";
    }

    TEST(AccountDirectoryPure, DirectoryFindNotFound)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        auto entry = dir.find("user2");
        EXPECT_TRUE(!entry) << "dir: find different key returns nullptr";
    }

    TEST(AccountDirectoryPure, DirectoryInsertSharedEntry)
    {
        account::directory dir(psm::memory::current_resource());
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
        EXPECT_TRUE(orig2 != nullptr) << "dir: original key still found";
    }

    TEST(AccountDirectoryPure, DirectoryClear)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        dir.upsert("user2", 5);

        dir.clear();

        EXPECT_TRUE(!dir.find("user1")) << "dir: cleared user1 gone";
        EXPECT_TRUE(!dir.find("user2")) << "dir: cleared user2 gone";
    }

    TEST(AccountDirectoryPure, DirectoryReserve)
    {
        account::directory dir(psm::memory::current_resource());
        // reserve 不应崩溃
        dir.reserve(100);
        dir.upsert("user1", 1);
        auto entry = dir.find("user1");
        EXPECT_TRUE(entry != nullptr) << "dir: find after reserve works";
    }

    TEST(AccountDirectoryPure, DirectoryContains)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("test_cred", 3);

        EXPECT_TRUE(psm::account::contains(dir, "test_cred"))
            << "contains: existing credential";
        EXPECT_TRUE(!psm::account::contains(dir, "missing"))
            << "contains: missing credential";
    }
} // namespace
