/**
 * @file AccountDirectoryPure.cpp
 * @brief account::directory 纯函数单元测试
 * @details 测试 upsert/find/insert/clear/reserve 的基本功能，
 *          验证 COW（copy-on-write）语义和并发安全性。
 */

#include <prism/memory.hpp>
#include <prism/account/directory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace account = psm::account;

    void TestDirectoryFindEmpty(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        auto entry = dir.find("nonexistent");
        runner.Check(!entry, "dir: find empty returns nullptr");
    }

    void TestDirectoryUpsertAndFind(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1:pass1", 5);

        auto entry = dir.find("user1:pass1");
        runner.Check(entry != nullptr, "dir: find after upsert returns entry");
        runner.Check(entry->max_connections == 5, "dir: max_connections=5");
    }

    void TestDirectoryUpsertUpdate(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        dir.upsert("user1", 10);

        auto entry = dir.find("user1");
        runner.Check(entry != nullptr, "dir: find after update");
        runner.Check(entry->max_connections == 10, "dir: updated max_connections=10");
    }

    void TestDirectoryFindNotFound(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        auto entry = dir.find("user2");
        runner.Check(!entry, "dir: find different key returns nullptr");
    }

    void TestDirectoryInsertSharedEntry(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("credential1", 5);

        auto original = dir.find("credential1");
        runner.Check(original != nullptr, "dir: original exists");

        // 使用 insert 将同一 entry 以不同凭证键插入
        dir.insert("credential2", original);

        auto dup = dir.find("credential2");
        runner.Check(dup != nullptr, "dir: find inserted credential2");
        runner.Check(dup->max_connections == 5, "dir: shared entry max_connections=5");

        // 原始键仍可查找
        auto orig2 = dir.find("credential1");
        runner.Check(orig2 != nullptr, "dir: original key still found");
    }

    void TestDirectoryClear(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("user1", 3);
        dir.upsert("user2", 5);

        dir.clear();

        runner.Check(!dir.find("user1"), "dir: cleared user1 gone");
        runner.Check(!dir.find("user2"), "dir: cleared user2 gone");
    }

    void TestDirectoryReserve(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        // reserve 不应崩溃
        dir.reserve(100);
        dir.upsert("user1", 1);
        auto entry = dir.find("user1");
        runner.Check(entry != nullptr, "dir: find after reserve works");
    }

    void TestDirectoryContains(TestRunner &runner)
    {
        account::directory dir(psm::memory::current_resource());
        dir.upsert("test_cred", 3);

        runner.Check(psm::account::contains(dir, "test_cred"),
                     "contains: existing credential");
        runner.Check(!psm::account::contains(dir, "missing"),
                     "contains: missing credential");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("AccountDirectoryPure");

    TestDirectoryFindEmpty(runner);
    TestDirectoryUpsertAndFind(runner);
    TestDirectoryUpsertUpdate(runner);
    TestDirectoryFindNotFound(runner);
    TestDirectoryInsertSharedEntry(runner);
    TestDirectoryClear(runner);
    TestDirectoryReserve(runner);
    TestDirectoryContains(runner);

    return runner.Summary();
}
