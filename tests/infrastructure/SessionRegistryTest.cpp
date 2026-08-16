/**
 * @file SessionRegistryTest.cpp
 * @brief 会话注册表测试（T5-7 O6）
 * @details 覆盖：
 *          - put/remove/find/数量
 *          - 值拷贝快照隔离（快照不受后续修改影响）
 *          - 快照遍历安全（独立拷贝，无 L3 引用）
 *          - 批量注册/移除
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>

#include <common/core/runtime/session_registry.hpp>

namespace
{

    auto make_info(std::uint64_t id) -> psmtest::runtime::session_info
    {
        psmtest::runtime::session_info info;
        info.id = id;
        info.identity = "user-" + std::to_string(id);
        info.peer = "127.0.0.1";
        info.target = "example.com:443";
        info.protocol = 1;
        info.started_at = id * 100;
        return info;
    }

    TEST(SessionRegistry, PutFindRemove)
    {
        psmtest::runtime::session_registry reg;
        reg.put(make_info(1));
        reg.put(make_info(2));

        EXPECT_EQ(reg.size(), 2);
        psmtest::runtime::session_info out;
        EXPECT_TRUE(reg.find(1, out));
        EXPECT_EQ(out.identity, "user-1");
        EXPECT_TRUE(reg.find(2, out));
        EXPECT_EQ(out.peer, "127.0.0.1");

        EXPECT_FALSE(reg.find(99, out));

        EXPECT_TRUE(reg.remove(1));
        EXPECT_FALSE(reg.find(1, out));
        EXPECT_EQ(reg.size(), 1);
        EXPECT_FALSE(reg.remove(1));
    }

    TEST(SessionRegistry, SnapshotIsolation)
    {
        psmtest::runtime::session_registry reg;
        reg.put(make_info(1));

        auto snap1 = reg.snapshot();
        reg.put(make_info(2)); // 后续修改
        reg.remove(1);

        // 旧快照不受影响（值拷贝隔离）
        ASSERT_EQ(snap1->size(), 1);
        EXPECT_EQ(snap1->at(1).identity, "user-1");
        EXPECT_EQ(reg.size(), 1);
    }

    TEST(SessionRegistry, SnapshotTraversalSafe)
    {
        psmtest::runtime::session_registry reg;
        for (std::uint64_t i = 1; i <= 10; ++i)
        {
            reg.put(make_info(i));
        }

        const auto snap = reg.snapshot();
        std::uint64_t sum_ids = 0;
        for (const auto &[id, info] : *snap)
        {
            sum_ids += id;
            EXPECT_EQ(info.started_at, id * 100);
        }
        EXPECT_EQ(sum_ids, 55);

        // 快照与注册表解耦（修改注册表不影响遍历中的快照）
        reg.remove(5);
        EXPECT_EQ(snap->size(), 10);
        EXPECT_EQ(reg.size(), 9);
    }

    TEST(SessionRegistry, BulkPutRemove)
    {
        psmtest::runtime::session_registry reg;
        for (std::uint64_t i = 1; i <= 1000; ++i)
        {
            reg.put(make_info(i));
        }
        EXPECT_EQ(reg.size(), 1000);

        for (std::uint64_t i = 1; i <= 1000; i += 2)
        {
            reg.remove(i);
        }
        EXPECT_EQ(reg.size(), 500);
    }

    TEST(SessionRegistry, OverwriteSameId)
    {
        psmtest::runtime::session_registry reg;
        reg.put(make_info(1));
        auto info2 = make_info(1);
        info2.target = "updated";
        reg.put(info2);

        EXPECT_EQ(reg.size(), 1);
        psmtest::runtime::session_info out;
        EXPECT_TRUE(reg.find(1, out));
        EXPECT_EQ(out.target, "updated");
    }

} // namespace
