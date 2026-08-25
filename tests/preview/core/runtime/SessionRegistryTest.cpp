/**
 * @file SessionRegistryTest.cpp
 * @brief 会话注册表测试（T5-7 O6）
 * @details 覆盖：
 *          - Put/Remove/Find/数量
 *          - 值拷贝快照隔离（快照不受后续修改影响）
 *          - 快照遍历安全（独立拷贝，无 L3 引用）
 *          - 批量注册/移除
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>

#include <common/Core/Runtime/SessionRegistry.hpp>

namespace
{

    auto make_info(std::uint64_t Id) -> Preview::Runtime::SessionInfo
    {
        Preview::Runtime::SessionInfo Info;
        Info.Id = Id;
        Info.identity = "user-" + std::to_string(Id);
        Info.peer = "127.0.0.1";
        Info.Target = "example.com:443";
        Info.Protocol = 1;
        Info.StartedAt = Id * 100;
        return Info;
    }

    TEST(SessionRegistry, PutFindRemove)
    {
        Preview::Runtime::SessionRegistry reg;
        reg.Put(make_info(1));
        reg.Put(make_info(2));

        EXPECT_EQ(reg.Size(), 2);
        Preview::Runtime::SessionInfo out;
        EXPECT_TRUE(reg.Find(1, out));
        EXPECT_EQ(out.identity, "user-1");
        EXPECT_TRUE(reg.Find(2, out));
        EXPECT_EQ(out.peer, "127.0.0.1");

        EXPECT_FALSE(reg.Find(99, out));

        EXPECT_TRUE(reg.Remove(1));
        EXPECT_FALSE(reg.Find(1, out));
        EXPECT_EQ(reg.Size(), 1);
        EXPECT_FALSE(reg.Remove(1));
    }

    TEST(SessionRegistry, SnapshotIsolation)
    {
        Preview::Runtime::SessionRegistry reg;
        reg.Put(make_info(1));

        auto snap1 = reg.Snapshot();
        reg.Put(make_info(2)); // 后续修改
        reg.Remove(1);

        // 旧快照不受影响（值拷贝隔离）
        ASSERT_EQ(snap1->size(), 1);
        EXPECT_EQ(snap1->at(1).identity, "user-1");
        EXPECT_EQ(reg.Size(), 1);
    }

    TEST(SessionRegistry, SnapshotTraversalSafe)
    {
        Preview::Runtime::SessionRegistry reg;
        for (std::uint64_t i = 1; i <= 10; ++i)
        {
            reg.Put(make_info(i));
        }

        const auto snap = reg.Snapshot();
        std::uint64_t sum_ids = 0;
        for (const auto &[Id, Info] : *snap)
        {
            sum_ids += Id;
            EXPECT_EQ(Info.StartedAt, Id * 100);
        }
        EXPECT_EQ(sum_ids, 55);

        // 快照与注册表解耦（修改注册表不影响遍历中的快照）
        reg.Remove(5);
        EXPECT_EQ(snap->size(), 10);
        EXPECT_EQ(reg.Size(), 9);
    }

    TEST(SessionRegistry, BulkPutRemove)
    {
        Preview::Runtime::SessionRegistry reg;
        for (std::uint64_t i = 1; i <= 1000; ++i)
        {
            reg.Put(make_info(i));
        }
        EXPECT_EQ(reg.Size(), 1000);

        for (std::uint64_t i = 1; i <= 1000; i += 2)
        {
            reg.Remove(i);
        }
        EXPECT_EQ(reg.Size(), 500);
    }

    TEST(SessionRegistry, OverwriteSameId)
    {
        Preview::Runtime::SessionRegistry reg;
        reg.Put(make_info(1));
        auto info2 = make_info(1);
        info2.Target = "updated";
        reg.Put(info2);

        EXPECT_EQ(reg.Size(), 1);
        Preview::Runtime::SessionInfo out;
        EXPECT_TRUE(reg.Find(1, out));
        EXPECT_EQ(out.Target, "updated");
    }

} // namespace
