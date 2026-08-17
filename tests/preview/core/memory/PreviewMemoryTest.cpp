/**
 * @file PreviewMemoryTest.cpp
 * @brief preview 内存体系测试（core/memory）
 * @details 覆盖 preview::memory 基础设施：
 * 1. 容器别名（string/vector 使用 PMR 分配器）
 * 2. 内存池系统（global_pool/local_pool/hot_pool）
 * 3. frame_arena 会话级竞技场（分配/reset/耗尽回退）
 * 4. session_resource 会话内存上下文（make_string/make_vector）
 * 5. current_resource/effective_mr 资源选择
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/memory/pool.hpp>

namespace
{

    // ── 1. 容器别名 ──

    TEST(PreviewMemory, ContainerAliases)
    {
        preview::memory::string s;
        s.assign("hello");
        EXPECT_EQ(s, "hello");

        preview::memory::vector<std::uint8_t> v;
        v.push_back(1);
        v.push_back(2);
        EXPECT_EQ(v.size(), 2U);
        EXPECT_EQ(v[0], 1U);
    }

    // ── 2. 内存池系统 ──

    TEST(PreviewMemory, PoolSystem)
    {
        EXPECT_NE(preview::memory::system::global_pool(), nullptr);
        EXPECT_NE(preview::memory::system::local_pool(), nullptr);
        EXPECT_NE(preview::memory::system::hot_pool(), nullptr);
        // hot_pool 与 local_pool 语义等价（线程局部）
        EXPECT_EQ(preview::memory::system::hot_pool(), preview::memory::system::local_pool());
    }

    // ── 3. frame_arena ──

    TEST(PreviewMemory, FrameArenaAllocateReset)
    {
        preview::memory::frame_arena arena;
        auto mr = arena.get();
        ASSERT_NE(mr, nullptr);

        preview::memory::string s(mr);
        s.assign("frame");
        EXPECT_EQ(s, "frame");

        preview::memory::vector<std::uint8_t> v(mr);
        v.push_back(0xAB);
        EXPECT_EQ(v.size(), 1U);

        // reset 后旧对象失效但可重新分配
        arena.reset();
        preview::memory::string s2(mr);
        s2.assign("after-reset");
        EXPECT_EQ(s2, "after-reset");
    }

    TEST(PreviewMemory, FrameArenaExhaustionFallback)
    {
        // 8KB 栈缓冲耗尽后回退线程局部池，不崩溃
        preview::memory::frame_arena arena;
        auto mr = arena.get();
        std::vector<preview::memory::string> objs;
        for (int i = 0; i < 200; ++i)
        {
            preview::memory::string s(mr);
            s.assign(64, static_cast<char>('a' + (i % 26)));
            objs.push_back(std::move(s));
        }
        EXPECT_EQ(objs.size(), 200U);
        EXPECT_EQ(objs[199].size(), 64U);
    }

    TEST(PreviewMemory, FrameArenaSize)
    {
        EXPECT_EQ(preview::memory::frame_arena<>::size(), 8192U);
        EXPECT_EQ(preview::memory::frame_arena<4096>::size(), 4096U);
    }

    // ── 4. session_resource ──

    TEST(PreviewMemory, SessionResource)
    {
        preview::memory::session_resource mem;
        auto s = mem.make_string("context");
        EXPECT_EQ(s, "context");

        auto v = mem.make_vector<std::byte>();
        v.push_back(std::byte{0x01});
        EXPECT_EQ(v.size(), 1U);

        mem.reset();
        EXPECT_EQ(mem.make_string("after-reset"), "after-reset");
        EXPECT_EQ(preview::memory::session_resource<>::arena_size(), 8192U);
    }

    // ── 5. 资源选择 ──

    TEST(PreviewMemory, ResourceSelection)
    {
        EXPECT_NE(preview::memory::current_resource(), nullptr);
        EXPECT_EQ(preview::memory::effective_mr(nullptr), preview::memory::current_resource());

        preview::memory::frame_arena arena;
        EXPECT_EQ(preview::memory::effective_mr(arena.get()), arena.get());
    }

} // namespace