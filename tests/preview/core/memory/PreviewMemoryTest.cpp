/**
 * @file PreviewMemoryTest.cpp
 * @brief Preview 内存体系测试（core/memory）
 * @details 覆盖 Preview::Memory 基础设施：
 * 1. 容器别名（string/vector 使用 PMR 分配器）
 * 2. 内存池系统（GlobalPool/LocalPool/HotPool）
 * 3. FrameArena 会话级竞技场（分配/Reset/耗尽回退）
 * 4. SessionResource 会话内存上下文（MakeString/MakeVector）
 * 5. CurrentResource/EffectiveMr 资源选择
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Foundation/Memory/Pool.hpp>

namespace
{

    // ── 1. 容器别名 ──

    TEST(PreviewMemory, ContainerAliases)
    {
        Preview::Memory::String s;
        s.assign("hello");
        EXPECT_EQ(s, "hello");

        Preview::Memory::Vector<std::uint8_t> v;
        v.push_back(1);
        v.push_back(2);
        EXPECT_EQ(v.size(), 2U);
        EXPECT_EQ(v[0], 1U);
    }

    // ── 2. 内存池系统 ──

    TEST(PreviewMemory, PoolSystem)
    {
        EXPECT_NE(Preview::Memory::System::GlobalPool(), nullptr);
        EXPECT_NE(Preview::Memory::System::LocalPool(), nullptr);
        EXPECT_NE(Preview::Memory::System::HotPool(), nullptr);
        // HotPool 与 LocalPool 语义等价（线程局部）
        EXPECT_EQ(Preview::Memory::System::HotPool(), Preview::Memory::System::LocalPool());
    }

    // ── 3. FrameArena ──

    TEST(PreviewMemory, FrameArenaAllocateReset)
    {
        Preview::Memory::FrameArena Arena;
        auto mr = Arena.Get();
        ASSERT_NE(mr, nullptr);

        Preview::Memory::String s(mr);
        s.assign("Frame");
        EXPECT_EQ(s, "Frame");

        Preview::Memory::Vector<std::uint8_t> v(mr);
        v.push_back(0xAB);
        EXPECT_EQ(v.size(), 1U);

        // Reset 后旧对象失效但可重新分配
        Arena.Reset();
        Preview::Memory::String s2(mr);
        s2.assign("after-Reset");
        EXPECT_EQ(s2, "after-Reset");
    }

    TEST(PreviewMemory, FrameArenaExhaustionFallback)
    {
        // 8KB 栈缓冲耗尽后回退线程局部池，不崩溃
        Preview::Memory::FrameArena Arena;
        auto mr = Arena.Get();
        std::vector<Preview::Memory::String> objs;
        for (int i = 0; i < 200; ++i)
        {
            Preview::Memory::String s(mr);
            s.assign(64, static_cast<char>('a' + (i % 26)));
            objs.push_back(std::move(s));
        }
        EXPECT_EQ(objs.size(), 200U);
        EXPECT_EQ(objs[199].size(), 64U);
    }

    TEST(PreviewMemory, FrameArenaSize)
    {
        EXPECT_EQ(Preview::Memory::FrameArena<>::Size(), 8192U);
        EXPECT_EQ(Preview::Memory::FrameArena<4096>::Size(), 4096U);
    }

    // ── 4. SessionResource ──

    TEST(PreviewMemory, SessionResource)
    {
        Preview::Memory::SessionResource mem;
        auto s = mem.MakeString("Context");
        EXPECT_EQ(s, "Context");

        auto v = mem.MakeVector<std::byte>();
        v.push_back(std::byte{0x01});
        EXPECT_EQ(v.size(), 1U);

        mem.Reset();
        EXPECT_EQ(mem.MakeString("after-Reset"), "after-Reset");
        EXPECT_EQ(Preview::Memory::SessionResource<>::GetArenaSize(), 8192U);
    }

    // ── 5. 资源选择 ──

    TEST(PreviewMemory, ResourceSelection)
    {
        EXPECT_NE(Preview::Memory::CurrentResource(), nullptr);
        EXPECT_EQ(Preview::Memory::EffectiveMr(nullptr), Preview::Memory::CurrentResource());

        Preview::Memory::FrameArena Arena;
        EXPECT_EQ(Preview::Memory::EffectiveMr(Arena.Get()), Arena.Get());
    }

} // namespace
