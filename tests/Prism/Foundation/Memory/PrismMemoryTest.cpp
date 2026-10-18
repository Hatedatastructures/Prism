/**
 * @file PrismMemoryTest.cpp
 * @brief Prism 内存体系测试（Core/Memory）
 * @details 覆盖 Prism::Memory 基础设施：
 * 1. 容器别名（string/vector 使用 PMR 分配器）
 * 2. 内存池系统（GlobalPool/LocalPool/HotPool）
 * 3. FrameArena 会话级竞技场（分配/Reset/耗尽回退）
 * 4. SessionResource 会话内存上下文（MakeString/MakeVector）
 * 5. CurrentResource/EffectiveMr 资源选择
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <Prism/Foundation/FlatBuffer.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Foundation/Memory/Pool.hpp>

namespace
{

    // ── 1. 容器别名 ──

    TEST(PrismMemory, ContainerAliases)
    {
        Prism::Memory::String s;
        s.assign("hello");
        EXPECT_EQ(s, "hello");

        Prism::Memory::Vector<std::uint8_t> v;
        v.push_back(1);
        v.push_back(2);
        EXPECT_EQ(v.size(), 2U);
        EXPECT_EQ(v[0], 1U);
    }

    // ── 2. 内存池系统 ──

    TEST(PrismMemory, PoolSystem)
    {
        EXPECT_NE(Prism::Memory::System::GlobalPool(), nullptr);
        EXPECT_NE(Prism::Memory::System::LocalPool(), nullptr);
        EXPECT_NE(Prism::Memory::System::HotPool(), nullptr);
        // HotPool 与 LocalPool 语义等价（线程局部）
        EXPECT_EQ(Prism::Memory::System::HotPool(), Prism::Memory::System::LocalPool());
    }

    // ── 3. FrameArena ──

    TEST(PrismMemory, FrameArenaAllocateReset)
    {
        Prism::Memory::FrameArena Arena;
        auto mr = Arena.Get();
        ASSERT_NE(mr, nullptr);

        Prism::Memory::String s(mr);
        s.assign("Frame");
        EXPECT_EQ(s, "Frame");

        Prism::Memory::Vector<std::uint8_t> v(mr);
        v.push_back(0xAB);
        EXPECT_EQ(v.size(), 1U);

        // Reset 后旧对象失效但可重新分配
        Arena.Reset();
        Prism::Memory::String s2(mr);
        s2.assign("after-Reset");
        EXPECT_EQ(s2, "after-Reset");
    }

    TEST(PrismMemory, FrameArenaExhaustionFallback)
    {
        // 8KB 栈缓冲耗尽后回退线程局部池，不崩溃
        Prism::Memory::FrameArena Arena;
        auto mr = Arena.Get();
        std::vector<Prism::Memory::String> objs;
        for (int i = 0; i < 200; ++i)
        {
            Prism::Memory::String s(mr);
            s.assign(64, static_cast<char>('a' + (i % 26)));
            objs.push_back(std::move(s));
        }
        EXPECT_EQ(objs.size(), 200U);
        EXPECT_EQ(objs[199].size(), 64U);
    }

    TEST(PrismMemory, FrameArenaSize)
    {
        EXPECT_EQ(Prism::Memory::FrameArena<>::Size(), 8192U);
        EXPECT_EQ(Prism::Memory::FrameArena<4096>::Size(), 4096U);
    }

    // ── 4. SessionResource ──

    TEST(PrismMemory, SessionResource)
    {
        Prism::Memory::SessionResource mem;
        auto s = mem.MakeString("Context");
        EXPECT_EQ(s, "Context");

        auto v = mem.MakeVector<std::byte>();
        v.push_back(std::byte{0x01});
        EXPECT_EQ(v.size(), 1U);

        mem.Reset();
        EXPECT_EQ(mem.MakeString("after-Reset"), "after-Reset");
        EXPECT_EQ(Prism::Memory::SessionResource<>::GetArenaSize(), 8192U);
    }

    // ── 5. 资源选择 ──

    TEST(PrismMemory, ResourceSelection)
    {
        EXPECT_NE(Prism::Memory::CurrentResource(), nullptr);
        EXPECT_EQ(Prism::Memory::EffectiveMr(nullptr), Prism::Memory::CurrentResource());

        Prism::Memory::FrameArena Arena;
        EXPECT_EQ(Prism::Memory::EffectiveMr(Arena.Get()), Arena.Get());
    }

    TEST(FlatBuffer, HonorsConfiguredInitialSizeAfterShrink)
    {
        Prism::FlatBuffer buffer(8);
        const std::vector<std::uint8_t> payload(32, 0xA5);

        ASSERT_EQ(buffer.Append(payload), payload.size());
        buffer.Consume(buffer.Size());
        buffer.ShrinkToFit();

        EXPECT_EQ(buffer.Capacity(), 8u);
    }

    TEST(FlatBuffer, RejectsPrepareSizeOverflow)
    {
        Prism::FlatBuffer buffer(1);
        const std::array<std::uint8_t, 1> byte{0x01};
        ASSERT_EQ(buffer.Append(byte), 1u);

        EXPECT_TRUE(buffer.Prepare(std::numeric_limits<std::size_t>::max()).empty());
        EXPECT_EQ(buffer.Size(), 1u);
    }

} // namespace
