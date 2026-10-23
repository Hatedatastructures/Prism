/**
 * @file MemoryPointerTest.cpp
 * @brief 内存指针体系测试
 * @details 验证 FrameArena/SessionResource 的正确性、生命周期、协议集成与策略约束。
 *          性能对比位于同模块的 Performance 子目录并由 perf label 单独筛选。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Foundation/Memory/Pool.hpp>

namespace
{

    // ── 1. 正确性 ──

    TEST(MemoryPointer, ArenaAllocateAndReset)
    {
        Prism::Memory::FrameArena Arena;
        auto Resource = Arena.Get();
        ASSERT_NE(Resource, nullptr);

        // 分配字符串
        Prism::Memory::String StringValue(Resource);
        StringValue.assign("hello");
        EXPECT_EQ(StringValue, "hello");

        // 分配 vector
        Prism::Memory::Vector<std::uint8_t> Values(Resource);
        Values.push_back(1);
        Values.push_back(2);
        EXPECT_EQ(Values.size(), 2U);

        // reset 后旧对象失效但可重新分配
        Arena.Reset();
        Prism::Memory::String ResetString(Resource);
        ResetString.assign("world");
        EXPECT_EQ(ResetString, "world");
    }

    TEST(MemoryPointer, SessionMemoryContext)
    {
        Prism::Memory::SessionResource Memory;
        auto ContextString = Memory.MakeString("context-string");
        EXPECT_EQ(ContextString, "context-string");

        auto Values = Memory.MakeVector<std::byte>();
        Values.push_back(std::byte{0xAB});
        EXPECT_EQ(Values.size(), 1U);

        Memory.Reset();
        EXPECT_EQ(Memory.MakeString("after-reset"), "after-reset");
    }

    TEST(MemoryPointer, ArenaBufferExhaustionFallback)
    {
        // 8KB 缓冲耗尽后回退上游（local_pool），不崩溃
        Prism::Memory::FrameArena Arena;
        auto Resource = Arena.Get();
        std::vector<Prism::Memory::String> Objects;
        for (int Index = 0; Index < 200; ++Index)
        {
            Prism::Memory::String StringValue(Resource);
            StringValue.assign(64, static_cast<char>('a' + (Index % 26)));
            Objects.push_back(std::move(StringValue));
        }
        EXPECT_EQ(Objects.size(), 200U);
        // 数据完整
        EXPECT_EQ(Objects[0][0], 'a');
        EXPECT_EQ(Objects[199][0], 'a' + (199 % 26));
    }

    // ── 2. 生命周期 ──

    TEST(MemoryPointer, ArenaLifetimeWithinScope)
    {
        Prism::Memory::String *StringPointer = nullptr;
        {
            Prism::Memory::FrameArena Arena;
            auto Resource = Arena.Get();
            auto StringValue = std::make_unique<Prism::Memory::String>(Resource);
            StringValue->assign("scoped");
            StringPointer = StringValue.get();
            EXPECT_EQ(*StringPointer, "scoped");
        }
        // 离开作用域后 arena 析构，指针不再有效（不访问——仅验证不崩溃）
        SUCCEED();
    }

    // ── 3. 与协议层集成模式（conn 持有 SessionResource） ──

    TEST(MemoryPointer, ConnHoldsSessionMemory)
    {
        // 模拟 conn 持有 SessionResource：arena 分配随 conn 存活
        struct FakeConn
        {
            Prism::Memory::SessionResource<> Memory;
            auto TargetString() -> Prism::Memory::String
            {
                return Memory.MakeString("conn-target");
            }
        };
        auto Connection = std::make_shared<FakeConn>();
        auto Target = Connection->TargetString();
        EXPECT_EQ(Target, "conn-target");
    }

    // ── 4. 策略约束（memory_policy concept） ──

    // 合法策略：SessionResource<> 应满足约束
    static_assert(Prism::Memory::Restrict<Prism::Memory::SessionResource<>>);
    // 自定义大小同样满足
    static_assert(Prism::Memory::Restrict<Prism::Memory::SessionResource<32768>>);
    // 非策略类型不满足约束（编译期拒绝）
    static_assert(!Prism::Memory::Restrict<int>);
    static_assert(!Prism::Memory::Restrict<std::string>);

    TEST(MemoryPointer, MemoryPolicyConstraint)
    {
        // 策略容器类型可用性
        using ResourceType = Prism::Memory::SessionResource<>;
        ResourceType Memory;
        typename ResourceType::template Buffer<std::uint8_t> Buffer = Memory.MakeBuffer<std::uint8_t>(64);
        EXPECT_EQ(Buffer.size(), 64U);
        typename ResourceType::DynamicString StringValue = Memory.MakeString("policy-str");
        EXPECT_EQ(StringValue, "policy-str");
        EXPECT_EQ(ResourceType::GetArenaSize(), 8192U);
    }

    TEST(MemoryPointer, MakeBufferUsesSelectedResource)
    {
        Prism::Memory::SessionResource<> Memory;

        auto Small = Memory.MakeBuffer<std::uint8_t>(64);
        EXPECT_EQ(Small.get_allocator().resource(), Memory.Arena());

        auto Large = Memory.MakeBuffer<std::uint8_t>(8193);
        EXPECT_EQ(Large.get_allocator().resource(), Prism::Memory::System::LocalPool());

        auto Wide = Memory.MakeBuffer<std::uint64_t>(2048);
        EXPECT_EQ(Wide.get_allocator().resource(), Prism::Memory::System::LocalPool());
    }

} // namespace
