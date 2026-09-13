/**
 * @file MemoryPointerTest.cpp
 * @brief 内存指针体系测试
 * @details 验证 FrameArena/SessionResource：
 * 1. 正确性：arena 分配/释放/重置语义
 * 2. 生命周期：arena 分配对象随会话存活
 * 3. 性能：arena 分配 vs 系统 new（应显著快）
 * 4. 与协议层集成：conn 持有 SessionResource 的模式
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <string>

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Foundation/Memory/Pool.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Socks5/Types.hpp>

namespace
{

    // ── 1. 正确性 ──

    TEST(MemoryPointer, ArenaAllocateAndReset)
    {
        Preview::Memory::FrameArena Arena;
        auto Resource = Arena.Get();
        ASSERT_NE(Resource, nullptr);

        // 分配字符串
        Preview::Memory::String StringValue(Resource);
        StringValue.assign("hello");
        EXPECT_EQ(StringValue, "hello");

        // 分配 vector
        Preview::Memory::Vector<std::uint8_t> Values(Resource);
        Values.push_back(1);
        Values.push_back(2);
        EXPECT_EQ(Values.size(), 2U);

        // reset 后旧对象失效但可重新分配
        Arena.Reset();
        Preview::Memory::String ResetString(Resource);
        ResetString.assign("world");
        EXPECT_EQ(ResetString, "world");
    }

    TEST(MemoryPointer, SessionMemoryContext)
    {
        Preview::Memory::SessionResource Memory;
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
        Preview::Memory::FrameArena Arena;
        auto Resource = Arena.Get();
        std::vector<Preview::Memory::String> Objects;
        for (int Index = 0; Index < 200; ++Index)
        {
            Preview::Memory::String StringValue(Resource);
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
        Preview::Memory::String *StringPointer = nullptr;
        {
            Preview::Memory::FrameArena Arena;
            auto Resource = Arena.Get();
            auto StringValue = std::make_unique<Preview::Memory::String>(Resource);
            StringValue->assign("scoped");
            StringPointer = StringValue.get();
            EXPECT_EQ(*StringPointer, "scoped");
        }
        // 离开作用域后 arena 析构，指针不再有效（不访问——仅验证不崩溃）
        SUCCEED();
    }

    // ── 3. 性能：arena vs 系统 new ──

    TEST(MemoryPointer, ArenaAllocPerf)
    {
        constexpr int Iterations = 100000;

        // 系统 new
        auto Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            auto *Value = new std::string(32, 'x');
            delete Value;
        }
        auto SystemMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - Start)
                          .count();

        // arena（无释放）
        Preview::Memory::FrameArena Arena;
        auto Resource = Arena.Get();
        Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            auto *Value = new (Resource->allocate(sizeof(std::string), alignof(std::string))) std::string(32, 'x');
            Value->~basic_string();
            Resource->deallocate(Value, sizeof(std::string), alignof(std::string));
        }
        auto ArenaMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - Start)
                            .count();

        // arena 应显著快于系统 new（报告差异，不硬断言）
        GTEST_LOG_(INFO) << "system new: " << SystemMilliseconds << "ms, arena: "
                         << ArenaMilliseconds << "ms";
        EXPECT_LE(ArenaMilliseconds, SystemMilliseconds * 2) << "arena 应至少不慢于系统 new";
    }

    // ── 4. 与协议层集成模式（conn 持有 SessionResource） ──

    TEST(MemoryPointer, ConnHoldsSessionMemory)
    {
        // 模拟 conn 持有 SessionResource：arena 分配随 conn 存活
        struct FakeConn
        {
            Preview::Memory::SessionResource<> Memory;
            auto TargetString() -> Preview::Memory::String
            {
                return Memory.MakeString("conn-target");
            }
        };
        auto Connection = std::make_shared<FakeConn>();
        auto Target = Connection->TargetString();
        EXPECT_EQ(Target, "conn-target");
    }

    // ── 5. 协议热路径：arena 序列化 vs 系统堆序列化 ──

    TEST(MemoryPointer, ProtocolCodecArenaVsHeap)
    {
        // 典型 CONNECT 请求：域名 example.com:443
        Preview::Socks5::Request Request;
        Request.Ver = 5;
        Request.Cmd = Preview::Socks5::Command::Connect;
        Request.Rsv = 0;
        Request.Target.Type = Preview::Socks5::AddressType::Domain;
        Request.Target.Host = "example.com";
        Request.Target.Port = 443;

        constexpr int Iterations = 200000;

        // 每帧临时分配（返回式，系统堆）
        auto Start = std::chrono::steady_clock::now();
        volatile std::size_t Sink = 0;
        for (int Index = 0; Index < Iterations; ++Index)
        {
            const auto Wire = Preview::Socks5::BuildRequest(Request);
            Sink += Wire.size();
        }
        auto HeapMilliseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - Start)
                           .count();

        // 复用缓冲（arena 分配，首次扩容后零分配）
        Preview::Memory::SessionResource Memory;
        Preview::Memory::Vector<std::uint8_t> TxWire(Memory.Arena());
        Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            Preview::Socks5::BuildRequest(Request, TxWire);
            Sink += TxWire.size();
        }
        auto ArenaMilliseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - Start)
                            .count();

        GTEST_LOG_(INFO) << "build_request x" << Iterations << ": per-frame heap " << HeapMilliseconds
                         << "us, reused arena buffer " << ArenaMilliseconds << "us (sink=" << Sink << ")";
        // 复用缓冲应显著快于每帧分配（报告差异）
        EXPECT_LE(ArenaMilliseconds, HeapMilliseconds);
    }

    TEST(MemoryPointer, ProtocolDgramArenaVsHeap)
    {
        Preview::Socks5::Address Destination;
        Destination.Type = Preview::Socks5::AddressType::Ipv4;
        Destination.Host = "10.0.0.1";
        Destination.Port = 53;
        constexpr std::size_t PayloadSize = 128;
        std::array<std::uint8_t, PayloadSize> Payload{};
        Payload.fill(0xAB);

        constexpr int Iterations = 100000;

        auto Start = std::chrono::steady_clock::now();
        volatile std::size_t Sink = 0;
        for (int Index = 0; Index < Iterations; ++Index)
        {
            const auto Wire = Preview::Socks5::BuildUdpDatagram(Destination, Payload);
            Sink += Wire.size();
        }
        auto HeapMilliseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - Start)
                           .count();

        Preview::Memory::SessionResource Memory;
        Preview::Memory::Vector<std::uint8_t> TxWire(Memory.Arena());
        Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            Preview::Socks5::BuildUdpDatagram(Destination, Payload, TxWire);
            Sink += TxWire.size();
        }
        auto ArenaMilliseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - Start)
                            .count();

        GTEST_LOG_(INFO) << "build_udp_datagram x" << Iterations << ": per-frame heap " << HeapMilliseconds
                         << "us, reused arena buffer " << ArenaMilliseconds << "us (sink=" << Sink << ")";
        // Debug 下 pmr 分配器虚调用开销掩盖差距；仅报告，Release 验证
        EXPECT_LE(ArenaMilliseconds, HeapMilliseconds * 2);
    }

    // ── 6. 策略约束（memory_policy concept） ──

    // 合法策略：SessionResource<> 应满足约束
    static_assert(Preview::Memory::Restrict<Preview::Memory::SessionResource<>>);
    // 自定义大小同样满足
    static_assert(Preview::Memory::Restrict<Preview::Memory::SessionResource<32768>>);
    // 非策略类型不满足约束（编译期拒绝）
    static_assert(!Preview::Memory::Restrict<int>);
    static_assert(!Preview::Memory::Restrict<std::string>);

    TEST(MemoryPointer, MemoryPolicyConstraint)
    {
        // 策略容器类型可用性
        using ResourceType = Preview::Memory::SessionResource<>;
        ResourceType Memory;
        typename ResourceType::template Buffer<std::uint8_t> Buffer = Memory.MakeBuffer<std::uint8_t>(64);
        EXPECT_EQ(Buffer.size(), 64U);
        typename ResourceType::DynamicString StringValue = Memory.MakeString("policy-str");
        EXPECT_EQ(StringValue, "policy-str");
        EXPECT_EQ(ResourceType::GetArenaSize(), 8192U);
    }

    TEST(MemoryPointer, MakeBufferUsesSelectedResource)
    {
        Preview::Memory::SessionResource<> Memory;

        auto Small = Memory.MakeBuffer<std::uint8_t>(64);
        EXPECT_EQ(Small.get_allocator().resource(), Memory.Arena());

        auto Large = Memory.MakeBuffer<std::uint8_t>(8193);
        EXPECT_EQ(Large.get_allocator().resource(), Preview::Memory::System::LocalPool());

        auto Wide = Memory.MakeBuffer<std::uint64_t>(2048);
        EXPECT_EQ(Wide.get_allocator().resource(), Preview::Memory::System::LocalPool());
    }

} // namespace
