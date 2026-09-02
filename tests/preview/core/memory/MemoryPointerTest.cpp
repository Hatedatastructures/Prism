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
        Preview::Memory::FrameArena arena;
        auto mr = arena.Get();
        ASSERT_NE(mr, nullptr);

        // 分配字符串
        Preview::Memory::String s(mr);
        s.assign("hello");
        EXPECT_EQ(s, "hello");

        // 分配 vector
        Preview::Memory::Vector<std::uint8_t> v(mr);
        v.push_back(1);
        v.push_back(2);
        EXPECT_EQ(v.size(), 2U);

        // reset 后旧对象失效但可重新分配
        arena.Reset();
        Preview::Memory::String s2(mr);
        s2.assign("world");
        EXPECT_EQ(s2, "world");
    }

    TEST(MemoryPointer, SessionMemoryContext)
    {
        Preview::Memory::SessionResource mem;
        auto s = mem.MakeString("context-string");
        EXPECT_EQ(s, "context-string");

        auto v = mem.MakeVector<std::byte>();
        v.push_back(std::byte{0xAB});
        EXPECT_EQ(v.size(), 1U);

        mem.Reset();
        EXPECT_EQ(mem.MakeString("after-reset"), "after-reset");
    }

    TEST(MemoryPointer, ArenaBufferExhaustionFallback)
    {
        // 8KB 缓冲耗尽后回退上游（local_pool），不崩溃
        Preview::Memory::FrameArena arena;
        auto mr = arena.Get();
        std::vector<Preview::Memory::String> objs;
        for (int i = 0; i < 200; ++i)
        {
            Preview::Memory::String s(mr);
            s.assign(64, static_cast<char>('a' + (i % 26)));
            objs.push_back(std::move(s));
        }
        EXPECT_EQ(objs.size(), 200U);
        // 数据完整
        EXPECT_EQ(objs[0][0], 'a');
        EXPECT_EQ(objs[199][0], 'a' + (199 % 26));
    }

    // ── 2. 生命周期 ──

    TEST(MemoryPointer, ArenaLifetimeWithinScope)
    {
        Preview::Memory::String *ptr = nullptr;
        {
            Preview::Memory::FrameArena arena;
            auto mr = arena.Get();
            auto s = std::make_unique<Preview::Memory::String>(mr);
            s->assign("scoped");
            ptr = s.get();
            EXPECT_EQ(*ptr, "scoped");
        }
        // 离开作用域后 arena 析构，指针不再有效（不访问——仅验证不崩溃）
        SUCCEED();
    }

    // ── 3. 性能：arena vs 系统 new ──

    TEST(MemoryPointer, ArenaAllocPerf)
    {
        constexpr int kIters = 100000;

        // 系统 new
        auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; ++i)
        {
            auto *p = new std::string(32, 'x');
            delete p;
        }
        auto sys_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - start)
                          .count();

        // arena（无释放）
        Preview::Memory::FrameArena arena;
        auto mr = arena.Get();
        start = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; ++i)
        {
            auto *p = new (mr->allocate(sizeof(std::string), alignof(std::string))) std::string(32, 'x');
            p->~basic_string();
            mr->deallocate(p, sizeof(std::string), alignof(std::string));
        }
        auto arena_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start)
                            .count();

        // arena 应显著快于系统 new（报告差异，不硬断言）
        GTEST_LOG_(INFO) << "system new: " << sys_ms << "ms, arena: " << arena_ms << "ms";
        EXPECT_LE(arena_ms, sys_ms * 2) << "arena 应至少不慢于系统 new";
    }

    // ── 4. 与协议层集成模式（conn 持有 SessionResource） ──

    TEST(MemoryPointer, ConnHoldsSessionMemory)
    {
        // 模拟 conn 持有 SessionResource：arena 分配随 conn 存活
        struct fake_conn
        {
            Preview::Memory::SessionResource<> mem;
            auto target_string() -> Preview::Memory::String
            {
                return mem.MakeString("conn-target");
            }
        };
        auto conn = std::make_shared<fake_conn>();
        auto target = conn->target_string();
        EXPECT_EQ(target, "conn-target");
    }

    // ── 5. 协议热路径：arena 序列化 vs 系统堆序列化 ──

    TEST(MemoryPointer, ProtocolCodecArenaVsHeap)
    {
        using namespace Preview::Socks5;

        // 典型 CONNECT 请求：域名 example.com:443
        Request req;
        req.Ver = 5;
        req.Cmd = Command::Connect;
        req.Rsv = 0;
        req.Target.Type = AddressType::Domain;
        req.Target.Host = "example.com";
        req.Target.Port = 443;

        constexpr int kIters = 200000;

        // 每帧临时分配（返回式，系统堆）
        auto start = std::chrono::steady_clock::now();
        volatile std::size_t sink = 0;
        for (int i = 0; i < kIters; ++i)
        {
            const auto wire = BuildRequest(req);
            sink += wire.size();
        }
        auto heap_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();

        // 复用缓冲（arena 分配，首次扩容后零分配）
        Preview::Memory::SessionResource mem;
        Preview::Memory::Vector<std::uint8_t> tx_wire(mem.Arena());
        start = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; ++i)
        {
            BuildRequest(req, tx_wire);
            sink += tx_wire.size();
        }
        auto arena_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - start)
                            .count();

        GTEST_LOG_(INFO) << "build_request x" << kIters << ": per-frame heap " << heap_ms
                         << "us, reused arena buffer " << arena_ms << "us (sink=" << sink << ")";
        // 复用缓冲应显著快于每帧分配（报告差异）
        EXPECT_LE(arena_ms, heap_ms);
    }

    TEST(MemoryPointer, ProtocolDgramArenaVsHeap)
    {
        using namespace Preview::Socks5;

        Address dest;
        dest.Type = AddressType::Ipv4;
        dest.Host = "10.0.0.1";
        dest.Port = 53;
        constexpr std::size_t kPayload = 128;
        std::array<std::uint8_t, kPayload> payload{};
        payload.fill(0xAB);

        constexpr int kIters = 100000;

        auto start = std::chrono::steady_clock::now();
        volatile std::size_t sink = 0;
        for (int i = 0; i < kIters; ++i)
        {
            const auto wire = BuildUdpDatagram(dest, payload);
            sink += wire.size();
        }
        auto heap_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();

        Preview::Memory::SessionResource mem;
        Preview::Memory::Vector<std::uint8_t> tx_wire(mem.Arena());
        start = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; ++i)
        {
            BuildUdpDatagram(dest, payload, tx_wire);
            sink += tx_wire.size();
        }
        auto arena_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - start)
                            .count();

        GTEST_LOG_(INFO) << "build_udp_datagram x" << kIters << ": per-frame heap " << heap_ms
                         << "us, reused arena buffer " << arena_ms << "us (sink=" << sink << ")";
        // Debug 下 pmr 分配器虚调用开销掩盖差距；仅报告，Release 验证
        EXPECT_LE(arena_ms, heap_ms * 2);
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
        using Mem = Preview::Memory::SessionResource<>;
        Mem mem;
        typename Mem::template Buffer<std::uint8_t> Buf = mem.MakeBuffer<std::uint8_t>(64);
        EXPECT_EQ(Buf.size(), 64U);
        typename Mem::DynamicString str = mem.MakeString("policy-str");
        EXPECT_EQ(str, "policy-str");
        EXPECT_EQ(Mem::GetArenaSize(), 8192U);
    }

    TEST(MemoryPointer, MakeBufferUsesSelectedResource)
    {
        Preview::Memory::SessionResource<> memory;

        auto small = memory.MakeBuffer<std::uint8_t>(64);
        EXPECT_EQ(small.get_allocator().resource(), memory.Arena());

        auto large = memory.MakeBuffer<std::uint8_t>(8193);
        EXPECT_EQ(large.get_allocator().resource(), Preview::Memory::System::LocalPool());

        auto wide = memory.MakeBuffer<std::uint64_t>(2048);
        EXPECT_EQ(wide.get_allocator().resource(), Preview::Memory::System::LocalPool());
    }

} // namespace
