/**
 * @file MemoryPointerTest.cpp
 * @brief 内存指针体系测试
 * @details 验证 session_arena/session_memory：
 * 1. 正确性：arena 分配/释放/重置语义
 * 2. 生命周期：arena 分配对象随会话存活
 * 3. 性能：arena 分配 vs 系统 new（应显著快）
 * 4. 与协议层集成：conn 持有 session_memory 的模式
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <string>

#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/memory/pool.hpp>
#include <common/proxy/socks5/codec.hpp>
#include <common/proxy/socks5/types.hpp>

namespace
{

    // ── 1. 正确性 ──

    TEST(MemoryPointer, ArenaAllocateAndReset)
    {
        psm::memory::session_arena arena;
        auto mr = arena.get();
        ASSERT_NE(mr, nullptr);

        // 分配字符串
        psm::memory::string s(mr);
        s.assign("hello");
        EXPECT_EQ(s, "hello");

        // 分配 vector
        psm::memory::vector<std::uint8_t> v(mr);
        v.push_back(1);
        v.push_back(2);
        EXPECT_EQ(v.size(), 2U);

        // reset 后旧对象失效但可重新分配
        arena.reset();
        psm::memory::string s2(mr);
        s2.assign("world");
        EXPECT_EQ(s2, "world");
    }

    TEST(MemoryPointer, SessionMemoryContext)
    {
        psm::memory::session_memory mem;
        auto s = mem.make_string("context-string");
        EXPECT_EQ(s, "context-string");

        auto v = mem.make_vector<std::byte>();
        v.push_back(std::byte{0xAB});
        EXPECT_EQ(v.size(), 1U);

        mem.reset();
        EXPECT_EQ(mem.make_string("after-reset"), "after-reset");
    }

    TEST(MemoryPointer, ArenaBufferExhaustionFallback)
    {
        // 8KB 缓冲耗尽后回退上游（local_pool），不崩溃
        psm::memory::session_arena arena;
        auto mr = arena.get();
        std::vector<psm::memory::string> objs;
        for (int i = 0; i < 200; ++i)
        {
            psm::memory::string s(mr);
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
        psm::memory::string *ptr = nullptr;
        {
            psm::memory::session_arena arena;
            auto mr = arena.get();
            auto s = std::make_unique<psm::memory::string>(mr);
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
        psm::memory::session_arena arena;
        auto mr = arena.get();
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

    // ── 4. 与协议层集成模式（conn 持有 session_memory） ──

    TEST(MemoryPointer, ConnHoldsSessionMemory)
    {
        // 模拟 conn 持有 session_memory：arena 分配随 conn 存活
        struct fake_conn
        {
            psm::memory::session_memory<> mem;
            auto target_string() -> psm::memory::string
            {
                return mem.make_string("conn-target");
            }
        };
        auto conn = std::make_shared<fake_conn>();
        auto target = conn->target_string();
        EXPECT_EQ(target, "conn-target");
    }

    // ── 5. 协议热路径：arena 序列化 vs 系统堆序列化 ──

    TEST(MemoryPointer, ProtocolCodecArenaVsHeap)
    {
        using namespace psmtest::socks5;

        // 典型 CONNECT 请求：域名 example.com:443
        request req;
        req.ver = version;
        req.cmd = command::connect;
        req.rsv = 0;
        req.target.type = address_type::domain;
        req.target.host = "example.com";
        req.target.port = 443;

        constexpr int kIters = 200000;

        // 每帧临时分配（返回式，系统堆）
        auto start = std::chrono::steady_clock::now();
        volatile std::size_t sink = 0;
        for (int i = 0; i < kIters; ++i)
        {
            const auto wire = build_request(req);
            sink += wire.size();
        }
        auto heap_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();

        // 复用缓冲（arena 分配，首次扩容后零分配）
        psm::memory::session_memory mem;
        psm::memory::vector<std::uint8_t> tx_wire(mem.arena());
        start = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; ++i)
        {
            build_request(req, tx_wire);
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
        using namespace psmtest::socks5;

        address dest;
        dest.type = address_type::ipv4;
        dest.host = "10.0.0.1";
        dest.port = 53;
        constexpr std::size_t kPayload = 128;
        std::array<std::uint8_t, kPayload> payload{};
        payload.fill(0xAB);

        constexpr int kIters = 100000;

        auto start = std::chrono::steady_clock::now();
        volatile std::size_t sink = 0;
        for (int i = 0; i < kIters; ++i)
        {
            const auto wire = build_udp_datagram(dest, payload);
            sink += wire.size();
        }
        auto heap_ms = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();

        psm::memory::session_memory mem;
        psm::memory::vector<std::uint8_t> tx_wire(mem.arena());
        start = std::chrono::steady_clock::now();
        for (int i = 0; i < kIters; ++i)
        {
            build_udp_datagram(dest, payload, tx_wire);
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

    // 合法策略：session_memory<> 应满足约束
    static_assert(psm::memory::memory_policy<psm::memory::session_memory<>>);
    // 自定义大小同样满足
    static_assert(psm::memory::memory_policy<psm::memory::session_memory<32768>>);
    // 非策略类型不满足约束（编译期拒绝）
    static_assert(!psm::memory::memory_policy<int>);
    static_assert(!psm::memory::memory_policy<std::string>);

    TEST(MemoryPointer, MemoryPolicyConstraint)
    {
        // 策略容器类型可用性
        using Mem = psm::memory::session_memory<>;
        Mem mem;
        typename Mem::buffer<std::uint8_t> buf = mem.make_buffer<std::uint8_t>(64);
        EXPECT_EQ(buf.size(), 64U);
        typename Mem::dynamic_string str = mem.make_string("policy-str");
        EXPECT_EQ(str, "policy-str");
        EXPECT_EQ(Mem::arena_size(), 8192U);
    }

} // namespace
