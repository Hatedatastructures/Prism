/**
 * @file ResourceBench.cpp
 * @brief 资源占用基准测试
 * @details 测量 PMR 内存分配性能，单线程测试避免竞态。
 */

#include <benchmark/benchmark.h>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>

using namespace psm;

namespace
{
    struct mock_session
    {
        memory::vector<std::byte> inbound_buffer;
        memory::vector<std::byte> outbound_buffer;

        explicit mock_session(memory::resource_pointer mr)
            : inbound_buffer(mr), outbound_buffer(mr)
        {
            inbound_buffer.resize(64 * 1024);
            outbound_buffer.resize(64 * 1024);
        }
    };
} // namespace

// ============================================================
// 内存分配吞吐量测试（单线程）
// ============================================================

static void BM_MemoryAllocRate_FrameArena(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;

    for (auto _ : state)
    {
        arena.reset();

        auto mr = arena.get();
        memory::vector<std::byte> buf(mr);
        buf.resize(64 * 1024);

        benchmark::DoNotOptimize(buf.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 1024);
}

static void BM_MemoryAllocRate_ThreadLocalPool(benchmark::State &state)
{
    memory::system::enable_global_pooling();

    for (auto _ : state)
    {
        auto mr = memory::system::thread_local_pool();
        memory::vector<std::byte> buf(mr);
        buf.resize(64 * 1024);

        benchmark::DoNotOptimize(buf.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 1024);
}

static void BM_MemoryAllocRate_GlobalPool(benchmark::State &state)
{
    memory::system::enable_global_pooling();

    for (auto _ : state)
    {
        auto mr = memory::system::global_pool();
        memory::vector<std::byte> buf(mr);
        buf.resize(64 * 1024);

        benchmark::DoNotOptimize(buf.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 1024);
}

// ============================================================
// 会话内存占用测试（单线程）
// ============================================================

static void BM_SessionMemoryUsage_100(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    std::vector<std::unique_ptr<mock_session>> sessions;

    for (auto _ : state)
    {
        state.PauseTiming();
        sessions.clear();
        for (int i = 0; i < 100; ++i)
        {
            sessions.emplace_back(std::make_unique<mock_session>(mr));
        }
        state.ResumeTiming();

        for (auto &session : sessions)
        {
            std::memcpy(session->inbound_buffer.data(),
                        session->outbound_buffer.data(), 1024);
            benchmark::DoNotOptimize(session->inbound_buffer.data());
        }
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 100 * 1024);
}

static void BM_SessionMemoryUsage_1K(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    std::vector<std::unique_ptr<mock_session>> sessions;

    for (auto _ : state)
    {
        state.PauseTiming();
        sessions.clear();
        for (int i = 0; i < 1000; ++i)
        {
            sessions.emplace_back(std::make_unique<mock_session>(mr));
        }
        state.ResumeTiming();

        for (auto &session : sessions)
        {
            std::memcpy(session->inbound_buffer.data(),
                        session->outbound_buffer.data(), 1024);
            benchmark::DoNotOptimize(session->inbound_buffer.data());
        }
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 1000 * 1024);
}

// ============================================================
// PMR 容器性能（单线程）
// ============================================================

static void BM_PmrStringAllocation(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();

        memory::string str(mr);
        str.resize(256);

        benchmark::DoNotOptimize(str.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 256);
}

static void BM_PmrVectorPushBack(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();

        memory::vector<std::byte> vec(mr);
        for (int i = 0; i < 1000; ++i)
        {
            vec.push_back(static_cast<std::byte>(i));
        }

        benchmark::DoNotOptimize(vec.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()) * 1000);
}

static void BM_PmrVectorResize(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();

        memory::vector<std::byte> vec(mr);
        vec.resize(64 * 1024);

        benchmark::DoNotOptimize(vec.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * 1024);
}

// ============================================================
// BENCHMARK 注册
// ============================================================

BENCHMARK(BM_MemoryAllocRate_FrameArena)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_MemoryAllocRate_ThreadLocalPool)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_MemoryAllocRate_GlobalPool)->Unit(benchmark::kNanosecond);

BENCHMARK(BM_SessionMemoryUsage_100)->Unit(benchmark::kMillisecond)->Iterations(10);
BENCHMARK(BM_SessionMemoryUsage_1K)->Unit(benchmark::kMillisecond)->Iterations(5);

BENCHMARK(BM_PmrStringAllocation)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_PmrVectorPushBack)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_PmrVectorResize)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();