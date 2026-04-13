#include <benchmark/benchmark.h>
#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>
#include <string>
#include <vector>

using namespace psm;

static std::string make_payload(std::size_t size, char fill)
{
    return std::string(size, fill);
}

static void BM_EmptyLoop(benchmark::State &state)
{
    std::uint64_t value = 0;
    for (auto _ : state)
    {
        benchmark::DoNotOptimize(value++);
    }
}

static void BM_PauseResumeOnly(benchmark::State &state)
{
    std::uint64_t value = 0;
    for (auto _ : state)
    {
        state.PauseTiming();
        value += 1;
        state.ResumeTiming();
        benchmark::DoNotOptimize(value);
    }
}

static void BM_StdStringAllocation(benchmark::State &state)
{
    for (auto _ : state)
    {
        std::string s;
        s.assign("Hello World, this is a test string to bypass SSO");
        benchmark::DoNotOptimize(s);
    }
}

static void BM_StdStringAssign_Size(benchmark::State &state)
{
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)), 'x');
    for (auto _ : state)
    {
        std::string s;
        s.assign(payload);
        benchmark::DoNotOptimize(s);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(payload.size()));
}

static void BM_PmrStringAllocation_DefaultResource(benchmark::State &state)
{
    memory::system::enable_global_pooling();

    for (auto _ : state)
    {
        memory::string s;
        s.assign("Hello World, this is a test string to bypass SSO");
        benchmark::DoNotOptimize(s);
    }
}

static void BM_PmrStringAssign_DefaultResource_Size(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)), 'y');

    for (auto _ : state)
    {
        memory::string s;
        s.assign(payload);
        benchmark::DoNotOptimize(s);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(payload.size()));
}

static void BM_PmrStringAssign_NewDeleteResource_Size(benchmark::State &state)
{
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)), 'n');
    auto *mr = std::pmr::new_delete_resource();

    for (auto _ : state)
    {
        memory::string s(mr);
        s.assign(payload);
        benchmark::DoNotOptimize(s);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(payload.size()));
}

static void BM_PmrStringAssign_GlobalPool_Size(benchmark::State &state)
{
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)), 'g');
    auto *mr = memory::system::global_pool();

    for (auto _ : state)
    {
        memory::string s(mr);
        s.assign(payload);
        benchmark::DoNotOptimize(s);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(payload.size()));
}

static void BM_PmrStringAssign_ThreadLocalPool_Size(benchmark::State &state)
{
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)), 't');
    auto *mr = memory::system::thread_local_pool();

    for (auto _ : state)
    {
        memory::string s(mr);
        s.assign(payload);
        benchmark::DoNotOptimize(s);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(payload.size()));
}

static void BM_PmrStringAllocation_FrameArena(benchmark::State &state)
{
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();
        memory::string s(mr);
        s.assign("Hello World, this is a test string to bypass SSO");
        benchmark::DoNotOptimize(s);
    }
}

static void BM_PmrStringAssign_FrameArena_Size(benchmark::State &state)
{
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)), 'z');
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();
        memory::string s(mr);
        s.assign(payload);
        benchmark::DoNotOptimize(s);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(payload.size()));
}

static void BM_PmrStringAssign_FrameArena_Batch(benchmark::State &state)
{
    const auto payload = make_payload(static_cast<std::size_t>(state.range(0)), 'b');
    const auto batch = static_cast<std::size_t>(state.range(1));

    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();
        for (std::size_t i = 0; i < batch; ++i)
        {
            memory::string s(mr);
            s.assign(payload);
            benchmark::DoNotOptimize(s);
        }
    }

    state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(batch));
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(batch) *
                            static_cast<std::int64_t>(payload.size()));
}

static void BM_FrameArenaResetOnly(benchmark::State &state)
{
    memory::frame_arena arena;
    for (auto _ : state)
    {
        arena.reset();
        benchmark::DoNotOptimize(arena.get());
    }
}

static void BM_StdVectorPush(benchmark::State &state)
{
    const std::size_t count = static_cast<std::size_t>(state.range(0));
    for (auto _ : state)
    {
        std::vector<std::uint64_t> values;
        values.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            values.push_back(static_cast<std::uint64_t>(i));
        }
        benchmark::DoNotOptimize(values);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(count * sizeof(std::uint64_t)));
}

static void BM_PmrVectorPush_NewDeleteResource(benchmark::State &state)
{
    const std::size_t count = static_cast<std::size_t>(state.range(0));
    auto *mr = std::pmr::new_delete_resource();

    for (auto _ : state)
    {
        memory::vector<std::uint64_t> values(mr);
        values.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            values.push_back(static_cast<std::uint64_t>(i));
        }
        benchmark::DoNotOptimize(values);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(count * sizeof(std::uint64_t)));
}

static void BM_PmrVectorPush_GlobalPool(benchmark::State &state)
{
    const std::size_t count = static_cast<std::size_t>(state.range(0));
    auto *mr = memory::system::global_pool();

    for (auto _ : state)
    {
        memory::vector<std::uint64_t> values(mr);
        values.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            values.push_back(static_cast<std::uint64_t>(i));
        }
        benchmark::DoNotOptimize(values);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(count * sizeof(std::uint64_t)));
}

static void BM_PmrVectorPush_ThreadLocalPool(benchmark::State &state)
{
    const std::size_t count = static_cast<std::size_t>(state.range(0));
    auto *mr = memory::system::thread_local_pool();

    for (auto _ : state)
    {
        memory::vector<std::uint64_t> values(mr);
        values.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            values.push_back(static_cast<std::uint64_t>(i));
        }
        benchmark::DoNotOptimize(values);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(count * sizeof(std::uint64_t)));
}

static void BM_PmrVectorPush_DefaultResource(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    const std::size_t count = static_cast<std::size_t>(state.range(0));
    for (auto _ : state)
    {
        memory::vector<std::uint64_t> values;
        values.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            values.push_back(static_cast<std::uint64_t>(i));
        }
        benchmark::DoNotOptimize(values);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(count * sizeof(std::uint64_t)));
}

static void BM_PmrVectorPush_FrameArena(benchmark::State &state)
{
    const std::size_t count = static_cast<std::size_t>(state.range(0));
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();
        memory::vector<std::uint64_t> values(mr);
        values.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            values.push_back(static_cast<std::uint64_t>(i));
        }
        benchmark::DoNotOptimize(values);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(count * sizeof(std::uint64_t)));
}

BENCHMARK(BM_EmptyLoop);
BENCHMARK(BM_PauseResumeOnly);
BENCHMARK(BM_StdStringAllocation);
BENCHMARK(BM_StdStringAssign_Size)->Arg(0)->Arg(8)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_PmrStringAllocation_DefaultResource);
BENCHMARK(BM_PmrStringAssign_DefaultResource_Size)->Arg(0)->Arg(8)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_PmrStringAssign_NewDeleteResource_Size)->Arg(0)->Arg(8)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_PmrStringAssign_GlobalPool_Size)->Arg(0)->Arg(8)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_PmrStringAssign_ThreadLocalPool_Size)->Arg(0)->Arg(8)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_PmrStringAllocation_FrameArena);
BENCHMARK(BM_PmrStringAssign_FrameArena_Size)->Arg(0)->Arg(8)->Arg(32)->Arg(128)->Arg(512)->Arg(4096);
BENCHMARK(BM_PmrStringAssign_FrameArena_Batch)->Args({32, 256})->Args({128, 128})->Args({512, 32});
BENCHMARK(BM_FrameArenaResetOnly);
BENCHMARK(BM_StdVectorPush)->Arg(8)->Arg(64)->Arg(256)->Arg(4096);
BENCHMARK(BM_PmrVectorPush_NewDeleteResource)->Arg(8)->Arg(64)->Arg(256)->Arg(4096);
BENCHMARK(BM_PmrVectorPush_GlobalPool)->Arg(8)->Arg(64)->Arg(256)->Arg(4096);
BENCHMARK(BM_PmrVectorPush_ThreadLocalPool)->Arg(8)->Arg(64)->Arg(256)->Arg(4096);
BENCHMARK(BM_PmrVectorPush_DefaultResource)->Arg(8)->Arg(64)->Arg(256)->Arg(4096);
BENCHMARK(BM_PmrVectorPush_FrameArena)->Arg(8)->Arg(64)->Arg(256)->Arg(4096);

BENCHMARK_MAIN();
