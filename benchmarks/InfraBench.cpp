/**
 * @file InfraBench.cpp
 * @brief 统计与账户基础设施基准测试
 * @details 测量 stats::counter 原子操作、account::entry 流量累加、
 *          account::lease RAII 生命周期、account::directory 查找与更新性能。
 *          这些原语在每条连接和每次转发中被调用，延迟直接影响吞吐。
 */

#include <benchmark/benchmark.h>
#include <prism/account/stats/counter.hpp>
#include <prism/account/entry.hpp>
#include <prism/account/directory.hpp>
#include <prism/foundation/memory/pool.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace
{

// ============================================================
// stats::counter 基准测试
// ============================================================

void BM_Counter_Increment(benchmark::State &state)
{
    psm::stats::counter ctr;
    for (auto _ : state)
    {
        ctr.increment();
        benchmark::DoNotOptimize(ctr.load());
    }
}
BENCHMARK(BM_Counter_Increment);

void BM_Counter_IncrementBy(benchmark::State &state)
{
    psm::stats::counter ctr;
    const auto n = static_cast<std::uint64_t>(state.range(0));
    for (auto _ : state)
    {
        ctr.increment(n);
        benchmark::DoNotOptimize(ctr.load());
    }
}
BENCHMARK(BM_Counter_IncrementBy)->Arg(100)->Arg(1024)->Arg(65536);

void BM_Counter_Decrement(benchmark::State &state)
{
    psm::stats::counter ctr;
    for (auto _ : state)
    {
        ctr.decrement();
        benchmark::DoNotOptimize(ctr.load());
    }
}
BENCHMARK(BM_Counter_Decrement);

void BM_Counter_Load(benchmark::State &state)
{
    psm::stats::counter ctr;
    ctr.increment(1000);
    for (auto _ : state)
    {
        auto v = ctr.load();
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_Counter_Load);

void BM_Counter_Exchange(benchmark::State &state)
{
    psm::stats::counter ctr;
    for (auto _ : state)
    {
        auto old = ctr.exchange(0);
        benchmark::DoNotOptimize(old);
        ctr.increment(old + 1);
    }
}
BENCHMARK(BM_Counter_Exchange);

void BM_Counter_IncrementAndLoad(benchmark::State &state)
{
    psm::stats::counter ctr;
    for (auto _ : state)
    {
        ctr.increment();
        auto v = ctr.load();
        benchmark::DoNotOptimize(v);
    }
}
BENCHMARK(BM_Counter_IncrementAndLoad);

// ============================================================
// account::entry 流量累加基准测试
// ============================================================

void BM_Entry_AccumulateUplink(benchmark::State &state)
{
    psm::account::entry ent;
    const auto bytes = static_cast<std::uint64_t>(state.range(0));
    for (auto _ : state)
    {
        psm::account::accumulate_uplink(&ent, bytes);
        benchmark::DoNotOptimize(ent.uplink_bytes.load());
    }
}
BENCHMARK(BM_Entry_AccumulateUplink)->Arg(64)->Arg(1024)->Arg(16384);

void BM_Entry_AccumulateDownlink(benchmark::State &state)
{
    psm::account::entry ent;
    const auto bytes = static_cast<std::uint64_t>(state.range(0));
    for (auto _ : state)
    {
        psm::account::accumulate_downlink(&ent, bytes);
        benchmark::DoNotOptimize(ent.downlink_bytes.load());
    }
}
BENCHMARK(BM_Entry_AccumulateDownlink)->Arg(64)->Arg(1024)->Arg(16384);

void BM_Entry_AccumulateUplink_Nullptr(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::account::accumulate_uplink(nullptr, 1024);
    }
}
BENCHMARK(BM_Entry_AccumulateUplink_Nullptr);

// ============================================================
// account::lease RAII 生命周期基准测试
// ============================================================

void BM_Lease_ConstructDestroy(benchmark::State &state)
{
    auto ent = std::make_shared<psm::account::entry>();
    ent->active_connections.fetch_add(1, std::memory_order_relaxed);
    for (auto _ : state)
    {
        // 模拟租约获取：先递增计数，再构造 lease
        ent->active_connections.fetch_add(1, std::memory_order_relaxed);
        {
            psm::account::lease l(ent);
            benchmark::DoNotOptimize(l.get());
        }
    }
}
BENCHMARK(BM_Lease_ConstructDestroy);

// ============================================================
// account::directory 基准测试
// ============================================================

/// 构建含 N 个账户的目录（返回 shared_ptr 绕过不可拷贝限制）
auto make_directory(std::size_t n) -> std::shared_ptr<psm::account::directory>
{
    auto dir = std::make_shared<psm::account::directory>();
    dir->reserve(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        auto cred = std::string("credential-") + std::to_string(i);
        dir->upsert(cred, 100);
    }
    return dir;
}

/// 预构建的测试目录
const auto dir_10 = make_directory(10);
const auto dir_100 = make_directory(100);
const auto dir_1000 = make_directory(1000);

void BM_Directory_Find_Hit(benchmark::State &state)
{
    const auto n = static_cast<std::size_t>(state.range(0));
    const psm::account::directory *dir = nullptr;
    if (n <= 10) { dir = dir_10.get(); }
    else if (n <= 100) { dir = dir_100.get(); }
    else { dir = dir_1000.get(); }

    const auto key = std::string("credential-") + std::to_string(n / 2);
    for (auto _ : state)
    {
        auto result = dir->find(key);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Directory_Find_Hit)->Arg(10)->Arg(100)->Arg(1000);

void BM_Directory_Find_Miss(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = dir_100->find("nonexistent-credential");
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Directory_Find_Miss);

void BM_Directory_Contains(benchmark::State &state)
{
    const auto key = std::string("credential-50");
    for (auto _ : state)
    {
        auto result = psm::account::contains(*dir_100, key);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Directory_Contains);

void BM_Directory_TryAcquire_Success(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto l = psm::account::try_acquire(*dir_100, "credential-50");
        benchmark::DoNotOptimize(static_cast<bool>(l));
        // lease 析构时递减计数
    }
}
BENCHMARK(BM_Directory_TryAcquire_Success);

void BM_Directory_TryAcquire_Miss(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto l = psm::account::try_acquire(*dir_100, "nonexistent-credential");
        benchmark::DoNotOptimize(static_cast<bool>(l));
    }
}
BENCHMARK(BM_Directory_TryAcquire_Miss);

void BM_Directory_TryAcquire_Capped(benchmark::State &state)
{
    // 创建一个 max_connections=1 的账户，填满后测试拒绝路径
    psm::account::directory capped_dir;
    capped_dir.upsert("capped-user", 1);

    // 先占用唯一名额
    auto holder = psm::account::try_acquire(capped_dir, "capped-user");
    for (auto _ : state)
    {
        auto l = psm::account::try_acquire(capped_dir, "capped-user");
        benchmark::DoNotOptimize(static_cast<bool>(l));
    }
}
BENCHMARK(BM_Directory_TryAcquire_Capped);

void BM_Directory_Upsert(benchmark::State &state)
{
    // 每次迭代创建新目录避免 COW 积累
    for (auto _ : state)
    {
        state.PauseTiming();
        psm::account::directory dir;
        state.ResumeTiming();

        dir.upsert("new-credential", 50);
        benchmark::DoNotOptimize(dir.find("new-credential"));
    }
}
BENCHMARK(BM_Directory_Upsert);

} // namespace

BENCHMARK_MAIN();
