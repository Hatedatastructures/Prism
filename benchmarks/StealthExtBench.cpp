/**
 * @file StealthExtBench.cpp
 * @brief RestLS 脚本引擎 + AnyTLS padding 工厂基准测试
 * @details 测量 RestLS script_engine 解析与分配、
 *          AnyTLS padding_factory 解析与生成性能。
 *          script_engine 在每次 TLS 写入时调用 allocate，
 *          padding_factory 在每个 AnyTLS 连接建立时解析并按包生成填充。
 */

#include <benchmark/benchmark.h>
#include <prism/stealth/facade/restls/script.hpp>
#include <prism/stealth/stack/anytls/padding.hpp>
#include <prism/foundation/memory/container.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace
{

using namespace psm::stealth::restls;
using psm::stealth::anytls::padding_factory;

// ============================================================
// 测试数据
// ============================================================

/// 简单 script：固定 512 字节
const auto script_simple = std::string("512");

/// 中等 script：含范围和响应
const auto script_medium = std::string("512~1024,r,1~256,r,256~512");

/// 长脚本：多行组合
const auto script_long = std::string("256~512,r,512~1024,r,1024~2048,r,512,1024,2048,r,256~1024");

/// 无数据的 script（超过可用数据量）
const auto script_no_data = std::string("32768");

// ============================================================
// script_engine 基准测试
// ============================================================

void BM_Script_Parse_Simple(benchmark::State &state)
{
    for (auto _ : state)
    {
        script_engine engine(script_simple);
        benchmark::DoNotOptimize(engine.size());
    }
}
BENCHMARK(BM_Script_Parse_Simple);

void BM_Script_Parse_Medium(benchmark::State &state)
{
    for (auto _ : state)
    {
        script_engine engine(script_medium);
        benchmark::DoNotOptimize(engine.size());
    }
}
BENCHMARK(BM_Script_Parse_Medium);

void BM_Script_Parse_Long(benchmark::State &state)
{
    for (auto _ : state)
    {
        script_engine engine(script_long);
        benchmark::DoNotOptimize(engine.size());
    }
}
BENCHMARK(BM_Script_Parse_Long);

void BM_Script_Allocate_Simple(benchmark::State &state)
{
    script_engine engine(script_simple);
    for (auto _ : state)
    {
        auto alloc = engine.allocate(0, 512);
        benchmark::DoNotOptimize(alloc.payload_len);
    }
}
BENCHMARK(BM_Script_Allocate_Simple);

void BM_Script_Allocate_Medium(benchmark::State &state)
{
    script_engine engine(script_medium);
    for (auto _ : state)
    {
        auto alloc = engine.allocate(0, 1024);
        benchmark::DoNotOptimize(alloc.payload_len);
    }
}
BENCHMARK(BM_Script_Allocate_Medium);

void BM_Script_Allocate_Long(benchmark::State &state)
{
    script_engine engine(script_long);
    for (auto _ : state)
    {
        auto alloc = engine.allocate(0, 2048);
        benchmark::DoNotOptimize(alloc.payload_len);
    }
}
BENCHMARK(BM_Script_Allocate_Long);

void BM_Script_Allocate_NoData(benchmark::State &state)
{
    script_engine engine(script_no_data);
    for (auto _ : state)
    {
        auto alloc = engine.allocate(0, 64);
        benchmark::DoNotOptimize(alloc.payload_len);
    }
}
BENCHMARK(BM_Script_Allocate_NoData);

void BM_Script_Allocate_AdvancingCounter(benchmark::State &state)
{
    script_engine engine(script_medium);
    std::uint64_t counter = 0;
    for (auto _ : state)
    {
        auto alloc = engine.allocate(counter, 1024);
        benchmark::DoNotOptimize(alloc.payload_len);
        ++counter;
    }
}
BENCHMARK(BM_Script_Allocate_AdvancingCounter);

// ============================================================
// padding_factory 基准测试
// ============================================================

/// 简单 padding：固定停止点和单一规则
const auto padding_simple = std::string("100:64~128");

/// 中等 padding：多规则
const auto padding_medium = std::string("500:64~128,128~256,256~512");

/// 长填充方案
const auto padding_long = std::string("1000:64~128,128~256,256~512,512~1024,1024~2048");

void BM_Padding_Parse_Simple(benchmark::State &state)
{
    for (auto _ : state)
    {
        padding_factory factory(padding_simple);
        benchmark::DoNotOptimize(factory.enabled());
    }
}
BENCHMARK(BM_Padding_Parse_Simple);

void BM_Padding_Parse_Medium(benchmark::State &state)
{
    for (auto _ : state)
    {
        padding_factory factory(padding_medium);
        benchmark::DoNotOptimize(factory.enabled());
    }
}
BENCHMARK(BM_Padding_Parse_Medium);

void BM_Padding_Parse_Long(benchmark::State &state)
{
    for (auto _ : state)
    {
        padding_factory factory(padding_long);
        benchmark::DoNotOptimize(factory.enabled());
    }
}
BENCHMARK(BM_Padding_Parse_Long);

void BM_Padding_GenerateSizes_Simple(benchmark::State &state)
{
    padding_factory factory(padding_simple);
    for (auto _ : state)
    {
        auto sizes = factory.generate_sizes(100);
        benchmark::DoNotOptimize(sizes.size());
    }
}
BENCHMARK(BM_Padding_GenerateSizes_Simple);

void BM_Padding_GenerateSizes_Medium(benchmark::State &state)
{
    padding_factory factory(padding_medium);
    for (auto _ : state)
    {
        auto sizes = factory.generate_sizes(300);
        benchmark::DoNotOptimize(sizes.size());
    }
}
BENCHMARK(BM_Padding_GenerateSizes_Medium);

void BM_Padding_GenerateSizes_Long(benchmark::State &state)
{
    padding_factory factory(padding_long);
    for (auto _ : state)
    {
        auto sizes = factory.generate_sizes(800);
        benchmark::DoNotOptimize(sizes.size());
    }
}
BENCHMARK(BM_Padding_GenerateSizes_Long);

void BM_Padding_GenerateSizes_BeyondStop(benchmark::State &state)
{
    padding_factory factory(padding_medium);
    for (auto _ : state)
    {
        auto sizes = factory.generate_sizes(1000);
        benchmark::DoNotOptimize(sizes.size());
    }
}
BENCHMARK(BM_Padding_GenerateSizes_BeyondStop);

void BM_Padding_Enabled_True(benchmark::State &state)
{
    padding_factory factory(padding_simple);
    for (auto _ : state)
    {
        auto e = factory.enabled();
        benchmark::DoNotOptimize(e);
    }
}
BENCHMARK(BM_Padding_Enabled_True);

void BM_Padding_Enabled_False(benchmark::State &state)
{
    padding_factory factory;
    for (auto _ : state)
    {
        auto e = factory.enabled();
        benchmark::DoNotOptimize(e);
    }
}
BENCHMARK(BM_Padding_Enabled_False);

} // namespace

BENCHMARK_MAIN();
