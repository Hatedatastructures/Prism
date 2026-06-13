/**
 * @file AnyTLSFrameBench.cpp
 * @brief AnyTLS 帧序列化与解析基准测试
 * @details 测量 AnyTLS 多路复用帧操作性能：
 *          7 字节帧头序列化、帧头解析（合法/非法数据）、
 *          序列化+解析往返、批量序列化。
 *          帧操作在每个流的每次读写中被调用。
 */

#include <benchmark/benchmark.h>
#include <prism/stealth/stack/anytls/mux/frame.hpp>
#include <prism/core/memory/container.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace
{

using namespace psm::stealth::anytls;

// ============================================================
// 测试数据
// ============================================================

/// PSH 帧：stream_id=1, length=1024
const frame_header hdr_psh{
    .cmd = command::psh,
    .stream_id = 1,
    .length = 1024,
};

/// SYN 帧：stream_id=42, length=0
const frame_header hdr_syn{
    .cmd = command::syn,
    .stream_id = 42,
    .length = 0,
};

/// FIN 帧：stream_id=7, length=0
const frame_header hdr_fin{
    .cmd = command::fin,
    .stream_id = 7,
    .length = 0,
};

/// settings 帧：stream_id=0, length=256
const frame_header hdr_settings{
    .cmd = command::settings,
    .stream_id = 0,
    .length = 256,
};

/// waste 帧：stream_id=0, length=64
const frame_header hdr_waste{
    .cmd = command::waste,
    .stream_id = 0,
    .length = 64,
};

/// 序列化一帧用于 parse 测试
auto serialize_frame(const frame_header &hdr) -> std::vector<std::uint8_t>
{
    auto bytes = hdr.serialize();
    return {bytes.begin(), bytes.end()};
}

const auto bytes_psh = serialize_frame(hdr_psh);
const auto bytes_syn = serialize_frame(hdr_syn);
const auto bytes_fin = serialize_frame(hdr_fin);

/// 短数据（< 7 字节，parse 应返回 nullopt）
const std::vector<std::uint8_t> short_data = {0x01, 0x00, 0x00};

/// 空数据
const std::vector<std::uint8_t> empty_data;

// ============================================================
// 序列化基准测试
// ============================================================

void BM_Frame_Serialize_Psh(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto bytes = hdr_psh.serialize();
        benchmark::DoNotOptimize(bytes.data());
    }
}
BENCHMARK(BM_Frame_Serialize_Psh);

void BM_Frame_Serialize_Syn(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto bytes = hdr_syn.serialize();
        benchmark::DoNotOptimize(bytes.data());
    }
}
BENCHMARK(BM_Frame_Serialize_Syn);

void BM_Frame_Serialize_Fin(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto bytes = hdr_fin.serialize();
        benchmark::DoNotOptimize(bytes.data());
    }
}
BENCHMARK(BM_Frame_Serialize_Fin);

void BM_Frame_Serialize_Settings(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto bytes = hdr_settings.serialize();
        benchmark::DoNotOptimize(bytes.data());
    }
}
BENCHMARK(BM_Frame_Serialize_Settings);

// ============================================================
// 解析基准测试
// ============================================================

void BM_Frame_Parse_ValidPsh(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = frame_header::parse(bytes_psh);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Frame_Parse_ValidPsh);

void BM_Frame_Parse_ValidSyn(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = frame_header::parse(bytes_syn);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Frame_Parse_ValidSyn);

void BM_Frame_Parse_ShortData(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = frame_header::parse(short_data);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Frame_Parse_ShortData);

void BM_Frame_Parse_EmptyData(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = frame_header::parse(empty_data);
        benchmark::DoNotOptimize(r.has_value());
    }
}
BENCHMARK(BM_Frame_Parse_EmptyData);

// ============================================================
// 往返基准测试
// ============================================================

void BM_Frame_Roundtrip(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto bytes = hdr_psh.serialize();
        auto parsed = frame_header::parse(bytes);
        benchmark::DoNotOptimize(parsed.has_value());
    }
}
BENCHMARK(BM_Frame_Roundtrip);

// ============================================================
// 批量序列化基准测试
// ============================================================

void BM_Frame_SerializeBatch(benchmark::State &state)
{
    const frame_header headers[] = {hdr_psh, hdr_syn, hdr_fin, hdr_settings, hdr_waste};
    for (auto _ : state)
    {
        for (const auto &h : headers)
        {
            auto bytes = h.serialize();
            benchmark::DoNotOptimize(bytes.data());
        }
    }
}
BENCHMARK(BM_Frame_SerializeBatch);

} // namespace

BENCHMARK_MAIN();
