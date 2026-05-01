/**
 * @file MuxConnBench.cpp
 * @brief smux/yamux 多路复用帧处理吞吐量基准测试
 * @details 测试帧编解码性能，不涉及实际 socket I/O（避免竞态条件）。
 *          对标 Go 版 BenchmarkConnSmux 的帧处理部分。
 */

#include <benchmark/benchmark.h>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/multiplex/yamux/frame.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

using namespace psm;

// ============================================================
// 辅助：帧构建函数
// ============================================================

namespace
{
    /**
     * @brief 构建 smux PSH 帧
     */
    memory::vector<std::byte> build_smux_data_frame(std::uint32_t stream_id,
                                                     std::span<const std::byte> payload,
                                                     memory::resource_pointer mr)
    {
        memory::vector<std::byte> frame(mr);
        const auto length = static_cast<std::uint16_t>(payload.size());

        frame.resize(8 + payload.size());
        frame[0] = std::byte{0x01};                              // version
        frame[1] = std::byte{0x02};                              // cmd=PSH
        frame[2] = static_cast<std::byte>(length & 0xFF);        // length LE
        frame[3] = static_cast<std::byte>(length >> 8);
        frame[4] = static_cast<std::byte>(stream_id & 0xFF);     // stream_id LE
        frame[5] = static_cast<std::byte>((stream_id >> 8) & 0xFF);
        frame[6] = static_cast<std::byte>((stream_id >> 16) & 0xFF);
        frame[7] = static_cast<std::byte>((stream_id >> 24) & 0xFF);

        if (!payload.empty())
            std::memcpy(frame.data() + 8, payload.data(), payload.size());

        return frame;
    }

    /**
     * @brief 构建 yamux Data 帧
     */
    memory::vector<std::byte> build_yamux_data_frame(std::uint32_t stream_id,
                                                      std::span<const std::byte> payload,
                                                      memory::resource_pointer mr)
    {
        memory::vector<std::byte> frame(mr);
        const auto length = static_cast<std::uint32_t>(payload.size());

        frame.resize(12 + payload.size());
        frame[0] = std::byte{0x00};                               // version
        frame[1] = std::byte{0x00};                               // type=Data
        frame[2] = std::byte{0x00};                               // flags=none
        frame[3] = std::byte{0x00};
        frame[4] = static_cast<std::byte>((stream_id >> 24) & 0xFF); // stream_id BE
        frame[5] = static_cast<std::byte>((stream_id >> 16) & 0xFF);
        frame[6] = static_cast<std::byte>((stream_id >> 8) & 0xFF);
        frame[7] = static_cast<std::byte>(stream_id & 0xFF);
        frame[8] = static_cast<std::byte>((length >> 24) & 0xFF);    // length BE
        frame[9] = static_cast<std::byte>((length >> 16) & 0xFF);
        frame[10] = static_cast<std::byte>((length >> 8) & 0xFF);
        frame[11] = static_cast<std::byte>(length & 0xFF);

        if (!payload.empty())
            std::memcpy(frame.data() + 12, payload.data(), payload.size());

        return frame;
    }

    std::vector<std::byte> make_payload(std::size_t size)
    {
        std::vector<std::byte> payload(size);
        for (std::size_t i = 0; i < size; ++i)
            payload[i] = static_cast<std::byte>(i & 0xFF);
        return payload;
    }
} // namespace

// ============================================================
// smux 帧序列化吞吐量
// ============================================================

static void BM_SmuxFrameSerialize(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    for (auto _ : state)
    {
        arena.reset();
        auto frame = build_smux_data_frame(1,
            std::span<const std::byte>(payload.data(), payload_size), mr);
        benchmark::DoNotOptimize(frame.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(8 + payload_size));
}

// ============================================================
// smux 帧反序列化吞吐量
// ============================================================

static void BM_SmuxFrameDeserialize(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    // 预构建帧
    arena.reset();
    auto frame = build_smux_data_frame(1,
        std::span<const std::byte>(payload.data(), payload_size), mr);

    for (auto _ : state)
    {
        auto hdr = multiplex::smux::deserialization(std::span<const std::byte>(frame.data(), 8));
        benchmark::DoNotOptimize(hdr);
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(8));
}

// ============================================================
// yamux 帧序列化吞吐量
// ============================================================

static void BM_YamuxFrameSerialize(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    for (auto _ : state)
    {
        arena.reset();
        auto frame = build_yamux_data_frame(1,
            std::span<const std::byte>(payload.data(), payload_size), mr);
        benchmark::DoNotOptimize(frame.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(12 + payload_size));
}

// ============================================================
// yamux 帧反序列化吞吐量
// ============================================================

static void BM_YamuxFrameDeserialize(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload_size = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(payload_size);

    arena.reset();
    auto frame = build_yamux_data_frame(1,
        std::span<const std::byte>(payload.data(), payload_size), mr);

    for (auto _ : state)
    {
        auto hdr = multiplex::yamux::parse_header(std::span<const std::byte>(frame.data(), 12));
        benchmark::DoNotOptimize(hdr);
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(12));
}

// ============================================================
// smux 多流帧构建（模拟多流场景，不涉及 socket）
// ============================================================

static void BM_SmuxMultiStreamBuild_4(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload = make_payload(16 * 1024);

    for (auto _ : state)
    {
        arena.reset();

        // 模拟 4 个流各自构建帧
        for (std::uint32_t stream_id = 1; stream_id <= 4; ++stream_id)
        {
            auto frame = build_smux_data_frame(stream_id,
                std::span<const std::byte>(payload.data(), payload.size()), mr);
            benchmark::DoNotOptimize(frame.data());
        }
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 4 * (8 + 16 * 1024));
}

static void BM_SmuxMultiStreamBuild_16(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload = make_payload(16 * 1024);

    for (auto _ : state)
    {
        arena.reset();

        for (std::uint32_t stream_id = 1; stream_id <= 16; ++stream_id)
        {
            auto frame = build_smux_data_frame(stream_id,
                std::span<const std::byte>(payload.data(), payload.size()), mr);
            benchmark::DoNotOptimize(frame.data());
        }
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16 * (8 + 16 * 1024));
}

static void BM_SmuxMultiStreamBuild_64(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload = make_payload(16 * 1024);

    for (auto _ : state)
    {
        arena.reset();

        for (std::uint32_t stream_id = 1; stream_id <= 64; ++stream_id)
        {
            auto frame = build_smux_data_frame(stream_id,
                std::span<const std::byte>(payload.data(), payload.size()), mr);
            benchmark::DoNotOptimize(frame.data());
        }
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * (8 + 16 * 1024));
}

// ============================================================
// yamux 多流帧构建
// ============================================================

static void BM_YamuxMultiStreamBuild_4(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload = make_payload(16 * 1024);

    for (auto _ : state)
    {
        arena.reset();

        for (std::uint32_t stream_id = 1; stream_id <= 4; ++stream_id)
        {
            auto frame = build_yamux_data_frame(stream_id,
                std::span<const std::byte>(payload.data(), payload.size()), mr);
            benchmark::DoNotOptimize(frame.data());
        }
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 4 * (12 + 16 * 1024));
}

static void BM_YamuxMultiStreamBuild_16(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload = make_payload(16 * 1024);

    for (auto _ : state)
    {
        arena.reset();

        for (std::uint32_t stream_id = 1; stream_id <= 16; ++stream_id)
        {
            auto frame = build_yamux_data_frame(stream_id,
                std::span<const std::byte>(payload.data(), payload.size()), mr);
            benchmark::DoNotOptimize(frame.data());
        }
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16 * (12 + 16 * 1024));
}

static void BM_YamuxMultiStreamBuild_64(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload = make_payload(16 * 1024);

    for (auto _ : state)
    {
        arena.reset();

        for (std::uint32_t stream_id = 1; stream_id <= 64; ++stream_id)
        {
            auto frame = build_yamux_data_frame(stream_id,
                std::span<const std::byte>(payload.data(), payload.size()), mr);
            benchmark::DoNotOptimize(frame.data());
        }
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 64 * (12 + 16 * 1024));
}

// ============================================================
// smux 内存分配统计
// ============================================================

static void BM_SmuxAllocsPerOp(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    const auto payload = make_payload(128 * 1024);

    for (auto _ : state)
    {
        arena.reset();

        auto frame = build_smux_data_frame(1,
            std::span<const std::byte>(payload.data(), payload.size()), mr);

        benchmark::DoNotOptimize(frame.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(128 * 1024 + 8));
}

// ============================================================
// BENCHMARK 注册
// ============================================================

BENCHMARK(BM_SmuxFrameSerialize)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Arg(128 * 1024)
    ->Unit(benchmark::kNanosecond);

BENCHMARK(BM_SmuxFrameDeserialize)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Arg(128 * 1024)
    ->Unit(benchmark::kNanosecond);

BENCHMARK(BM_YamuxFrameSerialize)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Arg(128 * 1024)
    ->Unit(benchmark::kNanosecond);

BENCHMARK(BM_YamuxFrameDeserialize)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Arg(128 * 1024)
    ->Unit(benchmark::kNanosecond);

BENCHMARK(BM_SmuxMultiStreamBuild_4)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_SmuxMultiStreamBuild_16)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_SmuxMultiStreamBuild_64)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_YamuxMultiStreamBuild_4)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_YamuxMultiStreamBuild_16)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_YamuxMultiStreamBuild_64)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_SmuxAllocsPerOp)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();