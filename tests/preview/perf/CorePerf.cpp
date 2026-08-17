/**
 * @file CorePerf.cpp
 * @brief 底层工具层性能基准（新 core 模块热路径）
 * @details 覆盖：
 * 1. fault：错误码检查（succeeded/failed）
 * 2. memory：PMR 分配/释放
 * 3. crypto：AEAD 加解密吞吐
 * 4. qpack：HTTP/3 头块编解码
 * 5. middleware：relay 转发吞吐
 * @note 使用 Google Benchmark，输出 ops/s 与 MB/s。
 */

#include <benchmark/benchmark.h>

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/memory/pool.hpp>
#include <common/core/crypto/aead.hpp>
#include <common/protocols/http3/qpack.hpp>

namespace
{

    // ── 1. fault 错误码检查 ──

    static void BM_FaultSucceeded(benchmark::State &state)
    {
        preview::fault::code c = preview::fault::code::success;
        for (auto _ : state)
        {
            benchmark::DoNotOptimize(preview::fault::succeeded(c));
        }
    }
    BENCHMARK(BM_FaultSucceeded);

    static void BM_FaultDescribe(benchmark::State &state)
    {
        const auto c = preview::fault::code::timeout;
        for (auto _ : state)
        {
            benchmark::DoNotOptimize(preview::fault::describe(c));
        }
    }
    BENCHMARK(BM_FaultDescribe);

    // ── 2. PMR 内存分配 ──

    static void BM_MemoryPoolAlloc(benchmark::State &state)
    {
        auto mr = preview::memory::current_resource();
        for (auto _ : state)
        {
            auto *p = mr->allocate(64, alignof(std::max_align_t));
            benchmark::DoNotOptimize(p);
            mr->deallocate(p, 64, alignof(std::max_align_t));
        }
    }
    BENCHMARK(BM_MemoryPoolAlloc);

    static void BM_MemoryStringAppend(benchmark::State &state)
    {
        auto mr = preview::memory::current_resource();
        for (auto _ : state)
        {
            preview::memory::string s(mr);
            s.append("hello");
            s.append("world");
            benchmark::DoNotOptimize(s.size());
        }
    }
    BENCHMARK(BM_MemoryStringAppend);

    // ── 3. AEAD 加解密 ──

    static void BM_AeadSeal16KB(benchmark::State &state)
    {
        std::array<std::uint8_t, 32> key{};
        std::fill(key.begin(), key.end(), 0x42);
        preview::crypto::aead_context ctx(preview::crypto::aead_cipher::aes_128_gcm, key);

        std::array<std::uint8_t, 16384> plain{};
        std::array<std::uint8_t, 32> seed{};
        std::fill(seed.begin(), seed.end(), 0x7);
        std::array<std::uint8_t, 16384 + 16> cipher{};
        // 运行时种子，防止编译期常量折叠
        for (std::size_t i = 0; i < plain.size(); ++i)
            plain[i] = static_cast<std::uint8_t>(seed[i % seed.size()] + i);

        std::size_t total = 0;
        for (auto _ : state)
        {
            auto ec = ctx.seal(cipher, plain);
            benchmark::DoNotOptimize(ec);
            total += plain.size();
        }
        state.SetBytesProcessed(static_cast<std::int64_t>(total));
    }
    BENCHMARK(BM_AeadSeal16KB);

    // ── 4. QPACK 编解码 ──

    static void BM_QpackEncodeAuth(benchmark::State &state)
    {
        std::array<std::uint8_t, 512> buf{};
        for (auto _ : state)
        {
            auto offset = preview::http3::qpack::encode_prefix(buf);
            offset += preview::http3::qpack::encode_literal(
                ":method", "POST", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
            offset += preview::http3::qpack::encode_literal(
                ":path", "/auth", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
            offset += preview::http3::qpack::encode_literal(
                "hysteria-auth", "password123",
                std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
            benchmark::DoNotOptimize(offset);
        }
    }
    BENCHMARK(BM_QpackEncodeAuth);

    static void BM_QpackDecodeAuth(benchmark::State &state)
    {
        auto mr = preview::memory::current_resource();
        std::array<std::uint8_t, 512> buf{};
        auto offset = preview::http3::qpack::encode_prefix(buf);
        offset += preview::http3::qpack::encode_literal(
            ":method", "POST", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
        offset += preview::http3::qpack::encode_literal(
            "hysteria-auth", "password123",
            std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));

        for (auto _ : state)
        {
            auto fields = preview::http3::qpack::decode_header_block(
                std::span<const std::uint8_t>(buf.data(), offset), mr);
            benchmark::DoNotOptimize(fields.size());
        }
    }
    BENCHMARK(BM_QpackDecodeAuth);

} // namespace

BENCHMARK_MAIN();
