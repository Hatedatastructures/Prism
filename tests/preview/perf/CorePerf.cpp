/**
 * @file CorePerf.cpp
 * @brief 底层工具层性能基准（新 core 模块热路径）
 * @details 覆盖：
 * 1. fault：错误码检查（Succeeded/Failed）
 * 2. memory：PMR 分配/释放
 * 3. crypto：AEAD 加解密吞吐
 * 4. qpack：HTTP/3 头块编解码
 * 5. Middleware：relay 转发吞吐
 * @note 使用 Google Benchmark，输出 ops/s 与 MB/s。
 */

#include <benchmark/benchmark.h>

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pool.hpp>
#include <common/Core/Crypto/Aead.hpp>
#include <common/Protocols/Http3/Qpack.hpp>

namespace
{

    // ── 1. fault 错误码检查 ──

    static void BM_FaultSucceeded(benchmark::State &State)
    {
        Preview::Fault::Code c = Preview::Fault::Code::success;
        for (auto _ : State)
        {
            benchmark::DoNotOptimize(Preview::Fault::Succeeded(c));
        }
    }
    BENCHMARK(BM_FaultSucceeded);

    static void BM_FaultDescribe(benchmark::State &State)
    {
        const auto c = Preview::Fault::Code::timeout;
        for (auto _ : State)
        {
            benchmark::DoNotOptimize(Preview::Fault::Describe(c));
        }
    }
    BENCHMARK(BM_FaultDescribe);

    // ── 2. PMR 内存分配 ──

    static void BM_MemoryPoolAlloc(benchmark::State &State)
    {
        auto mr = Preview::Memory::CurrentResource();
        for (auto _ : State)
        {
            auto *p = mr->allocate(64, alignof(std::max_align_t));
            benchmark::DoNotOptimize(p);
            mr->deallocate(p, 64, alignof(std::max_align_t));
        }
    }
    BENCHMARK(BM_MemoryPoolAlloc);

    static void BM_MemoryStringAppend(benchmark::State &State)
    {
        auto mr = Preview::Memory::CurrentResource();
        for (auto _ : State)
        {
            Preview::Memory::string s(mr);
            s.append("hello");
            s.append("world");
            benchmark::DoNotOptimize(s.size());
        }
    }
    BENCHMARK(BM_MemoryStringAppend);

    // ── 3. AEAD 加解密 ──

    static void BM_AeadSeal16KB(benchmark::State &State)
    {
        std::array<std::uint8_t, 32> key{};
        std::fill(key.begin(), key.end(), 0x42);
        Preview::Crypto::AeadContext ctx(Preview::Crypto::AeadCipher::aes_128_gcm, key);

        std::array<std::uint8_t, 16384> plain{};
        std::array<std::uint8_t, 32> seed{};
        std::fill(seed.begin(), seed.end(), 0x7);
        std::array<std::uint8_t, 16384 + 16> cipher{};
        // 运行时种子，防止编译期常量折叠
        for (std::size_t i = 0; i < plain.size(); ++i)
            plain[i] = static_cast<std::uint8_t>(seed[i % seed.size()] + i);

        std::size_t Total = 0;
        for (auto _ : State)
        {
            auto ec = ctx.Seal(cipher, plain);
            benchmark::DoNotOptimize(ec);
            Total += plain.size();
        }
        State.SetBytesProcessed(static_cast<std::int64_t>(Total));
    }
    BENCHMARK(BM_AeadSeal16KB);

    // ── 4. QPACK 编解码 ──

    static void BM_QpackEncodeAuth(benchmark::State &State)
    {
        std::array<std::uint8_t, 512> buf{};
        for (auto _ : State)
        {
            auto offset = Preview::Http3::Qpack::EncodePrefix(buf);
            offset += Preview::Http3::Qpack::EncodeLiteral(
                ":Method", "POST", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
            offset += Preview::Http3::Qpack::EncodeLiteral(
                ":Path", "/Auth", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
            offset += Preview::Http3::Qpack::EncodeLiteral(
                "hysteria-Auth", "password123",
                std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
            benchmark::DoNotOptimize(offset);
        }
    }
    BENCHMARK(BM_QpackEncodeAuth);

    static void BM_QpackDecodeAuth(benchmark::State &State)
    {
        auto mr = Preview::Memory::CurrentResource();
        std::array<std::uint8_t, 512> buf{};
        auto offset = Preview::Http3::Qpack::EncodePrefix(buf);
        offset += Preview::Http3::Qpack::EncodeLiteral(
            ":Method", "POST", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
        offset += Preview::Http3::Qpack::EncodeLiteral(
            "hysteria-Auth", "password123",
            std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));

        for (auto _ : State)
        {
            auto fields = Preview::Http3::Qpack::DecodeHeaderBlock(
                std::span<const std::uint8_t>(buf.data(), offset), mr);
            benchmark::DoNotOptimize(fields.size());
        }
    }
    BENCHMARK(BM_QpackDecodeAuth);

} // namespace

BENCHMARK_MAIN();
