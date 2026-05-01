/**
 * @file RealityBench.cpp
 * @brief Reality TLS 伪装完整握手流程基准测试
 * @details 测量 Reality 握手完整流程性能，
 *          对标 sing-box/Xray Reality 握手时间。
 */

#include <benchmark/benchmark.h>
#include <prism/crypto/x25519.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/memory/pool.hpp>
#include <prism/memory/container.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

using namespace psm;

// ============================================================
// 辅助：生成测试数据
// ============================================================

namespace
{
    /**
     * @brief 生成 X25519 测试密钥对
     * @return 密钥对结构
     */
    auto generate_test_keypair()
    {
        return crypto::generate_x25519_keypair();
    }

    /**
     * @brief 生成模拟 ClientHello 数据
     * @return 模拟的 TLS ClientHello 字节序列
     */
    std::vector<std::uint8_t> make_mock_clienthello()
    {
        std::vector<std::uint8_t> clienthello(512);

        // TLS record header
        clienthello[0] = 0x16;  // Handshake
        clienthello[1] = 0x03;  // TLS 1.2 legacy version
        clienthello[2] = 0x03;
        clienthello[3] = 0x00;  // Length (2 bytes)
        clienthello[4] = 0xFF;

        // Handshake header
        clienthello[5] = 0x01;  // ClientHello

        // 填充随机数据
        for (std::size_t i = 5; i < 512; ++i)
            clienthello[i] = static_cast<std::uint8_t>(i & 0xFF);

        return clienthello;
    }

    /**
     * @brief 生成模拟 ServerHello 数据
     * @return 模拟的 TLS ServerHello 字节序列
     */
    std::vector<std::uint8_t> make_mock_serverhello()
    {
        std::vector<std::uint8_t> serverhello(128);

        // TLS record header
        serverhello[0] = 0x16;  // Handshake
        serverhello[1] = 0x03;  // TLS 1.3
        serverhello[2] = 0x03;
        serverhello[3] = 0x00;  // Length
        serverhello[4] = 0x7A;

        // Handshake header
        serverhello[5] = 0x02;  // ServerHello

        for (std::size_t i = 5; i < 128; ++i)
            serverhello[i] = static_cast<std::uint8_t>(i & 0xFF);

        return serverhello;
    }
} // namespace

// ============================================================
// Reality 完整握手流程测试
// ============================================================

static void BM_RealityFullHandshake(benchmark::State &state)
{
    memory::system::enable_global_pooling();

    // 预生成服务端密钥对
    auto server_keypair = generate_test_keypair();

    for (auto _ : state)
    {
        // 1. 生成客户端临时密钥对
        auto client_keypair = crypto::generate_x25519_keypair();

        // 2. X25519 密钥交换
        auto [exchange_ec, shared_secret] = crypto::x25519(
            client_keypair.private_key, server_keypair.public_key);
        if (fault::failed(exchange_ec))
            state.SkipWithError("X25519 exchange failed");

        // 3. HKDF 密钥派生
        // Extract: PRK = HKDF-Extract(salt, shared_secret)
        auto prk = crypto::hkdf_extract({}, shared_secret);

        // Expand: key = HKDF-Expand(PRK, info, 32)
        const std::array<std::uint8_t, 13> info = {
            't', 'l', 's', '1', '3', ' ', 'r', 'e', 'a', 'l', 'i', 't', 'y'
        };
        auto [expand_ec, session_key] = crypto::hkdf_expand(prk, info, 32);
        if (fault::failed(expand_ec))
            state.SkipWithError("HKDF expand failed");

        // 4. 构建 TLS 伪装响应
        auto serverhello = make_mock_serverhello();
        auto clienthello = make_mock_clienthello();

        benchmark::DoNotOptimize(session_key.data());
        benchmark::DoNotOptimize(serverhello.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

// ============================================================
// 仅 X25519 密钥交换测试
// ============================================================

static void BM_RealityX25519Only(benchmark::State &state)
{
    auto server_keypair = generate_test_keypair();

    for (auto _ : state)
    {
        auto client_keypair = crypto::generate_x25519_keypair();

        auto [ec, shared_secret] = crypto::x25519(
            client_keypair.private_key, server_keypair.public_key);
        if (fault::failed(ec))
            state.SkipWithError("X25519 exchange failed");

        benchmark::DoNotOptimize(shared_secret.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

// ============================================================
// 仅 TLS 伪装测试
// ============================================================

static void BM_RealityTlsMockOnly(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto serverhello = make_mock_serverhello();
        auto clienthello = make_mock_clienthello();

        benchmark::DoNotOptimize(serverhello.data());
        benchmark::DoNotOptimize(clienthello.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * (512 + 128));
}

// ============================================================
// Reality 握手各阶段分解测试
// ============================================================

static void BM_RealityKeyGen(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto keypair = crypto::generate_x25519_keypair();
        benchmark::DoNotOptimize(keypair.private_key.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

static void BM_RealityDerivePublic(benchmark::State &state)
{
    auto keypair = generate_test_keypair();

    for (auto _ : state)
    {
        auto public_key = crypto::derive_x25519_public_key(keypair.private_key);
        benchmark::DoNotOptimize(public_key.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

static void BM_RealityKeyExchange(benchmark::State &state)
{
    auto client_keypair = generate_test_keypair();
    auto server_keypair = generate_test_keypair();

    for (auto _ : state)
    {
        auto [ec, shared_secret] = crypto::x25519(
            client_keypair.private_key, server_keypair.public_key);
        if (fault::failed(ec))
            state.SkipWithError("Key exchange failed");

        benchmark::DoNotOptimize(shared_secret.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

static void BM_RealityHkdfExtract(benchmark::State &state)
{
    auto [_, shared_secret] = crypto::x25519(
        generate_test_keypair().private_key,
        generate_test_keypair().public_key);

    for (auto _ : state)
    {
        auto prk = crypto::hkdf_extract({}, shared_secret);
        benchmark::DoNotOptimize(prk.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

static void BM_RealityHkdfExpand(benchmark::State &state)
{
    auto prk = crypto::hkdf_extract({}, {});

    const std::array<std::uint8_t, 13> info = {
        't', 'l', 's', '1', '3', ' ', 'r', 'e', 'a', 'l', 'i', 't', 'y'
    };

    for (auto _ : state)
    {
        auto [ec, key] = crypto::hkdf_expand(prk, info, 32);
        if (fault::failed(ec))
            state.SkipWithError("HKDF expand failed");

        benchmark::DoNotOptimize(key.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

// ============================================================
// Reality 握手内存占用测试
// ============================================================

static void BM_RealityMemoryUsage(benchmark::State &state)
{
    memory::system::enable_global_pooling();
    memory::frame_arena arena;
    auto mr = arena.get();

    for (auto _ : state)
    {
        arena.reset();

        // Reality 握手典型内存分配
        memory::vector<std::uint8_t> clienthello(mr);
        memory::vector<std::uint8_t> serverhello(mr);
        memory::vector<std::uint8_t> shared_secret(mr);
        memory::vector<std::uint8_t> session_key(mr);

        clienthello.resize(512);
        serverhello.resize(128);
        shared_secret.resize(32);
        session_key.resize(32);

        benchmark::DoNotOptimize(clienthello.data());
        benchmark::DoNotOptimize(serverhello.data());
        benchmark::DoNotOptimize(shared_secret.data());
        benchmark::DoNotOptimize(session_key.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * (512 + 128 + 32 + 32));
}

// ============================================================
// BENCHMARK 注册
// ============================================================

BENCHMARK(BM_RealityFullHandshake)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RealityX25519Only)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RealityTlsMockOnly)->Unit(benchmark::kNanosecond);

BENCHMARK(BM_RealityKeyGen)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RealityDerivePublic)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RealityKeyExchange)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RealityHkdfExtract)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_RealityHkdfExpand)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_RealityMemoryUsage)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();