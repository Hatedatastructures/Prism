/**
 * @file CryptoBench.cpp
 * @brief 加密操作基准测试
 * @details 测量 AEAD (AES-128/256-GCM) 加解密、BLAKE3 密钥派生、
 * SS2022 Salt Pool 重放检测等加密操作的性能。
 */

#include <benchmark/benchmark.h>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/protocol/shadowsocks/salts.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>

using namespace psm;

// ============================================================
// AEAD Seal/Open 基准测试
// ============================================================

static void BM_AeadSealAes128Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 16> key{};
    crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, key);

    std::vector<std::uint8_t> plaintext(1024, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));

    for (auto _ : state)
    {
        auto ec = ctx.seal(ciphertext, plaintext);
        if (fault::failed(ec))
            state.SkipWithError("seal failed");
        benchmark::DoNotOptimize(ciphertext);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(plaintext.size()));
}

static void BM_AeadOpenAes128Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> nonce{};
    crypto::aead_context seal_ctx(crypto::aead_cipher::aes_128_gcm, key);

    std::vector<std::uint8_t> plaintext(1024, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));
    seal_ctx.seal(ciphertext, plaintext, nonce, {});

    std::vector<std::uint8_t> decrypted(crypto::aead_context::open_output_size(ciphertext.size()));
    crypto::aead_context open_ctx(crypto::aead_cipher::aes_128_gcm, key);

    for (auto _ : state)
    {
        auto ec = open_ctx.open(decrypted, ciphertext, nonce, {});
        if (fault::failed(ec))
            state.SkipWithError("open failed");
        benchmark::DoNotOptimize(decrypted);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(plaintext.size()));
}

static void BM_AeadSealAes256Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 32> key{};
    crypto::aead_context ctx(crypto::aead_cipher::aes_256_gcm, key);

    std::vector<std::uint8_t> plaintext(1024, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));

    for (auto _ : state)
    {
        auto ec = ctx.seal(ciphertext, plaintext);
        if (fault::failed(ec))
            state.SkipWithError("seal failed");
        benchmark::DoNotOptimize(ciphertext);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(plaintext.size()));
}

static void BM_AeadOpenAes256Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    crypto::aead_context seal_ctx(crypto::aead_cipher::aes_256_gcm, key);

    std::vector<std::uint8_t> plaintext(1024, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));
    seal_ctx.seal(ciphertext, plaintext, nonce, {});

    std::vector<std::uint8_t> decrypted(crypto::aead_context::open_output_size(ciphertext.size()));
    crypto::aead_context open_ctx(crypto::aead_cipher::aes_256_gcm, key);

    for (auto _ : state)
    {
        auto ec = open_ctx.open(decrypted, ciphertext, nonce, {});
        if (fault::failed(ec))
            state.SkipWithError("open failed");
        benchmark::DoNotOptimize(decrypted);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(plaintext.size()));
}

// ============================================================
// BLAKE3 密钥派生基准测试
// ============================================================

static void BM_Blake3DeriveKey(benchmark::State &state)
{
    std::array<std::uint8_t, 32> material{};
    for (std::size_t i = 0; i < material.size(); ++i)
        material[i] = static_cast<std::uint8_t>(i);

    for (auto _ : state)
    {
        auto key = crypto::derive_key("shadowsocks 2022 session subkey", material, 32);
        benchmark::DoNotOptimize(key);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 32);
}

// ============================================================
// Salt Pool 基准测试
// ============================================================

static void BM_SaltPoolCheckAndInsert(benchmark::State &state)
{
    protocol::shadowsocks::salt_pool pool(3600);
    std::mt19937 rng(42);

    for (auto _ : state)
    {
        std::array<std::uint8_t, 16> salt{};
        for (auto &b : salt)
            b = static_cast<std::uint8_t>(rng());

        auto result = pool.check_and_insert(salt);
        benchmark::DoNotOptimize(result);
    }
}

// ============================================================
// BENCHMARK 注册
// ============================================================

BENCHMARK(BM_AeadSealAes128Gcm);
BENCHMARK(BM_AeadOpenAes128Gcm);
BENCHMARK(BM_AeadSealAes256Gcm);
BENCHMARK(BM_AeadOpenAes256Gcm);
BENCHMARK(BM_Blake3DeriveKey);
BENCHMARK(BM_SaltPoolCheckAndInsert);

BENCHMARK_MAIN();
