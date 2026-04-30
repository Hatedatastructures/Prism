/**
 * @file CryptoBench.cpp
 * @brief 加密操作基准测试
 * @details 测量 AEAD (AES-128/256-GCM) 持续加解密吞吐量、
 *          BLAKE3 密钥派生、X25519 密钥交换、HKDF 密钥派生等性能。
 */

#include <benchmark/benchmark.h>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/protocol/shadowsocks/salts.hpp>
#include <prism/fault.hpp>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>

using namespace psm;

// ============================================================
// AEAD 持续加解密吞吐量基准测试
// 模拟真实数据流：循环加密/解密 64KB buffer
// ============================================================

static void BM_AeadContinuousSealAes128Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 16> key{};
    crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, key);

    constexpr std::size_t buf_size = 65536;
    std::vector<std::uint8_t> plaintext(buf_size, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));

    for (auto _ : state)
    {
        auto ec = ctx.seal(ciphertext, plaintext);
        if (fault::failed(ec))
            state.SkipWithError("seal failed");
        benchmark::DoNotOptimize(ciphertext);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buf_size));
}

static void BM_AeadContinuousOpenAes128Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> nonce{};

    constexpr std::size_t buf_size = 65536;
    std::vector<std::uint8_t> plaintext(buf_size, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));

    crypto::aead_context seal_ctx(crypto::aead_cipher::aes_128_gcm, key);
    seal_ctx.seal(ciphertext, plaintext, nonce, {});

    std::vector<std::uint8_t> decrypted(buf_size);
    crypto::aead_context open_ctx(crypto::aead_cipher::aes_128_gcm, key);

    for (auto _ : state)
    {
        auto ec = open_ctx.open(decrypted, ciphertext, nonce, {});
        if (fault::failed(ec))
            state.SkipWithError("open failed");
        benchmark::DoNotOptimize(decrypted);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buf_size));
}

static void BM_AeadContinuousSealAes256Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 32> key{};
    crypto::aead_context ctx(crypto::aead_cipher::aes_256_gcm, key);

    constexpr std::size_t buf_size = 65536;
    std::vector<std::uint8_t> plaintext(buf_size, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));

    for (auto _ : state)
    {
        auto ec = ctx.seal(ciphertext, plaintext);
        if (fault::failed(ec))
            state.SkipWithError("seal failed");
        benchmark::DoNotOptimize(ciphertext);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buf_size));
}

static void BM_AeadContinuousOpenAes256Gcm(benchmark::State &state)
{
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};

    constexpr std::size_t buf_size = 65536;
    std::vector<std::uint8_t> plaintext(buf_size, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));

    crypto::aead_context seal_ctx(crypto::aead_cipher::aes_256_gcm, key);
    seal_ctx.seal(ciphertext, plaintext, nonce, {});

    std::vector<std::uint8_t> decrypted(buf_size);
    crypto::aead_context open_ctx(crypto::aead_cipher::aes_256_gcm, key);

    for (auto _ : state)
    {
        auto ec = open_ctx.open(decrypted, ciphertext, nonce, {});
        if (fault::failed(ec))
            state.SkipWithError("open failed");
        benchmark::DoNotOptimize(decrypted);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(buf_size));
}

// AEAD 多 payload 大小对比
static void BM_AeadSeal_MultiSize(benchmark::State &state)
{
    std::array<std::uint8_t, 32> key{};
    crypto::aead_context ctx(crypto::aead_cipher::aes_256_gcm, key);

    const auto size = static_cast<std::size_t>(state.range(0));
    std::vector<std::uint8_t> plaintext(size, 0x42);
    std::vector<std::uint8_t> ciphertext(crypto::aead_context::seal_output_size(plaintext.size()));

    for (auto _ : state)
    {
        auto ec = ctx.seal(ciphertext, plaintext);
        if (fault::failed(ec))
            state.SkipWithError("seal failed");
        benchmark::DoNotOptimize(ciphertext);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(size));
}

static void BM_AeadOpen_MultiSize(benchmark::State &state)
{
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    crypto::aead_context seal_ctx(crypto::aead_cipher::aes_256_gcm, key);

    const auto size = static_cast<std::size_t>(state.range(0));
    std::vector<std::uint8_t> plaintext(size, 0x42);
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
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(size));
}

// ============================================================
// BLAKE3 密钥派生基准测试（SS2022 核心）
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
// X25519 密钥交换基准测试（Reality 握手核心）
// ============================================================

static void BM_X25519Keygen(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto keypair = crypto::generate_x25519_keypair();
        benchmark::DoNotOptimize(keypair);
    }
}

static void BM_X25519DerivePublic(benchmark::State &state)
{
    std::array<std::uint8_t, 32> private_key{};
    for (std::size_t i = 0; i < private_key.size(); ++i)
        private_key[i] = static_cast<std::uint8_t>(i);

    for (auto _ : state)
    {
        auto public_key = crypto::derive_x25519_public_key(private_key);
        benchmark::DoNotOptimize(public_key);
    }
}

static void BM_X25519KeyExchange(benchmark::State &state)
{
    auto alice = crypto::generate_x25519_keypair();
    auto bob = crypto::generate_x25519_keypair();

    for (auto _ : state)
    {
        auto [ec, shared] = crypto::x25519(alice.private_key, bob.public_key);
        benchmark::DoNotOptimize(shared);
    }
}

// ============================================================
// HKDF 密钥派生基准测试（TLS 1.3 密钥调度核心）
// ============================================================

static void BM_HkdfExtract(benchmark::State &state)
{
    std::array<std::uint8_t, 32> salt{};
    std::array<std::uint8_t, 32> ikm{};
    for (std::size_t i = 0; i < ikm.size(); ++i)
        ikm[i] = static_cast<std::uint8_t>(i);

    for (auto _ : state)
    {
        auto prk = crypto::hkdf_extract(salt, ikm);
        benchmark::DoNotOptimize(prk);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 32);
}

static void BM_HkdfExpand(benchmark::State &state)
{
    std::array<std::uint8_t, 32> prk{};
    std::array<std::uint8_t, 16> info{0x01, 0x02, 0x03, 0x04};

    for (auto _ : state)
    {
        auto [ec, output] = crypto::hkdf_expand(prk, info, 32);
        benchmark::DoNotOptimize(output);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 32);
}

static void BM_HkdfExpandLabel(benchmark::State &state)
{
    std::array<std::uint8_t, 32> secret{};
    std::array<std::uint8_t, 32> context{};
    for (std::size_t i = 0; i < context.size(); ++i)
        context[i] = static_cast<std::uint8_t>(i);

    for (auto _ : state)
    {
        auto [ec, output] = crypto::hkdf_expand_label(secret, "key", context, 16);
        benchmark::DoNotOptimize(output);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16);
}

// ============================================================
// Salt Pool 重放保护基准测试
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

// AEAD 持续加解密吞吐量
BENCHMARK(BM_AeadContinuousSealAes128Gcm);
BENCHMARK(BM_AeadContinuousOpenAes128Gcm);
BENCHMARK(BM_AeadContinuousSealAes256Gcm);
BENCHMARK(BM_AeadContinuousOpenAes256Gcm);

// AEAD 多 payload 大小
BENCHMARK(BM_AeadSeal_MultiSize)->Arg(16)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)->Arg(65536);
BENCHMARK(BM_AeadOpen_MultiSize)->Arg(16)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)->Arg(65536);

// BLAKE3 密钥派生
BENCHMARK(BM_Blake3DeriveKey);

// X25519 密钥交换
BENCHMARK(BM_X25519Keygen);
BENCHMARK(BM_X25519DerivePublic);
BENCHMARK(BM_X25519KeyExchange);

// HKDF 密钥派生
BENCHMARK(BM_HkdfExtract);
BENCHMARK(BM_HkdfExpand);
BENCHMARK(BM_HkdfExpandLabel);

// Salt Pool 重放保护
BENCHMARK(BM_SaltPoolCheckAndInsert);

BENCHMARK_MAIN();
