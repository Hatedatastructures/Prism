/**
 * @file CryptoMiscBench.cpp
 * @brief 加密辅助操作基准测试
 * @details 测量加密辅助操作性能：
 *          Base64 编码（RFC 4648，不同长度输入）、
 *          AES-ECB 块加密/解密（16 字节块操作）。
 *          Base64 用于配置解析和凭证编码，
 *          ECB 块操作是 Shadowsocks 等协议的基础组件。
 */

#include <benchmark/benchmark.h>
#include <prism/crypto/base64.hpp>
#include <prism/crypto/block.hpp>
#include <prism/memory/container.hpp>

#include <array>
#include <cstdint>

namespace
{

// ============================================================
// 测试数据（const 全局对象）
// ============================================================

/// 16 字节递增序列输入
auto make_short_input() -> std::array<std::uint8_t, 16>
{
    std::array<std::uint8_t, 16> input{};
    for (std::size_t i = 0; i < input.size(); ++i)
    {
        input[i] = static_cast<std::uint8_t>(i);
    }
    return input;
}

const auto g_short_input = make_short_input();

/// 256 字节循环序列输入
auto make_medium_input() -> psm::memory::vector<std::uint8_t>
{
    psm::memory::vector<std::uint8_t> input(256, 0);
    for (std::size_t i = 0; i < input.size(); ++i)
    {
        input[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    return input;
}

const auto g_medium_input = make_medium_input();

/// 4096 字节循环序列输入
auto make_long_input() -> psm::memory::vector<std::uint8_t>
{
    psm::memory::vector<std::uint8_t> input(4096, 0);
    for (std::size_t i = 0; i < input.size(); ++i)
    {
        input[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    return input;
}

const auto g_long_input = make_long_input();

/// 全零 16 字节输入（二进制边界测试）
const std::array<std::uint8_t, 16> g_zero_input{};

/// 16 字节递增密钥
auto make_ecb_key() -> std::array<std::uint8_t, 16>
{
    std::array<std::uint8_t, 16> key{};
    for (std::size_t i = 0; i < key.size(); ++i)
    {
        key[i] = static_cast<std::uint8_t>(i);
    }
    return key;
}

const auto g_ecb_key = make_ecb_key();

/// 16 字节递增明文
auto make_ecb_plaintext() -> std::array<std::uint8_t, 16>
{
    std::array<std::uint8_t, 16> pt{};
    for (std::size_t i = 0; i < pt.size(); ++i)
    {
        pt[i] = static_cast<std::uint8_t>(i);
    }
    return pt;
}

const auto g_ecb_plaintext = make_ecb_plaintext();

/// 预计算的 ECB 密文（用于解密测试）
const auto g_ecb_ciphertext = psm::crypto::ecb_encrypt(g_ecb_plaintext, g_ecb_key);

/// 批量测试：100 个不同密钥
auto make_batch_keys() -> psm::memory::vector<std::array<std::uint8_t, 16>>
{
    psm::memory::vector<std::array<std::uint8_t, 16>> keys(100);
    for (std::size_t k = 0; k < keys.size(); ++k)
    {
        for (std::size_t i = 0; i < 16; ++i)
        {
            keys[k][i] = static_cast<std::uint8_t>((k * 16 + i) & 0xFF);
        }
    }
    return keys;
}

const auto g_batch_keys = make_batch_keys();

/// 批量测试：100 块明文
auto make_batch_blocks() -> psm::memory::vector<std::array<std::uint8_t, 16>>
{
    psm::memory::vector<std::array<std::uint8_t, 16>> blocks(100);
    for (std::size_t b = 0; b < blocks.size(); ++b)
    {
        for (std::size_t i = 0; i < 16; ++i)
        {
            blocks[b][i] = static_cast<std::uint8_t>((b + i) & 0xFF);
        }
    }
    return blocks;
}

const auto g_batch_blocks = make_batch_blocks();

// ============================================================
// Base64 编码基准测试
// ============================================================

/// @brief 测量 16 字节短输入 Base64 编码性能
void BM_CryptoMisc_Base64Encode_Short(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = psm::crypto::base64_encode(g_short_input);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16);
}
BENCHMARK(BM_CryptoMisc_Base64Encode_Short);

/// @brief 测量 256 字节中等输入 Base64 编码性能
void BM_CryptoMisc_Base64Encode_Medium(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = psm::crypto::base64_encode(g_medium_input);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 256);
}
BENCHMARK(BM_CryptoMisc_Base64Encode_Medium);

/// @brief 测量 4096 字节长输入 Base64 编码性能
void BM_CryptoMisc_Base64Encode_Long(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = psm::crypto::base64_encode(g_long_input);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 4096);
}
BENCHMARK(BM_CryptoMisc_Base64Encode_Long);

/// @brief 测量全零二进制输入 Base64 编码性能
void BM_CryptoMisc_Base64Encode_Binary(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = psm::crypto::base64_encode(g_zero_input);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16);
}
BENCHMARK(BM_CryptoMisc_Base64Encode_Binary);

// ============================================================
// AES-ECB 块操作基准测试
// ============================================================

/// @brief 测量 AES-ECB 单块加密性能
void BM_CryptoMisc_EcbEncrypt(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto ciphertext = psm::crypto::ecb_encrypt(g_ecb_plaintext, g_ecb_key);
        benchmark::DoNotOptimize(ciphertext);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16);
}
BENCHMARK(BM_CryptoMisc_EcbEncrypt);

/// @brief 测量 AES-ECB 单块解密性能
void BM_CryptoMisc_EcbDecrypt(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto decrypted = psm::crypto::ecb_decrypt(g_ecb_ciphertext, g_ecb_key);
        benchmark::DoNotOptimize(decrypted);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 16);
}
BENCHMARK(BM_CryptoMisc_EcbDecrypt);

/// @brief 测量 AES-ECB 加密再解密的完整往返性能
void BM_CryptoMisc_EcbRoundtrip(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto ciphertext = psm::crypto::ecb_encrypt(g_ecb_plaintext, g_ecb_key);
        auto decrypted = psm::crypto::ecb_decrypt(ciphertext, g_ecb_key);
        benchmark::DoNotOptimize(decrypted);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 32);
}
BENCHMARK(BM_CryptoMisc_EcbRoundtrip);

/// @brief 测量 100 块不同密钥批量加密的吞吐量
void BM_CryptoMisc_EcbBatch(benchmark::State &state)
{
    for (auto _ : state)
    {
        for (std::size_t i = 0; i < 100; ++i)
        {
            auto ciphertext = psm::crypto::ecb_encrypt(g_batch_blocks[i], g_batch_keys[i]);
            benchmark::DoNotOptimize(ciphertext);
        }
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * 100 * 16);
}
BENCHMARK(BM_CryptoMisc_EcbBatch);

} // namespace

BENCHMARK_MAIN();
