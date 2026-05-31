/**
 * @file StealthBench.cpp
 * @brief 伪装方案密码学原语基准测试
 * @details 测量 RestLS 和 ShadowTLS 的热路径密码操作性能。
 *          RestLS 基于 BLAKE3 keyed mode，ShadowTLS 基于 HMAC-SHA1。
 *          这些函数在每条连接的握手和数据传输阶段被调用，延迟直接影响吞吐。
 */

#include <benchmark/benchmark.h>
#include <prism/stealth/facade/restls/crypto.hpp>
#include <prism/stealth/facade/shadowtls/util/auth.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace
{

// ============================================================
// RestLS 测试数据
// ============================================================

/// 测试密码
const auto test_password = std::string("test-password-for-benchmark-2024");

/// 从密码派生的 RestlsSecret
const auto test_secret = psm::stealth::restls::derive_secret(test_password);

/// TLS ServerHello server_random（32 字节）
std::array<std::uint8_t, 32> make_server_random()
{
    std::array<std::uint8_t, 32> rnd{};
    for (std::size_t i = 0; i < 32; ++i)
    {
        rnd[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }
    return rnd;
}
const auto test_server_random = make_server_random();

/// TLS 记录头（5 字节: 0x17 0x03 0x03 + 长度）
std::array<std::uint8_t, 5> make_tls_header()
{
    std::array<std::uint8_t, 5> hdr{};
    hdr[0] = 0x17; // application_data
    hdr[1] = 0x03;
    hdr[2] = 0x03;
    hdr[3] = 0x00; // length = 256
    hdr[4] = 0x00;
    return hdr;
}
const auto test_tls_header = make_tls_header();

/// client_finished（模拟加密 TLS record，64 字节）
std::vector<std::uint8_t> make_client_finished()
{
    std::vector<std::uint8_t> cf(64);
    for (std::size_t i = 0; i < cf.size(); ++i)
    {
        cf[i] = static_cast<std::uint8_t>(i);
    }
    return cf;
}
const auto test_client_finished = make_client_finished();

/// payload_after_mac（模拟 masked_len + masked_cmd + data + padding，128 字节）
std::vector<std::uint8_t> make_payload()
{
    std::vector<std::uint8_t> p(128);
    for (std::size_t i = 0; i < p.size(); ++i)
    {
        p[i] = static_cast<std::uint8_t>(i ^ 0xAA);
    }
    return p;
}
const auto test_payload = make_payload();

/// plaintext_sample（模拟明文数据样本，32 字节）
std::vector<std::uint8_t> make_plaintext_sample()
{
    std::vector<std::uint8_t> s(32);
    for (std::size_t i = 0; i < s.size(); ++i)
    {
        s[i] = static_cast<std::uint8_t>(i * 3 + 1);
    }
    return s;
}
const auto test_plaintext_sample = make_plaintext_sample();

/// 小数据块（16 字节，用于 xor_with_mask 测试）
std::vector<std::uint8_t> make_small_data()
{
    std::vector<std::uint8_t> d(16);
    for (std::size_t i = 0; i < d.size(); ++i)
    {
        d[i] = static_cast<std::uint8_t>(i);
    }
    return d;
}

/// 大数据块（4096 字节，用于 xor_with_mask 测试）
std::vector<std::uint8_t> make_large_data()
{
    std::vector<std::uint8_t> d(4096);
    for (std::size_t i = 0; i < d.size(); ++i)
    {
        d[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    return d;
}

// ============================================================
// ShadowTLS 测试数据
// ============================================================

/// ShadowTLS 测试密码
const auto stls_password = std::string("shadowtls-auth-password");

/// ShadowTLS server_random（32 字节）
std::vector<std::byte> make_stls_server_random()
{
    std::vector<std::byte> rnd(32);
    for (std::size_t i = 0; i < rnd.size(); ++i)
    {
        rnd[i] = static_cast<std::byte>(i * 11 + 7);
    }
    return rnd;
}
const auto stls_server_random = make_stls_server_random();

/// ShadowTLS payload（64 字节）
std::vector<std::byte> make_stls_payload()
{
    std::vector<std::byte> p(64);
    for (std::size_t i = 0; i < p.size(); ++i)
    {
        p[i] = static_cast<std::byte>(i ^ 0x55);
    }
    return p;
}
const auto stls_payload = make_stls_payload();

/// ShadowTLS ClientHello 帧数据（含 TLS 记录头，模拟最小合法帧）
std::vector<std::byte> make_stls_client_hello()
{
    // TLS record header (5B) + handshake header (4B) + version (2B) + random (32B)
    // + session_id_len (1B) + session_id (32B, 后 4 字节放 HMAC)
    std::vector<std::byte> ch(5 + 4 + 2 + 32 + 1 + 32);
    ch[0] = static_cast<std::byte>(0x16); // handshake
    ch[1] = static_cast<std::byte>(0x03);
    ch[2] = static_cast<std::byte>(0x01);
    // 填充一些随机数据
    for (std::size_t i = 5; i < ch.size(); ++i)
    {
        ch[i] = static_cast<std::byte>(i & 0xFF);
    }
    return ch;
}
const auto stls_client_hello = make_stls_client_hello();

// ============================================================
// RestLS 基准测试
// ============================================================

void BM_Restls_DeriveSecret(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto secret = psm::stealth::restls::derive_secret(test_password);
        benchmark::DoNotOptimize(secret.data());
    }
}
BENCHMARK(BM_Restls_DeriveSecret);

void BM_Restls_ComputeServerMask(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto mask = psm::stealth::restls::compute_server_mask(test_secret, test_server_random);
        benchmark::DoNotOptimize(mask.data());
    }
}
BENCHMARK(BM_Restls_ComputeServerMask);

void BM_Restls_ComputeAuthMac_C2S(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::stealth::restls::auth_mac_input input{
            test_secret,
            test_server_random,
            psm::stealth::restls::flow_direction::to_server,
            1,
            test_client_finished,
            test_tls_header,
            test_payload,
        };
        auto mac = psm::stealth::restls::compute_auth_mac(input);
        benchmark::DoNotOptimize(mac.data());
    }
}
BENCHMARK(BM_Restls_ComputeAuthMac_C2S);

void BM_Restls_ComputeAuthMac_S2C(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::stealth::restls::auth_mac_input input{
            test_secret,
            test_server_random,
            psm::stealth::restls::flow_direction::to_client,
            5,
            {}, // S2C 无 client_finished
            test_tls_header,
            test_payload,
        };
        auto mac = psm::stealth::restls::compute_auth_mac(input);
        benchmark::DoNotOptimize(mac.data());
    }
}
BENCHMARK(BM_Restls_ComputeAuthMac_S2C);

void BM_Restls_ComputeMask_C2S(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::stealth::restls::mask_input input{
            test_secret,
            test_server_random,
            psm::stealth::restls::flow_direction::to_server,
            1,
            test_plaintext_sample,
        };
        auto mask = psm::stealth::restls::compute_mask(input);
        benchmark::DoNotOptimize(mask.data());
    }
}
BENCHMARK(BM_Restls_ComputeMask_C2S);

void BM_Restls_ComputeMask_S2C(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::stealth::restls::mask_input input{
            test_secret,
            test_server_random,
            psm::stealth::restls::flow_direction::to_client,
            10,
            test_plaintext_sample,
        };
        auto mask = psm::stealth::restls::compute_mask(input);
        benchmark::DoNotOptimize(mask.data());
    }
}
BENCHMARK(BM_Restls_ComputeMask_S2C);

void BM_Restls_XorWithMask_Small(benchmark::State &state)
{
    auto mask = psm::stealth::restls::compute_server_mask(test_secret, test_server_random);
    std::size_t bytes_processed = 0;
    for (auto _ : state)
    {
        auto data = make_small_data();
        psm::stealth::restls::xor_with_mask(data, mask);
        benchmark::DoNotOptimize(data.data());
        bytes_processed += data.size();
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(bytes_processed));
}
BENCHMARK(BM_Restls_XorWithMask_Small);

void BM_Restls_XorWithMask_Large(benchmark::State &state)
{
    auto mask = psm::stealth::restls::compute_server_mask(test_secret, test_server_random);
    std::size_t bytes_processed = 0;
    for (auto _ : state)
    {
        auto data = make_large_data();
        psm::stealth::restls::xor_with_mask(data, mask);
        benchmark::DoNotOptimize(data.data());
        bytes_processed += data.size();
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(bytes_processed));
}
BENCHMARK(BM_Restls_XorWithMask_Large);

// ============================================================
// ShadowTLS 基准测试
// ============================================================

void BM_ShadowTLS_ComputeHmac(benchmark::State &state)
{
    std::vector<std::byte> data(64);
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        data[i] = static_cast<std::byte>(i);
    }
    for (auto _ : state)
    {
        auto hmac = psm::stealth::shadowtls::compute_hmac(
            stls_password,
            reinterpret_cast<const std::byte *>(data.data()),
            data.size());
        benchmark::DoNotOptimize(hmac.data());
    }
}
BENCHMARK(BM_ShadowTLS_ComputeHmac);

void BM_ShadowTLS_VerifyClientHello(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = psm::stealth::shadowtls::verify_client_hello(stls_client_hello, stls_password);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ShadowTLS_VerifyClientHello);

void BM_ShadowTLS_ComputeWriteHmac(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto hmac = psm::stealth::shadowtls::compute_write_hmac(stls_password, stls_server_random, stls_payload);
        benchmark::DoNotOptimize(hmac.data());
    }
}
BENCHMARK(BM_ShadowTLS_ComputeWriteHmac);

void BM_ShadowTLS_ComputeWriteKey(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto key = psm::stealth::shadowtls::compute_write_key(stls_password, stls_server_random);
        benchmark::DoNotOptimize(key.data());
    }
}
BENCHMARK(BM_ShadowTLS_ComputeWriteKey);

} // namespace

BENCHMARK_MAIN();
