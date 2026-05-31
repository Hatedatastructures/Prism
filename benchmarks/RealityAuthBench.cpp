/**
 * @file RealityAuthBench.cpp
 * @brief Reality 认证与密钥派生基准测试
 * @details 测量 Reality 握手热路径性能：SNI/shortId 匹配、hex 解码、
 *          X25519 密钥交换 + HKDF 派生（authenticate）、握手/应用密钥派生、
 *          Finished verify 计算、TLS 记录构建与 AEAD 加密。
 *          authenticate 是最重的单次操作（X25519 + HKDF + AES-GCM），
 *          延迟直接影响 TLS 握手吞吐。
 */

#include <benchmark/benchmark.h>
#include <prism/stealth/facade/reality/util/auth.hpp>
#include <prism/stealth/facade/reality/util/keygen.hpp>
#include <prism/stealth/facade/reality/util/response.hpp>
#include <prism/stealth/facade/reality/config.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/memory/container.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace
{

using namespace psm::stealth::reality;
namespace mem = psm::memory;

// ============================================================
// 测试数据
// ============================================================

/// 构建测试用 config
auto make_config() -> config
{
    config cfg;
    cfg.dest = "www.example.com:443";
    cfg.server_names.push_back(mem::string("www.example.com"));
    cfg.server_names.push_back(mem::string("example.com"));
    // 真实 base64 编码 X25519 私钥（测试用随机值）
    cfg.private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    cfg.short_ids.push_back(mem::string("abcdef1234567890"));
    cfg.short_ids.push_back(mem::string("0102030405060708"));
    return cfg;
}
const auto test_config = make_config();

/// 构建测试用 hello_features
auto make_hello_features() -> psm::protocol::tls::hello_features
{
    psm::protocol::tls::hello_features feat;
    feat.server_name = mem::string("www.example.com");
    feat.session_id_len = 32;
    feat.session_id.resize(32);
    for (std::size_t i = 0; i < 32; ++i)
    {
        feat.session_id[i] = static_cast<std::uint8_t>(i);
    }
    feat.has_x25519 = true;
    for (std::size_t i = 0; i < 32; ++i)
    {
        feat.x25519_key[i] = static_cast<std::uint8_t>(i * 3 + 1);
    }
    feat.random = {};
    return feat;
}
const auto test_features = make_hello_features();

/// 测试 SNI 列表
const mem::vector<mem::string> test_server_names = [] {
    mem::vector<mem::string> names;
    names.push_back(mem::string("www.example.com"));
    names.push_back(mem::string("example.com"));
    names.push_back(mem::string("test.example.com"));
    return names;
}();

/// 测试 shortId 列表
const mem::vector<mem::string> test_short_ids = [] {
    mem::vector<mem::string> ids;
    ids.push_back(mem::string("abcdef1234567890"));
    ids.push_back(mem::string("0102030405060708"));
    ids.push_back(mem::string("aabbccddeeff0011"));
    return ids;
}();

/// 32 字节共享密钥（模拟 X25519 输出）
std::array<std::uint8_t, 32> make_shared_secret()
{
    std::array<std::uint8_t, 32> ss{};
    for (std::size_t i = 0; i < 32; ++i)
    {
        ss[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }
    return ss;
}
const auto test_shared_secret = make_shared_secret();

/// 模拟 ClientHello 消息（64 字节）
std::vector<std::uint8_t> make_chello_msg()
{
    std::vector<std::uint8_t> msg(64);
    for (std::size_t i = 0; i < msg.size(); ++i)
    {
        msg[i] = static_cast<std::uint8_t>(i);
    }
    return msg;
}
const auto test_chello = make_chello_msg();

/// 模拟 ServerHello 消息（64 字节）
std::vector<std::uint8_t> make_shello_msg()
{
    std::vector<std::uint8_t> msg(64);
    for (std::size_t i = 0; i < msg.size(); ++i)
    {
        msg[i] = static_cast<std::uint8_t>(i ^ 0x55);
    }
    return msg;
}
const auto test_shello = make_shello_msg();

/// 模拟 32 字节密钥
std::array<std::uint8_t, 32> make_key_32()
{
    std::array<std::uint8_t, 32> k{};
    for (std::size_t i = 0; i < 32; ++i)
    {
        k[i] = static_cast<std::uint8_t>(i * 5 + 2);
    }
    return k;
}
const auto test_key_32 = make_key_32();

/// 16 字节密钥（AES-128）
std::array<std::uint8_t, 16> make_aes_key()
{
    std::array<std::uint8_t, 16> k{};
    for (std::size_t i = 0; i < 16; ++i)
    {
        k[i] = static_cast<std::uint8_t>(i * 11 + 7);
    }
    return k;
}
const auto test_aes_key = make_aes_key();

/// 12 字节 IV（AEAD nonce）
std::array<std::uint8_t, 12> make_iv()
{
    std::array<std::uint8_t, 12> iv{};
    for (std::size_t i = 0; i < 12; ++i)
    {
        iv[i] = static_cast<std::uint8_t>(i + 0xA0);
    }
    return iv;
}
const auto test_iv = make_iv();

/// 明文数据（64 字节）
std::vector<std::uint8_t> make_plaintext()
{
    std::vector<std::uint8_t> pt(64);
    for (std::size_t i = 0; i < pt.size(); ++i)
    {
        pt[i] = static_cast<std::uint8_t>(i);
    }
    return pt;
}
const auto test_plaintext = make_plaintext();

/// 大明文数据（4096 字节）
std::vector<std::uint8_t> make_large_plaintext()
{
    std::vector<std::uint8_t> pt(4096);
    for (std::size_t i = 0; i < pt.size(); ++i)
    {
        pt[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    return pt;
}
const auto test_large_plaintext = make_large_plaintext();

// ============================================================
// SNI 匹配基准测试
// ============================================================

void BM_Reality_MatchSni_Hit(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = match_sni("www.example.com", test_server_names);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Reality_MatchSni_Hit);

void BM_Reality_MatchSni_Miss(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = match_sni("nonexistent.com", test_server_names);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Reality_MatchSni_Miss);

// ============================================================
// shortId 匹配基准测试
// ============================================================

void BM_Reality_MatchShortId_Hit(benchmark::State &state)
{
    // 8 字节 shortId
    const std::array<std::uint8_t, 8> sid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    for (auto _ : state)
    {
        auto r = match_shortid(sid, test_short_ids);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Reality_MatchShortId_Hit);

void BM_Reality_MatchShortId_Miss(benchmark::State &state)
{
    const std::array<std::uint8_t, 8> sid = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8};
    for (auto _ : state)
    {
        auto r = match_shortid(sid, test_short_ids);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_Reality_MatchShortId_Miss);

// ============================================================
// hex 解码基准测试
// ============================================================

void BM_Reality_HexDecode_Short(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = hex_decode("0102030405060708");
        benchmark::DoNotOptimize(r.data());
    }
}
BENCHMARK(BM_Reality_HexDecode_Short);

void BM_Reality_HexDecode_Long(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = hex_decode("abcdef1234567890aabbccddeeff0011");
        benchmark::DoNotOptimize(r.data());
    }
}
BENCHMARK(BM_Reality_HexDecode_Long);

// ============================================================
// 密钥派生基准测试
// ============================================================

void BM_Reality_DeriveHsKeys(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto result = derive_hs_keys(test_shared_secret, test_chello, test_shello);
        benchmark::DoNotOptimize(result.first);
    }
}
BENCHMARK(BM_Reality_DeriveHsKeys);

void BM_Reality_DeriveAppKeys(benchmark::State &state)
{
    // 先派生握手密钥作为输入
    auto hs_result = derive_hs_keys(test_shared_secret, test_chello, test_shello);
    auto &keys = hs_result.second;
    for (auto _ : state)
    {
        state.PauseTiming();
        key_material keys_copy = keys;
        state.ResumeTiming();

        auto rc = derive_app_keys(keys.master_secret, test_key_32, keys_copy);
        benchmark::DoNotOptimize(rc);
    }
}
BENCHMARK(BM_Reality_DeriveAppKeys);

void BM_Reality_ComputeVerify(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto v = compute_verify(test_key_32, test_key_32);
        benchmark::DoNotOptimize(v.data());
    }
}
BENCHMARK(BM_Reality_ComputeVerify);

// ============================================================
// TLS 记录构建与加密基准测试
// ============================================================

void BM_Reality_MakeRecord(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = make_record(0x17, test_plaintext);
        benchmark::DoNotOptimize(r.data());
    }
}
BENCHMARK(BM_Reality_MakeRecord);

void BM_Reality_EncryptRecord(benchmark::State &state)
{
    for (auto _ : state)
    {
        encrypt_params params;
        params.key = test_aes_key;
        params.iv = test_iv;
        params.sequence = 1;
        params.content_type = 0x17;
        params.plaintext = test_plaintext;
        auto r = encrypt_record(params);
        benchmark::DoNotOptimize(r.first);
    }
}
BENCHMARK(BM_Reality_EncryptRecord);

void BM_Reality_EncryptRecord_Large(benchmark::State &state)
{
    for (auto _ : state)
    {
        encrypt_params params;
        params.key = test_aes_key;
        params.iv = test_iv;
        params.sequence = 1;
        params.content_type = 0x17;
        params.plaintext = test_large_plaintext;
        auto r = encrypt_record(params);
        benchmark::DoNotOptimize(r.first);
    }
}
BENCHMARK(BM_Reality_EncryptRecord_Large);

} // namespace

BENCHMARK_MAIN();
