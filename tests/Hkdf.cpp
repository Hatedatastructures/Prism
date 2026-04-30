/**
 * @file Hkdf.cpp
 * @brief HKDF/HMAC/SHA256 加密模块单元测试
 * @details 测试 psm::crypto 命名空间下的 HMAC-SHA256、HMAC-SHA512、
 * HKDF-Extract、HKDF-Expand、HKDF-Expand-Label 以及 SHA-256 功能。
 * 覆盖 RFC 4231、RFC 5869 标准测试向量、空输入边界条件以及 TLS 1.3 标签扩展。
 */

#include <prism/crypto/hkdf.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    psm::testing::TestRunner runner("Hkdf");

    /**
     * @brief 将字节数组转换为十六进制字符串
     */
    template<std::size_t N>
    auto ToHex(const std::array<std::uint8_t, N> &data) -> std::string
    {
        static constexpr char hex_table[] = "0123456789abcdef";
        std::string result;
        result.reserve(N * 2);
        for (const auto byte : data)
        {
            result.push_back(hex_table[(byte >> 4) & 0x0F]);
            result.push_back(hex_table[byte & 0x0F]);
        }
        return result;
    }

    /**
     * @brief 将 std::vector<uint8_t> 转换为十六进制字符串
     */
    auto ToHex(const std::vector<std::uint8_t> &data) -> std::string
    {
        static constexpr char hex_table[] = "0123456789abcdef";
        std::string result;
        result.reserve(data.size() * 2);
        for (const auto byte : data)
        {
            result.push_back(hex_table[(byte >> 4) & 0x0F]);
            result.push_back(hex_table[byte & 0x0F]);
        }
        return result;
    }
} // namespace

// ============================================================================
// HMAC-SHA256 测试
// ============================================================================

/**
 * @brief 测试 HMAC-SHA256（RFC 4231 Test Case 2）
 * @details key="Jefe", data="what do ya want for nothing?"
 * 期望结果: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
 */
void TestHmacSha256()
{
    runner.LogInfo("=== TestHmacSha256 ===");

    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";
    constexpr std::string_view expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    auto mac = psm::crypto::hmac_sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(key.data()), key.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}
    );

    auto hex = ToHex(mac);
    if (hex != expected)
    {
        runner.LogFail("HMAC-SHA256 mismatch: got " + hex + ", expected " + std::string{expected});
        return;
    }

    runner.LogPass("HmacSha256");
}

/**
 * @brief 测试 HMAC-SHA256 空密钥
 * @details 空密钥不应崩溃，应产生确定性的输出
 */
void TestHmacSha256EmptyKey()
{
    runner.LogInfo("=== TestHmacSha256EmptyKey ===");

    const std::string data = "test data";
    const std::string empty_key;

    auto mac = psm::crypto::hmac_sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(empty_key.data()), empty_key.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}
    );

    // 验证输出为 32 字节（SHA256_LEN）
    if (ToHex(mac).size() != 64)
    {
        runner.LogFail("HMAC-SHA256 with empty key should produce 32 bytes");
        return;
    }

    runner.LogPass("HmacSha256EmptyKey");
}

/**
 * @brief 测试 HMAC-SHA256 空数据
 * @details 非空密钥 + 空数据不应崩溃
 */
void TestHmacSha256EmptyData()
{
    runner.LogInfo("=== TestHmacSha256EmptyData ===");

    const std::string key = "secret";
    const std::string empty_data;

    auto mac = psm::crypto::hmac_sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(key.data()), key.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(empty_data.data()), empty_data.size()}
    );

    // 验证输出为 32 字节
    if (ToHex(mac).size() != 64)
    {
        runner.LogFail("HMAC-SHA256 with empty data should produce 32 bytes");
        return;
    }

    // With known vector: HMAC-SHA256("secret", "") = f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169
    constexpr std::string_view expected = "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169";
    auto hex = ToHex(mac);
    if (hex != expected)
    {
        runner.LogFail("HMAC-SHA256('secret', '') mismatch: got " + hex + ", expected " + std::string{expected});
        return;
    }

    runner.LogPass("HmacSha256EmptyData");
}

// ============================================================================
// HMAC-SHA512 测试
// ============================================================================

/**
 * @brief 测试 HMAC-SHA512（RFC 4231 Test Case 2）
 * @details key="Jefe", data="what do ya want for nothing?"
 * 期望结果: 164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554
 *         975868eeab628229e6076c88e35c52ab043e2c02055d59b7c3a4c5e8c85e3e2d
 */
void TestHmacSha512()
{
    runner.LogInfo("=== TestHmacSha512 ===");

    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";
    constexpr std::string_view expected =
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";

    auto mac = psm::crypto::hmac_sha512(
        std::span{reinterpret_cast<const std::uint8_t*>(key.data()), key.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}
    );

    auto hex = ToHex(mac);
    if (hex != expected)
    {
        runner.LogFail("HMAC-SHA512 mismatch: got " + hex);
        return;
    }

    runner.LogPass("HmacSha512");
}

// ============================================================================
// HKDF-Extract 测试（RFC 5869 Test Case 1）
// ============================================================================

/**
 * @brief 测试 HKDF-Extract（RFC 5869 Test Case 1）
 * @details IKM = 22 bytes of 0x0b, salt = 0x000102...0c (13 bytes)
 * 期望 PRK = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
 */
void TestHkdfExtract()
{
    runner.LogInfo("=== TestHkdfExtract ===");

    // IKM: 22 bytes of 0x0b
    const std::array<std::uint8_t, 22> ikm = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };

    // salt: 13 bytes 0x00..0x0c
    const std::array<std::uint8_t, 13> salt = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    constexpr std::string_view expected_prk =
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

    auto prk = psm::crypto::hkdf_extract(salt, ikm);

    auto hex = ToHex(prk);
    if (hex != expected_prk)
    {
        runner.LogFail("HKDF-Extract PRK mismatch: got " + hex);
        return;
    }

    runner.LogPass("HkdfExtract");
}

// ============================================================================
// HKDF-Expand 测试（RFC 5869 Test Case 1）
// ============================================================================

/**
 * @brief 测试 HKDF-Expand（RFC 5869 Test Case 1）
 * @details PRK 来自 Extract 步骤，info = 0xf0f1...f9 (10 bytes), length = 42
 * 期望 OKM = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
 *         34007208d5b887185865
 */
void TestHkdfExpand()
{
    runner.LogInfo("=== TestHkdfExpand ===");

    // PRK 来自 Extract 步骤
    const std::array<std::uint8_t, 32> prk = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };

    // info: 10 bytes 0xf0..0xf9
    const std::array<std::uint8_t, 10> info = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };

    constexpr std::string_view expected_okm =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865";

    auto [err, okm] = psm::crypto::hkdf_expand(prk, info, 42);

    if (err != psm::fault::code::success)
    {
        runner.LogFail("HKDF-Expand returned error");
        return;
    }

    auto hex = ToHex(okm);
    if (hex != expected_okm)
    {
        runner.LogFail("HKDF-Expand OKM mismatch: got " + hex);
        return;
    }

    if (okm.size() != 42)
    {
        runner.LogFail("HKDF-Expand output length should be 42, got " + std::to_string(okm.size()));
        return;
    }

    runner.LogPass("HkdfExpand");
}

// ============================================================================
// HKDF-Expand-Label 测试（TLS 1.3 风格）
// ============================================================================

/**
 * @brief 测试 HKDF-Expand-Label（TLS 1.3 风格）
 * @details 使用简单 secret + label "key" + 空 context，验证长度正确
 * 并且输出是确定性的
 */
void TestHkdfExpandLabel()
{
    runner.LogInfo("=== TestHkdfExpandLabel ===");

    // 使用一个简单的 32 字节 secret
    const std::array<std::uint8_t, 32> secret = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    constexpr std::string_view label = "key";
    constexpr std::size_t out_len = 32;

    auto [err, output] = psm::crypto::hkdf_expand_label(
        secret, label, {}, out_len
    );

    if (err != psm::fault::code::success)
    {
        runner.LogFail("HKDF-Expand-Label returned error");
        return;
    }

    if (output.size() != out_len)
    {
        runner.LogFail("HKDF-Expand-Label output length should be " +
                       std::to_string(out_len) + ", got " + std::to_string(output.size()));
        return;
    }

    // 第二次调用应产生相同结果（确定性）
    auto [err2, output2] = psm::crypto::hkdf_expand_label(
        secret, label, {}, out_len
    );

    if (err2 != psm::fault::code::success)
    {
        runner.LogFail("HKDF-Expand-Label second call returned error");
        return;
    }

    if (output != output2)
    {
        runner.LogFail("HKDF-Expand-Label should be deterministic");
        return;
    }

    runner.LogPass("HkdfExpandLabel");
}

// ============================================================================
// SHA-256 测试
// ============================================================================

/**
 * @brief 测试 SHA-256 空字符串
 * @details SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 */
void TestSha256Empty()
{
    runner.LogInfo("=== TestSha256Empty ===");

    constexpr std::string_view expected =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const std::string empty;
    auto hash = psm::crypto::sha256(std::span{reinterpret_cast<const std::uint8_t*>(empty.data()), empty.size()});

    auto hex = ToHex(hash);
    if (hex != expected)
    {
        runner.LogFail("SHA-256('') mismatch: got " + hex);
        return;
    }

    runner.LogPass("Sha256Empty");
}

/**
 * @brief 测试 SHA-256 已知向量
 * @details SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
void TestSha256Known()
{
    runner.LogInfo("=== TestSha256Known ===");

    constexpr std::string_view expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    const std::string data = "abc";
    auto hash = psm::crypto::sha256(std::span{reinterpret_cast<const std::uint8_t*>(data.data()), data.size()});

    auto hex = ToHex(hash);
    if (hex != expected)
    {
        runner.LogFail("SHA-256('abc') mismatch: got " + hex);
        return;
    }

    runner.LogPass("Sha256Known");
}

/**
 * @brief 测试 SHA-256 span 重载
 * @details 使用两个数据块拼接的 overload 验证 SHA-256("a", "bc") == SHA-256("abc")
 */
void TestSha256Span()
{
    runner.LogInfo("=== TestSha256Span ===");

    const std::string a = "a";
    const std::string bc = "bc";
    const std::string abc = "abc";

    constexpr std::string_view expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    // 单块 span
    auto hash_single = psm::crypto::sha256(std::span{reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()});

    // 两块 span 重载: SHA-256("a" || "bc")
    auto hash_two = psm::crypto::sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(a.data()), a.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(bc.data()), bc.size()}
    );

    // 三块 span 重载: SHA-256("" || "a" || "bc")
    const std::string empty_str;
    auto hash_three = psm::crypto::sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(empty_str.data()), empty_str.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(a.data()), a.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(bc.data()), bc.size()}
    );

    if (ToHex(hash_single) != expected)
    {
        runner.LogFail("SHA-256 single span mismatch");
        return;
    }

    if (ToHex(hash_two) != expected)
    {
        runner.LogFail("SHA-256 two-span mismatch: got " + ToHex(hash_two));
        return;
    }

    if (ToHex(hash_three) != expected)
    {
        runner.LogFail("SHA-256 three-span mismatch: got " + ToHex(hash_three));
        return;
    }

    // 验证两块和三块重载结果一致
    if (hash_two != hash_three)
    {
        runner.LogFail("SHA-256 two-span and three-span should match");
        return;
    }

    runner.LogPass("Sha256Span");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 HMAC-SHA256、HMAC-SHA512、
 * HKDF-Extract、HKDF-Expand、HKDF-Expand-Label 以及 SHA-256 测试用例。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化全局 PMR 内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    runner.LogInfo("Starting HKDF/HMAC/SHA256 tests...");

    // HMAC-SHA256 测试
    TestHmacSha256();
    TestHmacSha256EmptyKey();
    TestHmacSha256EmptyData();

    // HMAC-SHA512 测试
    TestHmacSha512();

    // HKDF 测试
    TestHkdfExtract();
    TestHkdfExpand();
    TestHkdfExpandLabel();

    // SHA-256 测试
    TestSha256Empty();
    TestSha256Known();
    TestSha256Span();

    runner.LogInfo("HKDF tests completed.");

    return runner.Summary();
}
