/**
 * @file Hkdf.cpp
 * @brief HKDF/HMAC/SHA256 加密模块单元测试
 * @details 测试 psm::crypto 命名空间下的 HMAC-SHA256、HMAC-SHA512、
 * HKDF-Extract、HKDF-Expand、HKDF-Expand-Label 以及 SHA-256 功能。
 * 覆盖 RFC 4231、RFC 5869 标准测试向量、空输入边界条件以及 TLS 1.3 标签扩展。
 */

#include <gtest/gtest.h>

#include <prism/crypto/hkdf.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{
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
TEST(Hkdf, HmacSha256)
{
    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";
    constexpr std::string_view expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    auto mac = psm::crypto::hmac_sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(key.data()), key.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}
    );

    auto hex = ToHex(mac);
    EXPECT_EQ(hex, expected)
        << "HMAC-SHA256 mismatch";
}

/**
 * @brief 测试 HMAC-SHA256 空密钥
 * @details 空密钥不应崩溃，应产生确定性的输出
 */
TEST(Hkdf, HmacSha256EmptyKey)
{
    const std::string data = "test data";
    const std::string empty_key;

    auto mac = psm::crypto::hmac_sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(empty_key.data()), empty_key.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}
    );

    // 验证输出为 32 字节（SHA256_LEN）
    EXPECT_EQ(ToHex(mac).size(), 64u)
        << "HMAC-SHA256 with empty key should produce 32 bytes";
}

/**
 * @brief 测试 HMAC-SHA256 空数据
 * @details 非空密钥 + 空数据不应崩溃
 */
TEST(Hkdf, HmacSha256EmptyData)
{
    const std::string key = "secret";
    const std::string empty_data;

    auto mac = psm::crypto::hmac_sha256(
        std::span{reinterpret_cast<const std::uint8_t*>(key.data()), key.size()},
        std::span{reinterpret_cast<const std::uint8_t*>(empty_data.data()), empty_data.size()}
    );

    // 验证输出为 32 字节
    ASSERT_EQ(ToHex(mac).size(), 64u)
        << "HMAC-SHA256 with empty data should produce 32 bytes";

    // With known vector: HMAC-SHA256("secret", "") = f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169
    constexpr std::string_view expected = "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169";
    auto hex = ToHex(mac);
    EXPECT_EQ(hex, expected)
        << "HMAC-SHA256('secret', '') mismatch";
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
TEST(Hkdf, HmacSha512)
{
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
    EXPECT_EQ(hex, expected)
        << "HMAC-SHA512 mismatch";
}

// ============================================================================
// HKDF-Extract 测试（RFC 5869 Test Case 1）
// ============================================================================

/**
 * @brief 测试 HKDF-Extract（RFC 5869 Test Case 1）
 * @details IKM = 22 bytes of 0x0b, salt = 0x000102...0c (13 bytes)
 * 期望 PRK = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
 */
TEST(Hkdf, HkdfExtract)
{
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
    EXPECT_EQ(hex, expected_prk)
        << "HKDF-Extract PRK mismatch";
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
TEST(Hkdf, HkdfExpand)
{
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

    ASSERT_EQ(err, psm::fault::code::success) << "HKDF-Expand returned error";

    auto hex = ToHex(okm);
    EXPECT_EQ(hex, expected_okm) << "HKDF-Expand OKM mismatch";
    EXPECT_EQ(okm.size(), 42u)
        << "HKDF-Expand output length should be 42";
}

// ============================================================================
// HKDF-Expand-Label 测试（TLS 1.3 风格）
// ============================================================================

/**
 * @brief 测试 HKDF-Expand-Label（TLS 1.3 风格）
 * @details 使用简单 secret + label "key" + 空 context，验证长度正确
 * 并且输出是确定性的
 */
TEST(Hkdf, HkdfExpandLabel)
{
    // 使用一个简单的 32 字节 secret
    const std::array<std::uint8_t, 32> secret = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    constexpr std::string_view label = "key";
    constexpr std::size_t out_len = 32;

    auto [err, output] = psm::crypto::expand_label(
        {secret, label, {}, out_len}
    );

    ASSERT_EQ(err, psm::fault::code::success) << "HKDF-Expand-Label returned error";
    ASSERT_EQ(output.size(), out_len) << "HKDF-Expand-Label output length mismatch";

    // 第二次调用应产生相同结果（确定性）
    auto [err2, output2] = psm::crypto::expand_label(
        {secret, label, {}, out_len}
    );

    ASSERT_EQ(err2, psm::fault::code::success) << "HKDF-Expand-Label second call returned error";
    EXPECT_EQ(output, output2) << "HKDF-Expand-Label should be deterministic";
}

// ============================================================================
// SHA-256 测试
// ============================================================================

/**
 * @brief 测试 SHA-256 空字符串
 * @details SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 */
TEST(Hkdf, Sha256Empty)
{
    constexpr std::string_view expected =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const std::string empty;
    auto hash = psm::crypto::sha256(std::span{reinterpret_cast<const std::uint8_t*>(empty.data()), empty.size()});

    auto hex = ToHex(hash);
    EXPECT_EQ(hex, expected) << "SHA-256('') mismatch";
}

/**
 * @brief 测试 SHA-256 已知向量
 * @details SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
TEST(Hkdf, Sha256Known)
{
    constexpr std::string_view expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    const std::string data = "abc";
    auto hash = psm::crypto::sha256(std::span{reinterpret_cast<const std::uint8_t*>(data.data()), data.size()});

    auto hex = ToHex(hash);
    EXPECT_EQ(hex, expected) << "SHA-256('abc') mismatch";
}

/**
 * @brief 测试 SHA-256 span 重载
 * @details 使用两个数据块拼接的 overload 验证 SHA-256("a", "bc") == SHA-256("abc")
 */
TEST(Hkdf, Sha256Span)
{
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

    EXPECT_EQ(ToHex(hash_single), expected) << "SHA-256 single span mismatch";
    EXPECT_EQ(ToHex(hash_two), expected) << "SHA-256 two-span mismatch";
    EXPECT_EQ(ToHex(hash_three), expected) << "SHA-256 three-span mismatch";

    // 验证两块和三块重载结果一致
    EXPECT_EQ(hash_two, hash_three) << "SHA-256 two-span and three-span should match";
}

// ============================================================================
// 边界条件测试
// ============================================================================

TEST(Hkdf, HkdfExpandOverflow)
{
    std::array<std::uint8_t, 32> prk{};
    prk[0] = 0xAA;

    // length > 255 * 32 = 8160 -> invalid_argument
    auto [ec, out] = psm::crypto::hkdf_expand(prk, std::span<const std::uint8_t>{}, 8161);
    EXPECT_EQ(ec, psm::fault::code::invalid_argument) << "hkdf_expand overflow: invalid_argument";
    EXPECT_TRUE(out.empty()) << "hkdf_expand overflow: empty output";
}

TEST(Hkdf, HkdfExpandShortPrk)
{
    // PRK < 32 字节 -> invalid_argument
    const std::array<std::uint8_t, 16> short_prk{};
    auto [ec, out] = psm::crypto::hkdf_expand(short_prk, std::span<const std::uint8_t>{}, 16);
    EXPECT_EQ(ec, psm::fault::code::invalid_argument) << "hkdf_expand short prk: invalid_argument";
    EXPECT_TRUE(out.empty()) << "hkdf_expand short prk: empty output";
}

TEST(Hkdf, ExpandLabelTooLong)
{
    std::array<std::uint8_t, 32> secret{};
    secret[0] = 0x01;

    // label + "tls13 " prefix > 255 -> invalid_argument
    std::string long_label(250, 'A'); // "tls13 " (6) + 250 = 256 > 255
    auto [ec, out] = psm::crypto::expand_label({secret, long_label, {}, 16});
    EXPECT_EQ(ec, psm::fault::code::invalid_argument) << "expand_label long label: invalid_argument";
    EXPECT_TRUE(out.empty()) << "expand_label long label: empty output";
}

TEST(Hkdf, ExpandLabelContextTooLong)
{
    std::array<std::uint8_t, 32> secret{};
    secret[0] = 0x01;

    // context > 255 字节 -> invalid_argument
    std::vector<std::uint8_t> long_context(256, 'X');
    auto [ec, out] = psm::crypto::expand_label({secret, "key",
        std::span<const std::uint8_t>{long_context.data(), long_context.size()}, 16});
    EXPECT_EQ(ec, psm::fault::code::invalid_argument) << "expand_label long context: invalid_argument";
    EXPECT_TRUE(out.empty()) << "expand_label long context: empty output";
}
