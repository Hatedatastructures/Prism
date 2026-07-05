/**
 * @file Crypto.cpp
 * @brief 加密工具单元测试
 * @details 测试 psm::crypto 命名空间下的 SHA224 哈希、十六进制校验、
 * 凭据归一化以及 Base64 解码功能，覆盖空输入、已知向量、输出长度、
 * URL-safe 变体、空白跳过、非法字符、填充处理、长输入等场景。
 */

#include <gtest/gtest.h>

#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <string>
#include <string_view>

// ============================================================================
// SHA224 测试
// ============================================================================

/**
 * @brief 测试 SHA224 空字符串哈希
 */
TEST(Crypto, Sha224Empty)
{
    // SHA-224 对空串的标准哈希向量
    auto hash = psm::crypto::sha224("");
    // SHA-224 输出 28 字节 = 56 个十六进制字符
    ASSERT_EQ(hash.size(), 56u) << "SHA224('') should produce 56 hex chars";
    // 对照 RFC 4634 附录的已知向量
    EXPECT_EQ(hash, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        << "SHA224('') mismatch";
}

/**
 * @brief 测试 SHA224 已知向量
 */
TEST(Crypto, Sha224KnownVector)
{
    // SHA-224 对 "abc" 的 NIST 标准测试向量
    auto hash = psm::crypto::sha224("abc");
    EXPECT_EQ(hash, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
        << "SHA224('abc') mismatch";
}

/**
 * @brief 测试 SHA224 输出长度恒为 56
 */
TEST(Crypto, Sha224OutputLength)
{
    // 普通长度输入
    {
        auto hash = psm::crypto::sha224("any input");
        EXPECT_EQ(hash.size(), 56u) << "SHA224('any input') should be 56 chars";
    }

    // 长输入：验证多块处理不影响输出长度
    {
        auto hash = psm::crypto::sha224("a longer string with more data to hash for testing purposes");
        EXPECT_EQ(hash.size(), 56u) << "SHA224(long string) should be 56 chars";
    }

    // 单字节输入
    {
        auto hash = psm::crypto::sha224("x");
        EXPECT_EQ(hash.size(), 56u) << "SHA224('x') should be 56 chars";
    }
}

/**
 * @brief 测试 is_hex 函数
 */
TEST(Crypto, IsHexString)
{
    // 合法十六进制字符（含大小写）
    EXPECT_TRUE(psm::crypto::is_hex("0123456789abcdefABCDEF"))
        << "'0123456789abcdefABCDEF' should be hex";

    // 含非十六进制字符 'xyz'
    EXPECT_FALSE(psm::crypto::is_hex("xyz"))
        << "'xyz' should not be hex";

    // 空串视为合法（vacuously true）
    EXPECT_TRUE(psm::crypto::is_hex(""))
        << "empty string should be hex (trivially)";

    // 'g' 超出十六进制范围
    EXPECT_FALSE(psm::crypto::is_hex("0g"))
        << "'0g' should not be hex";
}

/**
 * @brief 测试 normalize_credential 函数
 */
TEST(Crypto, NormalizeCredential)
{
    {
        // 明文密码应被 SHA-224 哈希，不暴露原文
        auto result = psm::crypto::normalize_credential("password");
        EXPECT_NE(result, "password")
            << "normalize_credential('password') should hash, not return plaintext";
        // 哈希结果必须为 56 个十六进制字符
        EXPECT_EQ(result.size(), 56u)
            << "normalize_credential('password') should return 56-char hash";
    }

    {
        // 已是 56 位十六进制的凭据应原样返回
        const std::string hex56 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        auto result = psm::crypto::normalize_credential(hex56);
        EXPECT_EQ(result, psm::memory::string(hex56))
            << "56-char hex string should be returned as-is";
    }

    {
        // 短于 56 的字符串不是哈希值，须先哈希再返回
        auto result = psm::crypto::normalize_credential("short");
        EXPECT_NE(result, "short")
            << "normalize_credential('short') should hash, not return plaintext";
        EXPECT_EQ(result.size(), 56u)
            << "normalize_credential('short') should return 56-char hash";
    }
}

// ============================================================================
// Base64 测试
// ============================================================================

/**
 * @brief 测试 Base64 标准解码
 */
TEST(Crypto, Base64DecodeStandard)
{
    // 空输入应返回空串
    EXPECT_EQ(psm::crypto::base64_decode(""), "");
    // 1 字节输入 "f" -> Zg== (2 个填充)
    EXPECT_EQ(psm::crypto::base64_decode("Zg=="), "f");
    // 2 字节输入 "fo" -> Zm8= (1 个填充)
    EXPECT_EQ(psm::crypto::base64_decode("Zm8="), "fo");
    // 3 字节输入 "foo" -> Zm9v (无填充)
    EXPECT_EQ(psm::crypto::base64_decode("Zm9v"), "foo");
    // 4 字节输入 "foob" -> Zm9vYg==
    EXPECT_EQ(psm::crypto::base64_decode("Zm9vYg=="), "foob");
    // 5 字节输入 "fooba" -> Zm9vYmE=
    EXPECT_EQ(psm::crypto::base64_decode("Zm9vYmE="), "fooba");
    // 6 字节输入 "foobar" -> Zm9vYmFy
    EXPECT_EQ(psm::crypto::base64_decode("Zm9vYmFy"), "foobar");
}

/**
 * @brief 测试 Base64 URL-safe 变体解码
 */
TEST(Crypto, Base64DecodeUrlSafe)
{
    // 先验证标准编码的基线正确性
    ASSERT_EQ(psm::crypto::base64_decode("Zm9v"), "foo");

    // URL-safe 变体: '-' 替代 '+'，'_' 替代 '/'
    // "a+//" 和 "a-__" 应解码为相同二进制值
    auto standard = psm::crypto::base64_decode("a+//");
    auto url_safe = psm::crypto::base64_decode("a-__");
    EXPECT_EQ(standard, url_safe)
        << "URL-safe variant should decode to same result as standard";
}

/**
 * @brief 测试 Base64 解码跳过空白字符
 */
TEST(Crypto, Base64DecodeWhitespace)
{
    // 空格分隔的 Base64 应被容忍
    {
        auto result = psm::crypto::base64_decode("Z m 9 v");
        EXPECT_EQ(result, "foo");
    }

    // 换行符在 MIME 编码中常见，应被跳过
    {
        auto result = psm::crypto::base64_decode("Zm\n9v");
        EXPECT_EQ(result, "foo");
    }
}

/**
 * @brief 测试 Base64 非法字符返回空
 */
TEST(Crypto, Base64DecodeInvalidChars)
{
    // '!' 不在 Base64 字母表中，应返回空串表示失败
    auto result = psm::crypto::base64_decode("Zm9v!");
    EXPECT_TRUE(result.empty())
        << "base64_decode with invalid char '!' should return empty string";
}

/**
 * @brief 测试 Base64 不同填充量
 */
TEST(Crypto, Base64DecodePadding)
{
    // 无填充：输入恰好是 3 字节的倍数
    EXPECT_EQ(psm::crypto::base64_decode("Zm9v"), "foo");
    // 1 个填充：原始数据余 2 字节
    EXPECT_EQ(psm::crypto::base64_decode("Zm8="), "fo");
    // 2 个填充：原始数据余 1 字节
    EXPECT_EQ(psm::crypto::base64_decode("Zg=="), "f");
}

/**
 * @brief 测试 Base64 解码长输入
 */
TEST(Crypto, Base64DecodeLongInput)
{
    // 构造 1000 字节的重复模式，验证长输入编解码
    std::string long_input;
    long_input.reserve(1100);
    for (int i = 0; i < 100; ++i)
    {
        long_input += "HelloWorld";
    }
    const std::size_t expected_length = long_input.size(); // 1000

    // 标准 Base64 编码字母表
    static constexpr char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // 手工实现 Base64 编码，作为解码的验证基准
    auto encode_manual = [](const std::string &data) -> std::string
    {
        std::string out;
        out.reserve(((data.size() + 2) / 3) * 4);
        std::size_t i = 0;
        // 每 3 字节编码为 4 个 Base64 字符
        for (; i + 2 < data.size(); i += 3)
        {
            const auto a = static_cast<unsigned char>(data[i]);
            const auto b = static_cast<unsigned char>(data[i + 1]);
            const auto c = static_cast<unsigned char>(data[i + 2]);
            out.push_back(b64_table[a >> 2]);
            out.push_back(b64_table[((a & 0x03) << 4) | (b >> 4)]);
            out.push_back(b64_table[((b & 0x0F) << 2) | (c >> 6)]);
            out.push_back(b64_table[c & 0x3F]);
        }
        // 处理尾部不足 3 字节的残余数据
        if (i < data.size())
        {
            const auto a = static_cast<unsigned char>(data[i]);
            out.push_back(b64_table[a >> 2]);
            if (i + 1 < data.size())
            {
                const auto b = static_cast<unsigned char>(data[i + 1]);
                out.push_back(b64_table[((a & 0x03) << 4) | (b >> 4)]);
                out.push_back(b64_table[(b & 0x0F) << 2]);
            }
            else
            {
                out.push_back(b64_table[(a & 0x03) << 4]);
                out.push_back('=');
            }
            out.push_back('=');
        }
        return out;
    };

    std::string encoded = encode_manual(long_input);
    // 编码后解码，验证往返一致性
    auto decoded = psm::crypto::base64_decode(encoded);

    EXPECT_EQ(decoded, psm::memory::string(long_input))
        << "long input roundtrip encode/decode mismatch";

    // 确保解码后长度与原始一致
    EXPECT_EQ(decoded.size(), expected_length)
        << "decoded length mismatch";
}
