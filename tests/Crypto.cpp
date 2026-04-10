/**
 * @file Crypto.cpp
 * @brief 加密工具单元测试
 * @details 测试 psm::crypto 命名空间下的 SHA224 哈希、十六进制校验、
 * 凭据归一化以及 Base64 解码功能，覆盖空输入、已知向量、输出长度、
 * URL-safe 变体、空白跳过、非法字符、填充处理、长输入等场景。
 */

#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <string>
#include <string_view>

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    auto log_info(const std::string_view msg) -> void
    {
        psm::trace::info("[Crypto] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    auto log_pass(const std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[Crypto] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    auto log_fail(const std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[Crypto] FAIL: {}", msg);
    }
}

// ============================================================================
// SHA224 测试
// ============================================================================

/**
 * @brief 测试 SHA224 空字符串哈希
 */
void TestSha224Empty()
{
    log_info("=== TestSha224Empty ===");

    // SHA-224 对空串的标准哈希向量
    auto hash = psm::crypto::sha224("");
    // SHA-224 输出 28 字节 = 56 个十六进制字符
    if (hash.size() != 56)
    {
        log_fail("SHA224('') should produce 56 hex chars");
        return;
    }
    // 对照 RFC 4634 附录的已知向量
    if (hash != "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
    {
        log_fail("SHA224('') mismatch: got '" + hash + "'");
        return;
    }

    log_pass("Sha224Empty");
}

/**
 * @brief 测试 SHA224 已知向量
 */
void TestSha224KnownVector()
{
    log_info("=== TestSha224KnownVector ===");

    // SHA-224 对 "abc" 的 NIST 标准测试向量
    auto hash = psm::crypto::sha224("abc");
    if (hash != "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
    {
        log_fail("SHA224('abc') mismatch: got '" + hash + "'");
        return;
    }

    log_pass("Sha224KnownVector");
}

/**
 * @brief 测试 SHA224 输出长度恒为 56
 */
void TestSha224OutputLength()
{
    log_info("=== TestSha224OutputLength ===");

    // 普通长度输入
    {
        auto hash = psm::crypto::sha224("any input");
        // SHA-224 定长输出 56 个十六进制字符
        if (hash.size() != 56)
        {
            log_fail("SHA224('any input') should be 56 chars, got " + std::to_string(hash.size()));
            return;
        }
    }

    // 长输入：验证多块处理不影响输出长度
    {
        auto hash = psm::crypto::sha224("a longer string with more data to hash for testing purposes");
        if (hash.size() != 56)
        {
            log_fail("SHA224(long string) should be 56 chars");
            return;
        }
    }

    // 单字节输入
    {
        auto hash = psm::crypto::sha224("x");
        if (hash.size() != 56)
        {
            log_fail("SHA224('x') should be 56 chars");
            return;
        }
    }

    log_pass("Sha224OutputLength");
}

/**
 * @brief 测试 is_hex_string 函数
 */
void TestIsHexString()
{
    log_info("=== TestIsHexString ===");

    // 合法十六进制字符（含大小写）
    {
        if (!psm::crypto::is_hex_string("0123456789abcdefABCDEF"))
        {
            log_fail("'0123456789abcdefABCDEF' should be hex");
            return;
        }
    }

    // 含非十六进制字符 'xyz'
    {
        if (psm::crypto::is_hex_string("xyz"))
        {
            log_fail("'xyz' should not be hex");
            return;
        }
    }

    // 空串视为合法（vacuously true）
    {
        if (!psm::crypto::is_hex_string(""))
        {
            log_fail("empty string should be hex (trivially)");
            return;
        }
    }

    // 'g' 超出十六进制范围
    {
        if (psm::crypto::is_hex_string("0g"))
        {
            log_fail("'0g' should not be hex");
            return;
        }
    }

    log_pass("IsHexString");
}

/**
 * @brief 测试 normalize_credential 函数
 */
void TestNormalizeCredential()
{
    log_info("=== TestNormalizeCredential ===");

    {
        // 明文密码应被 SHA-224 哈希，不暴露原文
        auto result = psm::crypto::normalize_credential("password");
        if (result == "password")
        {
            log_fail("normalize_credential('password') should hash, not return plaintext");
            return;
        }
        // 哈希结果必须为 56 个十六进制字符
        if (result.size() != 56)
        {
            log_fail("normalize_credential('password') should return 56-char hash");
            return;
        }
    }

    {
        // 已是 56 位十六进制的凭据应原样返回
        const std::string hex56 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        auto result = psm::crypto::normalize_credential(hex56);
        if (result != hex56)
        {
            log_fail("56-char hex string should be returned as-is");
            return;
        }
    }

    {
        // 短于 56 的字符串不是哈希值，须先哈希再返回
        auto result = psm::crypto::normalize_credential("short");
        if (result == "short")
        {
            log_fail("normalize_credential('short') should hash, not return plaintext");
            return;
        }
        if (result.size() != 56)
        {
            log_fail("normalize_credential('short') should return 56-char hash");
            return;
        }
    }

    log_pass("NormalizeCredential");
}

// ============================================================================
// Base64 测试
// ============================================================================

/**
 * @brief 测试 Base64 标准解码
 */
void TestBase64DecodeStandard()
{
    log_info("=== TestBase64DecodeStandard ===");

    // 空输入应返回空串
    if (psm::crypto::base64_decode("") != "")
    {
        log_fail("base64_decode('') should be ''");
        return;
    }
    // 1 字节输入 "f" → Zg== (2 个填充)
    if (psm::crypto::base64_decode("Zg==") != "f")
    {
        log_fail("base64_decode('Zg==') should be 'f'");
        return;
    }
    // 2 字节输入 "fo" → Zm8= (1 个填充)
    if (psm::crypto::base64_decode("Zm8=") != "fo")
    {
        log_fail("base64_decode('Zm8=') should be 'fo'");
        return;
    }
    // 3 字节输入 "foo" → Zm9v (无填充)
    if (psm::crypto::base64_decode("Zm9v") != "foo")
    {
        log_fail("base64_decode('Zm9v') should be 'foo'");
        return;
    }
    // 4 字节输入 "foob" → Zm9vYg==
    if (psm::crypto::base64_decode("Zm9vYg==") != "foob")
    {
        log_fail("base64_decode('Zm9vYg==') should be 'foob'");
        return;
    }
    // 5 字节输入 "fooba" → Zm9vYmE=
    if (psm::crypto::base64_decode("Zm9vYmE=") != "fooba")
    {
        log_fail("base64_decode('Zm9vYmE=') should be 'fooba'");
        return;
    }
    // 6 字节输入 "foobar" → Zm9vYmFy
    if (psm::crypto::base64_decode("Zm9vYmFy") != "foobar")
    {
        log_fail("base64_decode('Zm9vYmFy') should be 'foobar'");
        return;
    }

    log_pass("Base64DecodeStandard");
}

/**
 * @brief 测试 Base64 URL-safe 变体解码
 */
void TestBase64DecodeUrlSafe()
{
    log_info("=== TestBase64DecodeUrlSafe ===");

    // 先验证标准编码的基线正确性
    if (psm::crypto::base64_decode("Zm9v") != "foo")
    {
        log_fail("standard 'Zm9v' baseline failed");
        return;
    }

    // URL-safe 变体: '-' 替代 '+'，'_' 替代 '/'
    // "a+//" 和 "a-__" 应解码为相同二进制值
    {
        auto standard = psm::crypto::base64_decode("a+//");
        auto url_safe = psm::crypto::base64_decode("a-__");
        if (standard != url_safe)
        {
            log_fail("URL-safe variant should decode to same result as standard");
            return;
        }
    }

    log_pass("Base64DecodeUrlSafe");
}

/**
 * @brief 测试 Base64 解码跳过空白字符
 */
void TestBase64DecodeWhitespace()
{
    log_info("=== TestBase64DecodeWhitespace ===");

    // 空格分隔的 Base64 应被容忍
    {
        auto result = psm::crypto::base64_decode("Z m 9 v");
        if (result != "foo")
        {
            log_fail("base64_decode('Z m 9 v') should be 'foo'");
            return;
        }
    }

    // 换行符在 MIME 编码中常见，应被跳过
    {
        auto result = psm::crypto::base64_decode("Zm\n9v");
        if (result != "foo")
        {
            log_fail("base64_decode('Zm\\n9v') should be 'foo'");
            return;
        }
    }

    log_pass("Base64DecodeWhitespace");
}

/**
 * @brief 测试 Base64 非法字符返回空
 */
void TestBase64DecodeInvalidChars()
{
    log_info("=== TestBase64DecodeInvalidChars ===");

    // '!' 不在 Base64 字母表中，应返回空串表示失败
    auto result = psm::crypto::base64_decode("Zm9v!");
    if (!result.empty())
    {
        log_fail("base64_decode with invalid char '!' should return empty string");
        return;
    }

    log_pass("Base64DecodeInvalidChars");
}

/**
 * @brief 测试 Base64 不同填充量
 */
void TestBase64DecodePadding()
{
    log_info("=== TestBase64DecodePadding ===");

    // 无填充：输入恰好是 3 字节的倍数
    if (psm::crypto::base64_decode("Zm9v") != "foo")
    {
        log_fail("0-padding decode failed");
        return;
    }

    // 1 个填充：原始数据余 2 字节
    if (psm::crypto::base64_decode("Zm8=") != "fo")
    {
        log_fail("1-padding decode failed");
        return;
    }

    // 2 个填充：原始数据余 1 字节
    if (psm::crypto::base64_decode("Zg==") != "f")
    {
        log_fail("2-padding decode failed");
        return;
    }

    log_pass("Base64DecodePadding");
}

/**
 * @brief 测试 Base64 解码长输入
 */
void TestBase64DecodeLongInput()
{
    log_info("=== TestBase64DecodeLongInput ===");

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

    if (decoded != long_input)
    {
        log_fail("long input roundtrip encode/decode mismatch");
        return;
    }

    // 确保解码后长度与原始一致
    if (decoded.size() != expected_length)
    {
        log_fail("decoded length should be " + std::to_string(expected_length) + ", got " + std::to_string(decoded.size()));
        return;
    }

    log_pass("Base64DecodeLongInput");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 SHA224 哈希、十六进制校验、
 * 凭据归一化以及 Base64 解码（标准/URL-safe/空白跳过/非法字符/填充/长输入）等测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化全局 PMR 内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    log_info("Starting crypto tests...");

    // SHA224 测试
    TestSha224Empty();
    TestSha224KnownVector();
    TestSha224OutputLength();
    TestIsHexString();
    TestNormalizeCredential();

    // Base64 测试
    TestBase64DecodeStandard();
    TestBase64DecodeUrlSafe();
    TestBase64DecodeWhitespace();
    TestBase64DecodeInvalidChars();
    TestBase64DecodePadding();
    TestBase64DecodeLongInput();

    log_info("Crypto tests completed.");
    psm::trace::info("[Crypto] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
