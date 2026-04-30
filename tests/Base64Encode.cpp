/**
 * @file Base64Encode.cpp
 * @brief Base64 编码单元测试
 * @details 测试 psm::crypto::base64_encode 函数，覆盖空输入、已知向量、
 * padding 变化、长二进制数据等场景。
 */

#include <prism/crypto/base64.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#ifdef WIN32
#include <windows.h>
#endif

#include <cstdint>
#include <string>
#include <vector>

namespace
{
    psm::testing::TestRunner runner("Base64Encode");
}

// ============================================================================
// Base64 编码测试
// ============================================================================

/**
 * @brief 测试空输入编码
 */
void TestBase64EncodeEmpty()
{
    runner.LogInfo("=== TestBase64EncodeEmpty ===");

    std::vector<std::uint8_t> empty;
    auto result = psm::crypto::base64_encode(empty);

    runner.Check(result.empty(), "Empty input produces empty string");
}

/**
 * @brief 测试已知 Base64 编码向量
 */
void TestBase64EncodeKnown()
{
    runner.LogInfo("=== TestBase64EncodeKnown ===");

    // "Man" (3 bytes, no padding) -> "TWFu"
    {
        std::vector<std::uint8_t> input{'M', 'a', 'n'};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "TWFu", "Base64('Man') == \"TWFu\"");
    }

    // "Ma" (2 bytes, 1 padding) -> "TWE="
    {
        std::vector<std::uint8_t> input{'M', 'a'};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "TWE=", "Base64('Ma') == \"TWE=\"");
    }

    // "M" (1 byte, 2 padding) -> "TQ=="
    {
        std::vector<std::uint8_t> input{'M'};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "TQ==", "Base64('M') == \"TQ==\"");
    }

    // "Hello, World!" (13 bytes) -> "SGVsbG8sIFdvcmxkIQ=="
    {
        std::string text = "Hello, World!";
        std::vector<std::uint8_t> input(text.begin(), text.end());
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "SGVsbG8sIFdvcmxkIQ==", "Base64('Hello, World!') == \"SGVsbG8sIFdvcmxkIQ==\"");
    }
}

/**
 * @brief 测试不同长度模 3 的 padding 变化
 */
void TestBase64EncodePaddingVariations()
{
    runner.LogInfo("=== TestBase64EncodePaddingVariations ===");

    // 1 byte mod 3 -> 2 padding chars
    {
        std::vector<std::uint8_t> input{0xFF};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "/w==", "1 byte input produces 2 padding chars");
    }

    // 2 bytes mod 3 -> 1 padding char
    {
        std::vector<std::uint8_t> input{0xFF, 0xFF};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "//8=", "2 bytes input produces 1 padding char");
    }

    // 3 bytes mod 3 -> no padding
    {
        std::vector<std::uint8_t> input{0xFF, 0xFF, 0xFF};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "////", "3 bytes input produces no padding");
    }

    // 4 bytes (1 full group + 1 remaining) -> 2 padding
    {
        std::vector<std::uint8_t> input{0x00, 0x00, 0x00, 0x01};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "AAAAAQ==", "4 bytes input ends with 2 padding");
    }

    // 5 bytes (1 full group + 2 remaining) -> 1 padding
    {
        std::vector<std::uint8_t> input{0x00, 0x00, 0x00, 0x01, 0x00};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "AAAAAQA=", "5 bytes input ends with 1 padding");
    }

    // 6 bytes (2 full groups) -> no padding
    {
        std::vector<std::uint8_t> input{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto result = psm::crypto::base64_encode(input);
        runner.Check(result == "AAAAAAAA", "6 bytes input produces no padding");
    }
}

/**
 * @brief 测试长二进制数据编码
 */
void TestBase64EncodeLong()
{
    runner.LogInfo("=== TestBase64EncodeLong ===");

    // 32 bytes of random-looking data
    std::vector<std::uint8_t> input = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8
    };

    auto result = psm::crypto::base64_encode(input);

    // 32 bytes -> ceil(32/3)*4 = 44 characters
    runner.Check(result.size() == 44, "32 bytes encode to 44 base64 characters");

    // Last 2 bytes (0xF9, 0xF8) -> 1 remaining byte mod 3 -> 2 padding
    runner.Check(result.back() == '=', "Long input ends with padding");

    // Verify against known encoding of this specific 32-byte sequence
    // 3q2+78r+ur4AAQIDBAUGBwgJCgsMDQ4P//79/Pv6+fg=
    runner.Check(
        result == "3q2+78r+ur4AAQIDBAUGBwgJCgsMDQ4P//79/Pv6+fg=",
        "Long input matches expected base64 output"
    );
}

// ============================================================================
// 主函数
// ============================================================================

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    // 初始化全局 PMR 内存池
    psm::memory::system::enable_global_pooling();
    // 初始化日志系统
    psm::trace::init({});

    runner.LogInfo("Starting Base64 encode tests...");

    TestBase64EncodeEmpty();
    TestBase64EncodeKnown();
    TestBase64EncodePaddingVariations();
    TestBase64EncodeLong();

    return runner.Summary();
}
