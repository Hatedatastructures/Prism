/**
 * @file Base64Encode.cpp
 * @brief Base64 编码单元测试
 * @details 测试 psm::crypto::base64_encode 函数，覆盖空输入、已知向量、
 * padding 变化、长二进制数据等场景。
 */

#include <prism/crypto/base64.hpp>
#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace
{
    TEST(Base64Encode, Empty)
    {
        std::vector<std::uint8_t> empty;
        auto result = psm::crypto::base64_encode(empty);

        EXPECT_TRUE(result.empty()) << "Empty input produces empty string";
    }

    TEST(Base64Encode, Known)
    {
        // "Man" (3 bytes, no padding) -> "TWFu"
        {
            std::vector<std::uint8_t> input{'M', 'a', 'n'};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "TWFu") << "Base64('Man') == \"TWFu\"";
        }

        // "Ma" (2 bytes, 1 padding) -> "TWE="
        {
            std::vector<std::uint8_t> input{'M', 'a'};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "TWE=") << "Base64('Ma') == \"TWE=\"";
        }

        // "M" (1 byte, 2 padding) -> "TQ=="
        {
            std::vector<std::uint8_t> input{'M'};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "TQ==") << "Base64('M') == \"TQ==\"";
        }

        // "Hello, World!" (13 bytes) -> "SGVsbG8sIFdvcmxkIQ=="
        {
            std::string text = "Hello, World!";
            std::vector<std::uint8_t> input(text.begin(), text.end());
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "SGVsbG8sIFdvcmxkIQ==") << "Base64('Hello, World!') == \"SGVsbG8sIFdvcmxkIQ==\"";
        }
    }

    TEST(Base64Encode, PaddingVariations)
    {
        // 1 byte mod 3 -> 2 padding chars
        {
            std::vector<std::uint8_t> input{0xFF};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "/w==") << "1 byte input produces 2 padding chars";
        }

        // 2 bytes mod 3 -> 1 padding char
        {
            std::vector<std::uint8_t> input{0xFF, 0xFF};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "//8=") << "2 bytes input produces 1 padding char";
        }

        // 3 bytes mod 3 -> no padding
        {
            std::vector<std::uint8_t> input{0xFF, 0xFF, 0xFF};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "////") << "3 bytes input produces no padding";
        }

        // 4 bytes (1 full group + 1 remaining) -> 2 padding
        {
            std::vector<std::uint8_t> input{0x00, 0x00, 0x00, 0x01};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "AAAAAQ==") << "4 bytes input ends with 2 padding";
        }

        // 5 bytes (1 full group + 2 remaining) -> 1 padding
        {
            std::vector<std::uint8_t> input{0x00, 0x00, 0x00, 0x01, 0x00};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "AAAAAQA=") << "5 bytes input ends with 1 padding";
        }

        // 6 bytes (2 full groups) -> no padding
        {
            std::vector<std::uint8_t> input{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            auto result = psm::crypto::base64_encode(input);
            EXPECT_TRUE(result == "AAAAAAAA") << "6 bytes input produces no padding";
        }
    }

    TEST(Base64Encode, Long)
    {
        // 32 bytes of random-looking data
        std::vector<std::uint8_t> input = {
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8
        };

        auto result = psm::crypto::base64_encode(input);

        // 32 bytes -> ceil(32/3)*4 = 44 characters
        EXPECT_TRUE(result.size() == 44) << "32 bytes encode to 44 base64 characters";

        // Last 2 bytes (0xF9, 0xF8) -> 1 remaining byte mod 3 -> 2 padding
        EXPECT_TRUE(result.back() == '=') << "Long input ends with padding";

        // Verify against known encoding of this specific 32-byte sequence
        EXPECT_TRUE(result == "3q2+78r+ur4AAQIDBAUGBwgJCgsMDQ4P//79/Pv6+fg=")
            << "Long input matches expected base64 output";
    }
} // namespace
