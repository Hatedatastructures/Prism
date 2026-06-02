/**
 * @file Blake3.cpp
 * @brief BLAKE3 密钥派生单元测试
 * @details 测试 psm::crypto::derive_key 命名空间下的 BLAKE3 密钥派生功能，
 * 覆盖确定性、不同上下文/材料、span 与 vector 重载一致性、输出长度、空输入等场景。
 */

#include <gtest/gtest.h>

#include <prism/crypto/blake3.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

/**
 * @brief 测试 BLAKE3 derive_key 确定性
 */
TEST(Blake3, DeriveKeyDeterministic)
{
    const std::array<std::uint8_t, 3> material = {0x01, 0x02, 0x03};

    auto key1 = psm::crypto::derive_key("test context", material, 32);
    auto key2 = psm::crypto::derive_key("test context", material, 32);

    ASSERT_EQ(key1.size(), 32u) << "derive_key should produce 32 bytes";
    EXPECT_EQ(key1, key2) << "derive_key with same inputs should produce identical output";
}

/**
 * @brief 测试不同 context 产生不同输出
 */
TEST(Blake3, DifferentContextDifferentOutput)
{
    const std::array<std::uint8_t, 3> material = {0x01, 0x02, 0x03};

    auto key_a = psm::crypto::derive_key("context A", material, 32);
    auto key_b = psm::crypto::derive_key("context B", material, 32);

    EXPECT_NE(key_a, key_b) << "different contexts should produce different keys";
}

/**
 * @brief 测试不同 material 产生不同输出
 */
TEST(Blake3, DifferentMaterialDifferentOutput)
{
    const std::array<std::uint8_t, 1> mat_a = {0x01};
    const std::array<std::uint8_t, 1> mat_b = {0x02};

    auto key_a = psm::crypto::derive_key("test", mat_a, 32);
    auto key_b = psm::crypto::derive_key("test", mat_b, 32);

    EXPECT_NE(key_a, key_b) << "different materials should produce different keys";
}

/**
 * @brief 测试 span 重载与 vector 重载输出一致
 */
TEST(Blake3, SpanVsVectorOverload)
{
    const std::array<std::uint8_t, 4> material = {0xAA, 0xBB, 0xCC, 0xDD};

    // vector 重载
    auto vec_result = psm::crypto::derive_key("test overload", material, 32);

    // span 重载
    std::vector<std::uint8_t> span_result(32);
    psm::crypto::derive_key("test overload", material, span_result);

    EXPECT_EQ(vec_result.size(), span_result.size())
        << "span and vector overloads should produce same size output";
    EXPECT_EQ(vec_result, span_result)
        << "span and vector overloads should produce identical output";
}

/**
 * @brief 测试输出长度匹配请求
 */
TEST(Blake3, OutputLengthMatchesRequest)
{
    const std::array<std::uint8_t, 4> material = {0x01, 0x02, 0x03, 0x04};

    // 请求 16 字节
    {
        auto key = psm::crypto::derive_key("len test", material, 16);
        EXPECT_EQ(key.size(), 16u) << "requested 16 bytes";
    }

    // 请求 64 字节
    {
        auto key = psm::crypto::derive_key("len test", material, 64);
        EXPECT_EQ(key.size(), 64u) << "requested 64 bytes";
    }
}

/**
 * @brief 测试空 material 不崩溃
 */
TEST(Blake3, EmptyMaterial)
{
    const std::span<const std::uint8_t> empty_material;
    auto key = psm::crypto::derive_key("empty material test", empty_material, 32);
    EXPECT_EQ(key.size(), 32u) << "empty material should still produce 32 bytes";
}

/**
 * @brief 测试空 context 不崩溃
 */
TEST(Blake3, EmptyContext)
{
    const std::array<std::uint8_t, 4> material = {0x01, 0x02, 0x03, 0x04};
    auto key = psm::crypto::derive_key("", material, 32);
    EXPECT_EQ(key.size(), 32u) << "empty context should still produce 32 bytes";
}
