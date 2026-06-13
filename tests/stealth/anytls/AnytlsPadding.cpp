/**
 * @file AnytlsPadding.cpp
 * @brief AnyTLS padding 方案解析器单元测试
 * @details 测试 padding_factory 构造和 generate_sizes 纯逻辑。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>
#include <prism/stealth/stack/anytls/padding.hpp>

#include <cstdint>

namespace
{
    TEST(AnytlsPadding, EmptyScheme)
    {
        psm::stealth::anytls::padding_factory factory("");
        EXPECT_TRUE(factory.enabled() == false) << "empty scheme → not enabled";
        EXPECT_TRUE(factory.stop == 0) << "empty scheme → stop = 0";
    }

    TEST(AnytlsPadding, DefaultFactory)
    {
        psm::stealth::anytls::padding_factory factory;
        EXPECT_TRUE(factory.enabled() == false) << "default factory → not enabled";
    }

    TEST(AnytlsPadding, SimpleScheme)
    {
        psm::stealth::anytls::padding_factory factory(
            "stop=3\n"
            "0=100-200\n"
            "1=50-50,c\n"
            "2=300-500");

        EXPECT_TRUE(factory.enabled() == true) << "simple scheme enabled";
        EXPECT_TRUE(factory.stop == 3) << "stop = 3";

        auto sizes0 = factory.generate_sizes(0);
        EXPECT_TRUE(!sizes0.empty()) << "pkt 0 has sizes";
        // "100-200" → single random value in [100, 200]
        EXPECT_TRUE(sizes0[0] >= 100 && sizes0[0] <= 200) << "pkt 0 size in [100,200]";

        auto sizes1 = factory.generate_sizes(1);
        EXPECT_TRUE(sizes1.size() == 2) << "pkt 1 has 2 segments";
        EXPECT_TRUE(sizes1[0] == 50) << "pkt 1 first segment = 50";
        EXPECT_TRUE(sizes1[1] == psm::stealth::anytls::padding_factory::checkmark) << "pkt 1 second segment is checkmark";
    }

    TEST(AnytlsPadding, GenerateBeyondStop)
    {
        psm::stealth::anytls::padding_factory factory("stop=2\n0=100-200");
        auto sizes = factory.generate_sizes(5);
        EXPECT_TRUE(sizes.size() == 1) << "beyond stop → single checkmark";
        EXPECT_TRUE(sizes[0] == psm::stealth::anytls::padding_factory::checkmark)
            << "beyond stop → checkmark";
    }

    TEST(AnytlsPadding, GenerateMissingPkt)
    {
        psm::stealth::anytls::padding_factory factory("stop=5\n0=100-200\n2=300-400");
        auto sizes = factory.generate_sizes(1);
        EXPECT_TRUE(sizes.size() == 1) << "missing pkt → single checkmark";
        EXPECT_TRUE(sizes[0] == psm::stealth::anytls::padding_factory::checkmark)
            << "missing pkt → checkmark";
    }

    TEST(AnytlsPadding, CheckmarkOnly)
    {
        psm::stealth::anytls::padding_factory factory("stop=2\n0=c");
        auto sizes = factory.generate_sizes(0);
        EXPECT_TRUE(sizes.size() == 1) << "checkmark only → single entry";
        EXPECT_TRUE(sizes[0] == psm::stealth::anytls::padding_factory::checkmark)
            << "checkmark only → checkmark value";
    }

    TEST(AnytlsPadding, Md5Computed)
    {
        psm::stealth::anytls::padding_factory factory("stop=1\n0=100-200");
        EXPECT_TRUE(!factory.md5.empty()) << "MD5 computed for non-empty scheme";
        EXPECT_TRUE(factory.md5.size() == 32) << "MD5 hex string is 32 chars";
    }

    TEST(AnytlsPadding, EmptySchemeNoMd5)
    {
        psm::stealth::anytls::padding_factory factory("");
        EXPECT_TRUE(factory.md5.empty()) << "empty scheme → no MD5";
    }

    TEST(AnytlsPadding, CrLfInScheme)
    {
        // CRLF line endings should be handled
        psm::stealth::anytls::padding_factory factory("stop=1\r\n0=100-200\r\n");
        EXPECT_TRUE(factory.enabled() == true) << "CRLF scheme enabled";
        EXPECT_TRUE(factory.stop == 1) << "CRLF stop = 1";
    }

} // namespace
