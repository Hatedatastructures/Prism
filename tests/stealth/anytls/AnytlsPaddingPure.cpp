/**
 * @file AnytlsPaddingPure.cpp
 * @brief AnyTLS padding 纯函数测试
 * @details 测试 parse_range / compute_md5_hex / random_in_range
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>
#include "../../src/prism/stealth/stack/anytls/padding.cpp"

namespace
{
    TEST(AnytlsPaddingPure, ParseRangeMinMax)
    {
        auto [lo, hi] = psm::stealth::anytls::parse_range("10-20");
        EXPECT_TRUE(lo == 10) << "parse_range: lo=10";
        EXPECT_TRUE(hi == 20) << "parse_range: hi=20";
    }

    TEST(AnytlsPaddingPure, ParseRangeSingleValue)
    {
        auto [lo, hi] = psm::stealth::anytls::parse_range("42");
        EXPECT_TRUE(lo == 42) << "parse_range: single lo=42";
        EXPECT_TRUE(hi == 42) << "parse_range: single hi=42";
    }

    TEST(AnytlsPaddingPure, ParseRangeZero)
    {
        auto [lo, hi] = psm::stealth::anytls::parse_range("0");
        EXPECT_TRUE(lo == 0) << "parse_range: zero lo=0";
        EXPECT_TRUE(hi == 0) << "parse_range: zero hi=0";
    }

    TEST(AnytlsPaddingPure, ComputeMd5Empty)
    {
        auto hex = psm::stealth::anytls::compute_md5_hex("");
        EXPECT_TRUE(hex == "d41d8cd98f00b204e9800998ecf8427e") << "md5: empty string";
    }

    TEST(AnytlsPaddingPure, ComputeMd5Hello)
    {
        auto hex = psm::stealth::anytls::compute_md5_hex("hello");
        EXPECT_TRUE(hex == "5d41402abc4b2a76b9719d911017c592") << "md5: hello";
    }

    TEST(AnytlsPaddingPure, ComputeMd5Length)
    {
        auto hex = psm::stealth::anytls::compute_md5_hex("test");
        EXPECT_TRUE(hex.size() == 32) << "md5: length=32";
    }

    TEST(AnytlsPaddingPure, RandomInRangeEqual)
    {
        auto val = psm::stealth::anytls::random_in_range(5, 5);
        EXPECT_TRUE(val == 5) << "random: lo==hi returns lo";
    }

    TEST(AnytlsPaddingPure, RandomInRangeGreater)
    {
        auto val = psm::stealth::anytls::random_in_range(10, 5);
        EXPECT_TRUE(val == 10) << "random: lo>hi returns lo";
    }

    TEST(AnytlsPaddingPure, RandomInRangeBounds)
    {
        auto val = psm::stealth::anytls::random_in_range(0, 100);
        EXPECT_TRUE(val >= 0 && val <= 100) << "random: in [0, 100]";
    }
} // namespace
