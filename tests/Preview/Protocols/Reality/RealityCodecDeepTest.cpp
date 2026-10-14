/**
 * @file RealityCodecDeepTest.cpp
 * @brief Reality 编解码器 Base64 和短 ID 边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <string>
#include <Preview/Protocols/Reality/Detail/Key.hpp>

namespace
{
    namespace Reality = Preview::Reality;
} // namespace

TEST(RealityCodecDeep, Base64UrlBranches)
    {
        // 1 字节余数编码（i + 1 == Size 分支）
        const std::array<std::uint8_t, 4> four{1, 2, 3, 4};
        const auto enc4 = Reality::Detail::Base64urlEncode(four);
        EXPECT_EQ(enc4.size(), 6u);
        // 2 字节余数编码
        const std::array<std::uint8_t, 2> two{'a', 'b'};
        const auto enc2 = Reality::Detail::Base64urlEncode(two);
        EXPECT_EQ(enc2.size(), 3u);
        // 3 字节整块 + 2 余数
        const std::array<std::uint8_t, 5> five{1, 2, 3, 4, 5};
        const auto enc5 = Reality::Detail::Base64urlEncode(five);
        EXPECT_EQ(enc5.size(), 7u);
        // 3 字节余数分支（i + 2 == Size）
        std::array<std::uint8_t, 8> eight{};
        eight.fill(0x55);
        EXPECT_EQ(Reality::Detail::Base64urlEncode(eight).size(), 11u);
        // 往返一致性
        const auto dec = Reality::Detail::Base64urlDecode(enc5);
        EXPECT_EQ(dec.size(), 5u);
        EXPECT_EQ(dec[0], 1u);

        // 非法字符解码 → 空
        EXPECT_TRUE(Reality::Detail::Base64urlDecode("a!b").empty());
        // 大写字母解码分支
        const auto up = Reality::Detail::Base64urlDecode("QUJD");
        EXPECT_EQ(up.size(), 3u);
        EXPECT_EQ(up[0], 'A');
        // 数字与小写分支
        const auto dn = Reality::Detail::Base64urlDecode("YWJj");
        EXPECT_EQ(dn.size(), 3u);
        EXPECT_EQ(dn[0], 'a');

        // ParseShortId：大写 hex 分支 + 非法长度 + 成功
        std::array<std::uint8_t, Reality::MaxShortIdLen> sid{};
        EXPECT_FALSE(Reality::Detail::ParseShortId("ABCD1234", sid));
        EXPECT_EQ(sid[0], 0xAB);
        EXPECT_TRUE(Reality::Detail::ParseShortId("ABC", sid));
        EXPECT_TRUE(Reality::Detail::ParseShortId("ZZ", sid));
    }

TEST(RealityCodecDeep, EmptyShortIdDecodesToZeroFilledBytes)
    {
        std::array<std::uint8_t, Reality::MaxShortIdLen> sid{};
        sid.fill(0xA5);
        EXPECT_FALSE(Reality::Detail::ParseShortId("", sid));
        EXPECT_EQ(sid, (std::array<std::uint8_t, Reality::MaxShortIdLen>{}));
    }

