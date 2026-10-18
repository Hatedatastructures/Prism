/**
 * @file ByteSpanTest.cpp
 * @brief Foundation ByteSpan 视图和转换契约测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <Prism/Foundation/ByteSpan.hpp>

namespace
{
    using Prism::As;
    using Prism::AsBytes;
    using Prism::AsBytesSpan;
    using Prism::AsStrView;
    using Prism::AsU8;
    using Prism::AsU8Span;
} // namespace

TEST(ByteSpan, ConstOverloads)
    {
        std::array<std::uint8_t, 4> U8{1, 2, 3, 4};
        const auto &ConstU8 = U8;
        const auto cb = AsBytes(std::span<const std::uint8_t>(ConstU8));
        EXPECT_EQ(cb.size(), 4u);
        EXPECT_EQ(static_cast<std::uint8_t>(cb[0]), 1u);

        std::string String = "abc";
        const auto StringU8 = AsU8Span(String);
        EXPECT_EQ(StringU8.size(), 3u);
        EXPECT_EQ(StringU8[0], 'a');

        const auto ByteSpan = AsBytesSpan(String);
        EXPECT_EQ(ByteSpan.size(), 3u);
        const std::string_view sv{"def"};
        EXPECT_EQ(AsBytesSpan(sv).size(), 3u);
        const char *Raw = "xy";
        EXPECT_EQ(AsBytesSpan(Raw, 2).size(), 2u);
        std::vector<std::uint8_t> Vector{9, 8};
        EXPECT_EQ(AsBytesSpan(Vector).size(), 2u);

        const auto StringViewBytes = AsStrView(std::span<const std::uint8_t>(U8.data(), 2));
        EXPECT_EQ(StringViewBytes.size(), 2u);
        const auto BytesView = AsBytes(std::span<std::uint8_t>(U8));
        EXPECT_EQ(AsStrView(BytesView.subspan(0, 2)).size(), 2u);
    }

TEST(ByteSpan, TemplateAs)
    {
        // 目标元素类型由模板参数控制（byte / uint8_t / char）
        std::string String = "abc";
        const auto Bytes = As<std::byte>(String);
        EXPECT_EQ(Bytes.size(), 3u);
        EXPECT_EQ(static_cast<char>(Bytes[0]), 'a');

        std::vector<std::uint8_t> Vector{1, 2, 3};
        const auto U8Vector = As<std::uint8_t>(Vector);
        EXPECT_EQ(U8Vector.size(), 3u);
        EXPECT_EQ(U8Vector[1], 2u);

        std::array<std::byte, 2> arr{std::byte{0x10}, std::byte{0x20}};
        const auto U8Array = As<std::uint8_t>(arr);
        EXPECT_EQ(U8Array[0], 0x10u);
        EXPECT_EQ(U8Array[1], 0x20u);

        // 只读源 → const 视图
        const std::string_view sv{"def"};
        const auto cbytes = As<std::byte>(sv);
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(cbytes)>, std::span<const std::byte>>));
        EXPECT_EQ(cbytes.size(), 3u);

        // 裸指针 + 长度 → uint8_t 只读视图
        const char *Raw = "xy";
        const auto rv = As<std::uint8_t>(Raw, 2);
        EXPECT_EQ(rv.size(), 2u);
        EXPECT_EQ(rv[1], 'y');
    }

TEST(ByteSpan, AsWriteThrough)
    {
        // 可变 string → span<byte> 可写（HTTP 读缓冲场景）
        std::string Buffer = "hello";
        const auto View = AsBytesSpan(Buffer);
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(View)>, std::span<std::byte>>));
        View[0] = std::byte{'H'};
        EXPECT_EQ(Buffer, "Hello");

        // span 右值保持可变视图，写穿到原数组
        std::array<std::uint8_t, 3> Data{1, 2, 3};
        const auto U8 = AsU8(std::span(Data));
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(U8)>, std::span<std::uint8_t>>));
        U8[0] = 9;
        EXPECT_EQ(Data[0], 9u);
    }

    // ───────────────────────── ws Codec ─────────────────────────

