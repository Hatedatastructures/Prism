/**
 * @file QpackInteropTest.cpp
 * @brief Generic QPACK interoperability and malformed block coverage.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Protocols/Http3/Qpack.hpp>

namespace
{

    auto HexToBytes(const std::string &Hex) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        for (std::size_t Index = 0; Index + 1 < Hex.size(); Index += 2)
        {
            const auto Decode = [](const char Character) -> int
            {
                if (Character >= '0' && Character <= '9')
                {
                    return Character - '0';
                }
                return Character - 'a' + 10;
            };
            Output.push_back(static_cast<std::uint8_t>(
                (Decode(Hex[Index]) << 4) | Decode(Hex[Index + 1])));
        }
        return Output;
    }

    TEST(QpackInterop, DecodeGoEncodedHeaderBlock)
    {
        const std::string Hex =
            "0000d451846076a67f50869fd2125b0c3f2f029fd2125b0c35876a6788ac684783d92044cf2f039fd2125b0c358845acf38107";
        const auto Data = HexToBytes(Hex);
        const auto Fields = Preview::Http3::Qpack::DecodeHeaderBlock(
            Data, Preview::Memory::CurrentResource());

        ASSERT_EQ(Fields.size(), 5U);
        std::map<std::string_view, std::string_view> Values;
        for (const auto &Field : Fields)
        {
            Values.emplace(
                std::string_view(Field.Name.data(), Field.Name.size()),
                std::string_view(Field.value.data(), Field.value.size()));
        }
        EXPECT_EQ(Values[":method"], "POST");
        EXPECT_EQ(Values[":path"], "/auth");
        EXPECT_EQ(Values[":authority"], "hysteria");
        EXPECT_EQ(Values["hysteria-auth"], "password123");
        EXPECT_EQ(Values["hysteria-cc-rx"], "0");
    }

    TEST(QpackInterop, EncodeDecodeRoundtripPreservesGenericFields)
    {
        std::array<std::uint8_t, 512> Data{};
        auto Offset = Preview::Http3::Qpack::EncodePrefix(Data);
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            ":method", "POST", std::span(Data).subspan(Offset));
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            "x-h3-test", "value", std::span(Data).subspan(Offset));

        const auto Fields = Preview::Http3::Qpack::DecodeHeaderBlock(
            std::span<const std::uint8_t>(Data.data(), Offset),
            Preview::Memory::CurrentResource());
        ASSERT_EQ(Fields.size(), 2U);
        EXPECT_EQ(Fields[0].Name, ":method");
        EXPECT_EQ(Fields[0].value, "POST");
        EXPECT_EQ(Fields[1].Name, "x-h3-test");
        EXPECT_EQ(Fields[1].value, "value");
    }

    TEST(QpackInterop, StaticIndexedFieldsUseCanonicalNames)
    {
        const std::array<std::uint8_t, 4> Data{0x00, 0x00, 0xD4, 0xC1};
        const auto Fields = Preview::Http3::Qpack::DecodeHeaderBlock(
            Data, Preview::Memory::CurrentResource());
        ASSERT_EQ(Fields.size(), 2U);
        EXPECT_EQ(Fields[0].Name, ":method");
        EXPECT_EQ(Fields[0].value, "POST");
        EXPECT_EQ(Fields[1].Name, ":path");
        EXPECT_EQ(Fields[1].value, "/");
    }

    TEST(QpackInterop, RejectsInvalidPrefixesAndDynamicReferences)
    {
        const auto Resource = Preview::Memory::CurrentResource();
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock({}, Resource).empty());
        const std::array<std::uint8_t, 2> RequiredCount{0x01, 0x00};
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(RequiredCount, Resource).empty());
        const std::array<std::uint8_t, 2> DeltaBase{0x00, 0x02};
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(DeltaBase, Resource).empty());
        const std::array<std::uint8_t, 4> DynamicName{0x00, 0x00, 0x40, 0x00};
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(DynamicName, Resource).empty());
    }

    TEST(QpackInterop, RejectsMalformedFieldAfterValidPrefix)
    {
        std::array<std::uint8_t, 512> Block{};
        auto Offset = Preview::Http3::Qpack::EncodePrefix(Block);
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            ":method", "POST", std::span(Block).subspan(Offset));
        Block[Offset++] = 0x40;
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(
                        std::span<const std::uint8_t>(Block.data(), Offset),
                        Preview::Memory::CurrentResource())
                        .empty());
    }

    TEST(QpackInterop, RejectsHeaderBudgetAndOversizedLiteral)
    {
        auto Block = std::vector<std::uint8_t>(2, 0);
        Block.insert(Block.end(), 129, 0xD4);
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(
                        Block, Preview::Memory::CurrentResource())
                        .empty());

        const std::string Value(16 * 1024 + 1, 'x');
        std::vector<std::uint8_t> Large(20 * 1024, 0);
        auto Offset = Preview::Http3::Qpack::EncodePrefix(Large);
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            "x-large", Value, std::span(Large).subspan(Offset));
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(
                        std::span<const std::uint8_t>(Large.data(), Offset),
                        Preview::Memory::CurrentResource())
                        .empty());
    }

} // namespace
