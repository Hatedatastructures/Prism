/**
 * @file QpackInteropTest.cpp
 * @brief QPACK 联通性测试（C++ 侧）
 * @details 用 Go 端（metacubex/qpack，quic-go 同栈）编码的
 * QPACK 头块字节，验证本库 Qpack::DecodeHeaderBlock 能正确解码。
 * Go 编码命令：tests/go/qpackcmp.exe Encode
 * 期望解码出 hysteria2 认证头字段。
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

#include <preview/Protocols/Http3/Auth.hpp>
#include <preview/Protocols/Http3/Qpack.hpp>
#include <preview/Foundation/Memory/Container.hpp>

namespace
{

    /// hex 字符串转字节
    auto hex_to_bytes(const std::string &hex) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            const auto hi = hex[i] <= '9' ? hex[i] - '0' : hex[i] - 'a' + 10;
            const auto lo = hex[i + 1] <= '9' ? hex[i + 1] - '0' : hex[i + 1] - 'a' + 10;
            out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }
        return out;
    }

    TEST(QpackInterop, DecodeGoEncodedAuthHeaders)
    {
        // Go 端 metacubex/qpack 编码（对齐 hysteria2 认证头）
        // fields: :method=POST, :path=/auth, :authority=hysteria,
        //         hysteria-auth=password123, hysteria-cc-rx=0
        const std::string go_hex =
            "0000d451846076a67f50869fd2125b0c3f2f029fd2125b0c35876a6788ac684783d92044cf2f039fd2125b0c358845acf38107";
        const auto Data = hex_to_bytes(go_hex);

        auto mr = Preview::Memory::CurrentResource();
        const auto fields = Preview::Http3::Qpack::DecodeHeaderBlock(Data, mr);

        // 期望完整解码出全部 5 个认证头字段（逐字段校验，防止空断言假通过）
        ASSERT_EQ(fields.size(), 5);
        std::map<std::string_view, std::string_view> got;
        for (const auto &f : fields)
        {
            const auto name = std::string_view(f.Name.data(), f.Name.size());
            const auto val = std::string_view(f.value.data(), f.value.size());
            got.emplace(name, val);
            GTEST_LOG_(INFO) << "field: " << name << " = " << val;
        }
        EXPECT_EQ(got[":method"], "POST");
        EXPECT_EQ(got[":path"], "/auth");
        EXPECT_EQ(got[":authority"], "hysteria");
        EXPECT_EQ(got["hysteria-auth"], "password123");
        EXPECT_EQ(got["hysteria-cc-rx"], "0");

        Preview::Http3::AuthRequest request(mr);
        EXPECT_TRUE(Preview::Http3::ParseAuthRequest(Data, request, mr));
        EXPECT_EQ(request.Path, "/auth");
    }

    TEST(QpackInterop, EncodeDecodeRoundtrip)
    {
        // C++ 编码 → 解码回环
        auto mr = Preview::Memory::CurrentResource();
        std::array<std::uint8_t, 512> buf{};
        auto offset = Preview::Http3::Qpack::EncodePrefix(buf);
        offset += Preview::Http3::Qpack::EncodeLiteral(
            ":method", "POST", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
        offset += Preview::Http3::Qpack::EncodeLiteral(
            "hysteria-auth", "password123",
            std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));

        const auto fields =
            Preview::Http3::Qpack::DecodeHeaderBlock(
                std::span<const std::uint8_t>(buf.data(), offset), mr);
        ASSERT_EQ(fields.size(), 2);
        EXPECT_EQ(std::string_view(fields[0].Name.data(), fields[0].Name.size()), ":method");
        EXPECT_EQ(std::string_view(fields[0].value.data(), fields[0].value.size()), "POST");
        EXPECT_EQ(std::string_view(fields[1].Name.data(), fields[1].Name.size()), "hysteria-auth");
        EXPECT_EQ(std::string_view(fields[1].value.data(), fields[1].value.size()), "password123");
    }

    TEST(QpackInterop, StaticIndexedFieldsUseCanonicalNames)
    {
        const std::array<std::uint8_t, 4> Data{0x00, 0x00, 0xD4, 0xC1};
        const auto fields = Preview::Http3::Qpack::DecodeHeaderBlock(
            std::span<const std::uint8_t>(Data), Preview::Memory::CurrentResource());

        ASSERT_EQ(fields.size(), 2);
        EXPECT_EQ(std::string_view(fields[0].Name), ":method");
        EXPECT_EQ(std::string_view(fields[0].value), "POST");
        EXPECT_EQ(std::string_view(fields[1].Name), ":path");
        EXPECT_EQ(std::string_view(fields[1].value), "/");
    }

    TEST(QpackInterop, LiteralAndIndexedFieldsParseAuth)
    {
        std::array<std::uint8_t, 512> Data{};
        auto Offset = Preview::Http3::Qpack::EncodePrefix(Data);
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            ":method", "POST", std::span<std::uint8_t>(Data.data() + Offset, Data.size() - Offset));
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            ":path", "/auth", std::span<std::uint8_t>(Data.data() + Offset, Data.size() - Offset));
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            ":authority", "hysteria", std::span<std::uint8_t>(Data.data() + Offset, Data.size() - Offset));
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            "hysteria-auth", "password123",
            std::span<std::uint8_t>(Data.data() + Offset, Data.size() - Offset));

        Preview::Http3::AuthRequest Request(Preview::Memory::CurrentResource());
        EXPECT_TRUE(Preview::Http3::ParseAuthRequest(
            std::span<const std::uint8_t>(Data.data(), Offset), Request,
            Preview::Memory::CurrentResource()));
        EXPECT_EQ(Request.Method, "POST");
        EXPECT_EQ(Request.Path, "/auth");
    }

    TEST(QpackInterop, InvalidPseudoHeadersAreRejected)
    {
        auto MakeBlock = [](std::initializer_list<std::pair<std::string_view, std::string_view>> Fields)
        {
            std::array<std::uint8_t, 512> Data{};
            auto Offset = Preview::Http3::Qpack::EncodePrefix(Data);
            for (const auto &[Name, Value] : Fields)
            {
                Offset += Preview::Http3::Qpack::EncodeLiteral(
                    Name, Value, std::span<std::uint8_t>(Data.data() + Offset, Data.size() - Offset));
            }
            return std::pair{Data, Offset};
        };

        const auto Duplicate = MakeBlock({{":method", "POST"}, {":method", "GET"},
                                           {":path", "/auth"}, {"hysteria-auth", "password123"}});
        const auto Unknown = MakeBlock({{":method", "POST"}, {":path", "/auth"},
                                        {":protocol", "webtransport"}, {"hysteria-auth", "password123"}});
        const auto WrongCase = MakeBlock({{":Method", "POST"}, {":path", "/auth"},
                                          {"hysteria-auth", "password123"}});

        Preview::Http3::AuthRequest DuplicateRequest(Preview::Memory::CurrentResource());
        Preview::Http3::AuthRequest UnknownRequest(Preview::Memory::CurrentResource());
        Preview::Http3::AuthRequest WrongCaseRequest(Preview::Memory::CurrentResource());

        EXPECT_FALSE(Preview::Http3::ParseAuthRequest(
            std::span<const std::uint8_t>(Duplicate.first.data(), Duplicate.second),
            DuplicateRequest,
            Preview::Memory::CurrentResource()));
        EXPECT_FALSE(Preview::Http3::ParseAuthRequest(
            std::span<const std::uint8_t>(Unknown.first.data(), Unknown.second),
            UnknownRequest,
            Preview::Memory::CurrentResource()));
        EXPECT_FALSE(Preview::Http3::ParseAuthRequest(
            std::span<const std::uint8_t>(WrongCase.first.data(), WrongCase.second),
            WrongCaseRequest,
            Preview::Memory::CurrentResource()));
    }

    TEST(QpackInterop, MissingAndTruncatedHeadersAreRejected)
    {
        std::array<std::uint8_t, 512> Data{};
        auto Offset = Preview::Http3::Qpack::EncodePrefix(Data);
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            "hysteria-auth", "password123", std::span<std::uint8_t>(Data.data() + Offset, Data.size() - Offset));

        Preview::Http3::AuthRequest Missing(Preview::Memory::CurrentResource());
        EXPECT_FALSE(Preview::Http3::ParseAuthRequest(
            std::span<const std::uint8_t>(Data.data(), Offset), Missing,
            Preview::Memory::CurrentResource()));

        Preview::Http3::AuthRequest Truncated(Preview::Memory::CurrentResource());
        EXPECT_FALSE(Preview::Http3::ParseAuthRequest(
            std::span<const std::uint8_t>(Data.data(), Offset - 1), Truncated,
            Preview::Memory::CurrentResource()));
    }

    TEST(QpackInterop, DynamicNameReferenceIsRejected)
    {
        const std::array<std::uint8_t, 4> DynamicName{0x00, 0x00, 0x40, 0x00};
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(
                        DynamicName, Preview::Memory::CurrentResource())
                        .empty());
    }

    TEST(QpackInterop, ValidHeadersFollowedByMalformedFieldAreRejected)
    {
        std::array<std::uint8_t, 512> Block{};
        auto Offset = Preview::Http3::Qpack::EncodePrefix(Block);
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            ":method", "POST", std::span(Block.data() + Offset, Block.size() - Offset));
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            ":path", "/auth", std::span(Block.data() + Offset, Block.size() - Offset));
        Offset += Preview::Http3::Qpack::EncodeLiteral(
            "hysteria-auth", "password123",
            std::span(Block.data() + Offset, Block.size() - Offset));
        Block[Offset++] = 0x40; // T=0：不支持动态名称引用

        Preview::Http3::AuthRequest Request(Preview::Memory::CurrentResource());
        EXPECT_TRUE(Preview::Http3::Qpack::DecodeHeaderBlock(
                        std::span<const std::uint8_t>(Block.data(), Offset),
                        Preview::Memory::CurrentResource())
                        .empty());
        EXPECT_FALSE(Preview::Http3::ParseAuthRequest(
            std::span<const std::uint8_t>(Block.data(), Offset), Request,
            Preview::Memory::CurrentResource()));
    }

} // namespace
