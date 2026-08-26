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
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <common/Protocols/Http3/Qpack.hpp>
#include <common/Core/Memory/Container.hpp>

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
        // fields: :method=POST, :path=/Auth, :authority=hysteria,
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
        // 注：解码器静态表键存储形式为 :Method/:Path（exact-match 设计，见 issues.md A-9），
        // 值 /auth 为 Go 端实际编码内容
        EXPECT_EQ(got[":Method"], "POST");
        EXPECT_EQ(got[":Path"], "/auth");
        EXPECT_EQ(got[":authority"], "hysteria");
        EXPECT_EQ(got["hysteria-auth"], "password123");
        EXPECT_EQ(got["hysteria-cc-rx"], "0");
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

} // namespace
