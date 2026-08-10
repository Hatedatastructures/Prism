/**
 * @file TrusttunnelCommon.cpp
 * @brief TrustTunnel 认证 common 模块测试（Basic Auth + HTTP/2 CONNECT 头）
 */

#include <common/trusttunnel/trusttunnel.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

TEST(TrusttunnelCommon, BasicAuth)
{
    const auto auth = trusttunnel::basic_auth("user", "pass");
    EXPECT_EQ(auth, "Basic dXNlcjpwYXNz");
}

TEST(TrusttunnelCommon, Base64Encode)
{
    const std::string s = "Hello, World!";
    EXPECT_EQ(trusttunnel::base64_encode(view(
                  reinterpret_cast<const std::uint8_t *>(s.data()), s.size())),
              "SGVsbG8sIFdvcmxkIQ==");
}

TEST(TrusttunnelCommon, H2ConnectHeaders)
{
    const auto auth = trusttunnel::basic_auth("prism", "secret");
    const auto block = trusttunnel::h2_connect_headers("example.com", 443, auth);
    ASSERT_GE(block.size(), 4);

    // :method CONNECT（静态表索引 7 → 0x87）
    EXPECT_EQ(block[0], 0x87);
    // :scheme https（静态表索引 23 → 0x97）
    EXPECT_EQ(block[1], 0x97);
}

TEST(TrusttunnelCommon, H2StatusParse)
{
    // 响应头块：:status 200（静态表索引 8 → 0x88）
    const std::uint8_t block[] = {0x88};
    std::uint16_t status = 0;
    ASSERT_TRUE(trusttunnel::parse_h2_status(view(block), status));
    EXPECT_EQ(status, 200);
}

TEST(TrusttunnelCommon, H2StatusLiteral)
{
    // 字面量 :status 404：名称引用静态表（HPACK 静态表 8 = :status）
    byte_writer w;
    w.write_u8(0x00 | 8); // 字面量名称引用 :status（不索引）
    w.write_u8(3);        // 值长度
    w.write_bytes("404");
    std::uint16_t status = 0;
    ASSERT_TRUE(trusttunnel::parse_h2_status(w.data(), status));
    EXPECT_EQ(status, 404);
}
