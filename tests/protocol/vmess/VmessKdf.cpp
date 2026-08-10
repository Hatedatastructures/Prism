/**
 * @file VmessKdf.cpp
 * @brief VMess KDF 与 cmdKey 派生测试
 * @details 验证嵌套 HMAC-SHA256 KDF 与 UUID 派生密钥的正确性。
 */

#include <prism/protocol/vmess/codec/kdf.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::protocol::vmess::codec::cmd_key_from_uuid;
    using psm::protocol::vmess::codec::kdf;
    using psm::protocol::vmess::codec::parse_uuid;

    /// 固定 UUID：123e4567-e89b-12d3-a456-426614174000
    auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        return {0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
                0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    }
}

TEST(VmessKdf, ParseUuid)
{
    std::array<std::uint8_t, 16> bytes{};
    ASSERT_TRUE(parse_uuid("123e4567-e89b-12d3-a456-426614174000", bytes));
    EXPECT_EQ(bytes, test_uuid());

    ASSERT_FALSE(parse_uuid("invalid-uuid-string", bytes));
    ASSERT_FALSE(parse_uuid("123e4567-e89b-12d3-a456-42661417400", bytes));
}

TEST(VmessKdf, CmdKeyDerivation)
{
    // cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    const auto key = cmd_key_from_uuid(test_uuid());
    EXPECT_EQ(key.size(), 16);

    // 确定性：同一 UUID 派生结果一致
    const auto key2 = cmd_key_from_uuid(test_uuid());
    EXPECT_EQ(key, key2);
}

TEST(VmessKdf, KdfDeterministic)
{
    const std::array<std::uint8_t, 16> key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const std::array<std::uint8_t, 8> nonce{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};

    const auto a = kdf(std::span<const std::uint8_t>(key), "VMess Header AEAD Key", key, nonce);
    const auto b = kdf(std::span<const std::uint8_t>(key), "VMess Header AEAD Key", key, nonce);
    EXPECT_EQ(a, b);
}

TEST(VmessKdf, KdfSinglePath)
{
    const std::array<std::uint8_t, 16> key{0};
    const auto result = kdf(std::span<const std::uint8_t>(key), "AES Auth ID Encryption");
    // 32 字节输出，非全零
    EXPECT_EQ(result.size(), 32);
    bool non_zero = false;
    for (const auto byte : result)
        non_zero = non_zero || byte != 0;
    EXPECT_TRUE(non_zero);
}

TEST(VmessKdf, KdfMatchesSingVmess)
{
    // 对照 sing-vmess v0.2.5 官方 KDF 输出（Go 程序实测验证）：
    // cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    // kdf(cmdKey, "AES Auth ID Encryption")[:16] = dc12105ad83e8d0f2b07e1e8ad02a66d
    const auto cmd = cmd_key_from_uuid(test_uuid());
    const auto auth_key = kdf(std::span<const std::uint8_t>(cmd), "AES Auth ID Encryption");

    constexpr std::array<std::uint8_t, 16> expected{
        0xdc, 0x12, 0x10, 0x5a, 0xd8, 0x3e, 0x8d, 0x0f,
        0x2b, 0x07, 0xe1, 0xe8, 0xad, 0x02, 0xa6, 0x6d};
    bool match = std::equal(auth_key.begin(), auth_key.begin() + 16, expected.begin());
    if (!match)
    {
        std::fprintf(stderr, "got: ");
        for (std::size_t i = 0; i < 16; ++i)
            std::fprintf(stderr, "%02x", auth_key[i]);
        std::fprintf(stderr, "\n");
    }
    EXPECT_TRUE(match);
}
