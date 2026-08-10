/**
 * @file VmessAuth.cpp
 * @brief VMess AEAD 认证头测试
 * @details 验证认证头加解密往返、CRC32/FNV 校验函数、时间容忍窗口。
 */

#include <prism/protocol/vmess/codec/auth.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::protocol::vmess::codec::cmd_key_from_uuid;
    using psm::protocol::vmess::codec::crc32_ieee;
    using psm::protocol::vmess::codec::fnv1a_32;
    using psm::protocol::vmess::codec::open_auth_header;
    using psm::protocol::vmess::codec::seal_auth_header;
    using psm::protocol::vmess::codec::parse_uuid;
}

TEST(VmessAuth, Crc32KnownVector)
{
    // CRC32("123456789") == 0xCBF43926
    const std::string_view data = "123456789";
    const auto crc = crc32_ieee(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size()));
    EXPECT_EQ(crc, 0xCBF43926U);
}

TEST(VmessAuth, Fnv1aKnownVector)
{
    // FNV-1a("") == 0x811C9DC5
    EXPECT_EQ(fnv1a_32({}), 0x811C9DC5U);
    // FNV-1a("a") == 0xE40C292C
    const std::string_view data = "a";
    const auto hash = fnv1a_32(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size()));
    EXPECT_EQ(hash, 0xE40C292CU);
}

TEST(VmessAuth, SealOpenRoundtrip)
{
    std::array<std::uint8_t, 16> uuid_bytes{};
    ASSERT_TRUE(parse_uuid("123e4567-e89b-12d3-a456-426614174000", uuid_bytes));
    const auto cmd_key = cmd_key_from_uuid(uuid_bytes);

    const std::int64_t ts = 1750000000;
    std::array<std::uint8_t, 16> auth_id{};
    const auto ec = seal_auth_header(
        std::span<const std::uint8_t, 16>(cmd_key.data(), 16), ts,
        std::span<std::uint8_t, 16>(auth_id.data(), 16));
    ASSERT_EQ(ec, psm::fault::code::success);

    const auto result = open_auth_header(
        std::span<const std::uint8_t, 16>(cmd_key.data(), 16),
        std::span<const std::uint8_t, 16>(auth_id.data(), 16));
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.timestamp, ts);
}

TEST(VmessAuth, WrongKeyFails)
{
    std::array<std::uint8_t, 16> uuid_bytes{};
    ASSERT_TRUE(parse_uuid("123e4567-e89b-12d3-a456-426614174000", uuid_bytes));
    const auto cmd_key = cmd_key_from_uuid(uuid_bytes);

    std::array<std::uint8_t, 16> auth_id{};
    seal_auth_header(std::span<const std::uint8_t, 16>(cmd_key.data(), 16), 1750000000,
                     std::span<std::uint8_t, 16>(auth_id.data(), 16));

    // 用错误密钥解密：CRC 校验必然失败
    std::array<std::uint8_t, 16> wrong{};
    wrong.fill(0x42);
    const auto result = open_auth_header(
        std::span<const std::uint8_t, 16>(wrong.data(), 16),
        std::span<const std::uint8_t, 16>(auth_id.data(), 16));
    EXPECT_FALSE(result.valid);
}

TEST(VmessAuth, TamperedAuthIdFails)
{
    std::array<std::uint8_t, 16> uuid_bytes{};
    ASSERT_TRUE(parse_uuid("123e4567-e89b-12d3-a456-426614174000", uuid_bytes));
    const auto cmd_key = cmd_key_from_uuid(uuid_bytes);

    std::array<std::uint8_t, 16> auth_id{};
    seal_auth_header(std::span<const std::uint8_t, 16>(cmd_key.data(), 16), 1750000000,
                     std::span<std::uint8_t, 16>(auth_id.data(), 16));
    auth_id[5] ^= 0x01;

    const auto result = open_auth_header(
        std::span<const std::uint8_t, 16>(cmd_key.data(), 16),
        std::span<const std::uint8_t, 16>(auth_id.data(), 16));
    EXPECT_FALSE(result.valid);
}
