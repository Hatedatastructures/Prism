/**
 * @file VlessConnPure.cpp
 * @brief VLESS conn 纯函数测试
 * @details 测试 uuid_to_string 格式化
 */

#include <prism/foundation/foundation.hpp>
#include "../../src/prism/proto/protocol/vless/conn.cpp"
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

namespace
{
    TEST(VlessConnPure, UuidAllZeros)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        EXPECT_TRUE(str == "00000000-0000-0000-0000-000000000000") << "uuid: all zeros";
    }

    TEST(VlessConnPure, UuidAllFF)
    {
        std::array<std::uint8_t, 16> uuid;
        uuid.fill(0xFF);
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        EXPECT_TRUE(str == "ffffffff-ffff-ffff-ffff-ffffffffffff") << "uuid: all 0xFF";
    }

    TEST(VlessConnPure, UuidKnownPattern)
    {
        std::array<std::uint8_t, 16> uuid = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        EXPECT_TRUE(str == "01234567-89ab-cdef-0123-456789abcdef") << "uuid: known pattern";
    }

    TEST(VlessConnPure, UuidLength)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        EXPECT_TRUE(str.size() == 36) << "uuid: length=36";
    }

    TEST(VlessConnPure, UuidDashPositions)
    {
        std::array<std::uint8_t, 16> uuid = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef};
        auto str = psm::protocol::vless::uuid_to_string(uuid);
        EXPECT_TRUE(str[8] == '-') << "uuid: dash at 8";
        EXPECT_TRUE(str[13] == '-') << "uuid: dash at 13";
        EXPECT_TRUE(str[18] == '-') << "uuid: dash at 18";
        EXPECT_TRUE(str[23] == '-') << "uuid: dash at 23";
    }
} // namespace

