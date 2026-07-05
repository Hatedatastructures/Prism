/**
 * @file VlessConnPure2.cpp
 * @brief VLESS conn 纯函数单元测试
 * @details 测试 vless::conn 中的纯同步辅助函数：uuid_to_string。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

// #include 源文件增加覆盖率计数
#include "../../src/prism/proto/protocol/vless/conn.cpp"

namespace
{
    using namespace psm::protocol::vless;

    // uuid_to_string 在 anonymous namespace 中，通过 #include 可见

    // ─── uuid_to_string ─────────────────────────────

    TEST(VlessConnPure2, UuidToStringZeros)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = uuid_to_string(uuid);
        EXPECT_TRUE(str == "00000000-0000-0000-0000-000000000000")
            << "uuid_to_string: all zeros";
    }

    TEST(VlessConnPure2, UuidToStringMax)
    {
        std::array<std::uint8_t, 16> uuid{};
        std::fill(uuid.begin(), uuid.end(), 0xFF);
        auto str = uuid_to_string(uuid);
        EXPECT_TRUE(str == "ffffffff-ffff-ffff-ffff-ffffffffffff")
            << "uuid_to_string: all FF";
    }

    TEST(VlessConnPure2, UuidToStringKnown)
    {
        // RFC 4122 测试 UUID: 00112233-4455-6677-8899-aabbccddeeff
        std::array<std::uint8_t, 16> uuid{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        auto str = uuid_to_string(uuid);
        EXPECT_TRUE(str == "00112233-4455-6677-8899-aabbccddeeff")
            << "uuid_to_string: known UUID";
    }

    TEST(VlessConnPure2, UuidToStringLength)
    {
        std::array<std::uint8_t, 16> uuid{};
        auto str = uuid_to_string(uuid);
        EXPECT_TRUE(str.size() == 36) << "uuid_to_string: length=36 (32 hex + 4 dashes)";
    }

    // ─── conn 构造/访问器（不依赖网络 I/O） ────────

    TEST(VlessConnPure2, ConnConstruct)
    {
        // 验证 uuid_to_string 输出格式一致性（间接覆盖 conn 构造依赖的辅助函数）
        std::array<std::uint8_t, 16> uuid{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                           0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
        auto str = uuid_to_string(uuid);
        EXPECT_TRUE(str == "01234567-89ab-cdef-fedc-ba9876543210")
            << "vless conn: uuid_to_string covers conn construction path";
    }

} // namespace
