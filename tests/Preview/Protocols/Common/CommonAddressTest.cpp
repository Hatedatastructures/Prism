/**
 * @file CommonAddressTest.cpp
 * @brief Preview Common Address 文本和二进制边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Common/Framing.hpp>

namespace
{
    namespace Protocol = Preview::Protocol;
    namespace Common = Preview::Protocol::Common;
} // namespace

TEST(CommonAddress, RejectsEmptyIpv4Segments)
{
    std::array<std::uint8_t, 4> Bytes{};
    EXPECT_FALSE(Common::ParseIpv4Text(".1.2.3", Bytes));
    EXPECT_FALSE(Common::ParseIpv4Text("1..2.3", Bytes));
    EXPECT_FALSE(Common::ParseIpv4Text("1.2.3.", Bytes));
}
