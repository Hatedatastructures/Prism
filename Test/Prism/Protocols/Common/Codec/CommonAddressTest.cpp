/**
 * @file CommonAddressTest.cpp
 * @brief Prism Common Address 文本和二进制边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Common/Framing.hpp>

namespace
{
    namespace Protocol = Prism::Protocol;
    namespace Common = Prism::Protocol::Common;
} // namespace

TEST(CommonAddress, RejectsEmptyIpv4Segments)
{
    std::array<std::uint8_t, 4> Bytes{};
    EXPECT_FALSE(Common::ParseIpv4Text(".1.2.3", Bytes));
    EXPECT_FALSE(Common::ParseIpv4Text("1..2.3", Bytes));
    EXPECT_FALSE(Common::ParseIpv4Text("1.2.3.", Bytes));
}
