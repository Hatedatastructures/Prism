/** @file DnsTransportWireTest.cpp @brief DNS TCP frame wire 边界测试。 */

#include <Prism/Net/Dns/Detail/Wire.hpp>

#include <boost/system/errc.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

TEST(DnsTransport, RejectsOversizedTcpFrameBeforeLengthEncoding)
{
    const std::vector<std::uint8_t> Maximum(Prism::Network::Dns::Detail::MaxFrameBytes, 0xA5);
    const std::vector<std::uint8_t> Oversized(Prism::Network::Dns::Detail::MaxFrameBytes + 1, 0xA5);

    const auto MaxFrame = Prism::Network::Dns::Detail::MakeTcpFrame(Maximum);
    ASSERT_TRUE(MaxFrame.has_value());
    EXPECT_EQ(MaxFrame->size(), Maximum.size() + 2);

    const auto OversizedFrame = Prism::Network::Dns::Detail::MakeTcpFrame(Oversized);
    ASSERT_FALSE(OversizedFrame.has_value());
    EXPECT_EQ(OversizedFrame.error(),
              boost::system::errc::make_error_code(boost::system::errc::message_size));
}
