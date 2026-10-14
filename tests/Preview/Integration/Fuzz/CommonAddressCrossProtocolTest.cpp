/**
 * @file CommonAddressCrossProtocolTest.cpp
 * @brief 跨协议地址构造负例矩阵测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Hysteria2/Codec.hpp>
#include <Preview/Protocols/Shadowsocks2022/RequestCodec.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>

namespace
{
    namespace Hysteria2 = Preview::Hysteria2;
    namespace Protocol = Preview::Protocol;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Tuic = Preview::Tuic;
    using Preview::Error;
} // namespace

TEST(CommonAddress, RejectsInvalidTextWithoutWritingWire)
{
    Socks5::Address Address{Socks5::AddressType::Ipv4, "300.1.1.1", 443};
    std::vector<std::uint8_t> Output{0xCC};

    Protocol::Common::EncodeAddress(Address, Output);
    EXPECT_EQ(Output, std::vector<std::uint8_t>({0xCC}));
    EXPECT_TRUE(Socks5::EncodeAddress(Address).empty());
    EXPECT_TRUE(Socks5::BuildRequest(
                    Socks5::Request{Socks5::Version, Socks5::Command::Connect, 0, Address})
                    .empty());
}

TEST(CommonAddress, RejectsInvalidAddressAcrossProtocolBuilders)
    {
        const Trojan::Address TrojanTarget{Trojan::AddressType::Ipv4, "1..2.3", 443};
        EXPECT_TRUE(Trojan::BuildRequest("credential", Trojan::Command::Connect, TrojanTarget).empty());
        EXPECT_TRUE(Trojan::BuildUdpPkt(TrojanTarget, {}).empty());

        const Hysteria2::Address HysteriaTarget{Hysteria2::AddressType::Ipv6, "not-an-ipv6", 443};
        EXPECT_TRUE(Hysteria2::BuildTcp(HysteriaTarget, {}).empty());

        Tuic::Message TuicMessage{};
        TuicMessage.Cmd = Tuic::CmdConnect;
        TuicMessage.dst = {Tuic::AddressType::Ipv4, "300.1.1.1", 443};
        EXPECT_TRUE(Tuic::Build(TuicMessage).empty());

        const Shadowsocks2022::Address SsTarget{
            Shadowsocks2022::AddressType::Domain, "", 443};
        EXPECT_TRUE(Shadowsocks2022::BuildVarHeader(SsTarget, 0).empty());
    }
