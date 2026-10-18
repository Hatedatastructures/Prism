/**
 * @file VlessCodecDeepTest.cpp
 * @brief VLESS 地址和请求解析边界测试。
 */

#include <boost/asio/buffer.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Vless/Codec.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Vless = Prism::Vless;
    using Prism::As;
    using Prism::AsBytes;
    using Prism::AsBytesSpan;
    using Prism::AsStrView;
    using Prism::AsU8;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::make_error_code;

auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }
} // namespace

TEST(VlessCodecDeep, EncodeAddressBranches)
    {
        Vless::Address Address{};
        // ipv4 编码（点分解析）
        Address.Type = Vless::AddressType::Ipv4;
        Address.Host = "10.0.0.1";
        Address.Port = 1001;
        const auto V4 = Vless::EncodeAddress(Address);
        EXPECT_EQ(V4.size(), 7u);
        EXPECT_EQ(V4[0], 0x01);
        EXPECT_EQ(V4[1], 10u);
        EXPECT_EQ(V4[4], 1u);
        // ipv6 编码
        Address.Type = Vless::AddressType::Ipv6;
        Address.Host.assign(16, 'z');
        const auto V6 = Vless::EncodeAddress(Address);
        EXPECT_EQ(V6.size(), 19u);
        EXPECT_EQ(V6[0], 0x03);
        EXPECT_EQ(V6[1], 'z');
    }

TEST(VlessCodecDeep, BuildRequestIpv6)
    {
        Vless::RequestHeader Header{};
        Header.Uuid.fill(0x11);
        Header.Cmd = Vless::Command::Udp;
        Header.Target.Type = Vless::AddressType::Ipv6;
        Header.Target.Host.assign(16, 'w');
        Header.Target.Port = 53;
        Header.Addons = {0x01, 0x02};
        const auto Wire = Vless::BuildRequest(Header);
        EXPECT_EQ(Wire.size(), 22u + 2u + 16u);
        EXPECT_EQ(Wire[23], 0x03); // ATYP = ipv6
    }

TEST(VlessCodecDeep, BuildRequestRejectsInvalidAddressAndLength)
    {
        Vless::RequestHeader Header{};
        Header.Uuid.fill(0x11);
        Header.Cmd = Vless::Command::Tcp;
        Header.Target.Port = 443;

        Header.Target.Type = Vless::AddressType::Ipv4;
        Header.Target.Host = "999.1.1.1";
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());

        Header.Target.Type = Vless::AddressType::Ipv6;
        Header.Target.Host = "not-an-ipv6";
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());

        Header.Target.Type = static_cast<Vless::AddressType>(0x7F);
        Header.Target.Host = "example.com";
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());

        Header.Target.Type = Vless::AddressType::Domain;
        Header.Target.Host.clear();
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());
        Header.Target.Host.assign(256, 'a');
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());
    }

TEST(VlessCodecDeep, EncodeAddressRejectsInvalidAddress)
    {
        Vless::Address Address;
        Address.Type = Vless::AddressType::Ipv4;
        Address.Host = "300.1.1.1";
        Address.Port = 443;
        EXPECT_TRUE(Vless::EncodeAddress(Address).empty());

        Address.Type = Vless::AddressType::Ipv6;
        Address.Host = "Short";
        EXPECT_TRUE(Vless::EncodeAddress(Address).empty());

        Address.Type = Vless::AddressType::Domain;
        Address.Host.clear();
        EXPECT_TRUE(Vless::EncodeAddress(Address).empty());

        Address.Type = static_cast<Vless::AddressType>(0x7F);
        Address.Host = "example.com";
        const std::array<std::uint8_t, 1> Payload{0x42};
        EXPECT_TRUE(Vless::BuildUdpPkt(Address, Payload).empty());
    }

TEST(VlessCodecDeep, ParseRequestBranches)
    {
        Vless::RequestHeader Header{};
        std::size_t Consumed = 0;
        std::vector<std::uint8_t> Base{0x00};
        Base.insert(Base.end(), 16, 0x11);
        Base.push_back(0x00); // addnl len
        Base.push_back(0x01); // cmd Tcp
        Base.push_back(0x00);
        Base.push_back(0x50); // port 80
        // ipv4 不足
        std::vector<std::uint8_t> V4 = Base;
        V4.push_back(0x01);
        V4.push_back(8);
        V4.push_back(8);
        EXPECT_EQ(Vless::ParseRequest(V4, Header, Consumed), Error::NeedMore);
        // ipv6 不足
        std::vector<std::uint8_t> V6 = Base;
        V6.push_back(0x03);
        V6.insert(V6.end(), 5, 0x42);
        EXPECT_EQ(Vless::ParseRequest(V6, Header, Consumed), Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> V6Ok = Base;
        V6Ok.push_back(0x03);
        V6Ok.insert(V6Ok.end(), 16, 0x42);
        EXPECT_EQ(Vless::ParseRequest(V6Ok, Header, Consumed), Error::None);
        EXPECT_EQ(Header.Target.Type, Vless::AddressType::Ipv6);
        EXPECT_EQ(Header.Target.Host, std::string(16, '\x42'));
        EXPECT_EQ(Header.Target.Port, 80u);
    }

TEST(VlessCodecDeep, ParserErrors)
    {
        std::array<std::uint8_t, 16> Uuid{};
        Uuid.fill(0x11);
        Vless::Parser Parser(Uuid);
        std::error_code ErrorCode;

        // 数据不足
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x00})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        Parser.Reset();
        // 版本错误
        std::vector<std::uint8_t> Bad{0x01};
        Bad.insert(Bad.end(), 16, 0x11);
        Bad.insert(Bad.end(), {0x00, 0x01, 0x00, 0x50, 0x01, 8, 8, 8, 8});
        EXPECT_EQ(Parser.Put(Net::buffer(Bad), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BadMagic));
        Parser.Reset();
        // UUID 不匹配
        std::vector<std::uint8_t> Wrong = Bad;
        Wrong[0] = 0x00;
        Wrong[1] = 0x22;
        EXPECT_EQ(Parser.Put(Net::buffer(Wrong), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::AuthFailed));
        Parser.Reset();
        // 成功（Uuid 匹配 + ipv4）
        std::vector<std::uint8_t> Ok{0x00};
        Ok.insert(Ok.end(), 16, 0x11);
        Ok.push_back(0x00);
        Ok.push_back(0x01);
        Ok.push_back(0x00);
        Ok.push_back(0x50);
        Ok.push_back(0x01);
        Ok.insert(Ok.end(), 4, 8);
        EXPECT_EQ(Parser.Put(Net::buffer(Ok), ErrorCode), Ok.size());
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Get().valid);
        EXPECT_EQ(Parser.Get().cmd, 0x01u);
    }
