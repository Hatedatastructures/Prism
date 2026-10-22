/**
 * @file Ss2022AddressCodecDeep.cpp
 * @brief Shadowsocks 2022 地址编码与解析深度测试
 * @details 覆盖 IPv6、域名、截断输入和未知地址类型分支。
 */
#include <cstdint>
#include <cstddef>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace ss = Prism::Shadowsocks2022;
    using Prism::Error;
    /** @brief 从初始值列表构造字节向量。 */
    auto MakeBytes(std::initializer_list<std::uint8_t> List)
        -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }
    auto RunAddressBranches() -> void
    {
        ss::Address Address{};
        Address.Type = ss::AddressType::Ipv6;
        Address.Host.assign(16, 'q');
        Address.Port = 8080;
        const auto EncodedIpv6 = ss::EncodeAddress(Address);
        EXPECT_EQ(EncodedIpv6.size(), 19u);
        EXPECT_EQ(EncodedIpv6[0], 0x04);
        std::size_t Offset = 0;
        EXPECT_EQ(ss::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x01, 8, 8})), Address, Offset),
                  Error::NeedMore);
        Offset = 0;
        std::vector<std::uint8_t> Ipv6Wire{0x04};
        Ipv6Wire.insert(Ipv6Wire.end(), 5, 0x42);
        EXPECT_EQ(ss::ParseAddress(Ipv6Wire, Address, Offset), Error::NeedMore);
        Offset = 0;
        Ipv6Wire.assign(17, 0);
        Ipv6Wire[0] = 0x04;
        Ipv6Wire.insert(Ipv6Wire.end(), 2, 0);
        EXPECT_EQ(ss::ParseAddress(Ipv6Wire, Address, Offset), Error::None);
        EXPECT_EQ(Address.Host, std::string(16, 0));
        std::span<const std::uint8_t> Payload;
        EXPECT_EQ(ss::ParseVarHeader(std::span<const std::uint8_t>(MakeBytes({0x01, 8, 8})), Address, Payload),
                  Error::NeedMore);
        EXPECT_EQ(ss::ParseVarHeader(std::span<const std::uint8_t>(MakeBytes({0x04, 1})), Address, Payload),
                  Error::NeedMore);
        std::vector<std::uint8_t> Ipv6VarHeader{0x04};
        Ipv6VarHeader.insert(Ipv6VarHeader.end(), 16, 0x42);
        Ipv6VarHeader.push_back(0x00);
        Ipv6VarHeader.push_back(0x50);
        Ipv6VarHeader.push_back(0x00);
        Ipv6VarHeader.push_back(0x00);
        Ipv6VarHeader.push_back('x');
        EXPECT_EQ(ss::ParseVarHeader(Ipv6VarHeader, Address, Payload), Error::None);
        EXPECT_EQ(Address.Type, ss::AddressType::Ipv6);
        EXPECT_EQ(Address.Port, 80u);
        EXPECT_EQ(Payload.size(), 1u);
        std::vector<std::uint8_t> DomainTruncated{0x03, 0x05, 'a'};
        EXPECT_EQ(ss::ParseVarHeader(DomainTruncated, Address, Payload), Error::NeedMore);
        std::vector<std::uint8_t> DomainValid{0x03, 0x03, 'a', 'b', 'c', 0x00, 0x50, 0x00, 0x00};
        EXPECT_EQ(ss::ParseVarHeader(DomainValid, Address, Payload), Error::None);
        EXPECT_EQ(Address.Host, "abc");
    }
    TEST(Ss2022CodecDeep, AddressBranches)
    {
        RunAddressBranches();
    }
    TEST(Ss2022CodecDeep, RejectsUnknownAddressTypeInVarHeader)
    {
        const std::vector<std::uint8_t> Wire{0xFF, 0x00, 0x00, 0x50, 0x00, 0x00};
        ss::Address Target{};
        std::span<const std::uint8_t> Payload;
        EXPECT_EQ(ss::ParseVarHeader(Wire, Target, Payload), Error::BadAddress);
    }
} // namespace
