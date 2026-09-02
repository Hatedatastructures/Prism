/**
 * @file GoldenVectorTest.cpp
 * @brief 协议 golden vector 验证（RFC 示例 + VLESS 固定帧）
 * @details 用确定性字节序列验证 Preview 解析器与标准的兼容性：
 *          - SOCKS5 RFC 1928 示例帧（握手/CONNECT/响应）
 *          - VLESS 固定帧（version 0x00 + uuid + cmd + addr）
 *          - SOCKS5/VLESS 数据报 Build→Parse roundtrip
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Socks5/Types.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Trojan/Types.hpp>
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Protocols/Vless/Types.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>
#include <preview/Protocols/Vmess/Types.hpp>
#include <preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <preview/Protocols/Shadowsocks2022/Types.hpp>

namespace
{
    using namespace Preview;

    // ===== SOCKS5 RFC 1928 Golden Vectors =====

    // 客户端握手：05 01 00
    inline constexpr std::array<std::uint8_t, 3> socks5_greeting = {
        0x05, 0x01, 0x00};

    // CONNECT 请求（目标 127.0.0.1:80）：05 01 00 01 7f000001 0050
    inline constexpr std::array<std::uint8_t, 10> socks5_connect_req = {
        0x05, 0x01, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x00, 0x50};

    // CONNECT 请求（域名 example.com:443）：05 01 00 03 0b example.com 01BB
    inline constexpr std::array<std::uint8_t, 4 + 1 + 11 + 2> socks5_connect_domain = {
        0x05, 0x01, 0x00, 0x03,
        0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x01, 0xBB};

    // ===== VLESS Golden Vectors =====

    // VLESS TCP 请求：version=0x00, uuid=01..10, addnl=0, cmd=Tcp, port=443, domain=example.com
    inline const std::vector<std::uint8_t> vless_tcp_request = {
        0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x00, 0x01, 0x01, 0xBB, 0x02, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
}

TEST(GoldenVector, Socks5GreetingParse)
{
    // SOCKS5 握手帧：05 01 00 → ParseGreeting 真实解析
    Socks5::Greeting g;
    std::size_t consumed = 0;
    const auto err = Socks5::ParseGreeting(
        std::span<const std::uint8_t>(socks5_greeting), g, consumed);
    ASSERT_EQ(err, Error::None);
    EXPECT_EQ(g.Ver, 5);
    EXPECT_EQ(consumed, socks5_greeting.size());
    ASSERT_EQ(g.Methods.size(), 1u);
    EXPECT_EQ(g.Methods[0], static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth));
}

TEST(GoldenVector, Socks5ConnectReqParse)
{
    std::size_t consumed = 0;
    Socks5::Request req;
    const auto err = Socks5::ParseRequest(
        std::span<const std::uint8_t>(socks5_connect_req), req, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(req.Cmd, Socks5::Command::Connect);
    EXPECT_EQ(req.Target.Type, Socks5::AddressType::Ipv4);
    EXPECT_EQ(req.Target.Host, "127.0.0.1");
    EXPECT_EQ(req.Target.Port, 80u);
}

TEST(GoldenVector, Socks5ConnectDomainParse)
{
    std::size_t consumed = 0;
    Socks5::Request req;
    const auto err = Socks5::ParseRequest(
        std::span<const std::uint8_t>(socks5_connect_domain), req, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(req.Cmd, Socks5::Command::Connect);
    EXPECT_EQ(req.Target.Type, Socks5::AddressType::Domain);
    EXPECT_EQ(req.Target.Host, "example.com");
    EXPECT_EQ(req.Target.Port, 443u);
}

TEST(GoldenVector, Socks5SuccessReplyBuild)
{
    Socks5::Reply rep;
    rep.Ver = Socks5::Version;
    rep.Code = Socks5::ReplyCode::Success;
    rep.Bind.Type = Socks5::AddressType::Ipv4;
    rep.Bind.Host = "0.0.0.0";
    rep.Bind.Port = 0;
    const auto wire = Socks5::BuildReply(rep);
    ASSERT_FALSE(wire.empty());
    EXPECT_EQ(wire[0], 0x05);
    EXPECT_EQ(wire[1], 0x00);
}

TEST(GoldenVector, Socks5ConnectRoundtrip)
{
    // Build Request → Parse Request
    Socks5::Request req;
    req.Cmd = Socks5::Command::Connect;
    req.Target.Type = Socks5::AddressType::Domain;
    req.Target.Host = "example.com";
    req.Target.Port = 443;
    const auto wire = Socks5::BuildRequest(req);
    ASSERT_FALSE(wire.empty());
    std::size_t consumed = 0;
    Socks5::Request Parsed;
    const auto err = Socks5::ParseRequest(
        std::span<const std::uint8_t>(wire), Parsed, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(Parsed.Cmd, Socks5::Command::Connect);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
}

TEST(GoldenVector, DomainTooLongFailsClosed)
{
    Socks5::Address addr{Socks5::AddressType::Domain, std::string(300, 'a'), 443};
    const auto wire = Socks5::EncodeAddress(addr);
    // ATYP(1) + 空域名长度字节(1) + PORT(2) —— 不允许出现 300 字节载荷
    ASSERT_EQ(wire.size(), 4u);
    EXPECT_EQ(wire[1], 0x00);
}

TEST(GoldenVector, VlessTcpRequestParse)
{
    std::size_t consumed = 0;
    Vless::RequestHeader hdr;
    const auto err = Vless::ParseRequest(
        std::span<const std::uint8_t>(vless_tcp_request), hdr, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(hdr.Version, 0x00);
    EXPECT_EQ(hdr.Cmd, Vless::Command::Tcp);
    EXPECT_EQ(hdr.Target.Host, "example.com");
    EXPECT_EQ(hdr.Target.Port, 443u);
}

TEST(GoldenVector, VlessTcpRoundtrip)
{
    Vless::RequestHeader hdr;
    hdr.Version = Vless::ProtocolVersion;
    std::array<std::uint8_t, Vless::UuidLen> uuid = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    hdr.Uuid = uuid;
    hdr.Cmd = Vless::Command::Tcp;
    hdr.Target.Type = Vless::AddressType::Domain;
    hdr.Target.Host = "example.com";
    hdr.Target.Port = 443;
    const auto wire = Vless::BuildRequest(hdr);
    ASSERT_FALSE(wire.empty());
    std::size_t consumed = 0;
    Vless::RequestHeader Parsed;
    const auto err = Vless::ParseRequest(
        std::span<const std::uint8_t>(wire), Parsed, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
    EXPECT_EQ(Parsed.Uuid, uuid);
}

TEST(GoldenVector, Socks5UdpDatagramRoundtrip)
{
    Socks5::Address Target;
    Target.Type = Socks5::AddressType::Ipv4;
    Target.Host = "8.8.8.8";
    Target.Port = 53;
    std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto wire = Socks5::BuildUdpDatagram(
        Target, std::span<const std::uint8_t>(payload));
    ASSERT_FALSE(wire.empty());
    Socks5::Address parsed_target;
    std::span<const std::uint8_t> parsed_payload;
    const auto err = Socks5::ParseUdpDatagram(
        std::span<const std::uint8_t>(wire), parsed_target, parsed_payload);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(parsed_target.Host, "8.8.8.8");
    EXPECT_EQ(parsed_target.Port, 53u);
    ASSERT_EQ(parsed_payload.size(), payload.size());
    EXPECT_TRUE(std::equal(parsed_payload.begin(), parsed_payload.end(), payload.begin()));
}

TEST(GoldenVector, VlessUdpPacketRoundtrip)
{
    Vless::Address Target;
    Target.Type = Vless::AddressType::Domain;
    Target.Host = "example.com";
    Target.Port = 53;
    std::vector<std::uint8_t> payload = {0xCA, 0xFE};
    const auto wire = Vless::BuildUdpPkt(
        Target, std::span<const std::uint8_t>(payload));
    ASSERT_FALSE(wire.empty());
    Vless::Address parsed_target;
    std::span<const std::uint8_t> parsed_payload;
    const auto err = Vless::ParseUdpPkt(
        std::span<const std::uint8_t>(wire), parsed_target, parsed_payload);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(parsed_target.Host, "example.com");
    EXPECT_EQ(parsed_target.Port, 53u);
    ASSERT_EQ(parsed_payload.size(), payload.size());
    EXPECT_TRUE(std::equal(parsed_payload.begin(), parsed_payload.end(), payload.begin()));
}

TEST(GoldenVector, TrojanConnectRoundtrip)
{
    const auto cred = Trojan::Credential("Secret");
    Trojan::Address Target{Trojan::AddressType::Domain, "example.com", 443};
    const auto wire = Trojan::BuildRequest(cred, Trojan::Command::Connect, Target);
    ASSERT_FALSE(wire.empty());
    Trojan::RequestHeader Parsed;
    std::size_t consumed = 0;
    const auto err = Trojan::ParseRequest(std::span<const std::uint8_t>(wire), Parsed, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(Parsed.Cmd, Trojan::Command::Connect);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
}

TEST(GoldenVector, TrojanUdpPacketRoundtrip)
{
    Trojan::Address Target{Trojan::AddressType::Ipv4, "8.8.8.8", 53};
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    const auto wire = Trojan::BuildUdpPkt(Target, std::span<const std::uint8_t>(payload));
    ASSERT_FALSE(wire.empty());
    Trojan::Address parsed_target;
    std::span<const std::uint8_t> parsed_payload;
    const auto err = Trojan::ParseUdpPkt(std::span<const std::uint8_t>(wire), parsed_target, parsed_payload);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(parsed_target.Host, "8.8.8.8");
    EXPECT_EQ(parsed_target.Port, 53u);
    ASSERT_EQ(parsed_payload.size(), payload.size());
    EXPECT_TRUE(std::equal(parsed_payload.begin(), parsed_payload.end(), payload.begin()));
}

TEST(GoldenVector, TrojanCredentialLength)
{
    const auto cred = Trojan::Credential("Secret");
    EXPECT_EQ(cred.size(), Trojan::CredentialLen);
    // hex length 56, All hex chars
    for (char c : cred) { EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); }
}

TEST(GoldenVector, VmessRequestHeaderRoundtrip)
{
    Vmess::RequestHeader hdr;
    hdr.Version = Vmess::ProtocolVersion;
    hdr.Cmd = static_cast<std::uint8_t>(static_cast<std::uint8_t>(Vmess::Command::Tcp));
    hdr.Target.Type = Vmess::AddressType::Domain;
    hdr.Target.Host = "example.com";
    hdr.Target.Port = 443;
    std::array<std::uint8_t, 16> iv{}, key{};
    for (size_t i=0;i<16;++i){ iv[i]=static_cast<uint8_t>(i); key[i]=static_cast<uint8_t>(i+16); }
    const auto wire = Vmess::BuildRequestHeader(hdr, Vmess::RequestMeta{iv, key, 0x5A, 0});
    ASSERT_FALSE(wire.empty());
    Vmess::RequestHeader Parsed;
    Vmess::RequestMetaOut meta;
    const auto err = Vmess::ParseRequestHeader(std::span<const std::uint8_t>(wire), Parsed, meta);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
    EXPECT_EQ(Parsed.Cmd, static_cast<std::uint8_t>(Vmess::Command::Tcp));
}

TEST(GoldenVector, VmessChunkRoundtrip)
{
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> Nonce{};
    for (size_t i=0;i<16;++i) key[i]=static_cast<uint8_t>(i);
    for (size_t i=0;i<12;++i) Nonce[i]=static_cast<uint8_t>(i+1);
    Vmess::ChunkEncryptor enc{std::span<const std::uint8_t,16>(key), std::span<const std::uint8_t,12>(Nonce)};
    Vmess::ChunkDecryptor dec{std::span<const std::uint8_t,16>(key), std::span<const std::uint8_t,12>(Nonce)};
    const std::vector<std::uint8_t> plain = {0x01,0x02,0x03,0x04};
    std::vector<std::uint8_t> enc_buf(plain.size() + Vmess::ChunkEncryptor::Overhead);
    const auto n = enc.Seal(plain, enc_buf);
    ASSERT_GT(n, 0u);
    std::vector<std::uint8_t> dec_buf(n);
    std::size_t consumed=0;
    const auto err = dec.Open(std::span<const std::uint8_t>(enc_buf.data(), n), dec_buf, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(consumed, n);
    // Open() 写入定长 span（不 resize），比对解密出的明文内容
    ASSERT_GE(dec_buf.size(), plain.size());
    EXPECT_EQ(std::memcmp(dec_buf.data(), plain.data(), plain.size()), 0);
}

TEST(GoldenVector, SS2022FixedHeaderRoundtrip)
{
    const auto wire = Shadowsocks2022::ParseFixedHeader(
        Shadowsocks2022::HeaderTypeClient, 1700000000ULL, 32u);
    ASSERT_EQ(wire.size(), 11u);
    Shadowsocks2022::FixedHeader h{};
    EXPECT_EQ(Shadowsocks2022::ParseFixedHeader(wire, h), Error::None);
    EXPECT_EQ(h.Type, Shadowsocks2022::HeaderTypeClient);
    EXPECT_EQ(h.TimeSec, 1700000000ULL);
    EXPECT_EQ(h.VarLen, 32u);
}

TEST(GoldenVector, SS2022AddressRoundtrip)
{
    const Shadowsocks2022::Address Target{
        Shadowsocks2022::AddressType::Domain, "example.com", 443};
    const auto wire = Shadowsocks2022::EncodeAddress(Target);
    ASSERT_FALSE(wire.empty());
    Shadowsocks2022::Address Parsed;
    std::size_t off = 0;
    EXPECT_EQ(Shadowsocks2022::ParseAddress(wire, Parsed, off), Error::None);
    EXPECT_EQ(Parsed.Type, Shadowsocks2022::AddressType::Domain);
    EXPECT_EQ(Parsed.Host, "example.com");
    EXPECT_EQ(Parsed.Port, 443u);
    EXPECT_EQ(off, wire.size());
}

TEST(GoldenVector, SS2022UdpPacketRoundtrip)
{
    const std::array<std::uint8_t, 16> psk = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const std::array<std::uint8_t, 16> salt = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
    const auto key = Shadowsocks2022::SessionKey(psk, salt, 16);
    const Shadowsocks2022::Address dst{Shadowsocks2022::AddressType::Ipv4, "8.8.8.8", 53};
    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto packet = Shadowsocks2022::BuildUdpPacket(
        {key, 1, &dst, payload});
    ASSERT_FALSE(packet.empty());
    Shadowsocks2022::Address parsed_dst;
    std::vector<std::uint8_t> Parsed;
    EXPECT_EQ(Shadowsocks2022::ParseUdpPacket({key, packet, &parsed_dst, &Parsed}),
              Error::None);
    EXPECT_EQ(parsed_dst.Type, Shadowsocks2022::AddressType::Ipv4);
    EXPECT_EQ(parsed_dst.Host, "8.8.8.8");
    EXPECT_EQ(parsed_dst.Port, 53u);
    ASSERT_EQ(Parsed.size(), payload.size());
    EXPECT_TRUE(std::equal(Parsed.begin(), Parsed.end(), payload.begin()));
}
