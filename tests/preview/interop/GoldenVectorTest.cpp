/**
 * @file GoldenVectorTest.cpp
 * @brief 协议 golden vector 验证（RFC 示例 + VLESS 固定帧）
 * @details 用确定性字节序列验证 preview 解析器与标准的兼容性：
 *          - SOCKS5 RFC 1928 示例帧（握手/CONNECT/响应）
 *          - VLESS 固定帧（version 0x00 + uuid + cmd + addr）
 *          - SOCKS5/VLESS 数据报 build→parse roundtrip
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

#include <common/protocols/socks5/codec.hpp>
#include <common/protocols/socks5/types.hpp>
#include <common/protocols/trojan/codec.hpp>
#include <common/protocols/trojan/types.hpp>
#include <common/protocols/vless/codec.hpp>
#include <common/protocols/vless/types.hpp>
#include <common/protocols/vmess/codec.hpp>
#include <common/protocols/vmess/types.hpp>
#include <common/protocols/shadowsocks2022/codec.hpp>
#include <common/protocols/shadowsocks2022/types.hpp>

namespace
{
    using namespace preview;

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

    // VLESS TCP 请求：version=0x00, uuid=01..10, addnl=0, cmd=tcp, port=443, domain=example.com
    inline const std::vector<std::uint8_t> vless_tcp_request = {
        0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x00, 0x01, 0x01, 0xBB, 0x02, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
}

TEST(GoldenVector, Socks5GreetingParse)
{
    // SOCKS5 握手帧：05 01 00 → parse_greeting 真实解析
    socks5::greeting g;
    std::size_t consumed = 0;
    const auto err = socks5::parse_greeting(
        std::span<const std::uint8_t>(socks5_greeting), g, consumed);
    ASSERT_EQ(err, error::none);
    EXPECT_EQ(g.ver, 5);
    EXPECT_EQ(consumed, socks5_greeting.size());
    ASSERT_EQ(g.methods.size(), 1u);
    EXPECT_EQ(g.methods[0], static_cast<std::uint8_t>(socks5::auth_method::no_auth));
}

TEST(GoldenVector, Socks5ConnectReqParse)
{
    std::size_t consumed = 0;
    socks5::request req;
    const auto err = socks5::parse_request(
        std::span<const std::uint8_t>(socks5_connect_req), req, consumed);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(req.cmd, socks5::command::connect);
    EXPECT_EQ(req.target.type, socks5::address_type::ipv4);
    EXPECT_EQ(req.target.host, "127.0.0.1");
    EXPECT_EQ(req.target.port, 80u);
}

TEST(GoldenVector, Socks5ConnectDomainParse)
{
    std::size_t consumed = 0;
    socks5::request req;
    const auto err = socks5::parse_request(
        std::span<const std::uint8_t>(socks5_connect_domain), req, consumed);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(req.cmd, socks5::command::connect);
    EXPECT_EQ(req.target.type, socks5::address_type::domain);
    EXPECT_EQ(req.target.host, "example.com");
    EXPECT_EQ(req.target.port, 443u);
}

TEST(GoldenVector, Socks5SuccessReplyBuild)
{
    socks5::reply rep;
    rep.ver = socks5::version;
    rep.code = socks5::reply_code::success;
    rep.bind.type = socks5::address_type::ipv4;
    rep.bind.host = "0.0.0.0";
    rep.bind.port = 0;
    const auto wire = socks5::build_reply(rep);
    ASSERT_FALSE(wire.empty());
    EXPECT_EQ(wire[0], 0x05);
    EXPECT_EQ(wire[1], 0x00);
}

TEST(GoldenVector, Socks5ConnectRoundtrip)
{
    // build request → parse request
    socks5::request req;
    req.cmd = socks5::command::connect;
    req.target.type = socks5::address_type::domain;
    req.target.host = "example.com";
    req.target.port = 443;
    const auto wire = socks5::build_request(req);
    ASSERT_FALSE(wire.empty());
    std::size_t consumed = 0;
    socks5::request parsed;
    const auto err = socks5::parse_request(
        std::span<const std::uint8_t>(wire), parsed, consumed);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(parsed.cmd, socks5::command::connect);
    EXPECT_EQ(parsed.target.host, "example.com");
    EXPECT_EQ(parsed.target.port, 443u);
}

TEST(GoldenVector, DomainTooLongFailsClosed)
{
    socks5::address addr{socks5::address_type::domain, std::string(300, 'a'), 443};
    const auto wire = socks5::encode_address(addr);
    // ATYP(1) + 空域名长度字节(1) + PORT(2) —— 不允许出现 300 字节载荷
    ASSERT_EQ(wire.size(), 4u);
    EXPECT_EQ(wire[1], 0x00);
}

TEST(GoldenVector, VlessTcpRequestParse)
{
    std::size_t consumed = 0;
    vless::request_header hdr;
    const auto err = vless::parse_request(
        std::span<const std::uint8_t>(vless_tcp_request), hdr, consumed);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(hdr.version, 0x00);
    EXPECT_EQ(hdr.cmd, vless::command::tcp);
    EXPECT_EQ(hdr.target.host, "example.com");
    EXPECT_EQ(hdr.target.port, 443u);
}

TEST(GoldenVector, VlessTcpRoundtrip)
{
    vless::request_header hdr;
    hdr.version = vless::protocol_version;
    std::array<std::uint8_t, vless::uuid_len> uuid = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    hdr.uuid = uuid;
    hdr.cmd = vless::command::tcp;
    hdr.target.type = vless::address_type::domain;
    hdr.target.host = "example.com";
    hdr.target.port = 443;
    const auto wire = vless::build_request(hdr);
    ASSERT_FALSE(wire.empty());
    std::size_t consumed = 0;
    vless::request_header parsed;
    const auto err = vless::parse_request(
        std::span<const std::uint8_t>(wire), parsed, consumed);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(parsed.target.host, "example.com");
    EXPECT_EQ(parsed.target.port, 443u);
    EXPECT_EQ(parsed.uuid, uuid);
}

TEST(GoldenVector, Socks5UdpDatagramRoundtrip)
{
    socks5::address target;
    target.type = socks5::address_type::ipv4;
    target.host = "8.8.8.8";
    target.port = 53;
    std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto wire = socks5::build_udp_datagram(
        target, std::span<const std::uint8_t>(payload));
    ASSERT_FALSE(wire.empty());
    socks5::address parsed_target;
    std::span<const std::uint8_t> parsed_payload;
    const auto err = socks5::parse_udp_datagram(
        std::span<const std::uint8_t>(wire), parsed_target, parsed_payload);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(parsed_target.host, "8.8.8.8");
    EXPECT_EQ(parsed_target.port, 53u);
    ASSERT_EQ(parsed_payload.size(), payload.size());
    EXPECT_TRUE(std::equal(parsed_payload.begin(), parsed_payload.end(), payload.begin()));
}

TEST(GoldenVector, VlessUdpPacketRoundtrip)
{
    vless::address target;
    target.type = vless::address_type::domain;
    target.host = "example.com";
    target.port = 53;
    std::vector<std::uint8_t> payload = {0xCA, 0xFE};
    const auto wire = vless::build_udp_pkt(
        target, std::span<const std::uint8_t>(payload));
    ASSERT_FALSE(wire.empty());
    vless::address parsed_target;
    std::span<const std::uint8_t> parsed_payload;
    const auto err = vless::parse_udp_pkt(
        std::span<const std::uint8_t>(wire), parsed_target, parsed_payload);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(parsed_target.host, "example.com");
    EXPECT_EQ(parsed_target.port, 53u);
    ASSERT_EQ(parsed_payload.size(), payload.size());
    EXPECT_TRUE(std::equal(parsed_payload.begin(), parsed_payload.end(), payload.begin()));
}

TEST(GoldenVector, TrojanConnectRoundtrip)
{
    const auto cred = trojan::credential("secret");
    trojan::address target{trojan::address_type::domain, "example.com", 443};
    const auto wire = trojan::build_request(cred, trojan::command::connect, target);
    ASSERT_FALSE(wire.empty());
    trojan::request_header parsed;
    std::size_t consumed = 0;
    const auto err = trojan::parse_request(std::span<const std::uint8_t>(wire), parsed, consumed);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(parsed.cmd, trojan::command::connect);
    EXPECT_EQ(parsed.target.host, "example.com");
    EXPECT_EQ(parsed.target.port, 443u);
}

TEST(GoldenVector, TrojanUdpPacketRoundtrip)
{
    trojan::address target{trojan::address_type::ipv4, "8.8.8.8", 53};
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    const auto wire = trojan::build_udp_pkt(target, std::span<const std::uint8_t>(payload));
    ASSERT_FALSE(wire.empty());
    trojan::address parsed_target;
    std::span<const std::uint8_t> parsed_payload;
    const auto err = trojan::parse_udp_pkt(std::span<const std::uint8_t>(wire), parsed_target, parsed_payload);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(parsed_target.host, "8.8.8.8");
    EXPECT_EQ(parsed_target.port, 53u);
    ASSERT_EQ(parsed_payload.size(), payload.size());
    EXPECT_TRUE(std::equal(parsed_payload.begin(), parsed_payload.end(), payload.begin()));
}

TEST(GoldenVector, TrojanCredentialLength)
{
    const auto cred = trojan::credential("secret");
    EXPECT_EQ(cred.size(), trojan::credential_len);
    // hex length 56, all hex chars
    for (char c : cred) { EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); }
}

TEST(GoldenVector, VmessRequestHeaderRoundtrip)
{
    vmess::request_header hdr;
    hdr.version = vmess::protocol_version;
    hdr.cmd = vmess::command::tcp;
    hdr.target.type = vmess::address_type::domain;
    hdr.target.host = "example.com";
    hdr.target.port = 443;
    std::array<std::uint8_t, 16> iv{}, key{};
    for (size_t i=0;i<16;++i){ iv[i]=static_cast<uint8_t>(i); key[i]=static_cast<uint8_t>(i+16); }
    const auto wire = vmess::build_request_header(hdr, vmess::request_meta{iv, key, 0x5A, 0});
    ASSERT_FALSE(wire.empty());
    vmess::request_header parsed;
    vmess::request_meta_out meta;
    const auto err = vmess::parse_request_header(std::span<const std::uint8_t>(wire), parsed, meta);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(parsed.target.host, "example.com");
    EXPECT_EQ(parsed.target.port, 443u);
    EXPECT_EQ(parsed.cmd, vmess::command::tcp);
}

TEST(GoldenVector, VmessChunkRoundtrip)
{
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> nonce{};
    for (size_t i=0;i<16;++i) key[i]=static_cast<uint8_t>(i);
    for (size_t i=0;i<12;++i) nonce[i]=static_cast<uint8_t>(i+1);
    vmess::chunk_encryptor enc{std::span<const std::uint8_t,16>(key), std::span<const std::uint8_t,12>(nonce)};
    vmess::chunk_decryptor dec{std::span<const std::uint8_t,16>(key), std::span<const std::uint8_t,12>(nonce)};
    const std::vector<std::uint8_t> plain = {0x01,0x02,0x03,0x04};
    std::vector<std::uint8_t> enc_buf(plain.size() + vmess::chunk_encryptor::overhead);
    const auto n = enc.seal(plain, enc_buf);
    ASSERT_GT(n, 0u);
    std::vector<std::uint8_t> dec_buf(n);
    std::size_t consumed=0;
    const auto err = dec.open(std::span<const std::uint8_t>(enc_buf.data(), n), dec_buf, consumed);
    EXPECT_EQ(err, error::none);
    EXPECT_EQ(consumed, n);
    // open() 写入定长 span（不 resize），比对解密出的明文内容
    ASSERT_GE(dec_buf.size(), plain.size());
    EXPECT_EQ(std::memcmp(dec_buf.data(), plain.data(), plain.size()), 0);
}

TEST(GoldenVector, SS2022FixedHeaderRoundtrip)
{
    const auto wire = shadowsocks2022::build_fixed_header(
        shadowsocks2022::header_type_client, 1700000000ULL, 32u);
    ASSERT_EQ(wire.size(), 11u);
    shadowsocks2022::fixed_header h{};
    EXPECT_EQ(shadowsocks2022::parse_fixed_header(wire, h), error::none);
    EXPECT_EQ(h.type, shadowsocks2022::header_type_client);
    EXPECT_EQ(h.time_sec, 1700000000ULL);
    EXPECT_EQ(h.var_len, 32u);
}

TEST(GoldenVector, SS2022AddressRoundtrip)
{
    const shadowsocks2022::address target{
        shadowsocks2022::address_type::domain, "example.com", 443};
    const auto wire = shadowsocks2022::encode_address(target);
    ASSERT_FALSE(wire.empty());
    shadowsocks2022::address parsed;
    std::size_t off = 0;
    EXPECT_EQ(shadowsocks2022::parse_address(wire, parsed, off), error::none);
    EXPECT_EQ(parsed.type, shadowsocks2022::address_type::domain);
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.port, 443u);
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
    const auto key = shadowsocks2022::session_key(psk, salt, 16);
    const shadowsocks2022::address dst{shadowsocks2022::address_type::ipv4, "8.8.8.8", 53};
    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto packet = shadowsocks2022::build_udp_packet(
        {key, 1, &dst, payload});
    ASSERT_FALSE(packet.empty());
    shadowsocks2022::address parsed_dst;
    std::vector<std::uint8_t> parsed;
    EXPECT_EQ(shadowsocks2022::parse_udp_packet({key, packet, &parsed_dst, &parsed}),
              error::none);
    EXPECT_EQ(parsed_dst.type, shadowsocks2022::address_type::ipv4);
    EXPECT_EQ(parsed_dst.host, "8.8.8.8");
    EXPECT_EQ(parsed_dst.port, 53u);
    ASSERT_EQ(parsed.size(), payload.size());
    EXPECT_TRUE(std::equal(parsed.begin(), parsed.end(), payload.begin()));
}
