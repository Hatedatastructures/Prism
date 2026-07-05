/**
 * @file Smux.cpp
 * @brief smux 帧协议单元测试
 * @details 测试 smux 多路复用协议的帧编解码功能：
 * 帧头反序列化、地址解析、UDP 数据报编解码、length-prefixed 编解码等。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/proto/multiplex/parcel.hpp>
#include <prism/proto/multiplex/smux/frame.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstring>

using namespace psm::multiplex::smux;

// ---------- helpers ----------

/**
 * @brief 构造 8 字节 smux 帧头（小端序）
 */
[[nodiscard]] static std::array<std::byte, 8> make_header(std::uint8_t version, command cmd,
                                                   std::uint16_t length, std::uint32_t stream_id)
{
    std::array<std::byte, 8> buf{};
    buf[0] = static_cast<std::byte>(version);
    buf[1] = static_cast<std::byte>(cmd);
    buf[2] = static_cast<std::byte>(length & 0xFF);
    buf[3] = static_cast<std::byte>((length >> 8) & 0xFF);
    buf[4] = static_cast<std::byte>(stream_id & 0xFF);
    buf[5] = static_cast<std::byte>((stream_id >> 8) & 0xFF);
    buf[6] = static_cast<std::byte>((stream_id >> 16) & 0xFF);
    buf[7] = static_cast<std::byte>((stream_id >> 24) & 0xFF);
    return buf;
}

// ---------- deserialization ----------

/**
 * @brief 测试合法 SYN 帧反序列化
 */
TEST(Smux, DeserializeSyn)
{
    auto buf = make_header(0x01, command::syn, 0, 42);
    auto result = deserialization(buf);
    ASSERT_TRUE(result.has_value()) << "SYN deserialization returned nullopt";
    EXPECT_TRUE(result->cmd == command::syn) << "SYN cmd mismatch";
    EXPECT_TRUE(result->length == 0) << "SYN length mismatch";
    EXPECT_TRUE(result->stream_id == 42) << "SYN stream_id mismatch";
}

/**
 * @brief 测试合法 FIN 帧反序列化
 */
TEST(Smux, DeserializeFin)
{
    auto buf = make_header(0x01, command::fin, 100, 7);
    auto result = deserialization(buf);
    ASSERT_TRUE(result.has_value()) << "FIN deserialization returned nullopt";
    EXPECT_TRUE(result->cmd == command::fin) << "FIN cmd mismatch";
    EXPECT_TRUE(result->length == 100) << "FIN length mismatch";
    EXPECT_TRUE(result->stream_id == 7) << "FIN stream_id mismatch";
}

/**
 * @brief 测试合法 PSH 帧反序列化
 */
TEST(Smux, DeserializePush)
{
    auto buf = make_header(0x01, command::push, 65535, 0x12345678);
    auto result = deserialization(buf);
    ASSERT_TRUE(result.has_value()) << "PSH deserialization returned nullopt";
    EXPECT_TRUE(result->cmd == command::push) << "PSH cmd mismatch";
    EXPECT_TRUE(result->length == 65535) << "PSH length mismatch";
    EXPECT_TRUE(result->stream_id == 0x12345678) << "PSH stream_id mismatch";
}

/**
 * @brief 测试合法 NOP 帧反序列化
 */
TEST(Smux, DeserializeNop)
{
    auto buf = make_header(0x01, command::nop, 0, 0);
    auto result = deserialization(buf);
    ASSERT_TRUE(result.has_value()) << "NOP deserialization returned nullopt";
    EXPECT_TRUE(result->cmd == command::nop) << "NOP cmd mismatch";
    EXPECT_TRUE(result->stream_id == 0) << "NOP stream_id mismatch";
}

/**
 * @brief 测试数据不足（< 8 字节）
 */
TEST(Smux, DeserializeTruncated)
{
    std::array<std::byte, 4> short_buf{};
    auto result = deserialization(short_buf);
    EXPECT_TRUE(!result.has_value()) << "truncated data should return nullopt";
}

/**
 * @brief 测试非法版本号
 */
TEST(Smux, DeserializeBadVersion)
{
    auto buf = make_header(0x02, command::syn, 0, 1);
    auto result = deserialization(buf);
    EXPECT_TRUE(!result.has_value()) << "bad version should return nullopt";
}

/**
 * @brief 测试非法命令
 */
TEST(Smux, DeserializeBadCommand)
{
    auto buf = make_header(0x01, static_cast<command>(0xFF), 0, 1);
    auto result = deserialization(buf);
    EXPECT_TRUE(!result.has_value()) << "bad command should return nullopt";
}

/**
 * @brief 测试小端字节序
 */
TEST(Smux, DeserializeEndianness)
{
    std::array<std::byte, 8> buf{};
    buf[0] = std::byte{0x01}; // version
    buf[1] = std::byte{0x02}; // push
    buf[2] = std::byte{0x06}; // length low
    buf[3] = std::byte{0x05}; // length high
    buf[4] = std::byte{0x04}; // stream_id byte 0
    buf[5] = std::byte{0x03}; // stream_id byte 1
    buf[6] = std::byte{0x02}; // stream_id byte 2
    buf[7] = std::byte{0x01}; // stream_id byte 3

    auto result = deserialization(buf);
    ASSERT_TRUE(result.has_value()) << "endianness test deserialization failed";
    EXPECT_TRUE(result->length == 0x0506) << "endianness length mismatch";
    EXPECT_TRUE(result->stream_id == 0x01020304) << "endianness stream_id mismatch";
}

// ---------- parse_address ----------

/**
 * @brief 测试 IPv4 地址解析
 */
TEST(Smux, ParseAddressIPv4)
{
    psm::memory::vector<std::byte> buf;
    buf.push_back(std::byte{0x00}); // flags high
    buf.push_back(std::byte{0x01}); // flags low: is_udp=true, packet_addr=false
    buf.push_back(std::byte{0x01}); // ATYP IPv4
    buf.push_back(std::byte{127});  // 127
    buf.push_back(std::byte{0});    // 0
    buf.push_back(std::byte{0});    // 0
    buf.push_back(std::byte{1});    // 1  -> 127.0.0.1
    buf.push_back(std::byte{0x1F}); // port high
    buf.push_back(std::byte{0x90}); // port low -> 8080

    auto result = parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(result.has_value()) << "IPv4 address parse returned nullopt";
    EXPECT_TRUE(result->host == "127.0.0.1") << "IPv4 host mismatch: " << result->host;
    EXPECT_TRUE(result->port == 8080) << "IPv4 port mismatch";
    EXPECT_TRUE(result->is_udp) << "is_udp should be true";
    EXPECT_TRUE(result->addr != psm::multiplex::addr_mode::packet_addr) << "packet_addr should be false";
}

/**
 * @brief 测试域名地址解析
 */
TEST(Smux, ParseAddressDomain)
{
    const char *domain = "test.com";
    psm::memory::vector<std::byte> buf;
    buf.push_back(std::byte{0x00}); // flags high
    buf.push_back(std::byte{0x00}); // flags low
    buf.push_back(std::byte{0x03}); // ATYP domain
    buf.push_back(static_cast<std::byte>(std::strlen(domain)));
    for (const char *p = domain; *p; ++p)
    {
        buf.push_back(static_cast<std::byte>(*p));
    }
    buf.push_back(std::byte{0x00}); // port high
    buf.push_back(std::byte{0x50}); // port low -> 80

    auto result = parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(result.has_value()) << "domain address parse returned nullopt";
    EXPECT_TRUE(result->host == "test.com") << "domain host mismatch: " << result->host;
    EXPECT_TRUE(result->port == 80) << "domain port mismatch";
    EXPECT_TRUE(!result->is_udp) << "is_udp should be false";
}

/**
 * @brief 测试 IPv6 地址解析
 */
TEST(Smux, ParseAddressIPv6)
{
    psm::memory::vector<std::byte> buf;
    buf.push_back(std::byte{0x00}); // flags high
    buf.push_back(std::byte{0x03}); // flags low: is_udp=true, packet_addr=true
    buf.push_back(std::byte{0x04}); // ATYP IPv6
    for (int i = 0; i < 15; ++i)
    {
        buf.push_back(std::byte{0});
    }
    buf.push_back(std::byte{1});    // ::1
    buf.push_back(std::byte{0x00}); // port high
    buf.push_back(std::byte{0x50}); // port low -> 80

    auto result = parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(result.has_value()) << "IPv6 address parse returned nullopt";
    EXPECT_TRUE(result->host == "::1") << "IPv6 host mismatch: " << result->host;
    EXPECT_TRUE(result->port == 80) << "IPv6 port mismatch";
    EXPECT_TRUE(result->addr == psm::multiplex::addr_mode::packet_addr) << "packet_addr should be true";
}

/**
 * @brief 测试数据不足的地址解析
 */
TEST(Smux, ParseAddressTruncated)
{
    psm::memory::vector<std::byte> buf;
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01}); // ATYP IPv4 but no address bytes

    auto result = parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!result.has_value()) << "truncated address should return nullopt";
}

/**
 * @brief 测试非法 ATYP
 */
TEST(Smux, ParseAddressBadAtyp)
{
    psm::memory::vector<std::byte> buf;
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0xFF}); // invalid ATYP

    auto result = parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!result.has_value()) << "bad ATYP should return nullopt";
}

// ---------- UDP datagram roundtrip ----------

/**
 * @brief 测试 UDP 数据报编解码往返（IPv4）
 */
TEST(Smux, UdpDatagramRoundtripIPv4)
{
    const std::byte payload[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    auto encoded = build_dgram({"127.0.0.1", 9090, payload}, psm::memory::current_resource());
    auto result = parse_dgram(encoded, psm::memory::current_resource());

    ASSERT_TRUE(result.has_value()) << "UDP datagram parse returned nullopt";
    EXPECT_TRUE(result->host == "127.0.0.1") << "UDP host mismatch: " << result->host;
    EXPECT_TRUE(result->port == 9090) << "UDP port mismatch";
    EXPECT_TRUE(result->payload.size() == 3) << "UDP payload size mismatch";
    EXPECT_TRUE(result->payload[0] == std::byte{0xAA} && result->payload[2] == std::byte{0xCC})
        << "UDP payload content mismatch";
}

/**
 * @brief 测试 UDP 数据报编解码往返（域名）
 */
TEST(Smux, UdpDatagramRoundtripDomain)
{
    const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};
    auto encoded = build_dgram({"example.com", 443, payload}, psm::memory::current_resource());
    auto result = parse_dgram(encoded, psm::memory::current_resource());

    ASSERT_TRUE(result.has_value()) << "UDP datagram domain parse returned nullopt";
    EXPECT_TRUE(result->host == "example.com") << "UDP domain host mismatch: " << result->host;
    EXPECT_TRUE(result->port == 443) << "UDP domain port mismatch";
    EXPECT_TRUE(result->payload.size() == 2) << "UDP domain payload size mismatch";
}

/**
 * @brief 测试空数据的 UDP 解析
 */
TEST(Smux, UdpDatagramEmpty)
{
    psm::memory::vector<std::byte> empty_buf;
    auto result = parse_dgram(empty_buf, psm::memory::current_resource());
    EXPECT_TRUE(!result.has_value()) << "empty UDP datagram should return nullopt";
}

// ---------- length-prefixed roundtrip ----------

/**
 * @brief 测试 length-prefixed 编解码往返
 */
TEST(Smux, UdpLengthPrefixedRoundtrip)
{
    const std::byte payload[] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    auto encoded = build_prefixed(payload, psm::memory::current_resource());
    auto result = parse_prefixed(encoded);

    ASSERT_TRUE(result.has_value()) << "length-prefixed parse returned nullopt";
    EXPECT_TRUE(result->payload.size() == 4) << "length-prefixed payload size mismatch";
    EXPECT_TRUE(result->payload[0] == std::byte{0xDE} || result->payload[3] == std::byte{0xEF})
        << "length-prefixed payload content mismatch";
}

/**
 * @brief 测试数据不足的 length-prefixed 解析
 */
TEST(Smux, UdpLengthPrefixedTruncated)
{
    psm::memory::vector<std::byte> short_data;
    short_data.push_back(std::byte{0x00});

    auto result = parse_prefixed(short_data);
    EXPECT_TRUE(!result.has_value()) << "truncated length-prefixed should return nullopt";

    psm::memory::vector<std::byte> mismatch_data;
    mismatch_data.push_back(std::byte{0x00});
    mismatch_data.push_back(std::byte{0x10}); // length = 16
    mismatch_data.push_back(std::byte{0xAA}); // only 1 byte of payload

    auto result2 = parse_prefixed(mismatch_data);
    EXPECT_TRUE(!result2.has_value()) << "length-prefixed with oversized length should return nullopt";
}
