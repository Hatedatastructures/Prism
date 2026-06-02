/**
 * @file SmuxFrameExtra.cpp
 * @brief smux 帧协议补充测试
 * @details 补充 IPv6/domain 地址类型的 parse_dgram/build_dgram、parse_prefixed/build_prefixed、
 *          parse_address IPv6/domain 覆盖。
 */

#include <prism/memory.hpp>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>

namespace
{
    void TestDeserializationValid()
    {
        // Version=0x01, Cmd=SYN(0), Length=100 LE, StreamID=42 LE
        std::array<std::byte, 8> frame{};
        frame[0] = std::byte{0x01}; // version
        frame[1] = std::byte{0x00}; // cmd SYN
        frame[2] = std::byte{100};  // length low
        frame[3] = std::byte{0x00}; // length high
        frame[4] = std::byte{42};   // stream_id byte 0
        frame[5] = std::byte{0x00};
        frame[6] = std::byte{0x00};
        frame[7] = std::byte{0x00};

        auto hdr = psm::multiplex::smux::deserialization(frame);
        EXPECT_TRUE(hdr.has_value()) << "deserialization valid: has_value";
        EXPECT_TRUE(hdr->version == 0x01) << "deserialization valid: version";
        EXPECT_TRUE(hdr->cmd == psm::multiplex::smux::command::syn) << "deserialization valid: cmd=syn";
        EXPECT_TRUE(hdr->length == 100) << "deserialization valid: length=100";
        EXPECT_TRUE(hdr->stream_id == 42) << "deserialization valid: stream_id=42";
    }

    void TestDeserializationBadVersion()
    {
        std::array<std::byte, 8> frame{};
        frame[0] = std::byte{0x02}; // wrong version
        auto hdr = psm::multiplex::smux::deserialization(frame);
        EXPECT_TRUE(!hdr.has_value()) << "deserialization bad version: nullopt";
    }

    void TestDeserializationBadCmd()
    {
        std::array<std::byte, 8> frame{};
        frame[0] = std::byte{0x01}; // version ok
        frame[1] = std::byte{0xFF}; // invalid cmd
        auto hdr = psm::multiplex::smux::deserialization(frame);
        EXPECT_TRUE(!hdr.has_value()) << "deserialization bad cmd: nullopt";
    }

    void TestDeserializationShort()
    {
        std::array<std::byte, 4> short_frame{};
        auto hdr = psm::multiplex::smux::deserialization(short_frame);
        EXPECT_TRUE(!hdr.has_value()) << "deserialization short: nullopt";
    }

} // namespace

TEST(SmuxFrameExtra, DeserializationValid) { TestDeserializationValid(); }
TEST(SmuxFrameExtra, DeserializationBadVersion) { TestDeserializationBadVersion(); }
TEST(SmuxFrameExtra, DeserializationBadCmd) { TestDeserializationBadCmd(); }
TEST(SmuxFrameExtra, DeserializationShort) { TestDeserializationShort(); }

TEST(SmuxFrameExtra, BuildParseDgramIpv6)
{
    auto *mr = psm::memory::current_resource();
    psm::multiplex::smux::datagram_params params;
    params.host = "::1";
    params.port = 443;
    const std::byte payload[] = {std::byte{0xAA}, std::byte{0xBB}};
    params.payload = payload;

    auto built = psm::multiplex::smux::build_dgram(params, mr);
    EXPECT_TRUE(!built.empty()) << "build dgram ipv6: not empty";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[0]) == 0x04) << "build dgram ipv6: atyp=0x04";

    auto parsed = psm::multiplex::smux::parse_dgram(built, mr);
    EXPECT_TRUE(parsed.has_value()) << "parse dgram ipv6: has_value";
    EXPECT_TRUE(parsed->host == "::1") << "parse dgram ipv6: host=::1";
    EXPECT_TRUE(parsed->port == 443) << "parse dgram ipv6: port=443";
    EXPECT_TRUE(parsed->payload.size() == 2) << "parse dgram ipv6: payload_size=2";
}

TEST(SmuxFrameExtra, BuildParseDgramDomain)
{
    auto *mr = psm::memory::current_resource();
    psm::multiplex::smux::datagram_params params;
    params.host = "example.com";
    params.port = 80;
    const std::byte payload[] = {std::byte{0xCC}};
    params.payload = payload;

    auto built = psm::multiplex::smux::build_dgram(params, mr);
    EXPECT_TRUE(!built.empty()) << "build dgram domain: not empty";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[0]) == 0x03) << "build dgram domain: atyp=0x03";

    auto parsed = psm::multiplex::smux::parse_dgram(built, mr);
    EXPECT_TRUE(parsed.has_value()) << "parse dgram domain: has_value";
    EXPECT_TRUE(parsed->host == "example.com") << "parse dgram domain: host=example.com";
    EXPECT_TRUE(parsed->port == 80) << "parse dgram domain: port=80";
    EXPECT_TRUE(parsed->payload.size() == 1) << "parse dgram domain: payload_size=1";
}

TEST(SmuxFrameExtra, BuildParsePrefixed)
{
    auto *mr = psm::memory::current_resource();
    const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};

    auto built = psm::multiplex::smux::build_prefixed(payload, mr);
    EXPECT_TRUE(built.size() == 5) << "build prefixed: size=5 (2+3)";

    auto parsed = psm::multiplex::smux::parse_prefixed(built);
    EXPECT_TRUE(parsed.has_value()) << "parse prefixed: has_value";
    EXPECT_TRUE(parsed->payload.size() == 3) << "parse prefixed: payload_size=3";
    EXPECT_TRUE(parsed->consumed == 5) << "parse prefixed: consumed=5";
}

TEST(SmuxFrameExtra, ParsePrefixedShort)
{
    std::byte buf[1]{};
    auto parsed = psm::multiplex::smux::parse_prefixed(buf);
    EXPECT_TRUE(!parsed.has_value()) << "parse prefixed short: nullopt";
}

TEST(SmuxFrameExtra, ParseAddressIpv6)
{
    auto *mr = psm::memory::current_resource();
    // Flags(2) + ATYP(1) + IPv6(16) + Port(2) = 21
    std::vector<std::byte> data(21);
    data[0] = std::byte{0x00}; // flags high
    data[1] = std::byte{0x00}; // flags low
    data[2] = std::byte{0x04}; // IPv6
    // 16 bytes of IPv6 (::1 = 00..0015=01)
    data[19] = std::byte{0x01}; // port high
    data[20] = std::byte{0xBB}; // port low

    // Set ::1 in bytes 3..18
    data[18] = std::byte{0x01};

    auto parsed = psm::multiplex::smux::parse_address(data, mr);
    EXPECT_TRUE(parsed.has_value()) << "parse address ipv6: has_value";
    EXPECT_TRUE(parsed->port == 0x01BB) << "parse address ipv6: port";
    EXPECT_TRUE(parsed->offset == 21) << "parse address ipv6: offset=21";
}

TEST(SmuxFrameExtra, ParseAddressDomain)
{
    auto *mr = psm::memory::current_resource();
    // Flags(2) + ATYP(1) + Len(1) + "test"(4) + Port(2) = 10
    std::vector<std::byte> data(10);
    data[0] = std::byte{0x00};
    data[1] = std::byte{0x01}; // flags = UDP
    data[2] = std::byte{0x03}; // domain
    data[3] = std::byte{0x04}; // domain length = 4
    data[4] = std::byte{'t'};
    data[5] = std::byte{'e'};
    data[6] = std::byte{'s'};
    data[7] = std::byte{'t'};
    data[8] = std::byte{0x00}; // port high
    data[9] = std::byte{80};   // port low

    auto parsed = psm::multiplex::smux::parse_address(data, mr);
    EXPECT_TRUE(parsed.has_value()) << "parse address domain: has_value";
    EXPECT_TRUE(parsed->host == "test") << "parse address domain: host=test";
    EXPECT_TRUE(parsed->port == 80) << "parse address domain: port=80";
    EXPECT_TRUE(parsed->is_udp == true) << "parse address domain: is_udp=true";
    EXPECT_TRUE(parsed->offset == 10) << "parse address domain: offset=10";
}

TEST(SmuxFrameExtra, ParseDgramEmpty)
{
    auto *mr = psm::memory::current_resource();
    auto parsed = psm::multiplex::smux::parse_dgram({}, mr);
    EXPECT_TRUE(!parsed.has_value()) << "parse dgram empty: nullopt";
}

TEST(SmuxFrameExtra, ParseAddressIPv4)
{
    auto *mr = psm::memory::current_resource();
    // Flags(2) + ATYP(1) + IPv4(4) + Port(2) = 9
    std::vector<std::byte> data(9);
    data[0] = std::byte{0x00}; // flags high
    data[1] = std::byte{0x00}; // flags low (TCP)
    data[2] = std::byte{0x01}; // IPv4
    data[3] = std::byte{127};
    data[4] = std::byte{0};
    data[5] = std::byte{0};
    data[6] = std::byte{1};
    data[7] = std::byte{0x00}; // port high
    data[8] = std::byte{0x50}; // port low = 80

    auto parsed = psm::multiplex::smux::parse_address(data, mr);
    EXPECT_TRUE(parsed.has_value()) << "parse address ipv4: has_value";
    EXPECT_TRUE(parsed->host == "127.0.0.1") << "parse address ipv4: host=127.0.0.1";
    EXPECT_TRUE(parsed->port == 80) << "parse address ipv4: port=80";
    EXPECT_TRUE(parsed->offset == 9) << "parse address ipv4: offset=9";
}

TEST(SmuxFrameExtra, ParseAddressTooShort)
{
    auto *mr = psm::memory::current_resource();
    std::byte data[2]{};
    auto parsed = psm::multiplex::smux::parse_address(data, mr);
    EXPECT_TRUE(!parsed.has_value()) << "parse address too short: nullopt";
}

TEST(SmuxFrameExtra, ParseDgramIPv4)
{
    auto *mr = psm::memory::current_resource();
    // ATYP(1) + IPv4(4) + Port(2) + Length(2) + Payload(2) = 11
    std::vector<std::byte> data(11);
    data[0] = std::byte{0x01}; // IPv4
    data[1] = std::byte{127};
    data[2] = std::byte{0};
    data[3] = std::byte{0};
    data[4] = std::byte{1};
    data[5] = std::byte{0x00}; // port high
    data[6] = std::byte{0x50}; // port low = 80
    data[7] = std::byte{0x00}; // length high
    data[8] = std::byte{0x02}; // length low = 2
    data[9] = std::byte{0xAA};
    data[10] = std::byte{0xBB};

    auto parsed = psm::multiplex::smux::parse_dgram(data, mr);
    EXPECT_TRUE(parsed.has_value()) << "parse dgram ipv4: has_value";
    EXPECT_TRUE(parsed->host == "127.0.0.1") << "parse dgram ipv4: host=127.0.0.1";
    EXPECT_TRUE(parsed->port == 80) << "parse dgram ipv4: port=80";
    EXPECT_TRUE(parsed->payload.size() == 2) << "parse dgram ipv4: payload_size=2";

    // Round-trip with build_dgram
    psm::multiplex::smux::datagram_params params;
    params.host = "127.0.0.1";
    params.port = 80;
    const std::byte payload[] = {std::byte{0xAA}, std::byte{0xBB}};
    params.payload = payload;

    auto built = psm::multiplex::smux::build_dgram(params, mr);
    auto reparsed = psm::multiplex::smux::parse_dgram(built, mr);
    EXPECT_TRUE(reparsed.has_value()) << "parse dgram ipv4 round-trip: has_value";
    EXPECT_TRUE(reparsed->host == "127.0.0.1") << "parse dgram ipv4 round-trip: host=127.0.0.1";
    EXPECT_TRUE(reparsed->port == 80) << "parse dgram ipv4 round-trip: port=80";
    EXPECT_TRUE(reparsed->payload.size() == 2) << "parse dgram ipv4 round-trip: payload_size=2";
}

TEST(SmuxFrameExtra, ParseDgramUnknownAtyp)
{
    auto *mr = psm::memory::current_resource();
    std::vector<std::byte> data(10);
    data[0] = std::byte{0x05}; // unknown ATYP

    auto parsed = psm::multiplex::smux::parse_dgram(data, mr);
    EXPECT_TRUE(!parsed.has_value()) << "parse dgram unknown atyp: nullopt";
}

TEST(SmuxFrameExtra, ParseDgramTruncatedPayload)
{
    auto *mr = psm::memory::current_resource();
    // ATYP(1) + IPv4(4) + Port(2) + Length(2) = 9, but length says 100
    std::vector<std::byte> data(9);
    data[0] = std::byte{0x01}; // IPv4
    data[1] = std::byte{127};
    data[2] = std::byte{0};
    data[3] = std::byte{0};
    data[4] = std::byte{1};
    data[5] = std::byte{0x00}; // port high
    data[6] = std::byte{0x50}; // port low = 80
    data[7] = std::byte{0x00}; // length high
    data[8] = std::byte{0x64}; // length low = 100

    auto parsed = psm::multiplex::smux::parse_dgram(data, mr);
    EXPECT_TRUE(!parsed.has_value()) << "parse dgram truncated payload: nullopt";
}

TEST(SmuxFrameExtra, DeserializationMaxLength)
{
    // length = 0xFFFF = 65535, exactly max_frame_length (uint16_t max)
    std::array<std::byte, 8> frame{};
    frame[0] = std::byte{0x01}; // version
    frame[1] = std::byte{0x00}; // cmd SYN
    frame[2] = std::byte{0xFF}; // length low
    frame[3] = std::byte{0xFF}; // length high = 65535
    frame[4] = std::byte{0x01};
    frame[5] = std::byte{0x00};
    frame[6] = std::byte{0x00};
    frame[7] = std::byte{0x00};

    auto hdr = psm::multiplex::smux::deserialization(frame);
    EXPECT_TRUE(hdr.has_value()) << "deserialization max length 65535: has_value (not > max)";
}

TEST(SmuxFrameExtra, BuildDgramIPv4)
{
    auto *mr = psm::memory::current_resource();
    psm::multiplex::smux::datagram_params params;
    params.host = "127.0.0.1";
    params.port = 443;
    const std::byte payload[] = {std::byte{0xDE}, std::byte{0xAD}};
    params.payload = payload;

    auto built = psm::multiplex::smux::build_dgram(params, mr);
    EXPECT_TRUE(!built.empty()) << "build dgram ipv4: not empty";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[0]) == 0x01) << "build dgram ipv4: atyp=0x01";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[1]) == 127) << "build dgram ipv4: ip[0]=127";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[2]) == 0) << "build dgram ipv4: ip[1]=0";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[3]) == 0) << "build dgram ipv4: ip[2]=0";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[4]) == 1) << "build dgram ipv4: ip[3]=1";

    // Round-trip with parse_dgram
    auto parsed = psm::multiplex::smux::parse_dgram(built, mr);
    EXPECT_TRUE(parsed.has_value()) << "build dgram ipv4 round-trip: has_value";
    EXPECT_TRUE(parsed->host == "127.0.0.1") << "build dgram ipv4 round-trip: host=127.0.0.1";
    EXPECT_TRUE(parsed->port == 443) << "build dgram ipv4 round-trip: port=443";
    EXPECT_TRUE(parsed->payload.size() == 2) << "build dgram ipv4 round-trip: payload_size=2";
}

TEST(SmuxFrameExtra, BuildDgramEmptyPayload)
{
    auto *mr = psm::memory::current_resource();
    psm::multiplex::smux::datagram_params params;
    params.host = "127.0.0.1";
    params.port = 80;
    params.payload = {}; // empty

    auto built = psm::multiplex::smux::build_dgram(params, mr);
    EXPECT_TRUE(!built.empty()) << "build dgram empty payload: not empty";
    EXPECT_TRUE(built.size() == 9) << "build dgram empty payload: size=9";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[7]) == 0) << "build dgram empty payload: length_high=0";
    EXPECT_TRUE(static_cast<std::uint8_t>(built[8]) == 0) << "build dgram empty payload: length_low=0";
}
