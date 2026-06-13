/**
 * @file SmuxFrameError.cpp
 * @brief smux 帧格式错误路径与边界条件测试
 */

#include <prism/core/core.hpp>
#include <prism/proto/multiplex/smux/frame.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <gtest/gtest.h>

namespace
{
    using psm::multiplex::smux::command;
    using psm::multiplex::smux::datagram_params;
    using psm::multiplex::smux::deserialization;
    using psm::multiplex::smux::frame_hdrsize;
    using psm::multiplex::smux::max_frame_length;
    using psm::multiplex::smux::parse_address;
    using psm::multiplex::smux::parse_dgram;
    using psm::multiplex::smux::parse_prefixed;
    using psm::multiplex::smux::build_dgram;
    using psm::multiplex::smux::build_prefixed;
    using psm::multiplex::smux::protocol_version;

    // 辅助：构造 smux 帧头
    auto make_header(std::uint8_t ver, std::uint8_t cmd, std::uint16_t len,
                     std::uint32_t sid) -> std::array<std::byte, frame_hdrsize>
    {
        std::array<std::byte, frame_hdrsize> buf{};
        buf[0] = std::byte{ver};
        buf[1] = std::byte{cmd};
        buf[2] = std::byte{static_cast<unsigned char>(len & 0xFF)};
        buf[3] = std::byte{static_cast<unsigned char>((len >> 8) & 0xFF)};
        buf[4] = std::byte{static_cast<unsigned char>(sid & 0xFF)};
        buf[5] = std::byte{static_cast<unsigned char>((sid >> 8) & 0xFF)};
        buf[6] = std::byte{static_cast<unsigned char>((sid >> 16) & 0xFF)};
        buf[7] = std::byte{static_cast<unsigned char>((sid >> 24) & 0xFF)};
        return buf;
    }

} // namespace

TEST(SmuxFrameError, DeserializationBadVersion)
{
    auto hdr = make_header(0, static_cast<std::uint8_t>(command::syn), 10, 1);
    auto result = deserialization(hdr);
    EXPECT_TRUE(!result.has_value()) << "deserialization: bad version -> nullopt";
}

TEST(SmuxFrameError, DeserializationBadCommand)
{
    auto hdr = make_header(protocol_version, 0xFF, 10, 1);
    auto result = deserialization(hdr);
    EXPECT_TRUE(!result.has_value()) << "deserialization: bad command -> nullopt";
}

TEST(SmuxFrameError, DeserializationTooLong)
{
    auto hdr_max = make_header(protocol_version, static_cast<std::uint8_t>(command::push),
                               max_frame_length, 1);
    auto result = deserialization(hdr_max);
    EXPECT_TRUE(result.has_value()) << "deserialization: max_frame_length is valid";
}

TEST(SmuxFrameError, DeserializationValid)
{
    auto hdr = make_header(protocol_version, static_cast<std::uint8_t>(command::syn), 100, 42);
    auto result = deserialization(hdr);
    EXPECT_TRUE(result.has_value()) << "deserialization: valid frame";
    EXPECT_TRUE(result->cmd == command::syn) << "deserialization: cmd=syn";
    EXPECT_TRUE(result->stream_id == 42) << "deserialization: stream_id=42";
    EXPECT_TRUE(result->length == 100) << "deserialization: length=100";
}

TEST(SmuxFrameError, DeserializationTooShort)
{
    std::array<std::byte, 4> short_buf{};
    auto result = deserialization(short_buf);
    EXPECT_TRUE(!result.has_value()) << "deserialization: too short -> nullopt";
}

TEST(SmuxFrameError, DeserializationAllCommands)
{
    for (auto cmd : {command::syn, command::fin, command::push, command::nop})
    {
        auto hdr = make_header(protocol_version, static_cast<std::uint8_t>(cmd), 0, 1);
        auto result = deserialization(hdr);
        EXPECT_TRUE(result.has_value() && result->cmd == cmd)
            << "deserialization: valid command accepted";
    }
}

TEST(SmuxFrameError, ParseAddressIPv4Valid)
{
    std::array<std::byte, 9> buf{};
    buf[0] = std::byte{0x00}; // flags high
    buf[1] = std::byte{0x00}; // flags low
    buf[2] = std::byte{0x01}; // atype = IPv4
    buf[3] = std::byte{127};  // 127.0.0.1
    buf[4] = std::byte{0};
    buf[5] = std::byte{0};
    buf[6] = std::byte{1};
    buf[7] = std::byte{0};   // port high
    buf[8] = std::byte{80};  // port low

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_address(buf, &mr);
    EXPECT_TRUE(result.has_value()) << "parse_address: IPv4 valid";
    EXPECT_TRUE(result->host == "127.0.0.1") << "parse_address: IPv4 host";
    EXPECT_TRUE(result->port == 80) << "parse_address: IPv4 port";
}

TEST(SmuxFrameError, ParseAddressDomainValid)
{
    const char *domain = "example.com";
    auto dlen = static_cast<std::uint8_t>(std::strlen(domain));
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x00}); // flags high
    buf.push_back(std::byte{0x00}); // flags low
    buf.push_back(std::byte{0x03}); // atype = domain
    buf.push_back(std::byte{dlen});
    for (auto c : std::string_view(domain))
    {
        buf.push_back(std::byte{static_cast<unsigned char>(c)});
    }
    buf.push_back(std::byte{0x01});  // port high
    buf.push_back(std::byte{0xBB});  // port low (443 = 0x01BB)

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_address(buf, &mr);
    EXPECT_TRUE(result.has_value()) << "parse_address: domain valid";
    EXPECT_TRUE(result->host == "example.com") << "parse_address: domain host";
    EXPECT_TRUE(result->port == 443) << "parse_address: domain port";
}

TEST(SmuxFrameError, ParseAddressTooShort)
{
    std::array<std::byte, 2> short_buf{};
    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_address(short_buf, &mr);
    EXPECT_TRUE(!result.has_value()) << "parse_address: too short -> nullopt";
}

TEST(SmuxFrameError, ParseAddressUnknownAtype)
{
    std::array<std::byte, 5> buf{};
    buf[0] = std::byte{0x00};
    buf[1] = std::byte{0x00};
    buf[2] = std::byte{0x05}; // unknown atype
    buf[3] = std::byte{0};
    buf[4] = std::byte{0};

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_address(buf, &mr);
    EXPECT_TRUE(!result.has_value()) << "parse_address: unknown atype -> nullopt";
}

TEST(SmuxFrameError, ParseAddressUdpFlag)
{
    std::array<std::byte, 9> buf{};
    buf[0] = std::byte{0x00};
    buf[1] = std::byte{0x01}; // flags: UDP
    buf[2] = std::byte{0x01}; // IPv4
    buf[3] = std::byte{10};
    buf[4] = std::byte{0};
    buf[5] = std::byte{0};
    buf[6] = std::byte{1};
    buf[7] = std::byte{0};
    buf[8] = std::byte{53};

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_address(buf, &mr);
    EXPECT_TRUE(result.has_value()) << "parse_address: UDP flag valid";
    EXPECT_TRUE(result->is_udp) << "parse_address: is_udp=true";
}

TEST(SmuxFrameError, ParseAddressTruncatedIPv4)
{
    std::array<std::byte, 6> buf{};
    buf[0] = std::byte{0x00};
    buf[1] = std::byte{0x00};
    buf[2] = std::byte{0x01}; // IPv4 but only 1 byte addr
    buf[3] = std::byte{127};

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_address(buf, &mr);
    EXPECT_TRUE(!result.has_value()) << "parse_address: truncated IPv4 -> nullopt";
}

TEST(SmuxFrameError, ParseDgramEmpty)
{
    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_dgram({}, &mr);
    EXPECT_TRUE(!result.has_value()) << "parse_dgram: empty -> nullopt";
}

TEST(SmuxFrameError, ParseDgramUnknownAtype)
{
    std::array<std::byte, 3> buf{};
    buf[0] = std::byte{0x05}; // unknown

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_dgram(buf, &mr);
    EXPECT_TRUE(!result.has_value()) << "parse_dgram: unknown atype -> nullopt";
}

TEST(SmuxFrameError, ParseDgramTruncated)
{
    std::array<std::byte, 2> buf{};
    buf[0] = std::byte{0x01}; // IPv4 but no data

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_dgram(buf, &mr);
    EXPECT_TRUE(!result.has_value()) << "parse_dgram: truncated IPv4 -> nullopt";
}

TEST(SmuxFrameError, ParseDgramIPv4Valid)
{
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x01}); // IPv4
    buf.push_back(std::byte{127});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{0});
    buf.push_back(std::byte{1});
    buf.push_back(std::byte{0});   // port high
    buf.push_back(std::byte{80});  // port low
    buf.push_back(std::byte{0});   // length high
    buf.push_back(std::byte{4});   // length low
    buf.push_back(std::byte{0xDE});
    buf.push_back(std::byte{0xAD});
    buf.push_back(std::byte{0xBE});
    buf.push_back(std::byte{0xEF});

    auto mr = psm::memory::unsynchronized_pool();
    auto result = parse_dgram(buf, &mr);
    EXPECT_TRUE(result.has_value()) << "parse_dgram: IPv4 valid";
    EXPECT_TRUE(result->host == "127.0.0.1") << "parse_dgram: host";
    EXPECT_TRUE(result->port == 80) << "parse_dgram: port";
    EXPECT_TRUE(result->consumed == 13) << "parse_dgram: consumed";
}

TEST(SmuxFrameError, ParsePrefixedTooShort)
{
    std::array<std::byte, 1> buf{};
    auto result = parse_prefixed(buf);
    EXPECT_TRUE(!result.has_value()) << "parse_prefixed: too short -> nullopt";
}

TEST(SmuxFrameError, ParsePrefixedTruncated)
{
    std::array<std::byte, 4> buf{};
    buf[0] = std::byte{0x00};
    buf[1] = std::byte{0x20}; // claims 32 bytes but only 2 available

    auto result = parse_prefixed(buf);
    EXPECT_TRUE(!result.has_value()) << "parse_prefixed: truncated -> nullopt";
}

TEST(SmuxFrameError, ParsePrefixedValid)
{
    std::vector<std::byte> buf;
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x03}); // length = 3
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{0x02});
    buf.push_back(std::byte{0x03});

    auto result = parse_prefixed(buf);
    EXPECT_TRUE(result.has_value()) << "parse_prefixed: valid";
    EXPECT_TRUE(result->consumed == 5) << "parse_prefixed: consumed=5";
    EXPECT_TRUE(result->payload.size() == 3) << "parse_prefixed: payload=3";
}

TEST(SmuxFrameError, BuildDgramRoundtripIPv4)
{
    auto mr = psm::memory::unsynchronized_pool();
    const std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}};
    datagram_params params{
        .host = "127.0.0.1",
        .port = 443,
        .payload = data,
    };
    auto built = build_dgram(params, &mr);

    auto parsed = parse_dgram(built, &mr);
    EXPECT_TRUE(parsed.has_value()) << "build_dgram roundtrip: parsed";
    EXPECT_TRUE(parsed->host == "127.0.0.1") << "build_dgram roundtrip: host";
    EXPECT_TRUE(parsed->port == 443) << "build_dgram roundtrip: port";
    EXPECT_TRUE(parsed->payload.size() == 2) << "build_dgram roundtrip: payload size";
}

TEST(SmuxFrameError, BuildPrefixedRoundtrip)
{
    auto mr = psm::memory::unsynchronized_pool();
    const std::byte data[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    auto built = build_prefixed(data, &mr);

    auto parsed = parse_prefixed(built);
    EXPECT_TRUE(parsed.has_value()) << "build_prefixed roundtrip: parsed";
    EXPECT_TRUE(parsed->payload.size() == 3) << "build_prefixed roundtrip: payload size";
    EXPECT_TRUE(std::memcmp(parsed->payload.data(), data, 3) == 0)
        << "build_prefixed roundtrip: data matches";
}

TEST(SmuxFrameError, BuildDgramDomainRoundtrip)
{
    auto mr = psm::memory::unsynchronized_pool();
    const std::byte data[] = {std::byte{0xCC}};
    datagram_params params{
        .host = "example.com",
        .port = 8443,
        .payload = data,
    };
    auto built = build_dgram(params, &mr);

    auto parsed = parse_dgram(built, &mr);
    EXPECT_TRUE(parsed.has_value()) << "build_dgram domain: parsed";
    EXPECT_TRUE(parsed->host == "example.com") << "build_dgram domain: host";
    EXPECT_TRUE(parsed->port == 8443) << "build_dgram domain: port";
}
