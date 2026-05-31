/**
 * @file SmuxFrameError.cpp
 * @brief smux 帧格式错误路径与边界条件测试
 */

#include <prism/memory.hpp>
#include <prism/multiplex/smux/frame.hpp>
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

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

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

    void TestDeserializationBadVersion(TestRunner &runner)
    {
        auto hdr = make_header(0, static_cast<std::uint8_t>(command::syn), 10, 1);
        auto result = deserialization(hdr);
        runner.Check(!result.has_value(), "deserialization: bad version -> nullopt");
    }

    void TestDeserializationBadCommand(TestRunner &runner)
    {
        auto hdr = make_header(protocol_version, 0xFF, 10, 1);
        auto result = deserialization(hdr);
        runner.Check(!result.has_value(), "deserialization: bad command -> nullopt");
    }

    void TestDeserializationTooLong(TestRunner &runner)
    {
        // max_frame_length = 65535, 用超过最大值的长度
        auto hdr = make_header(protocol_version, static_cast<std::uint8_t>(command::syn),
                               0, 1);
        // 手动设置 length = 65536 (溢出为 0 但通过直接改字节)
        // 65536 = 0x10000, 但 uint16_t 只能表示到 65535
        // 改为直接测试 max_frame_length + 1 = 65536 不能放入 uint16_t
        // 所以测试 length = max_frame_length 是合法的
        auto hdr_max = make_header(protocol_version, static_cast<std::uint8_t>(command::push),
                                   max_frame_length, 1);
        auto result = deserialization(hdr_max);
        runner.Check(result.has_value(), "deserialization: max_frame_length is valid");
    }

    void TestDeserializationValid(TestRunner &runner)
    {
        auto hdr = make_header(protocol_version, static_cast<std::uint8_t>(command::syn), 100, 42);
        auto result = deserialization(hdr);
        runner.Check(result.has_value(), "deserialization: valid frame");
        runner.Check(result->cmd == command::syn, "deserialization: cmd=syn");
        runner.Check(result->stream_id == 42, "deserialization: stream_id=42");
        runner.Check(result->length == 100, "deserialization: length=100");
    }

    void TestDeserializationTooShort(TestRunner &runner)
    {
        std::array<std::byte, 4> short_buf{};
        auto result = deserialization(short_buf);
        runner.Check(!result.has_value(), "deserialization: too short -> nullopt");
    }

    void TestDeserializationAllCommands(TestRunner &runner)
    {
        for (auto cmd : {command::syn, command::fin, command::push, command::nop})
        {
            auto hdr = make_header(protocol_version, static_cast<std::uint8_t>(cmd), 0, 1);
            auto result = deserialization(hdr);
            runner.Check(result.has_value() && result->cmd == cmd,
                         "deserialization: valid command accepted");
        }
    }

    void TestParseAddressIPv4Valid(TestRunner &runner)
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
        runner.Check(result.has_value(), "parse_address: IPv4 valid");
        runner.Check(result->host == "127.0.0.1", "parse_address: IPv4 host");
        runner.Check(result->port == 80, "parse_address: IPv4 port");
    }

    void TestParseAddressDomainValid(TestRunner &runner)
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
        runner.Check(result.has_value(), "parse_address: domain valid");
        runner.Check(result->host == "example.com", "parse_address: domain host");
        runner.Check(result->port == 443, "parse_address: domain port");
    }

    void TestParseAddressTooShort(TestRunner &runner)
    {
        std::array<std::byte, 2> short_buf{};
        auto mr = psm::memory::unsynchronized_pool();
        auto result = parse_address(short_buf, &mr);
        runner.Check(!result.has_value(), "parse_address: too short -> nullopt");
    }

    void TestParseAddressUnknownAtype(TestRunner &runner)
    {
        std::array<std::byte, 5> buf{};
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x00};
        buf[2] = std::byte{0x05}; // unknown atype
        buf[3] = std::byte{0};
        buf[4] = std::byte{0};

        auto mr = psm::memory::unsynchronized_pool();
        auto result = parse_address(buf, &mr);
        runner.Check(!result.has_value(), "parse_address: unknown atype -> nullopt");
    }

    void TestParseAddressUdpFlag(TestRunner &runner)
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
        runner.Check(result.has_value(), "parse_address: UDP flag valid");
        runner.Check(result->is_udp, "parse_address: is_udp=true");
    }

    void TestParseAddressTruncatedIPv4(TestRunner &runner)
    {
        std::array<std::byte, 6> buf{};
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x00};
        buf[2] = std::byte{0x01}; // IPv4 but only 1 byte addr
        buf[3] = std::byte{127};

        auto mr = psm::memory::unsynchronized_pool();
        auto result = parse_address(buf, &mr);
        runner.Check(!result.has_value(), "parse_address: truncated IPv4 -> nullopt");
    }

    void TestParseDgramEmpty(TestRunner &runner)
    {
        auto mr = psm::memory::unsynchronized_pool();
        auto result = parse_dgram({}, &mr);
        runner.Check(!result.has_value(), "parse_dgram: empty -> nullopt");
    }

    void TestParseDgramUnknownAtype(TestRunner &runner)
    {
        std::array<std::byte, 3> buf{};
        buf[0] = std::byte{0x05}; // unknown

        auto mr = psm::memory::unsynchronized_pool();
        auto result = parse_dgram(buf, &mr);
        runner.Check(!result.has_value(), "parse_dgram: unknown atype -> nullopt");
    }

    void TestParseDgramTruncated(TestRunner &runner)
    {
        std::array<std::byte, 2> buf{};
        buf[0] = std::byte{0x01}; // IPv4 but no data

        auto mr = psm::memory::unsynchronized_pool();
        auto result = parse_dgram(buf, &mr);
        runner.Check(!result.has_value(), "parse_dgram: truncated IPv4 -> nullopt");
    }

    void TestParseDgramIPv4Valid(TestRunner &runner)
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
        runner.Check(result.has_value(), "parse_dgram: IPv4 valid");
        runner.Check(result->host == "127.0.0.1", "parse_dgram: host");
        runner.Check(result->port == 80, "parse_dgram: port");
        runner.Check(result->consumed == 13, "parse_dgram: consumed");
    }

    void TestParsePrefixedTooShort(TestRunner &runner)
    {
        std::array<std::byte, 1> buf{};
        auto result = parse_prefixed(buf);
        runner.Check(!result.has_value(), "parse_prefixed: too short -> nullopt");
    }

    void TestParsePrefixedTruncated(TestRunner &runner)
    {
        std::array<std::byte, 4> buf{};
        buf[0] = std::byte{0x00};
        buf[1] = std::byte{0x20}; // claims 32 bytes but only 2 available

        auto result = parse_prefixed(buf);
        runner.Check(!result.has_value(), "parse_prefixed: truncated -> nullopt");
    }

    void TestParsePrefixedValid(TestRunner &runner)
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x00});
        buf.push_back(std::byte{0x03}); // length = 3
        buf.push_back(std::byte{0x01});
        buf.push_back(std::byte{0x02});
        buf.push_back(std::byte{0x03});

        auto result = parse_prefixed(buf);
        runner.Check(result.has_value(), "parse_prefixed: valid");
        runner.Check(result->consumed == 5, "parse_prefixed: consumed=5");
        runner.Check(result->payload.size() == 3, "parse_prefixed: payload=3");
    }

    void TestBuildDgramRoundtripIPv4(TestRunner &runner)
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
        runner.Check(parsed.has_value(), "build_dgram roundtrip: parsed");
        runner.Check(parsed->host == "127.0.0.1", "build_dgram roundtrip: host");
        runner.Check(parsed->port == 443, "build_dgram roundtrip: port");
        runner.Check(parsed->payload.size() == 2, "build_dgram roundtrip: payload size");
    }

    void TestBuildPrefixedRoundtrip(TestRunner &runner)
    {
        auto mr = psm::memory::unsynchronized_pool();
        const std::byte data[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        auto built = build_prefixed(data, &mr);

        auto parsed = parse_prefixed(built);
        runner.Check(parsed.has_value(), "build_prefixed roundtrip: parsed");
        runner.Check(parsed->payload.size() == 3, "build_prefixed roundtrip: payload size");
        runner.Check(std::memcmp(parsed->payload.data(), data, 3) == 0,
                     "build_prefixed roundtrip: data matches");
    }

    void TestBuildDgramDomainRoundtrip(TestRunner &runner)
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
        runner.Check(parsed.has_value(), "build_dgram domain: parsed");
        runner.Check(parsed->host == "example.com", "build_dgram domain: host");
        runner.Check(parsed->port == 8443, "build_dgram domain: port");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("SmuxFrameError");

    TestDeserializationBadVersion(runner);
    TestDeserializationBadCommand(runner);
    TestDeserializationTooLong(runner);
    TestDeserializationValid(runner);
    TestDeserializationTooShort(runner);
    TestDeserializationAllCommands(runner);

    TestParseAddressIPv4Valid(runner);
    TestParseAddressDomainValid(runner);
    TestParseAddressTooShort(runner);
    TestParseAddressUnknownAtype(runner);
    TestParseAddressUdpFlag(runner);
    TestParseAddressTruncatedIPv4(runner);

    TestParseDgramEmpty(runner);
    TestParseDgramUnknownAtype(runner);
    TestParseDgramTruncated(runner);
    TestParseDgramIPv4Valid(runner);

    TestParsePrefixedTooShort(runner);
    TestParsePrefixedTruncated(runner);
    TestParsePrefixedValid(runner);

    TestBuildDgramRoundtripIPv4(runner);
    TestBuildPrefixedRoundtrip(runner);
    TestBuildDgramDomainRoundtrip(runner);

    return runner.Summary();
}
