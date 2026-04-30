/**
 * @file Smux.cpp
 * @brief smux 帧协议单元测试
 * @details 测试 smux 多路复用协议的帧编解码功能：
 * 帧头反序列化、地址解析、UDP 数据报编解码、length-prefixed 编解码等。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/smux/frame.hpp>

#include "common/TestRunner.hpp"

#include <array>
#include <cstring>

namespace
{
    psm::testing::TestRunner runner("Smux");
} // namespace

using namespace psm::multiplex::smux;

// ---------- helpers ----------

/**
 * @brief 构造 8 字节 smux 帧头（小端序）
 */
[[nodiscard]] std::array<std::byte, 8> make_header(std::uint8_t version, command cmd,
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
void TestDeserializeSyn()
{
    runner.LogInfo("=== TestDeserializeSyn ===");

    auto buf = make_header(0x01, command::syn, 0, 42);
    auto result = deserialization(buf);
    if (!result)
    {
        runner.LogFail("SYN deserialization returned nullopt");
        return;
    }
    if (result->cmd != command::syn)
    {
        runner.LogFail("SYN cmd mismatch");
        return;
    }
    if (result->length != 0)
    {
        runner.LogFail("SYN length mismatch");
        return;
    }
    if (result->stream_id != 42)
    {
        runner.LogFail("SYN stream_id mismatch");
        return;
    }

    runner.LogPass("deserialize SYN");
}

/**
 * @brief 测试合法 FIN 帧反序列化
 */
void TestDeserializeFin()
{
    runner.LogInfo("=== TestDeserializeFin ===");

    auto buf = make_header(0x01, command::fin, 100, 7);
    auto result = deserialization(buf);
    if (!result)
    {
        runner.LogFail("FIN deserialization returned nullopt");
        return;
    }
    if (result->cmd != command::fin)
    {
        runner.LogFail("FIN cmd mismatch");
        return;
    }
    if (result->length != 100)
    {
        runner.LogFail("FIN length mismatch");
        return;
    }
    if (result->stream_id != 7)
    {
        runner.LogFail("FIN stream_id mismatch");
        return;
    }

    runner.LogPass("deserialize FIN");
}

/**
 * @brief 测试合法 PSH 帧反序列化
 */
void TestDeserializePush()
{
    runner.LogInfo("=== TestDeserializePush ===");

    auto buf = make_header(0x01, command::push, 65535, 0x12345678);
    auto result = deserialization(buf);
    if (!result)
    {
        runner.LogFail("PSH deserialization returned nullopt");
        return;
    }
    if (result->cmd != command::push)
    {
        runner.LogFail("PSH cmd mismatch");
        return;
    }
    if (result->length != 65535)
    {
        runner.LogFail("PSH length mismatch");
        return;
    }
    if (result->stream_id != 0x12345678)
    {
        runner.LogFail("PSH stream_id mismatch");
        return;
    }

    runner.LogPass("deserialize PSH");
}

/**
 * @brief 测试合法 NOP 帧反序列化
 */
void TestDeserializeNop()
{
    runner.LogInfo("=== TestDeserializeNop ===");

    auto buf = make_header(0x01, command::nop, 0, 0);
    auto result = deserialization(buf);
    if (!result)
    {
        runner.LogFail("NOP deserialization returned nullopt");
        return;
    }
    if (result->cmd != command::nop)
    {
        runner.LogFail("NOP cmd mismatch");
        return;
    }
    if (result->stream_id != 0)
    {
        runner.LogFail("NOP stream_id mismatch");
        return;
    }

    runner.LogPass("deserialize NOP");
}

/**
 * @brief 测试数据不足（< 8 字节）
 */
void TestDeserializeTruncated()
{
    runner.LogInfo("=== TestDeserializeTruncated ===");

    std::array<std::byte, 4> short_buf{};
    auto result = deserialization(short_buf);
    if (result.has_value())
    {
        runner.LogFail("truncated data should return nullopt");
        return;
    }

    runner.LogPass("deserialize truncated");
}

/**
 * @brief 测试非法版本号
 */
void TestDeserializeBadVersion()
{
    runner.LogInfo("=== TestDeserializeBadVersion ===");

    auto buf = make_header(0x02, command::syn, 0, 1);
    auto result = deserialization(buf);
    if (result.has_value())
    {
        runner.LogFail("bad version should return nullopt");
        return;
    }

    runner.LogPass("deserialize bad version");
}

/**
 * @brief 测试非法命令
 */
void TestDeserializeBadCommand()
{
    runner.LogInfo("=== TestDeserializeBadCommand ===");

    auto buf = make_header(0x01, static_cast<command>(0xFF), 0, 1);
    auto result = deserialization(buf);
    if (result.has_value())
    {
        runner.LogFail("bad command should return nullopt");
        return;
    }

    runner.LogPass("deserialize bad command");
}

/**
 * @brief 测试小端字节序
 */
void TestDeserializeEndianness()
{
    runner.LogInfo("=== TestDeserializeEndianness ===");

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
    if (!result)
    {
        runner.LogFail("endianness test deserialization failed");
        return;
    }
    if (result->length != 0x0506)
    {
        runner.LogFail("endianness length mismatch");
        return;
    }
    if (result->stream_id != 0x01020304)
    {
        runner.LogFail("endianness stream_id mismatch");
        return;
    }

    runner.LogPass("deserialize endianness");
}

// ---------- parse_mux_address ----------

/**
 * @brief 测试 IPv4 地址解析
 */
void TestParseAddressIPv4()
{
    runner.LogInfo("=== TestParseAddressIPv4 ===");

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

    auto result = parse_mux_address(buf, psm::memory::current_resource());
    if (!result)
    {
        runner.LogFail("IPv4 address parse returned nullopt");
        return;
    }
    if (result->host != "127.0.0.1")
    {
        runner.LogFail(psm::memory::string("IPv4 host mismatch: ") + result->host);
        return;
    }
    if (result->port != 8080)
    {
        runner.LogFail("IPv4 port mismatch");
        return;
    }
    if (!result->is_udp)
    {
        runner.LogFail("is_udp should be true");
        return;
    }
    if (result->packet_addr)
    {
        runner.LogFail("packet_addr should be false");
        return;
    }

    runner.LogPass("parse address IPv4");
}

/**
 * @brief 测试域名地址解析
 */
void TestParseAddressDomain()
{
    runner.LogInfo("=== TestParseAddressDomain ===");

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

    auto result = parse_mux_address(buf, psm::memory::current_resource());
    if (!result)
    {
        runner.LogFail("domain address parse returned nullopt");
        return;
    }
    if (result->host != "test.com")
    {
        runner.LogFail(psm::memory::string("domain host mismatch: ") + result->host);
        return;
    }
    if (result->port != 80)
    {
        runner.LogFail("domain port mismatch");
        return;
    }
    if (result->is_udp)
    {
        runner.LogFail("is_udp should be false");
        return;
    }

    runner.LogPass("parse address domain");
}

/**
 * @brief 测试 IPv6 地址解析
 */
void TestParseAddressIPv6()
{
    runner.LogInfo("=== TestParseAddressIPv6 ===");

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

    auto result = parse_mux_address(buf, psm::memory::current_resource());
    if (!result)
    {
        runner.LogFail("IPv6 address parse returned nullopt");
        return;
    }
    if (result->host != "::1")
    {
        runner.LogFail(psm::memory::string("IPv6 host mismatch: ") + result->host);
        return;
    }
    if (result->port != 80)
    {
        runner.LogFail("IPv6 port mismatch");
        return;
    }
    if (!result->packet_addr)
    {
        runner.LogFail("packet_addr should be true");
        return;
    }

    runner.LogPass("parse address IPv6");
}

/**
 * @brief 测试数据不足的地址解析
 */
void TestParseAddressTruncated()
{
    runner.LogInfo("=== TestParseAddressTruncated ===");

    psm::memory::vector<std::byte> buf;
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01}); // ATYP IPv4 but no address bytes

    auto result = parse_mux_address(buf, psm::memory::current_resource());
    if (result.has_value())
    {
        runner.LogFail("truncated address should return nullopt");
        return;
    }

    runner.LogPass("parse address truncated");
}

/**
 * @brief 测试非法 ATYP
 */
void TestParseAddressBadAtyp()
{
    runner.LogInfo("=== TestParseAddressBadAtyp ===");

    psm::memory::vector<std::byte> buf;
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0xFF}); // invalid ATYP

    auto result = parse_mux_address(buf, psm::memory::current_resource());
    if (result.has_value())
    {
        runner.LogFail("bad ATYP should return nullopt");
        return;
    }

    runner.LogPass("parse address bad ATYP");
}

// ---------- UDP datagram roundtrip ----------

/**
 * @brief 测试 UDP 数据报编解码往返（IPv4）
 */
void TestUdpDatagramRoundtripIPv4()
{
    runner.LogInfo("=== TestUdpDatagramRoundtripIPv4 ===");

    const std::byte payload[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    auto encoded = build_udp_datagram("127.0.0.1", 9090, payload, psm::memory::current_resource());
    auto result = parse_udp_datagram(encoded, psm::memory::current_resource());

    if (!result)
    {
        runner.LogFail("UDP datagram parse returned nullopt");
        return;
    }
    if (result->host != "127.0.0.1")
    {
        runner.LogFail(psm::memory::string("UDP host mismatch: ") + result->host);
        return;
    }
    if (result->port != 9090)
    {
        runner.LogFail("UDP port mismatch");
        return;
    }
    if (result->payload.size() != 3)
    {
        runner.LogFail("UDP payload size mismatch");
        return;
    }
    if (result->payload[0] != std::byte{0xAA} || result->payload[2] != std::byte{0xCC})
    {
        runner.LogFail("UDP payload content mismatch");
        return;
    }

    runner.LogPass("UDP datagram roundtrip IPv4");
}

/**
 * @brief 测试 UDP 数据报编解码往返（域名）
 */
void TestUdpDatagramRoundtripDomain()
{
    runner.LogInfo("=== TestUdpDatagramRoundtripDomain ===");

    const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};
    auto encoded = build_udp_datagram("example.com", 443, payload, psm::memory::current_resource());
    auto result = parse_udp_datagram(encoded, psm::memory::current_resource());

    if (!result)
    {
        runner.LogFail("UDP datagram domain parse returned nullopt");
        return;
    }
    if (result->host != "example.com")
    {
        runner.LogFail(psm::memory::string("UDP domain host mismatch: ") + result->host);
        return;
    }
    if (result->port != 443)
    {
        runner.LogFail("UDP domain port mismatch");
        return;
    }
    if (result->payload.size() != 2)
    {
        runner.LogFail("UDP domain payload size mismatch");
        return;
    }

    runner.LogPass("UDP datagram roundtrip domain");
}

/**
 * @brief 测试空数据的 UDP 解析
 */
void TestUdpDatagramEmpty()
{
    runner.LogInfo("=== TestUdpDatagramEmpty ===");

    psm::memory::vector<std::byte> empty_buf;
    auto result = parse_udp_datagram(empty_buf, psm::memory::current_resource());
    if (result.has_value())
    {
        runner.LogFail("empty UDP datagram should return nullopt");
        return;
    }

    runner.LogPass("UDP datagram empty");
}

// ---------- length-prefixed roundtrip ----------

/**
 * @brief 测试 length-prefixed 编解码往返
 */
void TestUdpLengthPrefixedRoundtrip()
{
    runner.LogInfo("=== TestUdpLengthPrefixedRoundtrip ===");

    const std::byte payload[] = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    auto encoded = build_udp_length_prefixed(payload, psm::memory::current_resource());
    auto result = parse_udp_length_prefixed(encoded);

    if (!result)
    {
        runner.LogFail("length-prefixed parse returned nullopt");
        return;
    }
    if (result->payload.size() != 4)
    {
        runner.LogFail("length-prefixed payload size mismatch");
        return;
    }
    if (result->payload[0] != std::byte{0xDE} || result->payload[3] != std::byte{0xEF})
    {
        runner.LogFail("length-prefixed payload content mismatch");
        return;
    }

    runner.LogPass("UDP length-prefixed roundtrip");
}

/**
 * @brief 测试数据不足的 length-prefixed 解析
 */
void TestUdpLengthPrefixedTruncated()
{
    runner.LogInfo("=== TestUdpLengthPrefixedTruncated ===");

    psm::memory::vector<std::byte> short_data;
    short_data.push_back(std::byte{0x00});

    auto result = parse_udp_length_prefixed(short_data);
    if (result.has_value())
    {
        runner.LogFail("truncated length-prefixed should return nullopt");
        return;
    }

    psm::memory::vector<std::byte> mismatch_data;
    mismatch_data.push_back(std::byte{0x00});
    mismatch_data.push_back(std::byte{0x10}); // length = 16
    mismatch_data.push_back(std::byte{0xAA}); // only 1 byte of payload

    auto result2 = parse_udp_length_prefixed(mismatch_data);
    if (result2.has_value())
    {
        runner.LogFail("length-prefixed with oversized length should return nullopt");
        return;
    }

    runner.LogPass("UDP length-prefixed truncated");
}

int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("========== Smux Frame Tests ==========");

    TestDeserializeSyn();
    TestDeserializeFin();
    TestDeserializePush();
    TestDeserializeNop();
    TestDeserializeTruncated();
    TestDeserializeBadVersion();
    TestDeserializeBadCommand();
    TestDeserializeEndianness();

    TestParseAddressIPv4();
    TestParseAddressDomain();
    TestParseAddressIPv6();
    TestParseAddressTruncated();
    TestParseAddressBadAtyp();

    TestUdpDatagramRoundtripIPv4();
    TestUdpDatagramRoundtripDomain();
    TestUdpDatagramEmpty();

    TestUdpLengthPrefixedRoundtrip();
    TestUdpLengthPrefixedTruncated();

    return runner.Summary();
}
