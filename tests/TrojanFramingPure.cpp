/**
 * @file TrojanFramingPure.cpp
 * @brief Trojan framing 纯函数测试
 * @details 测试 parse_credential/parse_crlf/parse_cmd_atyp/build_udp_pkt/parse_udp_pkt 全分支
 */

#include <prism/memory.hpp>
#include <prism/protocol/trojan/framing.hpp>
#include <prism/protocol/trojan/constants.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::protocol::trojan::format::parse_credential;
    using psm::protocol::trojan::format::parse_crlf;
    using psm::protocol::trojan::format::parse_cmd_atyp;
    using psm::protocol::trojan::format::build_udp_pkt;
    using psm::protocol::trojan::format::parse_udp_pkt;
    using psm::protocol::trojan::format::udp_routed;
    using psm::protocol::trojan::command;
    using psm::protocol::trojan::address_type;

    void TestParseCredentialTooShort(TestRunner &runner)
    {
        std::array<std::uint8_t, 10> buf{};
        auto [ec, cred] = parse_credential(buf);
        runner.Check(ec == psm::fault::code::bad_message, "credential: too short");
    }

    void TestParseCredentialInvalidChar(TestRunner &runner)
    {
        std::array<std::uint8_t, 56> buf{};
        buf[0] = 'Z'; // not hex
        auto [ec, cred] = parse_credential(buf);
        runner.Check(ec == psm::fault::code::protocol_error, "credential: invalid char");
    }

    void TestParseCredentialValidHex(TestRunner &runner)
    {
        std::array<std::uint8_t, 56> buf{};
        for (int i = 0; i < 56; ++i)
        {
            buf[i] = static_cast<std::uint8_t>('a' + (i % 6));
        }
        auto [ec, cred] = parse_credential(buf);
        runner.Check(ec == psm::fault::code::success, "credential: valid hex -> success");
        runner.Check(cred[0] == 'a', "credential: first char = 'a'");
    }

    void TestParseCredentialValidDigits(TestRunner &runner)
    {
        std::array<std::uint8_t, 56> buf{};
        for (int i = 0; i < 56; ++i)
        {
            buf[i] = static_cast<std::uint8_t>('0' + (i % 10));
        }
        auto [ec, cred] = parse_credential(buf);
        runner.Check(ec == psm::fault::code::success, "credential: all digits -> success");
    }

    void TestParseCredentialValidUpperHex(TestRunner &runner)
    {
        std::array<std::uint8_t, 56> buf{};
        for (int i = 0; i < 56; ++i)
        {
            buf[i] = static_cast<std::uint8_t>('A' + (i % 6));
        }
        auto [ec, cred] = parse_credential(buf);
        runner.Check(ec == psm::fault::code::success, "credential: upper hex -> success");
    }

    void TestParseCrlfTooShort(TestRunner &runner)
    {
        std::array<std::uint8_t, 1> buf{};
        runner.Check(parse_crlf(buf) == psm::fault::code::bad_message, "crlf: too short");
    }

    void TestParseCrlfValid(TestRunner &runner)
    {
        std::array<std::uint8_t, 2> buf{'\r', '\n'};
        runner.Check(parse_crlf(buf) == psm::fault::code::success, "crlf: valid CRLF");
    }

    void TestParseCrlfInvalid(TestRunner &runner)
    {
        std::array<std::uint8_t, 2> buf{'\n', '\r'};
        runner.Check(parse_crlf(buf) == psm::fault::code::protocol_error, "crlf: wrong order");
    }

    void TestParseCmdAtypTooShort(TestRunner &runner)
    {
        std::array<std::uint8_t, 1> buf{};
        auto [ec, result] = parse_cmd_atyp(buf);
        runner.Check(ec == psm::fault::code::bad_message, "cmd_atyp: too short");
    }

    void TestParseCmdAtypValid(TestRunner &runner)
    {
        std::array<std::uint8_t, 2> buf{};
        buf[0] = static_cast<std::uint8_t>(command::connect);
        buf[1] = static_cast<std::uint8_t>(address_type::ipv4);
        auto [ec, result] = parse_cmd_atyp(buf);
        runner.Check(ec == psm::fault::code::success, "cmd_atyp: success");
        runner.Check(result.cmd == command::connect, "cmd_atyp: cmd=connect");
        runner.Check(result.atyp == address_type::ipv4, "cmd_atyp: atyp=ipv4");
    }

    void TestBuildUdpPktIPv4Roundtrip(TestRunner &runner)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        udp_routed frame;
        frame.destination_address = psm::protocol::common::ipv4_address{{{127, 0, 0, 1}}};
        frame.destination_port = 80;
        std::array<std::byte, 3> payload = {std::byte{1}, std::byte{2}, std::byte{3}};

        auto ec = build_udp_pkt(frame, payload, out);
        runner.Check(ec == psm::fault::code::success, "trojan build_udp IPv4: success");
        runner.Check(out.size() >= 11, "trojan build_udp IPv4: min size");

        auto [pec, result] = parse_udp_pkt(out);
        runner.Check(pec == psm::fault::code::success, "trojan roundtrip: parse success");
        runner.Check(result.destination_port == 80, "trojan roundtrip: port=80");
        runner.Check(result.payload_size == 3, "trojan roundtrip: payload_size=3");
    }

    void TestBuildUdpPktDomainRoundtrip(TestRunner &runner)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::common::domain_address domain{};
        domain.length = 7;
        const char *name = "test.co";
        std::copy_n(name, 7, domain.value.begin());

        udp_routed frame;
        frame.destination_address = domain;
        frame.destination_port = 443;

        auto ec = build_udp_pkt(frame, {}, out);
        runner.Check(ec == psm::fault::code::success, "trojan build_udp domain: success");

        auto [pec, result] = parse_udp_pkt(out);
        runner.Check(pec == psm::fault::code::success, "trojan domain roundtrip: parse success");
        runner.Check(result.destination_port == 443, "trojan domain roundtrip: port=443");
        runner.Check(result.payload_size == 0, "trojan domain roundtrip: payload_size=0");
    }

    void TestBuildUdpPktIPv6Roundtrip(TestRunner &runner)
    {
        psm::memory::vector<std::byte> out(psm::memory::current_resource());
        psm::protocol::common::ipv6_address addr{};
        addr.bytes[15] = 1;

        udp_routed frame;
        frame.destination_address = addr;
        frame.destination_port = 8443;

        auto ec = build_udp_pkt(frame, {}, out);
        runner.Check(ec == psm::fault::code::success, "trojan build_udp IPv6: success");

        auto [pec, result] = parse_udp_pkt(out);
        runner.Check(pec == psm::fault::code::success, "trojan IPv6 roundtrip: parse success");
        runner.Check(result.destination_port == 8443, "trojan IPv6 roundtrip: port=8443");
    }

    void TestParseUdpPktTooShort(TestRunner &runner)
    {
        std::array<std::byte, 5> buf{};
        auto [ec, result] = parse_udp_pkt(buf);
        runner.Check(ec == psm::fault::code::bad_message, "trojan parse_udp: too short");
    }

    void TestParseUdpPktUnknownAtyp(TestRunner &runner)
    {
        std::array<std::byte, 12> buf{};
        buf[0] = std::byte{0xFF};
        auto [ec, result] = parse_udp_pkt(buf);
        runner.Check(ec == psm::fault::code::unsupported_address, "trojan parse_udp: unknown atyp");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrojanFramingPure");

    TestParseCredentialTooShort(runner);
    TestParseCredentialInvalidChar(runner);
    TestParseCredentialValidHex(runner);
    TestParseCredentialValidDigits(runner);
    TestParseCredentialValidUpperHex(runner);
    TestParseCrlfTooShort(runner);
    TestParseCrlfValid(runner);
    TestParseCrlfInvalid(runner);
    TestParseCmdAtypTooShort(runner);
    TestParseCmdAtypValid(runner);
    TestBuildUdpPktIPv4Roundtrip(runner);
    TestBuildUdpPktDomainRoundtrip(runner);
    TestBuildUdpPktIPv6Roundtrip(runner);
    TestParseUdpPktTooShort(runner);
    TestParseUdpPktUnknownAtyp(runner);

    return runner.Summary();
}
