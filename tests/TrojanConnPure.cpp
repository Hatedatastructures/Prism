/**
 * @file TrojanConnPure.cpp
 * @brief Trojan conn 纯函数测试
 * @details 测试 validate_command/parse_address_from_buffer/verify_credential/parse_request_target
 */

#include <prism/memory.hpp>
#include "../src/prism/protocol/trojan/conn.cpp"
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::protocol::trojan::validate_command;
    using psm::protocol::trojan::parse_address_from_buffer;
    using psm::protocol::trojan::verify_credential;
    using psm::protocol::trojan::parse_request_target;
    using psm::protocol::trojan::command;
    using psm::protocol::trojan::address_type;
    using psm::protocol::trojan::config;

    void TestValidateCommandConnectAllowed(TestRunner &runner)
    {
        config cfg;
        cfg.enable_tcp = true;
        auto [ec, f] = validate_command(command::connect, cfg);
        runner.Check(ec == psm::fault::code::success, "validate: connect allowed");
    }

    void TestValidateCommandConnectForbidden(TestRunner &runner)
    {
        config cfg;
        cfg.enable_tcp = false;
        auto [ec, f] = validate_command(command::connect, cfg);
        runner.Check(ec == psm::fault::code::forbidden, "validate: connect forbidden");
    }

    void TestValidateCommandUdpAllowed(TestRunner &runner)
    {
        config cfg;
        cfg.enable_udp = true;
        auto [ec, f] = validate_command(command::udp_associate, cfg);
        runner.Check(ec == psm::fault::code::success, "validate: udp allowed");
    }

    void TestValidateCommandUdpForbidden(TestRunner &runner)
    {
        config cfg;
        cfg.enable_udp = false;
        auto [ec, f] = validate_command(command::udp_associate, cfg);
        runner.Check(ec == psm::fault::code::forbidden, "validate: udp forbidden");
    }

    void TestValidateCommandMux(TestRunner &runner)
    {
        config cfg;
        auto [ec, f] = validate_command(command::mux, cfg);
        runner.Check(ec == psm::fault::code::success, "validate: mux always allowed");
    }

    void TestValidateCommandUnknown(TestRunner &runner)
    {
        config cfg;
        auto [ec, f] = validate_command(static_cast<command>(0xFF), cfg);
        runner.Check(ec == psm::fault::code::unsupported_command, "validate: unknown cmd");
    }

    void TestParseAddressIPv4(TestRunner &runner)
    {
        std::array<std::uint8_t, 4> buf = {127, 0, 0, 1};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv4);
        runner.Check(ec == psm::fault::code::success, "parse_addr IPv4: success");
        runner.Check(sz == 4, "parse_addr IPv4: size=4");
    }

    void TestParseAddressIPv4TooShort(TestRunner &runner)
    {
        std::array<std::uint8_t, 2> buf = {127, 0};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv4);
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr IPv4: too short");
    }

    void TestParseAddressIPv6(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> buf{};
        buf[15] = 1;
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv6);
        runner.Check(ec == psm::fault::code::success, "parse_addr IPv6: success");
        runner.Check(sz == 16, "parse_addr IPv6: size=16");
    }

    void TestParseAddressIPv6TooShort(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> buf{};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv6);
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr IPv6: too short");
    }

    void TestParseAddressDomain(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(11);
        const char *name = "example.com";
        buf.insert(buf.end(), name, name + 11);
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::domain);
        runner.Check(ec == psm::fault::code::success, "parse_addr domain: success");
        runner.Check(sz == 12, "parse_addr domain: size=12");
    }

    void TestParseAddressDomainTooShort(TestRunner &runner)
    {
        std::array<std::uint8_t, 1> buf = {20};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::domain);
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr domain: too short");
    }

    void TestParseAddressDomainNoLen(TestRunner &runner)
    {
        std::array<std::uint8_t, 0> buf;
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::domain);
        runner.Check(ec == psm::fault::code::bad_message, "parse_addr domain: no len");
    }

    void TestParseAddressUnknown(TestRunner &runner)
    {
        std::array<std::uint8_t, 4> buf{};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, static_cast<address_type>(0xFF));
        runner.Check(ec == psm::fault::code::unsupported_address, "parse_addr: unknown atyp");
    }

    void TestVerifyCredentialSuccess(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf(58, 'a');
        for (int i = 0; i < 56; ++i)
            buf[i] = static_cast<std::uint8_t>('0' + (i % 10));
        buf[56] = '\r';
        buf[57] = '\n';

        std::array<char, 56> cred{};
        auto ec = verify_credential(buf, nullptr, cred);
        runner.Check(ec == psm::fault::code::success, "verify_cred: success no verifier");
        runner.Check(cred[0] == '0', "verify_cred: first char");
    }

    void TestVerifyCredentialWithVerifier(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf(58, 0);
        for (int i = 0; i < 56; ++i)
            buf[i] = static_cast<std::uint8_t>('a' + (i % 6));
        buf[56] = '\r';
        buf[57] = '\n';

        std::array<char, 56> cred{};
        bool called = false;
        auto verifier = [&called](std::string_view) -> bool
        {
            called = true;
            return true;
        };
        auto ec = verify_credential(buf, verifier, cred);
        runner.Check(ec == psm::fault::code::success, "verify_cred: verifier pass");
        runner.Check(called, "verify_cred: verifier called");
    }

    void TestVerifyCredentialVerifierRejects(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf(58, 0);
        for (int i = 0; i < 56; ++i)
            buf[i] = static_cast<std::uint8_t>('a' + (i % 6));
        buf[56] = '\r';
        buf[57] = '\n';

        std::array<char, 56> cred{};
        auto verifier = [](std::string_view) -> bool
        { return false; };
        auto ec = verify_credential(buf, verifier, cred);
        runner.Check(ec == psm::fault::code::auth_failed, "verify_cred: verifier rejects");
    }

    void TestVerifyCredentialBadCrlf(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf(58, 0);
        for (int i = 0; i < 56; ++i)
            buf[i] = static_cast<std::uint8_t>('a' + (i % 6));
        buf[56] = '\n';
        buf[57] = '\r';

        std::array<char, 56> cred{};
        auto ec = verify_credential(buf, nullptr, cred);
        runner.Check(ec == psm::fault::code::protocol_error, "verify_cred: bad crlf");
    }

    void TestVerifyCredentialBadHex(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf(58, 0);
        buf[0] = 'Z';
        buf[56] = '\r';
        buf[57] = '\n';

        std::array<char, 56> cred{};
        auto ec = verify_credential(buf, nullptr, cred);
        runner.Check(ec == psm::fault::code::protocol_error, "verify_cred: bad hex");
    }

    void TestParseRequestTargetIPv4(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(127);
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(1);
        buf.push_back(0x00);
        buf.push_back(0x50);
        buf.push_back('\r');
        buf.push_back('\n');

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, buf.size());
        runner.Check(ec == psm::fault::code::success, "target IPv4: success");
        runner.Check(port == 80, "target IPv4: port=80");
    }

    void TestParseRequestTargetPortTruncated(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(127);
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(1);
        buf.push_back(0x00);

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, buf.size());
        runner.Check(ec == psm::fault::code::bad_message, "target: port truncated");
    }

    void TestParseRequestTargetCrlfTruncated(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(127);
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(1);
        buf.push_back(0x00);
        buf.push_back(0x50);
        buf.push_back('\r');

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, buf.size());
        runner.Check(ec == psm::fault::code::bad_message, "target: crlf truncated");
    }

    void TestParseRequestTargetBadCrlf(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(127);
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(1);
        buf.push_back(0x00);
        buf.push_back(0x50);
        buf.push_back('\n');
        buf.push_back('\r');

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, buf.size());
        runner.Check(ec == psm::fault::code::protocol_error, "target: bad crlf");
    }

    void TestParseRequestTargetDomain(TestRunner &runner)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(11);
        const char *name = "example.com";
        buf.insert(buf.end(), name, name + 11);
        buf.push_back(0x01);
        buf.push_back(0xBB);
        buf.push_back('\r');
        buf.push_back('\n');

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::domain, buf.size());
        runner.Check(ec == psm::fault::code::success, "target domain: success");
        runner.Check(port == 443, "target domain: port=443");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrojanConnPure");

    TestValidateCommandConnectAllowed(runner);
    TestValidateCommandConnectForbidden(runner);
    TestValidateCommandUdpAllowed(runner);
    TestValidateCommandUdpForbidden(runner);
    TestValidateCommandMux(runner);
    TestValidateCommandUnknown(runner);
    TestParseAddressIPv4(runner);
    TestParseAddressIPv4TooShort(runner);
    TestParseAddressIPv6(runner);
    TestParseAddressIPv6TooShort(runner);
    TestParseAddressDomain(runner);
    TestParseAddressDomainTooShort(runner);
    TestParseAddressDomainNoLen(runner);
    TestParseAddressUnknown(runner);
    TestVerifyCredentialSuccess(runner);
    TestVerifyCredentialWithVerifier(runner);
    TestVerifyCredentialVerifierRejects(runner);
    TestVerifyCredentialBadCrlf(runner);
    TestVerifyCredentialBadHex(runner);
    TestParseRequestTargetIPv4(runner);
    TestParseRequestTargetPortTruncated(runner);
    TestParseRequestTargetCrlfTruncated(runner);
    TestParseRequestTargetBadCrlf(runner);
    TestParseRequestTargetDomain(runner);

    return runner.Summary();
}
