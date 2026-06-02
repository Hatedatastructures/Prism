/**
 * @file TrojanConnPure.cpp
 * @brief Trojan conn 纯函数测试
 * @details 测试 validate_command/parse_address_from_buffer/verify_credential/parse_request_target
 */

#include <prism/memory.hpp>
#include "../src/prism/protocol/trojan/conn.cpp"
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>


#include <gtest/gtest.h>

namespace
{
    using psm::protocol::trojan::validate_command;
    using psm::protocol::trojan::parse_address_from_buffer;
    using psm::protocol::trojan::verify_credential;
    using psm::protocol::trojan::parse_request_target;
    using psm::protocol::trojan::command;
    using psm::protocol::trojan::address_type;
    using psm::protocol::trojan::config;

    TEST(TrojanConnPure, ValidateCommandConnectAllowed)
    {
        config cfg;
        cfg.enable_tcp = true;
        auto [ec, f] = validate_command(command::connect, cfg);
        EXPECT_TRUE(ec == psm::fault::code::success) << "validate: connect allowed";
    }

    TEST(TrojanConnPure, ValidateCommandConnectForbidden)
    {
        config cfg;
        cfg.enable_tcp = false;
        auto [ec, f] = validate_command(command::connect, cfg);
        EXPECT_TRUE(ec == psm::fault::code::forbidden) << "validate: connect forbidden";
    }

    TEST(TrojanConnPure, ValidateCommandUdpAllowed)
    {
        config cfg;
        cfg.enable_udp = true;
        auto [ec, f] = validate_command(command::udp_associate, cfg);
        EXPECT_TRUE(ec == psm::fault::code::success) << "validate: udp allowed";
    }

    TEST(TrojanConnPure, ValidateCommandUdpForbidden)
    {
        config cfg;
        cfg.enable_udp = false;
        auto [ec, f] = validate_command(command::udp_associate, cfg);
        EXPECT_TRUE(ec == psm::fault::code::forbidden) << "validate: udp forbidden";
    }

    TEST(TrojanConnPure, ValidateCommandMux)
    {
        config cfg;
        auto [ec, f] = validate_command(command::mux, cfg);
        EXPECT_TRUE(ec == psm::fault::code::success) << "validate: mux always allowed";
    }

    TEST(TrojanConnPure, ValidateCommandUnknown)
    {
        config cfg;
        auto [ec, f] = validate_command(static_cast<command>(0xFF), cfg);
        EXPECT_TRUE(ec == psm::fault::code::unsupported_command) << "validate: unknown cmd";
    }

    TEST(TrojanConnPure, ParseAddressIPv4)
    {
        std::array<std::uint8_t, 4> buf = {127, 0, 0, 1};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv4);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_addr IPv4: success";
        EXPECT_TRUE(sz == 4) << "parse_addr IPv4: size=4";
    }

    TEST(TrojanConnPure, ParseAddressIPv4TooShort)
    {
        std::array<std::uint8_t, 2> buf = {127, 0};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv4);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_addr IPv4: too short";
    }

    TEST(TrojanConnPure, ParseAddressIPv6)
    {
        std::array<std::uint8_t, 16> buf{};
        buf[15] = 1;
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv6);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_addr IPv6: success";
        EXPECT_TRUE(sz == 16) << "parse_addr IPv6: size=16";
    }

    TEST(TrojanConnPure, ParseAddressIPv6TooShort)
    {
        std::array<std::uint8_t, 8> buf{};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::ipv6);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_addr IPv6: too short";
    }

    TEST(TrojanConnPure, ParseAddressDomain)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(11);
        const char *name = "example.com";
        buf.insert(buf.end(), name, name + 11);
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::domain);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_addr domain: success";
        EXPECT_TRUE(sz == 12) << "parse_addr domain: size=12";
    }

    TEST(TrojanConnPure, ParseAddressDomainTooShort)
    {
        std::array<std::uint8_t, 1> buf = {20};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::domain);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_addr domain: too short";
    }

    TEST(TrojanConnPure, ParseAddressDomainNoLen)
    {
        std::array<std::uint8_t, 0> buf;
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, address_type::domain);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_addr domain: no len";
    }

    TEST(TrojanConnPure, ParseAddressUnknown)
    {
        std::array<std::uint8_t, 4> buf{};
        auto [ec, addr, sz] = parse_address_from_buffer(buf, 0, static_cast<address_type>(0xFF));
        EXPECT_TRUE(ec == psm::fault::code::unsupported_address) << "parse_addr: unknown atyp";
    }

    TEST(TrojanConnPure, VerifyCredentialSuccess)
    {
        std::vector<std::uint8_t> buf(58, 'a');
        for (int i = 0; i < 56; ++i)
            buf[i] = static_cast<std::uint8_t>('0' + (i % 10));
        buf[56] = '\r';
        buf[57] = '\n';

        std::array<char, 56> cred{};
        auto ec = verify_credential(buf, nullptr, cred);
        EXPECT_TRUE(ec == psm::fault::code::success) << "verify_cred: success no verifier";
        EXPECT_TRUE(cred[0] == '0') << "verify_cred: first char";
    }

    TEST(TrojanConnPure, VerifyCredentialWithVerifier)
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
        EXPECT_TRUE(ec == psm::fault::code::success) << "verify_cred: verifier pass";
        EXPECT_TRUE(called) << "verify_cred: verifier called";
    }

    TEST(TrojanConnPure, VerifyCredentialVerifierRejects)
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
        EXPECT_TRUE(ec == psm::fault::code::auth_failed) << "verify_cred: verifier rejects";
    }

    TEST(TrojanConnPure, VerifyCredentialBadCrlf)
    {
        std::vector<std::uint8_t> buf(58, 0);
        for (int i = 0; i < 56; ++i)
            buf[i] = static_cast<std::uint8_t>('a' + (i % 6));
        buf[56] = '\n';
        buf[57] = '\r';

        std::array<char, 56> cred{};
        auto ec = verify_credential(buf, nullptr, cred);
        EXPECT_TRUE(ec == psm::fault::code::protocol_error) << "verify_cred: bad crlf";
    }

    TEST(TrojanConnPure, VerifyCredentialBadHex)
    {
        std::vector<std::uint8_t> buf(58, 0);
        buf[0] = 'Z';
        buf[56] = '\r';
        buf[57] = '\n';

        std::array<char, 56> cred{};
        auto ec = verify_credential(buf, nullptr, cred);
        EXPECT_TRUE(ec == psm::fault::code::protocol_error) << "verify_cred: bad hex";
    }

    TEST(TrojanConnPure, ParseRequestTargetIPv4)
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
        EXPECT_TRUE(ec == psm::fault::code::success) << "target IPv4: success";
        EXPECT_TRUE(port == 80) << "target IPv4: port=80";
    }

    TEST(TrojanConnPure, ParseRequestTargetPortTruncated)
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(127);
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(1);
        buf.push_back(0x00);

        auto [ec, addr, port] = parse_request_target(buf, 0, address_type::ipv4, buf.size());
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "target: port truncated";
    }

    TEST(TrojanConnPure, ParseRequestTargetCrlfTruncated)
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
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "target: crlf truncated";
    }

    TEST(TrojanConnPure, ParseRequestTargetBadCrlf)
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
        EXPECT_TRUE(ec == psm::fault::code::protocol_error) << "target: bad crlf";
    }

    TEST(TrojanConnPure, ParseRequestTargetDomain)
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
        EXPECT_TRUE(ec == psm::fault::code::success) << "target domain: success";
        EXPECT_TRUE(port == 443) << "target domain: port=443";
    }
} // namespace
