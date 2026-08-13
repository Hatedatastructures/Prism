/**
 * @file VmessHeader.cpp
 * @brief VMess 指令头编解码测试
 * @details 验证 seal_request/open_request 往返与响应头构造。
 */

#include <prism/protocol/vmess/codec/auth.hpp>
#include <prism/protocol/vmess/codec/header.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>

#include <cstring>

#include <gtest/gtest.h>

namespace
{
    using psm::protocol::vmess::codec::build_response;
    using psm::protocol::vmess::codec::cmd_key_from_uuid;
    using psm::protocol::vmess::codec::open_request;
    using psm::protocol::vmess::codec::parse_uuid;
    using psm::protocol::vmess::codec::request_header;
    using psm::protocol::vmess::codec::seal_request;

    auto test_cmd_key() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> uuid_bytes{};
        parse_uuid("123e4567-e89b-12d3-a456-426614174000", uuid_bytes);
        return cmd_key_from_uuid(uuid_bytes);
    }

    auto make_header() -> request_header
    {
        request_header header;
        header.version = psm::protocol::vmess::version;
        header.request_nonce.fill(0x11);
        header.request_key.fill(0x22);
        header.response_header = 0x77;
        header.option = static_cast<std::uint8_t>(psm::protocol::vmess::option::chunk_stream) |
                        static_cast<std::uint8_t>(psm::protocol::vmess::option::chunk_masking);
        header.security = static_cast<std::uint8_t>(psm::protocol::vmess::security::aes_128_gcm);
        header.command = static_cast<std::uint8_t>(psm::protocol::vmess::command::tcp);
        header.destination =
            psm::protocol::common::domain_address{.length = 11,
                                                  .value = []
                                                  {
                                                      std::array<char, 255> v{};
                                                      std::memcpy(v.data(), "example.com", 11);
                                                      return v;
                                                  }()};
        header.port = 443;
        return header;
    }
} // namespace

TEST(VmessHeader, SealOpenRoundtripDomain)
{
    const auto cmd_key = test_cmd_key();
    const auto header = make_header();

    std::array<std::uint8_t, 512> packet{};
    const auto ec = seal_request(std::span<const std::uint8_t, 16>(cmd_key.data(), 16), header, packet);
    ASSERT_EQ(ec, psm::fault::code::success);

    request_header out;
    std::array<std::uint8_t, 8> conn_nonce{};
    const auto open_ec = open_request(std::span<const std::uint8_t, 16>(cmd_key.data(), 16),
                                      std::span<const std::uint8_t>(packet.data(), 512), conn_nonce, out);
    ASSERT_EQ(open_ec, psm::fault::code::success);

    EXPECT_EQ(out.version, psm::protocol::vmess::version);
    EXPECT_EQ(out.request_nonce, header.request_nonce);
    EXPECT_EQ(out.request_key, header.request_key);
    EXPECT_EQ(out.response_header, header.response_header);
    EXPECT_EQ(out.option, header.option);
    EXPECT_EQ(out.security, header.security);
    EXPECT_EQ(out.command, header.command);
    EXPECT_EQ(out.port, 443U);
    const auto *dom = std::get_if<psm::protocol::common::domain_address>(&out.destination);
    ASSERT_NE(dom, nullptr);
    EXPECT_EQ(std::string_view(dom->value.data(), dom->length), "example.com");
}

TEST(VmessHeader, SealOpenRoundtripIpv4)
{
    const auto cmd_key = test_cmd_key();
    auto header = make_header();
    header.destination = psm::protocol::common::ipv4_address{{1, 2, 3, 4}};
    header.port = 8080;

    std::array<std::uint8_t, 512> packet{};
    seal_request(std::span<const std::uint8_t, 16>(cmd_key.data(), 16), header, packet);

    request_header out;
    std::array<std::uint8_t, 8> conn_nonce{};
    const auto open_ec = open_request(std::span<const std::uint8_t, 16>(cmd_key.data(), 16),
                                      std::span<const std::uint8_t>(packet.data(), 512), conn_nonce, out);
    ASSERT_EQ(open_ec, psm::fault::code::success);
    EXPECT_EQ(out.port, 8080U);
    const auto *ip4 = std::get_if<psm::protocol::common::ipv4_address>(&out.destination);
    ASSERT_NE(ip4, nullptr);
    EXPECT_EQ(ip4->bytes[0], 1);
    EXPECT_EQ(ip4->bytes[3], 4);
}

TEST(VmessHeader, WrongKeyOpenFails)
{
    const auto cmd_key = test_cmd_key();
    const auto header = make_header();

    std::array<std::uint8_t, 512> packet{};
    seal_request(std::span<const std::uint8_t, 16>(cmd_key.data(), 16), header, packet);

    std::array<std::uint8_t, 16> wrong{};
    wrong.fill(0x99);
    request_header out;
    std::array<std::uint8_t, 8> conn_nonce{};
    const auto open_ec = open_request(std::span<const std::uint8_t, 16>(wrong.data(), 16),
                                      std::span<const std::uint8_t>(packet.data(), 512), conn_nonce, out);
    EXPECT_NE(open_ec, psm::fault::code::success);
}

TEST(VmessHeader, ResponseHeaderBuilds)
{
    std::array<std::uint8_t, 16> req_key{};
    std::array<std::uint8_t, 16> req_nonce{};
    req_key.fill(0x33);
    req_nonce.fill(0x44);

    std::array<std::uint8_t, 38> resp{};
    const auto ec = build_response(std::span<const std::uint8_t, 16>(req_key.data(), 16),
                                   std::span<const std::uint8_t, 16>(req_nonce.data(), 16), 0x77, 0x05, false,
                                   std::span<std::uint8_t>(resp.data(), resp.size()));
    ASSERT_EQ(ec, psm::fault::code::success);
    // 38 字节非全零
    bool non_zero = false;
    for (const auto byte : resp)
    {
        non_zero = non_zero || byte != 0;
    }
    EXPECT_TRUE(non_zero);
}
