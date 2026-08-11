/**
 * @file VmessBeastTest.cpp
 * @brief VMess Beast 风格组件测试
 */

#include <common/vmess/vmess.hpp>

#include <gtest/gtest.h>

#include <ctime>

namespace
{
    using namespace psmtest;

    constexpr std::array<std::uint8_t, 16> kUuid{
        0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
        0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};

    TEST(VmessBeast, HandshakeRoundtrip)
    {
        vmess::message msg;
        msg.uuid = kUuid;
        msg.request_nonce.fill(0x11);
        msg.request_key.fill(0x22);
        msg.cmd = vmess::cmd_tcp;
        msg.dst.type = vmess::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;

        vmess::serializer s(kUuid);
        s.reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(s.is_done());

        vmess::parser p(kUuid);
        const auto n = p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, total);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().cmd, vmess::cmd_tcp);
        EXPECT_EQ(p.get().dst.host, "127.0.0.1");
        EXPECT_EQ(p.get().dst.port, 8080);
    }

    TEST(VmessBeast, WrongUuidRejected)
    {
        constexpr std::array<std::uint8_t, 16> other{
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
            0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44};
        vmess::message msg;
        msg.uuid = other;
        msg.request_nonce.fill(0x11);
        msg.request_key.fill(0x22);
        msg.cmd = vmess::cmd_tcp;
        msg.dst.type = vmess::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;

        vmess::serializer s(other);
        s.reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        vmess::parser p(kUuid);
        p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_EQ(ec, error::auth_failed);
    }

    TEST(VmessBeast, ChunkStreamRoundtrip)
    {
        std::array<std::uint8_t, 16> key{};
        key.fill(0x11);
        std::array<std::uint8_t, 16> iv{};
        iv.fill(0x22);

        vmess::chunk_stream enc;
        enc.init(key, iv);
        vmess::chunk_stream dec;
        dec.init(key, iv);

        const std::string payload = "vmess chunk payload";
        std::string wire;
        EXPECT_FALSE(enc.encrypt(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
            wire));

        std::string plain;
        const auto r = dec.decrypt(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(wire.data()), wire.size()),
            plain);
        EXPECT_FALSE(r.ec);
        EXPECT_EQ(r.consumed, wire.size());
        EXPECT_EQ(plain, payload);
    }

    TEST(VmessBeast, ResponseHeader)
    {
        vmess::message msg{};
        msg.request_key.fill(0x11);
        msg.request_nonce.fill(0x22);
        msg.resp_header = 0x77;
        std::string resp;
        EXPECT_FALSE(vmess::make_response(msg, resp));
        EXPECT_EQ(resp.size(), 38);
    }

} // namespace
