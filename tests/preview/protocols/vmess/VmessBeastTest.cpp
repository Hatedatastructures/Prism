/**
 * @file VmessBeastTest.cpp
 * @brief VMess Beast 风格组件测试
 */

#include <ctime>

#include <common/Protocols/Vmess/Vmess.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    constexpr std::array<std::uint8_t, 16> kUuid{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                 0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};

    TEST(VmessBeast, HandshakeRoundtrip)
    {
        Vmess::Message msg;
        msg.uuid = kUuid;
        msg.RequestNonce.fill(0x11);
        msg.RequestKey.fill(0x22);
        msg.Cmd = Vmess::CmdTcp;
        msg.dst.Type = Vmess::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;

        Vmess::Serializer s(kUuid);
        s.Reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(s.IsDone());

        Vmess::Parser p(kUuid);
        const auto n = p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, Total);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Cmd, Vmess::CmdTcp);
        EXPECT_EQ(p.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(p.Get().dst.Port, 8080);
    }

    TEST(VmessBeast, WrongUuidRejected)
    {
        constexpr std::array<std::uint8_t, 16> other{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
                                                     0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44};
        Vmess::Message msg;
        msg.uuid = other;
        msg.RequestNonce.fill(0x11);
        msg.RequestKey.fill(0x22);
        msg.Cmd = static_cast<std::uint8_t>(static_cast<std::uint8_t>(Vmess::Command::Tcp));
        msg.dst.Type = Vmess::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;

        Vmess::Serializer s(other);
        s.Reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Vmess::Parser p(kUuid);
        p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_EQ(ec, Error::AuthFailed);
    }

    TEST(VmessBeast, ChunkStreamRoundtrip)
    {
        std::array<std::uint8_t, 16> key{};
        key.fill(0x11);
        std::array<std::uint8_t, 16> iv{};
        iv.fill(0x22);

        Vmess::ChunkStream enc;
        enc.Init(key, iv);
        Vmess::ChunkStream dec;
        dec.Init(key, iv);

        const std::string payload = "vmess chunk payload";
        std::string wire;
        EXPECT_FALSE(enc.Encrypt(std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
                                 wire));

        std::string plain;
        const auto r = dec.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(wire.data()), wire.size()),
            plain);
        EXPECT_FALSE(r.Ec);
        EXPECT_EQ(r.Consumed, wire.size());
        EXPECT_EQ(plain, payload);
    }

    TEST(VmessBeast, ResponseHeader)
    {
        Vmess::Message msg{};
        msg.RequestKey.fill(0x11);
        msg.RequestNonce.fill(0x22);
        msg.RespHeader = 0x77;
        std::string resp;
        EXPECT_FALSE(Vmess::MakeResponse(msg, resp));
        EXPECT_EQ(resp.size(), 38);
    }

} // namespace
