/**
 * @file StealthMuxBeastTest.cpp
 * @brief Reality/Stealth/Mux Beast 风格组件测试
 */

#include <cstring>

#include <preview/Protocols/Mux/H2Mux/Session.hpp>
#include <preview/Protocols/Mux/Smux/Session.hpp>
#include <preview/Protocols/Mux/Yamux/Session.hpp>
#include <preview/Protocols/Anytls/Anytls.hpp>
#include <preview/Protocols/Gun/Gun.hpp>
#include <preview/Protocols/Reality/Reality.hpp>
#include <preview/Protocols/Restls/Restls.hpp>
#include <preview/Protocols/Shadowtls/Shadowtls.hpp>
#include <preview/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <preview/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    using namespace Preview::Mux;

    TEST(RealityBeast, KeypairAndBase64)
    {
        std::array<std::uint8_t, 32> priv{};
        std::array<std::uint8_t, 32> pub{};
        EXPECT_FALSE(Reality::GenerateKeypair(priv, pub));
        std::array<std::uint8_t, 32> derived{};
        EXPECT_FALSE(Reality::DerivePublicKey(priv, derived));
        EXPECT_EQ(derived, pub);

        const std::string enc = Reality::Base64urlEncode(priv);
        std::array<std::uint8_t, 32> Parsed{};
        EXPECT_FALSE(Reality::ParsePrivateKey(enc, Parsed));
        EXPECT_EQ(Parsed, priv);

        std::array<std::uint8_t, 8> sid{};
        EXPECT_FALSE(Reality::ParseShortId("45587ac66ce007e4", sid));
        EXPECT_EQ(sid[0], 0x45);
        EXPECT_EQ(sid[7], 0xE4);
        EXPECT_TRUE(Reality::ParseShortId("xyz", sid));
    }

    TEST(ShadowTlsBeast, SessionIdRoundtrip)
    {
        const std::string password = "shadowtls_password";
        // 构造固定 ClientHello（含 TLS 头）：记录头 + 握手头 + version + random + sidLen + sid
        std::vector<std::uint8_t> hello(5 + Shadowtls::SessionIdStart + 32 + 16, 0);
        hello[0] = 0x16;
        hello[5] = Shadowtls::HsTypeClienthello;
        hello[5 + Shadowtls::SessionIdStart - 1] = Shadowtls::TlsSessionIdSz;
        for (std::size_t i = 0; i < Shadowtls::TlsRndSize; ++i)
        {
            hello[5 + 1 + 3 + 2 + i] = static_cast<std::uint8_t>(i);
        }

        std::array<std::uint8_t, Shadowtls::TlsSessionIdSz> SessionId{};
        for (std::size_t i = 0; i < Shadowtls::TlsSessionIdSz - Shadowtls::HmacSize; ++i)
        {
            SessionId[i] = static_cast<std::uint8_t>(i * 7 + 3);
        }
        const auto handshake = std::span<const std::uint8_t>(hello).subspan(Shadowtls::TlsHdrsize);
        EXPECT_EQ(
            Shadowtls::GenerateSessionId(Shadowtls::SessionIdInput{password, handshake, SessionId}),
            Error::None);
        std::memcpy(hello.data() + 5 + Shadowtls::SessionIdStart, SessionId.data(),
                    Shadowtls::TlsSessionIdSz);

        // 校验通过
        EXPECT_TRUE(Shadowtls::VerifyClientHello(
            password,
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(hello.data()), hello.size())));

        // 错误密码校验失败
        EXPECT_FALSE(Shadowtls::VerifyClientHello(
            "wrong_password",
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(hello.data()), hello.size())));
    }

    TEST(RestlsBeast, AuthKeyDerivation)
    {
        const std::string password = "restls_password";
        const auto Secret = Restls::DeriveSecret(password);
        EXPECT_EQ(Secret.size(), 32u);

        std::array<std::uint8_t, 32> ServerRandom{};
        for (std::size_t i = 0; i < 32; ++i)
        {
            ServerRandom[i] = static_cast<std::uint8_t>(i);
        }
        const auto mask = Restls::ComputeServerMask(Secret, ServerRandom);
        EXPECT_EQ(mask.size(), Restls::HsMaclen);

        // 相同输入 → 相同输出
        const auto mask2 = Restls::ComputeServerMask(Secret, ServerRandom);
        EXPECT_EQ(mask, mask2);
    }

    TEST(AnyTlsBeast, AuthFrame)
    {
        const std::string password = "anytls_password";
        std::string Frame;
        EXPECT_EQ(Anytls::BuildAuthFrame(password, 16, Frame), Error::None);
        EXPECT_EQ(Frame.size(), Anytls::AuthFrameHdrlen + 16);

        std::array<std::uint8_t, Anytls::PasswordHashLen> Hash{};
        std::uint16_t PadLen = 0;
        EXPECT_EQ(
            Anytls::ParseAuthFrame(std::span<const std::uint8_t>(
                                         reinterpret_cast<const std::uint8_t *>(Frame.data()), Frame.size()),
                                     Hash, PadLen),
            Error::None);
        EXPECT_EQ(PadLen, 16u);
        EXPECT_TRUE(Anytls::VerifyAuth(password, Hash));
        EXPECT_FALSE(Anytls::VerifyAuth("wrong", Hash));
    }

    TEST(TrustTunnelBeast, BasicAuth)
    {
        const auto Auth = Trusttunnel::BasicAuth("user", "pass");
        EXPECT_EQ(Auth, "Basic dXNlcjpwYXNz");

        std::string user, pass;
        EXPECT_TRUE(Trusttunnel::ParseBasicAuth(Auth, user, pass));
        EXPECT_EQ(user, "user");
        EXPECT_EQ(pass, "pass");
        EXPECT_TRUE(Trusttunnel::VerifyBasicAuth(Auth, "user", "pass"));
        EXPECT_FALSE(Trusttunnel::VerifyBasicAuth(Auth, "user", "wrong"));
        EXPECT_FALSE(Trusttunnel::ParseBasicAuth("Bearer token", user, pass));
    }

    TEST(WsBeast, AcceptAndFrame)
    {
        // Sec-WebSocket-Accept 标准测试向量（RFC 6455 示例）
        const auto Accept = Ws::ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
        EXPECT_EQ(Accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

        // 帧编解码往返
        const std::string payload = "hello websocket";
        std::array<std::byte, 128> out{};
        const auto n = Ws::EncodeFrame(
            Ws::FrameInput{Ws::Opcode::Binary, true,
                            std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                       payload.size())},
            out);
        EXPECT_GT(n, 0u);

        Ws::FrameHeader hdr{};
        EXPECT_TRUE(Ws::ParseFrameHeader(std::span<const std::byte>(out).first(n), hdr));
        EXPECT_TRUE(hdr.Fin);
        EXPECT_EQ(hdr.Opcode, static_cast<std::uint8_t>(Ws::Opcode::Binary));
        EXPECT_FALSE(hdr.Masked);
        EXPECT_EQ(hdr.PayloadLen, payload.size());
        EXPECT_EQ(hdr.HeaderLen, 2u);
    }

    TEST(GunBeast, FrameRoundtrip)
    {
        const std::string payload = "hello gun grpc";
        const auto Frame = Gun::EncodeFrame(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));

        Gun::FrameHeader hdr{};
        EXPECT_TRUE(Gun::ParseFrameHeader(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Frame.data()), Frame.size()),
            hdr));
        EXPECT_EQ(hdr.PayloadLen, payload.size());
        EXPECT_EQ(hdr.HeaderLen + hdr.PayloadLen, Frame.size());

        // varint 编解码
        std::array<std::uint8_t, 5> vb{};
        const auto vn = Gun::EncodeVarint(300, vb);
        std::uint32_t val = 0;
        EXPECT_EQ(Gun::DecodeVarint(std::span<const std::uint8_t>(vb).first(vn), val), vn);
        EXPECT_EQ(val, 300u);
    }

    TEST(MuxBeast, SmuxFrame)
    {
        const std::string payload = "smux Data";
        const auto wire =
            Smux::BuildPush(42, std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
        Smux::FrameHeader out{};
        EXPECT_EQ(Smux::ParseHeader(std::span<const std::uint8_t>(wire), out), Error::None);
        EXPECT_EQ(out.cmd, Smux::Command::Push);
        EXPECT_EQ(out.StreamId, 42u);
        EXPECT_EQ(
            std::string(reinterpret_cast<const char *>(wire.data() + Smux::FrameHdrsize), payload.size()),
            payload);
    }

    TEST(MuxBeast, YamuxFrame)
    {
        const std::string payload = "yamux Data";
        const auto wire =
            Yamux::BuildData(Yamux::Flags::Ack, 7,
                              std::span<const std::uint8_t>(
                                  reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));
        Yamux::FrameHeader out{};
        EXPECT_EQ(Yamux::ParseHeader(std::span<const std::uint8_t>(wire), out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::Data);
        EXPECT_TRUE(Yamux::HasFlag(out.flag, Yamux::Flags::Ack));
        EXPECT_EQ(out.StreamId, 7u);
    }

    TEST(MuxBeast, H2muxFrame)
    {
        const std::string payload = "h2mux Data";
        const auto wire =
            H2Mux::Build(static_cast<H2Mux::FrameType>(0x0A), 3,
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()),
                                                       payload.size()));
        H2Mux::FrameHeader out{};
        (void)H2Mux::ParseHeader(std::span<const std::uint8_t>(wire), out);
        EXPECT_EQ(static_cast<std::uint8_t>(out.Type), 0x0A);
        EXPECT_EQ(out.StreamId, 3u);
        EXPECT_EQ(out.length, payload.size());
    }

} // namespace
