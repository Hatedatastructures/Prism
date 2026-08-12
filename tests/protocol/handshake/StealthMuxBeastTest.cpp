/**
 * @file StealthMuxBeastTest.cpp
 * @brief Reality/Stealth/Mux Beast 风格组件测试
 */

#include <common/reality/reality.hpp>
#include <common/shadowtls/shadowtls.hpp>
#include <common/restls/restls.hpp>
#include <common/anytls/anytls.hpp>
#include <common/trusttunnel/trusttunnel.hpp>
#include <common/ws/ws.hpp>
#include <common/gun/gun.hpp>
#include <common/mux/h2mux/session.hpp>
#include <common/mux/smux/session.hpp>
#include <common/mux/yamux/session.hpp>

#include <gtest/gtest.h>

#include <cstring>

namespace
{
    using namespace psmtest;
    using namespace psmtest::mux;

    TEST(RealityBeast, KeypairAndBase64)
    {
        std::array<std::uint8_t, 32> priv{};
        std::array<std::uint8_t, 32> pub{};
        EXPECT_FALSE(reality::generate_keypair(priv, pub));
        std::array<std::uint8_t, 32> derived{};
        EXPECT_FALSE(reality::derive_public_key(priv, derived));
        EXPECT_EQ(derived, pub);

        const std::string enc = reality::base64url_encode(priv);
        std::array<std::uint8_t, 32> parsed{};
        EXPECT_FALSE(reality::parse_private_key(enc, parsed));
        EXPECT_EQ(parsed, priv);

        std::array<std::uint8_t, 8> sid{};
        EXPECT_FALSE(reality::parse_short_id("45587ac66ce007e4", sid));
        EXPECT_EQ(sid[0], 0x45);
        EXPECT_EQ(sid[7], 0xE4);
        EXPECT_TRUE(reality::parse_short_id("xyz", sid));
    }

    TEST(ShadowTlsBeast, SessionIdRoundtrip)
    {
        const std::string password = "shadowtls_password";
        // 构造固定 ClientHello（含 TLS 头）：记录头 + 握手头 + version + random + sidLen + sid
        std::vector<std::uint8_t> hello(5 + shadowtls::session_id_start + 32 + 16, 0);
        hello[0] = 0x16;
        hello[5] = shadowtls::hs_type_clienthello;
        hello[5 + shadowtls::session_id_start - 1] = shadowtls::tls_session_id_sz;
        for (std::size_t i = 0; i < shadowtls::tls_rnd_size; ++i)
            hello[5 + 1 + 3 + 2 + i] = static_cast<std::uint8_t>(i);

        std::array<std::uint8_t, shadowtls::tls_session_id_sz> session_id{};
        for (std::size_t i = 0; i < shadowtls::tls_session_id_sz - shadowtls::hmac_size; ++i)
            session_id[i] = static_cast<std::uint8_t>(i * 7 + 3);
        const auto handshake = std::span<const std::uint8_t>(hello).subspan(shadowtls::tls_hdrsize);
        EXPECT_EQ(shadowtls::generate_session_id(password, handshake, session_id), error::none);
        std::memcpy(hello.data() + 5 + shadowtls::session_id_start, session_id.data(),
                    shadowtls::tls_session_id_sz);

        // 校验通过
        EXPECT_TRUE(shadowtls::verify_client_hello(
            password, std::span<const std::byte>(
                          reinterpret_cast<const std::byte *>(hello.data()), hello.size())));

        // 错误密码校验失败
        EXPECT_FALSE(shadowtls::verify_client_hello(
            "wrong_password", std::span<const std::byte>(
                                  reinterpret_cast<const std::byte *>(hello.data()), hello.size())));
    }

    TEST(RestlsBeast, AuthKeyDerivation)
    {
        const std::string password = "restls_password";
        const auto secret = restls::derive_secret(password);
        EXPECT_EQ(secret.size(), 32u);

        std::array<std::uint8_t, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i)
            server_random[i] = static_cast<std::uint8_t>(i);
        const auto mask = restls::compute_server_mask(secret, server_random);
        EXPECT_EQ(mask.size(), restls::hs_maclen);

        // 相同输入 → 相同输出
        const auto mask2 = restls::compute_server_mask(secret, server_random);
        EXPECT_EQ(mask, mask2);
    }

    TEST(AnyTlsBeast, AuthFrame)
    {
        const std::string password = "anytls_password";
        std::string frame;
        EXPECT_EQ(anytls::build_auth_frame(password, 16, frame), error::none);
        EXPECT_EQ(frame.size(), anytls::auth_frame_hdrlen + 16);

        std::array<std::uint8_t, anytls::password_hash_len> hash{};
        std::uint16_t pad_len = 0;
        EXPECT_EQ(anytls::parse_auth_frame(
                      std::span<const std::uint8_t>(
                          reinterpret_cast<const std::uint8_t *>(frame.data()), frame.size()),
                      hash, pad_len),
                  error::none);
        EXPECT_EQ(pad_len, 16u);
        EXPECT_TRUE(anytls::verify_auth(password, hash));
        EXPECT_FALSE(anytls::verify_auth("wrong", hash));
    }

    TEST(TrustTunnelBeast, BasicAuth)
    {
        const auto auth = trusttunnel::basic_auth("user", "pass");
        EXPECT_EQ(auth, "Basic dXNlcjpwYXNz");

        std::string user, pass;
        EXPECT_TRUE(trusttunnel::parse_basic_auth(auth, user, pass));
        EXPECT_EQ(user, "user");
        EXPECT_EQ(pass, "pass");
        EXPECT_TRUE(trusttunnel::verify_basic_auth(auth, "user", "pass"));
        EXPECT_FALSE(trusttunnel::verify_basic_auth(auth, "user", "wrong"));
        EXPECT_FALSE(trusttunnel::parse_basic_auth("Bearer token", user, pass));
    }

    TEST(WsBeast, AcceptAndFrame)
    {
        // Sec-WebSocket-Accept 标准测试向量（RFC 6455 示例）
        const auto accept = ws::compute_accept("dGhlIHNhbXBsZSBub25jZQ==");
        EXPECT_EQ(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

        // 帧编解码往返
        const std::string payload = "hello websocket";
        std::array<std::byte, 128> out{};
        const auto n = ws::encode_frame(ws::opcode::binary, true,
                                        std::span<const std::byte>(
                                            reinterpret_cast<const std::byte *>(payload.data()),
                                            payload.size()),
                                        out);
        EXPECT_GT(n, 0u);

        ws::frame_header hdr{};
        EXPECT_TRUE(ws::parse_frame_header(std::span<const std::byte>(out).first(n), hdr));
        EXPECT_TRUE(hdr.fin);
        EXPECT_EQ(hdr.opcode, static_cast<std::uint8_t>(ws::opcode::binary));
        EXPECT_FALSE(hdr.masked);
        EXPECT_EQ(hdr.payload_len, payload.size());
        EXPECT_EQ(hdr.header_len, 2u);
    }

    TEST(GunBeast, FrameRoundtrip)
    {
        const std::string payload = "hello gun grpc";
        const auto frame = gun::encode_frame(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));

        gun::frame_header hdr{};
        EXPECT_TRUE(gun::parse_frame_header(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(frame.data()), frame.size()),
            hdr));
        EXPECT_EQ(hdr.payload_len, payload.size());
        EXPECT_EQ(hdr.header_len + hdr.payload_len, frame.size());

        // varint 编解码
        std::array<std::uint8_t, 5> vb{};
        const auto vn = gun::encode_varint(300, vb);
        std::uint32_t val = 0;
        EXPECT_EQ(gun::decode_varint(std::span<const std::uint8_t>(vb).first(vn), val), vn);
        EXPECT_EQ(val, 300u);
    }

    TEST(MuxBeast, SmuxFrame)
    {
        const std::string payload = "smux data";
        const auto wire = smux::build_push(42, std::span<const std::uint8_t>(
                                                  reinterpret_cast<const std::uint8_t *>(payload.data()),
                                                  payload.size()));
        smux::frame_header out{};
        EXPECT_EQ(smux::parse_header(std::span<const std::uint8_t>(wire), out), error::none);
        EXPECT_EQ(out.cmd, smux::command::push);
        EXPECT_EQ(out.stream_id, 42u);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(wire.data() + smux::frame_hdrsize),
                              payload.size()),
                  payload);
    }

    TEST(MuxBeast, YamuxFrame)
    {
        const std::string payload = "yamux data";
        const auto wire = yamux::build_data(yamux::flags::ack, 7, std::span<const std::uint8_t>(
                                                                       reinterpret_cast<const std::uint8_t *>(payload.data()),
                                                                       payload.size()));
        yamux::frame_header out{};
        EXPECT_EQ(yamux::parse_header(std::span<const std::uint8_t>(wire), out), error::none);
        EXPECT_EQ(out.type, yamux::message_type::data);
        EXPECT_TRUE(yamux::has_flag(out.flag, yamux::flags::ack));
        EXPECT_EQ(out.stream_id, 7u);
    }

    TEST(MuxBeast, H2muxFrame)
    {
        const std::string payload = "h2mux data";
        const auto wire = h2mux::build(static_cast<h2mux::frame_type>(0x0A), 3,
                                       std::span<const std::uint8_t>(
                                           reinterpret_cast<const std::uint8_t *>(payload.data()),
                                           payload.size()));
        h2mux::frame_header out{};
        (void)h2mux::parse_header(std::span<const std::uint8_t>(wire), out);
        EXPECT_EQ(static_cast<std::uint8_t>(out.type), 0x0A);
        EXPECT_EQ(out.stream_id, 3u);
        EXPECT_EQ(out.length, payload.size());
    }

} // namespace
