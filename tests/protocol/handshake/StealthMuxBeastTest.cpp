/**
 * @file StealthMuxBeastTest.cpp
 * @brief Reality/Stealth/Mux Beast 风格组件测试
 */

#include <common/reality/reality.hpp>
#include <common/stealth/stealth.hpp>
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

    TEST(ShadowTlsBeast, FirstPacketRoundtrip)
    {
        const std::string password = "shadowtls_password";
        const std::array<std::uint8_t, 8> handshake{0x16, 0x03, 0x01, 0x00, 0x2A, 1, 2, 3};
        const std::string payload = "hello";

        std::string pkt;
        EXPECT_FALSE(shadowtls::build_first_packet(password, handshake,
                                                   std::span<const std::uint8_t>(
                                                       reinterpret_cast<const std::uint8_t *>(payload.data()),
                                                       payload.size()),
                                                   pkt));
        std::array<std::uint8_t, shadowtls::hash_len> hash{};
        std::size_t offset = 0;
        EXPECT_FALSE(shadowtls::parse_first_packet(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(pkt.data()), pkt.size()),
            hash, offset));
        EXPECT_EQ(offset, 5 + shadowtls::hash_len);

        std::array<std::uint8_t, shadowtls::hash_len> calc{};
        shadowtls::compute_hash(password, handshake, calc);
        EXPECT_EQ(hash, calc);
    }

    TEST(RestlsBeast, AuthPayload)
    {
        const std::string password = "restls_password";
        const std::array<std::uint8_t, 4> handshake{0x16, 0x03, 0x03, 0x2A};
        std::array<std::uint8_t, 32> key{};
        EXPECT_FALSE(restls::derive_auth_key(password, handshake, key));

        std::array<std::uint8_t, restls::auth_payload_len> payload{};
        EXPECT_FALSE(restls::build_auth_payload(1, key, payload));
        EXPECT_EQ(payload[0], 1);
        EXPECT_EQ(std::memcmp(payload.data() + 1, key.data(), 32), 0);
    }

    TEST(AnyTlsBeast, SessionKeyAndFrame)
    {
        const std::string secret = "tls-secret";
        std::array<std::uint8_t, 32> key1{};
        std::array<std::uint8_t, 32> key2{};
        const auto secret_span = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(secret.data()), secret.size());
        EXPECT_FALSE(anytls::derive_session_key(secret_span, {}, "ctx", key1));
        EXPECT_FALSE(anytls::derive_session_key(secret_span, {}, "ctx", key2));
        EXPECT_EQ(key1, key2);

        const std::array<std::uint8_t, 5> payload{1, 2, 3, 4, 5};
        std::string frame;
        EXPECT_FALSE(anytls::build_auth_frame(payload, frame));
        EXPECT_EQ(frame.size(), 7);
        EXPECT_EQ(frame[0], 0);
        EXPECT_EQ(frame[1], 5);
    }

    TEST(TrustTunnelBeast, BasicAuthAndHeaders)
    {
        std::string auth;
        EXPECT_FALSE(trusttunnel::basic_auth("user", "pass", auth));
        EXPECT_EQ(auth, "Basic dXNlcjpwYXNz");

        std::string headers;
        EXPECT_FALSE(trusttunnel::h2_connect_headers("example.com", 443, auth, headers));
        EXPECT_EQ(static_cast<std::uint8_t>(headers[0]), 0x80 | 7);
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
