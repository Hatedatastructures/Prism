/**
 * @file TlsSignalParse.cpp
 * @brief TLS ClientHello 解析器纯函数测试 — parse_client_hello 分支覆盖
 */

#include <prism/foundation/foundation.hpp>
#include <prism/proto/protocol/tls/types.hpp>
#include <prism/stealth/recognition/tls/signal.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <cstring>

namespace
{
    namespace tls_proto = psm::protocol::tls;
    using psm::recognition::tls::parse_client_hello;

    auto build_minimal_client_hello() -> std::vector<std::uint8_t>
    {
        // TLS record header (5 bytes)
        // ContentType=0x16 (Handshake), Version=0x0301, Length=varies
        // Handshake: type=0x01 (ClientHello), length(3 bytes)
        // ClientVersion: 0x0303
        // Random: 32 bytes of 0x42
        // SessionID: length=0
        // CipherSuites: length=2, one suite 0x1301
        // Compression: length=1, 0x00
        // Extensions: length=0

        std::vector<std::uint8_t> buf;
        // Record header
        buf.push_back(tls_proto::CT_HANDSHAKE);  // content type
        buf.push_back(0x03); buf.push_back(0x01); // version TLS 1.0 (record layer)
        buf.push_back(0x00); buf.push_back(0x00); // length placeholder (index 3-4)

        auto body_start = buf.size();
        // Handshake header
        buf.push_back(tls_proto::HS_CLIENT_HELLO);
        buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00); // length placeholder

        auto msg_start = buf.size();
        // ClientVersion
        buf.push_back(0x03); buf.push_back(0x03);
        // Random (32 bytes)
        for (int i = 0; i < 32; ++i) buf.push_back(0x42);
        // SessionID: length=0
        buf.push_back(0x00);
        // CipherSuites: length=2
        buf.push_back(0x00); buf.push_back(0x02);
        buf.push_back(0x13); buf.push_back(0x01); // TLS_AES_128_GCM_SHA256
        // Compression: length=1, null
        buf.push_back(0x01); buf.push_back(0x00);
        // No extensions

        auto msg_end = buf.size();
        auto handshake_len = msg_end - msg_start;

        // Fix handshake length
        buf[body_start + 1] = static_cast<std::uint8_t>((handshake_len >> 16) & 0xFF);
        buf[body_start + 2] = static_cast<std::uint8_t>((handshake_len >> 8) & 0xFF);
        buf[body_start + 3] = static_cast<std::uint8_t>(handshake_len & 0xFF);

        auto record_len = buf.size() - 5;
        buf[3] = static_cast<std::uint8_t>((record_len >> 8) & 0xFF);
        buf[4] = static_cast<std::uint8_t>(record_len & 0xFF);

        return buf;
    }

    auto append_sni_extension(std::vector<std::uint8_t> &buf, const std::string &hostname) -> void
    {
        // Extension: SNI (type=0x0000)
        // SNI entry: type=0x00 (hostname), length, name bytes
        auto name_len = static_cast<std::uint16_t>(hostname.size());
        auto list_entry_len = static_cast<std::uint16_t>(1 + 2 + name_len);
        auto list_len = list_entry_len;
        auto ext_len = static_cast<std::uint16_t>(2 + list_len);

        buf.push_back(0x00); buf.push_back(0x00); // ext type = SNI
        buf.push_back(static_cast<std::uint8_t>((ext_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(ext_len & 0xFF));
        // SNI list length
        buf.push_back(static_cast<std::uint8_t>((list_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(list_len & 0xFF));
        // Entry
        buf.push_back(0x00); // host_name type
        buf.push_back(static_cast<std::uint8_t>((name_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(name_len & 0xFF));
        for (auto c : hostname) buf.push_back(static_cast<std::uint8_t>(c));
    }

    auto append_x25519_key_share(std::vector<std::uint8_t> &buf, const std::array<std::uint8_t, 32> &key) -> void
    {
        auto key_len = static_cast<std::uint16_t>(key.size());
        auto entry_len = static_cast<std::uint16_t>(2 + 2 + key_len);
        auto ext_len = static_cast<std::uint16_t>(2 + entry_len);

        buf.push_back(static_cast<std::uint8_t>((tls_proto::EXT_KEY_SHARE >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::EXT_KEY_SHARE & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((ext_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(ext_len & 0xFF));
        // KeyShare list length
        buf.push_back(static_cast<std::uint8_t>((entry_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(entry_len & 0xFF));
        // Named group = X25519
        buf.push_back(static_cast<std::uint8_t>((tls_proto::GROUP_X25519 >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::GROUP_X25519 & 0xFF));
        // Key length
        buf.push_back(static_cast<std::uint8_t>((key_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(key_len & 0xFF));
        // Key data
        for (auto b : key) buf.push_back(b);
    }

    auto append_versions_extension(std::vector<std::uint8_t> &buf, const std::vector<std::uint16_t> &versions) -> void
    {
        auto list_len = static_cast<std::uint8_t>(versions.size() * 2);
        auto ext_len = static_cast<std::uint16_t>(1 + list_len);

        buf.push_back(static_cast<std::uint8_t>((tls_proto::EXT_SUPPORTED_VERSIONS >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::EXT_SUPPORTED_VERSIONS & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((ext_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(ext_len & 0xFF));
        buf.push_back(list_len);
        for (auto v : versions)
        {
            buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
            buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
        }
    }

    auto append_ech_extension(std::vector<std::uint8_t> &buf) -> void
    {
        // ECH extension with empty payload
        buf.push_back(static_cast<std::uint8_t>((tls_proto::EXT_ENCRYPTED_CLIENT_HELLO >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::EXT_ENCRYPTED_CLIENT_HELLO & 0xFF));
        buf.push_back(0x00); buf.push_back(0x00); // length=0
    }

    auto finalize_with_extensions(std::vector<std::uint8_t> &buf, std::size_t extensions_start) -> void
    {
        auto ext_total_len = buf.size() - extensions_start;
        // Insert 2-byte extension total length before the extensions
        buf.insert(buf.begin() + extensions_start, static_cast<std::uint8_t>(ext_total_len & 0xFF));
        buf.insert(buf.begin() + extensions_start, static_cast<std::uint8_t>((ext_total_len >> 8) & 0xFF));

        // Update handshake length (offset at 6,7,8)
        auto handshake_len = buf.size() - 9; // after record header + handshake type + length
        buf[6] = static_cast<std::uint8_t>((handshake_len >> 16) & 0xFF);
        buf[7] = static_cast<std::uint8_t>((handshake_len >> 8) & 0xFF);
        buf[8] = static_cast<std::uint8_t>(handshake_len & 0xFF);

        // Update record length (offset at 3,4)
        auto record_len = buf.size() - 5;
        buf[3] = static_cast<std::uint8_t>((record_len >> 8) & 0xFF);
        buf[4] = static_cast<std::uint8_t>(record_len & 0xFF);
    }

    TEST(TlsSignalParse, TooShort)
    {
        std::vector<std::uint8_t> short_buf(10, 0x16);
        auto [ec, features] = parse_client_hello({short_buf.data(), short_buf.size()});
        EXPECT_TRUE(psm::fault::failed(ec)) << "parse: too short -> error";
    }

    TEST(TlsSignalParse, NotHandshake)
    {
        auto buf = build_minimal_client_hello();
        buf[0] = 0x17; // Application Data, not handshake
        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(psm::fault::failed(ec)) << "parse: not handshake -> error";
    }

    TEST(TlsSignalParse, NotClientHello)
    {
        auto buf = build_minimal_client_hello();
        buf[5] = 0x02; // ServerHello, not ClientHello
        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(psm::fault::failed(ec)) << "parse: not ClientHello -> error";
    }

    TEST(TlsSignalParse, TruncatedBody)
    {
        auto buf = build_minimal_client_hello();
        // Set record body length larger than actual data
        buf[3] = 0xFF; buf[4] = 0xFF;
        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(psm::fault::failed(ec)) << "parse: truncated body -> error";
    }

    TEST(TlsSignalParse, MinimalValid)
    {
        auto buf = build_minimal_client_hello();
        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(!psm::fault::failed(ec)) << "parse: minimal valid -> success";
        EXPECT_TRUE(features.server_name.empty()) << "parse: minimal SNI empty";
        EXPECT_TRUE(!features.has_x25519) << "parse: minimal no x25519";
        EXPECT_TRUE(features.versions.empty()) << "parse: minimal no versions";
        EXPECT_TRUE(features.random[0] == 0x42) << "parse: minimal random[0]=0x42";
        EXPECT_TRUE(features.session_id_len == 0) << "parse: minimal session_id_len=0";
    }

    TEST(TlsSignalParse, WithSNI)
    {
        auto buf = build_minimal_client_hello();
        auto ext_start = buf.size();
        append_sni_extension(buf, "example.com");
        finalize_with_extensions(buf, ext_start);

        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(!psm::fault::failed(ec)) << "parse: SNI -> success";
        EXPECT_TRUE(features.server_name == "example.com") << "parse: SNI = example.com";
    }

    TEST(TlsSignalParse, WithX25519)
    {
        std::array<std::uint8_t, 32> key{};
        key[0] = 0xDE; key[31] = 0xAD;

        auto buf = build_minimal_client_hello();
        auto ext_start = buf.size();
        append_x25519_key_share(buf, key);
        finalize_with_extensions(buf, ext_start);

        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(!psm::fault::failed(ec)) << "parse: x25519 -> success";
        EXPECT_TRUE(features.has_x25519) << "parse: has_x25519=true";
        EXPECT_TRUE(features.x25519_key[0] == 0xDE) << "parse: x25519_key[0]=0xDE";
        EXPECT_TRUE(features.x25519_key[31] == 0xAD) << "parse: x25519_key[31]=0xAD";
    }

    TEST(TlsSignalParse, WithVersions)
    {
        auto buf = build_minimal_client_hello();
        auto ext_start = buf.size();
        append_versions_extension(buf, {tls_proto::VERSION_TLS12, tls_proto::VERSION_TLS13});
        finalize_with_extensions(buf, ext_start);

        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(!psm::fault::failed(ec)) << "parse: versions -> success";
        EXPECT_TRUE(features.versions.size() == 2) << "parse: 2 versions";
        EXPECT_TRUE(features.versions[0] == tls_proto::VERSION_TLS12) << "parse: versions[0]=TLS1.2";
        EXPECT_TRUE(features.versions[1] == tls_proto::VERSION_TLS13) << "parse: versions[1]=TLS1.3";
    }

    TEST(TlsSignalParse, WithECH)
    {
        auto buf = build_minimal_client_hello();
        auto ext_start = buf.size();
        append_ech_extension(buf);
        finalize_with_extensions(buf, ext_start);

        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(!psm::fault::failed(ec)) << "parse: ECH -> success";
        EXPECT_TRUE(features.has_ech) << "parse: has_ech=true";
    }

    TEST(TlsSignalParse, WithSessionID)
    {
        auto buf = build_minimal_client_hello();
        // SessionID is at offset after random (5+4+2+32 = 43)
        // In build_minimal_client_hello, session_id_len byte is at index 43
        // Set length=32 and insert 32 bytes
        std::size_t sid_len_pos = 43;
        buf[sid_len_pos] = 32;
        // Insert 32 session_id bytes after sid_len_pos
        std::vector<std::uint8_t> sid_bytes(32, 0xAA);
        sid_bytes[0] = 0x01; sid_bytes[1] = 0x08; sid_bytes[2] = 0x02; // reality marker
        buf.insert(buf.begin() + sid_len_pos + 1, sid_bytes.begin(), sid_bytes.end());

        // Rebuild lengths
        auto handshake_len = buf.size() - 9;
        buf[6] = static_cast<std::uint8_t>((handshake_len >> 16) & 0xFF);
        buf[7] = static_cast<std::uint8_t>((handshake_len >> 8) & 0xFF);
        buf[8] = static_cast<std::uint8_t>(handshake_len & 0xFF);
        auto record_len = buf.size() - 5;
        buf[3] = static_cast<std::uint8_t>((record_len >> 8) & 0xFF);
        buf[4] = static_cast<std::uint8_t>(record_len & 0xFF);

        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(!psm::fault::failed(ec)) << "parse: session_id -> success";
        EXPECT_TRUE(features.session_id_len == 32) << "parse: session_id_len=32";
        EXPECT_TRUE(features.session_id.size() == 32) << "parse: session_id size=32";
        EXPECT_TRUE(features.session_id[0] == 0x01) << "parse: session_id[0]=0x01 (reality marker)";
        EXPECT_TRUE(features.session_id[2] == 0x02) << "parse: session_id[2]=0x02 (reality marker)";
    }

    TEST(TlsSignalParse, InvalidSessionIDTooLong)
    {
        auto buf = build_minimal_client_hello();
        std::size_t sid_len_pos = 43;
        buf[sid_len_pos] = 64; // > SESSION_ID_MAX_LEN (32)

        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(psm::fault::failed(ec)) << "parse: session_id too long -> error";
    }

    TEST(TlsSignalParse, FullClientHello)
    {
        // Build a ClientHello with SNI + key_share + versions + ECH
        std::array<std::uint8_t, 32> key{};
        key[0] = 0xCA; key[15] = 0xFE;

        auto buf = build_minimal_client_hello();
        auto ext_start = buf.size();
        append_sni_extension(buf, "test.example.org");
        append_x25519_key_share(buf, key);
        append_versions_extension(buf, {tls_proto::VERSION_TLS13});
        append_ech_extension(buf);
        finalize_with_extensions(buf, ext_start);

        auto [ec, features] = parse_client_hello({buf.data(), buf.size()});
        EXPECT_TRUE(!psm::fault::failed(ec)) << "parse: full CH -> success";
        EXPECT_TRUE(features.server_name == "test.example.org") << "parse: full SNI";
        EXPECT_TRUE(features.has_x25519) << "parse: full has_x25519";
        EXPECT_TRUE(features.x25519_key[0] == 0xCA) << "parse: full key[0]";
        EXPECT_TRUE(features.versions.size() == 1) << "parse: full 1 version";
        EXPECT_TRUE(features.has_ech) << "parse: full has_ech";
        EXPECT_TRUE(features.random[0] == 0x42) << "parse: full random";
        EXPECT_TRUE(!features.raw_msg.empty()) << "parse: full raw_msg not empty";
        EXPECT_TRUE(!features.raw_record.empty()) << "parse: full raw_record not empty";
    }
} // namespace
