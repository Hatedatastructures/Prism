/**
 * @file TlsSignalParseExt.cpp
 * @brief TLS Signal 内部纯函数扩展测试
 * @details 直接测试 read_u16/read_u24/parse_sni/parse_key_share/parse_versions/parse_extensions
 */

#include <prism/foundation/foundation.hpp>
#include "../../src/prism/stealth/recognition/tls/signal.cpp"
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <cstring>

namespace
{
    namespace tls_proto = psm::protocol::tls;

    // ─── read_u16 / read_u24 ─────────────────────

    TEST(TlsSignalParseExt, ReadU16Basic)
    {
        std::uint8_t data[] = {0x01, 0x23};
        auto val = psm::recognition::tls::read_u16({data, 2}, 0);
        EXPECT_TRUE(val == 0x0123) << "read_u16: 0x0123";
    }

    TEST(TlsSignalParseExt, ReadU16Zero)
    {
        std::uint8_t data[] = {0x00, 0x00};
        auto val = psm::recognition::tls::read_u16({data, 2}, 0);
        EXPECT_TRUE(val == 0) << "read_u16: zero";
    }

    TEST(TlsSignalParseExt, ReadU16Max)
    {
        std::uint8_t data[] = {0xFF, 0xFF};
        auto val = psm::recognition::tls::read_u16({data, 2}, 0);
        EXPECT_TRUE(val == 0xFFFF) << "read_u16: max";
    }

    TEST(TlsSignalParseExt, ReadU16Offset)
    {
        std::uint8_t data[] = {0x00, 0xAB, 0xCD};
        auto val = psm::recognition::tls::read_u16({data, 3}, 1);
        EXPECT_TRUE(val == 0xABCD) << "read_u16: offset=1";
    }

    TEST(TlsSignalParseExt, ReadU24Basic)
    {
        std::uint8_t data[] = {0x01, 0x23, 0x45};
        auto val = psm::recognition::tls::read_u24({data, 3}, 0);
        EXPECT_TRUE(val == 0x012345) << "read_u24: 0x012345";
    }

    TEST(TlsSignalParseExt, ReadU24Zero)
    {
        std::uint8_t data[] = {0x00, 0x00, 0x00};
        auto val = psm::recognition::tls::read_u24({data, 3}, 0);
        EXPECT_TRUE(val == 0) << "read_u24: zero";
    }

    TEST(TlsSignalParseExt, ReadU24Max)
    {
        std::uint8_t data[] = {0xFF, 0xFF, 0xFF};
        auto val = psm::recognition::tls::read_u24({data, 3}, 0);
        EXPECT_TRUE(val == 0xFFFFFF) << "read_u24: max";
    }

    TEST(TlsSignalParseExt, ReadU24Offset)
    {
        std::uint8_t data[] = {0x00, 0x00, 0x01, 0x02};
        auto val = psm::recognition::tls::read_u24({data, 4}, 1);
        EXPECT_TRUE(val == 0x000102) << "read_u24: offset=1";
    }

    // ─── parse_sni ──────────────────────────────

    TEST(TlsSignalParseExt, ParseSniTooShort)
    {
        tls_proto::hello_features features;
        std::uint8_t data[] = {0x00}; // < 2 bytes
        psm::recognition::tls::parse_sni({data, 1}, features);
        EXPECT_TRUE(features.server_name.empty()) << "parse_sni: too short -> no SNI";
    }

    TEST(TlsSignalParseExt, ParseSniEmptyList)
    {
        tls_proto::hello_features features;
        std::uint8_t data[] = {0x00, 0x00}; // list_len=0
        psm::recognition::tls::parse_sni({data, 2}, features);
        EXPECT_TRUE(features.server_name.empty()) << "parse_sni: empty list";
    }

    TEST(TlsSignalParseExt, ParseSniHostname)
    {
        tls_proto::hello_features features;
        const char *name = "example.com";
        auto name_len = static_cast<std::uint16_t>(std::strlen(name));
        auto list_entry_len = static_cast<std::uint16_t>(1 + 2 + name_len);
        auto list_len = list_entry_len;

        psm::memory::vector<std::uint8_t> buf;
        buf.push_back(static_cast<std::uint8_t>((list_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(list_len & 0xFF));
        buf.push_back(tls_proto::SNAME_TYPE_HOSTNAME);
        buf.push_back(static_cast<std::uint8_t>((name_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(name_len & 0xFF));
        for (auto c : std::string_view(name))
            buf.push_back(static_cast<std::uint8_t>(c));

        psm::recognition::tls::parse_sni({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.server_name == "example.com") << "parse_sni: hostname found";
    }

    TEST(TlsSignalParseExt, ParseSniNonHostnameType)
    {
        tls_proto::hello_features features;
        // name_type=0x01 (not hostname), followed by a hostname entry
        const char *host = "test.org";
        auto host_len = static_cast<std::uint16_t>(std::strlen(host));

        psm::memory::vector<std::uint8_t> buf;
        // Entry 1: non-hostname type
        auto entry1_len = static_cast<std::uint16_t>(1 + 2 + 3);
        auto total_list = static_cast<std::uint16_t>(entry1_len + 1 + 2 + host_len);
        buf.push_back(static_cast<std::uint8_t>((total_list >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(total_list & 0xFF));
        // entry 1: type=0x01, len=3, data=0x00 0x00 0x00
        buf.push_back(0x01);
        buf.push_back(0x00); buf.push_back(0x03);
        buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00);
        // entry 2: hostname
        buf.push_back(tls_proto::SNAME_TYPE_HOSTNAME);
        buf.push_back(static_cast<std::uint8_t>((host_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(host_len & 0xFF));
        for (auto c : std::string_view(host))
            buf.push_back(static_cast<std::uint8_t>(c));

        psm::recognition::tls::parse_sni({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.server_name == "test.org") << "parse_sni: skips non-hostname, finds hostname";
    }

    TEST(TlsSignalParseExt, ParseSniTruncatedName)
    {
        tls_proto::hello_features features;
        // name_len says 100 but only 2 bytes available
        psm::memory::vector<std::uint8_t> buf;
        buf.push_back(0x00); buf.push_back(0x05); // list_len=5
        buf.push_back(tls_proto::SNAME_TYPE_HOSTNAME);
        buf.push_back(0x00); buf.push_back(0x64); // name_len=100
        buf.push_back(0x41); buf.push_back(0x42); // only 2 bytes

        psm::recognition::tls::parse_sni({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.server_name.empty()) << "parse_sni: truncated name -> no SNI";
    }

    // ─── parse_key_share ────────────────────────

    TEST(TlsSignalParseExt, ParseKeyShareTooShort)
    {
        tls_proto::hello_features features;
        std::uint8_t data[] = {0x00};
        psm::recognition::tls::parse_key_share({data, 1}, features);
        EXPECT_TRUE(!features.has_x25519) << "parse_key_share: too short -> no key";
    }

    TEST(TlsSignalParseExt, ParseKeyShareX25519)
    {
        tls_proto::hello_features features;
        std::array<std::uint8_t, 32> key{};
        key[0] = 0xCA; key[31] = 0xFE;

        psm::memory::vector<std::uint8_t> buf;
        auto entry_len = static_cast<std::uint16_t>(2 + 2 + 32);
        auto list_len = entry_len;
        auto ext_payload_len = static_cast<std::uint16_t>(2 + list_len);

        buf.push_back(static_cast<std::uint8_t>((list_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(list_len & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((tls_proto::GROUP_X25519 >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::GROUP_X25519 & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((32 >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(32 & 0xFF));
        for (auto b : key)
            buf.push_back(b);

        psm::recognition::tls::parse_key_share({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.has_x25519) << "parse_key_share: X25519 found";
        EXPECT_TRUE(features.x25519_key[0] == 0xCA) << "parse_key_share: key[0]=0xCA";
        EXPECT_TRUE(features.x25519_key[31] == 0xFE) << "parse_key_share: key[31]=0xFE";
    }

    TEST(TlsSignalParseExt, ParseKeyShareX25519Mlkem768)
    {
        tls_proto::hello_features features;
        // MLKEM768 hybrid: key is >= 32 bytes, first 32 are X25519 portion
        constexpr std::size_t hybrid_key_len = 32 + 1184; // X25519 + MLKEM768
        psm::memory::vector<std::uint8_t> key(hybrid_key_len, 0x00);
        key[0] = 0xDE; key[31] = 0xAD;

        psm::memory::vector<std::uint8_t> buf;
        auto entry_len = static_cast<std::uint16_t>(2 + 2 + hybrid_key_len);
        auto list_len = entry_len;

        buf.push_back(static_cast<std::uint8_t>((list_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(list_len & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((tls_proto::GROUP_X25519_MLKEM768 >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::GROUP_X25519_MLKEM768 & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((hybrid_key_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(hybrid_key_len & 0xFF));
        for (auto b : key)
            buf.push_back(b);

        psm::recognition::tls::parse_key_share({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.has_x25519) << "parse_key_share: X25519MLKEM768 found";
        EXPECT_TRUE(features.x25519_key[0] == 0xDE) << "parse_key_share: hybrid key[0]=0xDE";
        EXPECT_TRUE(features.x25519_key[31] == 0xAD) << "parse_key_share: hybrid key[31]=0xAD";
    }

    TEST(TlsSignalParseExt, ParseKeyShareWrongGroup)
    {
        tls_proto::hello_features features;
        psm::memory::vector<std::uint8_t> buf;
        auto entry_len = static_cast<std::uint16_t>(2 + 2 + 32);
        auto list_len = entry_len;

        buf.push_back(static_cast<std::uint8_t>((list_len >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(list_len & 0xFF));
        buf.push_back(0x00); buf.push_back(0x17); // SECP256R1, not X25519
        buf.push_back(0x00); buf.push_back(0x20); // key_len=32
        for (int i = 0; i < 32; ++i)
            buf.push_back(0x00);

        psm::recognition::tls::parse_key_share({buf.data(), buf.size()}, features);
        EXPECT_TRUE(!features.has_x25519) << "parse_key_share: wrong group -> no key";
    }

    TEST(TlsSignalParseExt, ParseKeyShareTruncatedKey)
    {
        tls_proto::hello_features features;
        psm::memory::vector<std::uint8_t> buf;
        buf.push_back(0x00); buf.push_back(0x06); // list_len=6
        buf.push_back(static_cast<std::uint8_t>((tls_proto::GROUP_X25519 >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::GROUP_X25519 & 0xFF));
        buf.push_back(0x00); buf.push_back(0x20); // key_len=32
        // But only 2 bytes of key data follow
        buf.push_back(0x01); buf.push_back(0x02);

        psm::recognition::tls::parse_key_share({buf.data(), buf.size()}, features);
        EXPECT_TRUE(!features.has_x25519) << "parse_key_share: truncated key -> no key";
    }

    // ─── parse_versions ─────────────────────────

    TEST(TlsSignalParseExt, ParseVersionsEmpty)
    {
        tls_proto::hello_features features;
        psm::recognition::tls::parse_versions({}, features);
        EXPECT_TRUE(features.versions.empty()) << "parse_versions: empty -> no versions";
    }

    TEST(TlsSignalParseExt, ParseVersionsSingle)
    {
        tls_proto::hello_features features;
        std::uint8_t data[] = {0x02, 0x03, 0x03}; // list_len=2, version=0x0303
        psm::recognition::tls::parse_versions({data, 3}, features);
        EXPECT_TRUE(features.versions.size() == 1) << "parse_versions: single version";
        EXPECT_TRUE(features.versions[0] == 0x0303) << "parse_versions: TLS 1.2";
    }

    TEST(TlsSignalParseExt, ParseVersionsMultiple)
    {
        tls_proto::hello_features features;
        // list_len=6, versions: 0x0303, 0x0304, 0x0301
        std::uint8_t data[] = {0x06, 0x03, 0x03, 0x03, 0x04, 0x03, 0x01};
        psm::recognition::tls::parse_versions({data, 7}, features);
        EXPECT_TRUE(features.versions.size() == 3) << "parse_versions: 3 versions";
        EXPECT_TRUE(features.versions[0] == 0x0303) << "parse_versions: v[0]=TLS1.2";
        EXPECT_TRUE(features.versions[1] == 0x0304) << "parse_versions: v[1]=TLS1.3";
        EXPECT_TRUE(features.versions[2] == 0x0301) << "parse_versions: v[2]=TLS1.0";
    }

    TEST(TlsSignalParseExt, ParseVersionsOddLength)
    {
        tls_proto::hello_features features;
        // list_len=3 (odd), but only 2 bytes available → parse 1 version
        std::uint8_t data[] = {0x03, 0x03, 0x03};
        psm::recognition::tls::parse_versions({data, 3}, features);
        EXPECT_TRUE(features.versions.size() == 1) << "parse_versions: odd list -> 1 version";
    }

    // ─── parse_extensions ───────────────────────

    TEST(TlsSignalParseExt, ParseExtensionsTooShort)
    {
        tls_proto::hello_features features;
        std::uint8_t data[] = {0x00};
        psm::recognition::tls::parse_extensions({data, 1}, features);
        EXPECT_TRUE(features.server_name.empty()) << "parse_extensions: too short -> nothing";
    }

    TEST(TlsSignalParseExt, ParseExtensionsEmpty)
    {
        tls_proto::hello_features features;
        std::uint8_t data[] = {0x00, 0x00}; // ext_total_len=0
        psm::recognition::tls::parse_extensions({data, 2}, features);
        EXPECT_TRUE(features.server_name.empty()) << "parse_extensions: empty -> nothing";
    }

    TEST(TlsSignalParseExt, ParseExtensionsUnknownType)
    {
        tls_proto::hello_features features;
        psm::memory::vector<std::uint8_t> buf;
        buf.push_back(0x00); buf.push_back(0x04); // ext_total_len=4
        buf.push_back(0xFF); buf.push_back(0x01); // unknown ext type
        buf.push_back(0x00); buf.push_back(0x00); // ext_len=0

        psm::recognition::tls::parse_extensions({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.server_name.empty()) << "parse_extensions: unknown type ignored";
        EXPECT_TRUE(!features.has_ech) << "parse_extensions: unknown type -> no ech";
    }

    TEST(TlsSignalParseExt, ParseExtensionsTruncatedExt)
    {
        tls_proto::hello_features features;
        psm::memory::vector<std::uint8_t> buf;
        buf.push_back(0x00); buf.push_back(0x08); // ext_total_len=8
        buf.push_back(0x00); buf.push_back(0x00); // SNI type
        buf.push_back(0x00); buf.push_back(0x10); // ext_len=16
        // Only 2 bytes follow instead of 16
        buf.push_back(0x00); buf.push_back(0x00);

        psm::recognition::tls::parse_extensions({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.server_name.empty()) << "parse_extensions: truncated ext -> break";
    }

    TEST(TlsSignalParseExt, ParseExtensionsEch)
    {
        tls_proto::hello_features features;
        psm::memory::vector<std::uint8_t> buf;
        auto ext_total = static_cast<std::uint16_t>(4);
        buf.push_back(static_cast<std::uint8_t>((ext_total >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(ext_total & 0xFF));
        // ECH extension
        buf.push_back(static_cast<std::uint8_t>((tls_proto::EXT_ENCRYPTED_CLIENT_HELLO >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(tls_proto::EXT_ENCRYPTED_CLIENT_HELLO & 0xFF));
        buf.push_back(0x00); buf.push_back(0x00); // ext_len=0

        psm::recognition::tls::parse_extensions({buf.data(), buf.size()}, features);
        EXPECT_TRUE(features.has_ech) << "parse_extensions: ECH found";
    }
} // namespace
