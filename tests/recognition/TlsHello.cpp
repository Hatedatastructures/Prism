/**
 * @file TlsHello.cpp
 * @brief TLS ClientHello 解析器单元测试
 * @details 测试 psm::tls::client_hello::from_bytes 和 to_features，
 * 覆盖正常解析和各种边界条件（截断缓冲区、无效字段、扩展解析等）。
 */

#include <prism/core/core.hpp>
#include <prism/proto/protocol/tls/hello.hpp>
#include <prism/proto/protocol/tls/record.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/core/core.hpp>
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <cstdint>
#include <span>
#include <vector>

namespace
{
    void write_u16(std::vector<std::uint8_t> &buf, std::uint16_t val)
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    void write_u24(std::vector<std::uint8_t> &buf, std::size_t val)
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    struct client_hello_builder
    {
        std::string sni_value;
        bool include_x25519{true};
        std::array<std::uint8_t, 32> x25519_key{};
        bool include_versions{true};
        std::vector<std::uint16_t> version_list;
        std::uint8_t session_id_len{0};
        std::vector<std::uint8_t> session_id;
        bool include_extensions{true};

        client_hello_builder()
        {
            x25519_key.fill(0x42);
            version_list.push_back(psm::protocol::tls::VERSION_TLS13);
        }

        [[nodiscard]] auto build() const -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> body;

            // HandshakeType = ClientHello
            body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);

            // Build handshake body first to compute length
            std::vector<std::uint8_t> hs_body;

            // ClientVersion
            hs_body.push_back(0x03);
            hs_body.push_back(0x03);

            // Random (32 bytes)
            for (int i = 0; i < 32; ++i)
                hs_body.push_back(static_cast<std::uint8_t>(i));

            // SessionID
            hs_body.push_back(session_id_len);
            for (std::size_t i = 0; i < session_id_len; ++i)
                hs_body.push_back(i < session_id.size() ? session_id[i] : static_cast<std::uint8_t>(i));

            // CipherSuites
            write_u16(hs_body, 2);
            write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);

            // CompressionMethods
            hs_body.push_back(1);
            hs_body.push_back(0x00);

            // Extensions
            if (include_extensions)
            {
                std::vector<std::uint8_t> ext_data;

                // SNI extension
                if (!sni_value.empty())
                {
                    const auto &name = sni_value;
                    std::vector<std::uint8_t> sni_ext;
                    write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + name.size())); // list length
                    sni_ext.push_back(0x00); // host_name type
                    write_u16(sni_ext, static_cast<std::uint16_t>(name.size()));
                    sni_ext.insert(sni_ext.end(), name.begin(), name.end());

                    write_u16(ext_data, psm::protocol::tls::EXT_SERVER_NAME);
                    write_u16(ext_data, static_cast<std::uint16_t>(sni_ext.size()));
                    ext_data.insert(ext_data.end(), sni_ext.begin(), sni_ext.end());
                }

                // key_share extension (X25519)
                if (include_x25519)
                {
                    std::vector<std::uint8_t> ks_ext;
                    write_u16(ks_ext, static_cast<std::uint16_t>(2 + 2 + 32)); // list length
                    write_u16(ks_ext, psm::protocol::tls::GROUP_X25519);
                    write_u16(ks_ext, 32);
                    ks_ext.insert(ks_ext.end(), x25519_key.begin(), x25519_key.end());

                    write_u16(ext_data, psm::protocol::tls::EXT_KEY_SHARE);
                    write_u16(ext_data, static_cast<std::uint16_t>(ks_ext.size()));
                    ext_data.insert(ext_data.end(), ks_ext.begin(), ks_ext.end());
                }

                // supported_versions extension
                if (include_versions && !version_list.empty())
                {
                    std::vector<std::uint8_t> sv_ext;
                    sv_ext.push_back(static_cast<std::uint8_t>(version_list.size() * 2));
                    for (auto v : version_list)
                        write_u16(sv_ext, v);

                    write_u16(ext_data, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
                    write_u16(ext_data, static_cast<std::uint16_t>(sv_ext.size()));
                    ext_data.insert(ext_data.end(), sv_ext.begin(), sv_ext.end());
                }

                // Extension block: 2-byte total length + data
                write_u16(hs_body, static_cast<std::uint16_t>(ext_data.size()));
                hs_body.insert(hs_body.end(), ext_data.begin(), ext_data.end());
            }

            // Handshake length (3 bytes)
            write_u24(body, hs_body.size());
            body.insert(body.end(), hs_body.begin(), hs_body.end());

            // TLS record header
            std::vector<std::uint8_t> record;
            record.push_back(psm::protocol::tls::CT_HANDSHAKE);
            write_u16(record, psm::protocol::tls::VERSION_TLS12);
            write_u16(record, static_cast<std::uint16_t>(body.size()));
            record.insert(record.end(), body.begin(), body.end());

            return record;
        }
    };

    // === Tests ===

    TEST(TlsHello, ParseValidClientHello)
    {
        client_hello_builder builder;
        builder.sni_value = "example.com";
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "valid ClientHello parses successfully";
        EXPECT_TRUE(ch.sni() == "example.com") << "SNI extracted correctly";
        EXPECT_TRUE(ch.has_x25519()) << "X25519 key_share detected";
        EXPECT_TRUE(!ch.versions().empty()) << "versions list not empty";
        EXPECT_TRUE(ch.session_id().empty()) << "empty session_id";
        EXPECT_TRUE(ch.random()[0] == 0 && ch.random()[31] == 31) << "random bytes preserved";
        EXPECT_TRUE(!ch.raw_record().empty()) << "raw_record preserved";
        EXPECT_TRUE(!ch.raw_msg().empty()) << "raw_msg preserved";
    }

    TEST(TlsHello, ParseWithSessionId)
    {
        client_hello_builder builder;
        builder.sni_value = "test.local";
        builder.session_id_len = 16;
        builder.session_id.resize(16, 0xAB);
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "ClientHello with session_id parses";
        EXPECT_TRUE(ch.session_id().size() == 16) << "session_id length is 16";
        EXPECT_TRUE(ch.session_id()[0] == 0xAB) << "session_id content preserved";
    }

    TEST(TlsHello, ParseNoExtensions)
    {
        client_hello_builder builder;
        builder.include_extensions = false;
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "ClientHello without extensions parses";
        EXPECT_TRUE(ch.sni().empty()) << "no SNI when no extensions";
        EXPECT_TRUE(!ch.has_x25519()) << "no X25519 when no extensions";
    }

    TEST(TlsHello, ParseNoKeyShare)
    {
        client_hello_builder builder;
        builder.include_x25519 = false;
        builder.sni_value = "nokey.example.com";
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "ClientHello without key_share parses";
        EXPECT_TRUE(!ch.has_x25519()) << "has_x25519 is false";
        EXPECT_TRUE(ch.sni() == "nokey.example.com") << "SNI still extracted";
    }

    TEST(TlsHello, ParseNoVersions)
    {
        client_hello_builder builder;
        builder.include_versions = false;
        builder.sni_value = "noversion.test";
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "ClientHello without versions parses";
        EXPECT_TRUE(ch.versions().empty()) << "versions list is empty";
    }

    TEST(TlsHello, ParseEmptySni)
    {
        client_hello_builder builder;
        builder.sni_value = "";
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "ClientHello with empty SNI parses";
        EXPECT_TRUE(ch.sni().empty()) << "SNI is empty";
    }

    TEST(TlsHello, ParseBufferTooShort)
    {
        std::vector<std::uint8_t> short_buf(10, 0x16);
        auto [ec, ch] = psm::tls::client_hello::from_bytes(short_buf);
        EXPECT_TRUE(psm::fault::failed(ec)) << "buffer < 44 bytes rejected";
        EXPECT_TRUE(ec == psm::fault::code::recorderr) << "error code is recorderr";
    }

    TEST(TlsHello, ParseWrongContentType)
    {
        client_hello_builder builder;
        auto raw = builder.build();
        raw[0] = 0x17; // CT_APPLICATION_DATA instead of CT_HANDSHAKE

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "wrong content type rejected";
    }

    TEST(TlsHello, ParseRecordBodyTruncated)
    {
        client_hello_builder builder;
        auto raw = builder.build();
        // Set record body length to larger than actual data
        raw[3] = 0xFF;
        raw[4] = 0xFF;

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "truncated record body rejected";
    }

    TEST(TlsHello, ParseWrongHandshakeType)
    {
        client_hello_builder builder;
        auto raw = builder.build();
        raw[5] = 0x02; // HS_SERVER_HELLO instead of HS_CLIENT_HELLO

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "wrong handshake type rejected";
    }

    TEST(TlsHello, ParseSessionIdTooLong)
    {
        client_hello_builder builder;
        builder.session_id_len = 33; // > SESSION_ID_MAX_LEN (32)
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "session_id > 32 bytes rejected";
    }

    TEST(TlsHello, ParseCipherLenOdd)
    {
        // Manually construct a ClientHello with odd cipher_suites length
        std::vector<std::uint8_t> raw;
        raw.push_back(psm::protocol::tls::CT_HANDSHAKE);
        // version + length placeholder
        write_u16(raw, 0x0303);
        // We'll fill in length later

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);

        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00); // random
        hs_body.push_back(0x00); // session_id_len = 0
        write_u16(hs_body, 3); // cipher_len = 3 (odd)
        hs_body.push_back(0x13);
        hs_body.push_back(0x01);
        hs_body.push_back(0x00);
        hs_body.push_back(1); // comp_methods_len
        hs_body.push_back(0x00);

        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "odd cipher_suites length rejected";
    }

    TEST(TlsHello, ToFeatures)
    {
        client_hello_builder builder;
        builder.sni_value = "features.test";
        std::array<std::uint8_t, 32> expected_key;
        expected_key.fill(0x42);
        builder.x25519_key = expected_key;
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "parse succeeds for to_features test";

        auto feat = ch.to_features();
        EXPECT_TRUE(feat.server_name == "features.test") << "to_features: server_name";
        EXPECT_TRUE(feat.has_x25519 == true) << "to_features: has_x25519";
        EXPECT_TRUE(feat.x25519_key == expected_key) << "to_features: x25519_key";
        EXPECT_TRUE(!feat.versions.empty()) << "to_features: versions not empty";
        EXPECT_TRUE(feat.session_id.empty()) << "to_features: session_id empty";
        EXPECT_TRUE(!feat.raw_msg.empty()) << "to_features: raw_msg not empty";
        EXPECT_TRUE(!feat.raw_record.empty()) << "to_features: raw_record not empty";
    }

    TEST(TlsHello, ParseMultipleVersions)
    {
        client_hello_builder builder;
        builder.version_list.clear();
        builder.version_list.push_back(psm::protocol::tls::VERSION_TLS12);
        builder.version_list.push_back(psm::protocol::tls::VERSION_TLS13);
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "multiple versions parses";
        EXPECT_TRUE(ch.versions().size() == 2) << "two versions extracted";
    }

    TEST(TlsHello, ParseX25519Mlkem768)
    {
        client_hello_builder builder;
        builder.include_x25519 = false;
        // Manually build key_share with X25519MLKEM768
        builder.sni_value = "hybrid.test";
        auto raw = builder.build();

        // Replace key_share extension manually: find EXT_KEY_SHARE and replace
        // Instead, build from scratch with the hybrid group
        std::vector<std::uint8_t> ks_ext;
        const std::uint16_t hybrid_key_len = 1216; // ML-KEM-768 + X25519
        write_u16(ks_ext, static_cast<std::uint16_t>(2 + 2 + hybrid_key_len));
        write_u16(ks_ext, psm::protocol::tls::GROUP_X25519_MLKEM768);
        write_u16(ks_ext, hybrid_key_len);
        // Fill with 0x42 for first 32 bytes (X25519 key), rest zeros
        for (std::size_t i = 0; i < 32; ++i)
            ks_ext.push_back(0x42);
        for (std::size_t i = 32; i < hybrid_key_len; ++i)
            ks_ext.push_back(0x00);

        // Inject into the raw buffer by rebuilding extensions
        // Find supported_versions extension position in raw and insert before it
        // Simpler: rebuild from scratch
        std::vector<std::uint8_t> ext_block;

        // SNI
        {
            const std::string &name = "hybrid.test";
            std::vector<std::uint8_t> sni_ext;
            write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + name.size()));
            sni_ext.push_back(0x00);
            write_u16(sni_ext, static_cast<std::uint16_t>(name.size()));
            sni_ext.insert(sni_ext.end(), name.begin(), name.end());

            write_u16(ext_block, psm::protocol::tls::EXT_SERVER_NAME);
            write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
            ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());
        }

        // key_share with hybrid
        write_u16(ext_block, psm::protocol::tls::EXT_KEY_SHARE);
        write_u16(ext_block, static_cast<std::uint16_t>(ks_ext.size()));
        ext_block.insert(ext_block.end(), ks_ext.begin(), ks_ext.end());

        // supported_versions
        {
            std::vector<std::uint8_t> sv_ext;
            sv_ext.push_back(2);
            write_u16(sv_ext, psm::protocol::tls::VERSION_TLS13);
            write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
            write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
            ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());
        }

        // Build full ClientHello
        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03); hs_body.push_back(0x03); // version
        hs_body.insert(hs_body.end(), 32, 0x00); // random
        hs_body.push_back(0x00); // session_id_len
        write_u16(hs_body, 2); // cipher_len
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1); hs_body.push_back(0x00); // compression

        write_u16(hs_body, static_cast<std::uint16_t>(ext_block.size()));
        hs_body.insert(hs_body.end(), ext_block.begin(), ext_block.end());

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::uint8_t> record;
        record.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(record, 0x0303);
        write_u16(record, static_cast<std::uint16_t>(body.size()));
        record.insert(record.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(record);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "X25519MLKEM768 hybrid key_share parses";
        EXPECT_TRUE(ch.has_x25519() == true) << "hybrid key_share sets has_x25519";
        EXPECT_TRUE(ch.sni() == "hybrid.test") << "SNI still extracted with hybrid";
    }

    TEST(TlsHello, ParseMaxSessionId)
    {
        client_hello_builder builder;
        builder.session_id_len = 32; // exactly SESSION_ID_MAX_LEN
        builder.session_id.resize(32, 0xFF);
        auto raw = builder.build();

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "session_id = 32 bytes accepted";
        EXPECT_TRUE(ch.session_id().size() == 32) << "session_id length is 32";
    }

    // === 解析边界条件测试 ===

    TEST(TlsHello, ParseHandshakeLenOverflow)
    {
        // handshake_len 指向 buffer 范围之外
        client_hello_builder builder;
        auto raw = builder.build();

        // 找到 handshake_len 字段（offset 6-8）并设置为一个超大值
        // record header: [0]=CT, [1-2]=ver, [3-4]=body_len
        // body: [5]=HS_TYPE, [6-8]=handshake_len(3 bytes)
        raw[6] = 0xFF;
        raw[7] = 0xFF;
        raw[8] = 0xFF;

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "handshake_len overflow → recorderr";
    }

    TEST(TlsHello, ParseCompLenOverflow)
    {
        // 构造 comp_len 导致 offset 越界的 ClientHello
        std::vector<std::uint8_t> raw;
        raw.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(raw, 0x0303);

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);

        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00); // random
        hs_body.push_back(0x00); // session_id_len = 0
        write_u16(hs_body, 2); // cipher_len = 2
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(0xFF); // comp_len = 255，远超剩余数据

        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "comp_len overflow → recorderr";
    }

    TEST(TlsHello, ParseSniNonHostnameType)
    {
        // SNI 列表中第一个条目 name_type != 0x00（非 hostname），应被跳过
        std::vector<std::uint8_t> ext_block;

        // SNI extension: 一个非 hostname 条目 + 一个 hostname 条目
        {
            const std::string name = "host.test";
            std::vector<std::uint8_t> sni_ext;
            // list_length = (1+2+3) + (1+2+9) = 6 + 12 = 18
            write_u16(sni_ext, 18);
            // 条目1: name_type=0x01（非 hostname），name_len=3, name="abc"
            sni_ext.push_back(0x01); // non-hostname type
            write_u16(sni_ext, 3);
            sni_ext.push_back('a');
            sni_ext.push_back('b');
            sni_ext.push_back('c');
            // 条目2: name_type=0x00（hostname），name_len=9, name="host.test"
            sni_ext.push_back(0x00);
            write_u16(sni_ext, static_cast<std::uint16_t>(name.size()));
            sni_ext.insert(sni_ext.end(), name.begin(), name.end());

            write_u16(ext_block, psm::protocol::tls::EXT_SERVER_NAME);
            write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
            ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());
        }

        // supported_versions
        {
            std::vector<std::uint8_t> sv_ext;
            sv_ext.push_back(2);
            write_u16(sv_ext, psm::protocol::tls::VERSION_TLS13);
            write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
            write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
            ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());
        }

        // Build ClientHello
        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1);
        hs_body.push_back(0x00);

        write_u16(hs_body, static_cast<std::uint16_t>(ext_block.size()));
        hs_body.insert(hs_body.end(), ext_block.begin(), ext_block.end());

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::uint8_t> record;
        record.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(record, 0x0303);
        write_u16(record, static_cast<std::uint16_t>(body.size()));
        record.insert(record.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(record);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "SNI non-hostname type: parses";
        EXPECT_TRUE(ch.sni() == "host.test") << "SNI non-hostname type: skips non-hostname, finds hostname";
    }

    TEST(TlsHello, ParseKeyshareNonX25519Group)
    {
        // key_share 中包含非 X25519 组（如 P-256），不应设置 has_x25519
        std::vector<std::uint8_t> ext_block;

        // SNI
        {
            const std::string name = "p256.test";
            std::vector<std::uint8_t> sni_ext;
            write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + name.size()));
            sni_ext.push_back(0x00);
            write_u16(sni_ext, static_cast<std::uint16_t>(name.size()));
            sni_ext.insert(sni_ext.end(), name.begin(), name.end());
            write_u16(ext_block, psm::protocol::tls::EXT_SERVER_NAME);
            write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
            ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());
        }

        // key_share with P-256 (group 0x0017), key_len=65
        {
            std::vector<std::uint8_t> ks_ext;
            write_u16(ks_ext, static_cast<std::uint16_t>(2 + 2 + 65));
            write_u16(ks_ext, 0x0017); // P-256
            write_u16(ks_ext, 65);
            ks_ext.insert(ks_ext.end(), 65, 0x42);
            write_u16(ext_block, psm::protocol::tls::EXT_KEY_SHARE);
            write_u16(ext_block, static_cast<std::uint16_t>(ks_ext.size()));
            ext_block.insert(ext_block.end(), ks_ext.begin(), ks_ext.end());
        }

        // supported_versions
        {
            std::vector<std::uint8_t> sv_ext;
            sv_ext.push_back(2);
            write_u16(sv_ext, psm::protocol::tls::VERSION_TLS13);
            write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
            write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
            ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());
        }

        // Build ClientHello
        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1);
        hs_body.push_back(0x00);

        write_u16(hs_body, static_cast<std::uint16_t>(ext_block.size()));
        hs_body.insert(hs_body.end(), ext_block.begin(), ext_block.end());

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::uint8_t> record;
        record.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(record, 0x0303);
        write_u16(record, static_cast<std::uint16_t>(body.size()));
        record.insert(record.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(record);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "P-256 key_share: parses";
        EXPECT_TRUE(ch.has_x25519() == false) << "P-256 key_share: has_x25519=false";
        EXPECT_TRUE(ch.sni() == "p256.test") << "P-256 key_share: SNI still extracted";
    }

    TEST(TlsHello, ParseKeyshareTruncated)
    {
        // key_share 中 key_len 超出 ext_data 范围
        std::vector<std::uint8_t> ext_block;

        // SNI
        {
            const std::string name = "trunc.test";
            std::vector<std::uint8_t> sni_ext;
            write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + name.size()));
            sni_ext.push_back(0x00);
            write_u16(sni_ext, static_cast<std::uint16_t>(name.size()));
            sni_ext.insert(sni_ext.end(), name.begin(), name.end());
            write_u16(ext_block, psm::protocol::tls::EXT_SERVER_NAME);
            write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
            ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());
        }

        // key_share: group=X25519, key_len=32, 但实际数据不足 32 字节
        {
            std::vector<std::uint8_t> ks_ext;
            write_u16(ks_ext, static_cast<std::uint16_t>(2 + 2 + 32)); // list_len 声称 36
            write_u16(ks_ext, psm::protocol::tls::GROUP_X25519);
            write_u16(ks_ext, 32);
            ks_ext.insert(ks_ext.end(), 10, 0x42); // 只给 10 字节，不足 32

            write_u16(ext_block, psm::protocol::tls::EXT_KEY_SHARE);
            write_u16(ext_block, static_cast<std::uint16_t>(ks_ext.size()));
            ext_block.insert(ext_block.end(), ks_ext.begin(), ks_ext.end());
        }

        // supported_versions
        {
            std::vector<std::uint8_t> sv_ext;
            sv_ext.push_back(2);
            write_u16(sv_ext, psm::protocol::tls::VERSION_TLS13);
            write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
            write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
            ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());
        }

        // Build ClientHello
        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1);
        hs_body.push_back(0x00);

        write_u16(hs_body, static_cast<std::uint16_t>(ext_block.size()));
        hs_body.insert(hs_body.end(), ext_block.begin(), ext_block.end());

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::uint8_t> record;
        record.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(record, 0x0303);
        write_u16(record, static_cast<std::uint16_t>(body.size()));
        record.insert(record.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(record);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "truncated key_share: parses without crash";
        EXPECT_TRUE(ch.has_x25519() == false) << "truncated key_share: has_x25519=false";
    }

    TEST(TlsHello, ParseVersionsEmpty)
    {
        // supported_versions ext_data.size() == 0 → 立即返回，versions 为空
        std::vector<std::uint8_t> ext_block;

        // supported_versions with empty ext_payload
        write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
        write_u16(ext_block, 0); // length = 0

        // Build ClientHello
        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1);
        hs_body.push_back(0x00);

        write_u16(hs_body, static_cast<std::uint16_t>(ext_block.size()));
        hs_body.insert(hs_body.end(), ext_block.begin(), ext_block.end());

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::uint8_t> record;
        record.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(record, 0x0303);
        write_u16(record, static_cast<std::uint16_t>(body.size()));
        record.insert(record.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(record);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "empty supported_versions: parses";
        EXPECT_TRUE(ch.versions().empty()) << "empty supported_versions: versions is empty";
    }

    TEST(TlsHello, ParseExtensionsTruncated)
    {
        // ext_len 指向超界数据 → 循环提前终止，不崩溃
        client_hello_builder builder;
        builder.sni_value = "exttrunc.test";
        auto raw = builder.build();

        // 找到扩展块起始位置（extensions 总长度字段），设置为超大值
        // 结构: record_hdr(5) + hs_type(1) + hs_len(3) + ver(2) + random(32) + sid_len(1) + cipher_len(2) + cipher(2) + comp_len(1) + comp(1) + ext_len(2)
        // = 5 + 1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 1 = 50 → ext_len 在 offset 50-51
        // 但实际位置取决于 session_id_len = 0，所以 offset = 5+1+3+2+32+1+2+2+1+1 = 50
        if (raw.size() > 51)
        {
            raw[50] = 0xFF;
            raw[51] = 0xFF;
        }

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "truncated extensions: parses without crash";
        // 由于 ext_len 超界，循环提前终止，可能未解析到任何扩展
    }
} // namespace
