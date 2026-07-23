/**
 * @file TlsHelloPure.cpp
 * @brief TLS ClientHello 纯函数补充测试
 * @details 测试 from(record) 重载 + 内部解析器边界条件
 */

#include <prism/foundation/foundation.hpp>
#include <prism/protocol/tls/hello.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>

#include <gtest/gtest.h>

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

    auto build_valid_hello() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> ext_block;

        const std::string name = "fromrecord.test";
        std::vector<std::uint8_t> sni_ext;
        write_u16(sni_ext, static_cast<std::uint16_t>(1 + 2 + name.size()));
        sni_ext.push_back(0x00);
        write_u16(sni_ext, static_cast<std::uint16_t>(name.size()));
        sni_ext.insert(sni_ext.end(), name.begin(), name.end());
        write_u16(ext_block, psm::protocol::tls::EXT_SERVER_NAME);
        write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
        ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());

        std::vector<std::uint8_t> ks_ext;
        write_u16(ks_ext, static_cast<std::uint16_t>(2 + 2 + 32));
        write_u16(ks_ext, psm::protocol::tls::GROUP_X25519);
        write_u16(ks_ext, 32);
        ks_ext.insert(ks_ext.end(), 32, 0x42);
        write_u16(ext_block, psm::protocol::tls::EXT_KEY_SHARE);
        write_u16(ext_block, static_cast<std::uint16_t>(ks_ext.size()));
        ext_block.insert(ext_block.end(), ks_ext.begin(), ks_ext.end());

        std::vector<std::uint8_t> sv_ext;
        sv_ext.push_back(2);
        write_u16(sv_ext, psm::protocol::tls::VERSION_TLS13);
        write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
        write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
        ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());

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

        std::vector<std::uint8_t> rec;
        rec.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(rec, psm::protocol::tls::VERSION_TLS12);
        write_u16(rec, static_cast<std::uint16_t>(body.size()));
        rec.insert(rec.end(), body.begin(), body.end());
        return rec;
    }

    TEST(TlsHelloPure, FromRecord)
    {
        auto raw = build_valid_hello();
        std::array<std::byte, 5> hdr = {
            std::byte{raw[0]},
            std::byte{raw[1]}, std::byte{raw[2]},
            std::byte{raw[3]}, std::byte{raw[4]}};

        psm::memory::vector<std::byte> payload(raw.size() - 5);
        for (std::size_t i = 5; i < raw.size(); ++i)
            payload[i - 5] = std::byte{raw[i]};

        auto rec = psm::tls::record::builder()
                       .type(static_cast<std::uint8_t>(hdr[0]))
                       .version((static_cast<std::uint16_t>(hdr[1]) << 8) | static_cast<std::uint16_t>(hdr[2]))
                       .payload(payload)
                       .build();

        auto [ec, ch] = psm::tls::client_hello::from(rec);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "from(record): success";
        EXPECT_TRUE(ch.sni() == "fromrecord.test") << "from(record): sni";
        EXPECT_TRUE(ch.has_x25519()) << "from(record): has_x25519";
        EXPECT_TRUE(!ch.versions().empty()) << "from(record): versions";
        EXPECT_TRUE(!ch.raw_record().empty()) << "from(record): raw_record";
        EXPECT_TRUE(!ch.raw_msg().empty()) << "from(record): raw_msg";
    }

    TEST(TlsHelloPure, FromBytesExactly44)
    {
        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1);
        hs_body.push_back(0x00);

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);
        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());

        std::vector<std::uint8_t> raw;
        raw.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(raw, 0x0303);
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "exactly 44 bytes: success";
        EXPECT_TRUE(ch.sni().empty()) << "exactly 44 bytes: no extensions";
    }

    TEST(TlsHelloPure, FromBytes43Fails)
    {
        std::vector<std::uint8_t> raw(43, 0x16);
        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "43 bytes: fails";
    }

    TEST(TlsHelloPure, FromBytesCipherLenTruncated)
    {
        std::vector<std::uint8_t> raw;
        raw.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(raw, 0x0303);

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);

        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(0x00);
        write_u16(hs_body, 200);
        hs_body.push_back(0x13);
        hs_body.push_back(0x01);

        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "cipher_len truncated: fails";
    }

    TEST(TlsHelloPure, FromBytesSessionIdBounds)
    {
        std::vector<std::uint8_t> raw;
        raw.push_back(psm::protocol::tls::CT_HANDSHAKE);
        write_u16(raw, 0x0303);

        std::vector<std::uint8_t> body;
        body.push_back(psm::protocol::tls::HS_CLIENT_HELLO);

        std::vector<std::uint8_t> hs_body;
        hs_body.push_back(0x03);
        hs_body.push_back(0x03);
        hs_body.insert(hs_body.end(), 32, 0x00);
        hs_body.push_back(20);
        hs_body.insert(hs_body.end(), 10, 0xAA);
        write_u16(hs_body, 2);
        write_u16(hs_body, psm::protocol::tls::CIPHER_AES_128_GCM_SHA256);
        hs_body.push_back(1);
        hs_body.push_back(0x00);

        write_u24(body, hs_body.size());
        body.insert(body.end(), hs_body.begin(), hs_body.end());
        write_u16(raw, static_cast<std::uint16_t>(body.size()));
        raw.insert(raw.end(), body.begin(), body.end());

        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::failed(ec)) << "session_id claims 20 but only 10 bytes: fails";
    }

    TEST(TlsHelloPure, SniOnlyNonHostnameExits)
    {
        std::vector<std::uint8_t> ext_block;

        std::vector<std::uint8_t> sni_ext;
        write_u16(sni_ext, 6);
        sni_ext.push_back(0x01);
        write_u16(sni_ext, 3);
        sni_ext.push_back('a');
        sni_ext.push_back('b');
        sni_ext.push_back('c');

        write_u16(ext_block, psm::protocol::tls::EXT_SERVER_NAME);
        write_u16(ext_block, static_cast<std::uint16_t>(sni_ext.size()));
        ext_block.insert(ext_block.end(), sni_ext.begin(), sni_ext.end());

        std::vector<std::uint8_t> sv_ext;
        sv_ext.push_back(2);
        write_u16(sv_ext, psm::protocol::tls::VERSION_TLS13);
        write_u16(ext_block, psm::protocol::tls::EXT_SUPPORTED_VERSIONS);
        write_u16(ext_block, static_cast<std::uint16_t>(sv_ext.size()));
        ext_block.insert(ext_block.end(), sv_ext.begin(), sv_ext.end());

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
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "SNI only non-hostname: parses";
        EXPECT_TRUE(ch.sni().empty()) << "SNI only non-hostname: sni empty";
    }

    TEST(TlsHelloPure, ToFeaturesSessionIdLen)
    {
        auto raw = build_valid_hello();
        auto [ec, ch] = psm::tls::client_hello::from_bytes(raw);
        EXPECT_TRUE(psm::fault::succeeded(ec)) << "to_features setup: success";

        auto feat = ch.to_features();
        EXPECT_TRUE(feat.session_id_len == 0) << "to_features: session_id_len=0";
        EXPECT_TRUE(feat.random[0] == 0x00) << "to_features: random[0]=0";
        EXPECT_TRUE(feat.random[31] == 0x00) << "to_features: random[31]=0";
        EXPECT_TRUE(feat.has_alpn == false) << "to_features: has_alpn=false";
        EXPECT_TRUE(feat.has_psk == false) << "to_features: has_psk=false";
        EXPECT_TRUE(feat.has_ech == false) << "to_features: has_ech=false";
    }

    TEST(TlsHelloPure, FromRecordBadPayload)
    {
        psm::memory::vector<std::byte> garbage(10, std::byte{0xFF});
        auto rec = psm::tls::record::builder()
                       .type(0x17)
                       .version(0x0303)
                       .payload(garbage)
                       .build();

        auto [ec, ch] = psm::tls::client_hello::from(rec);
        EXPECT_TRUE(psm::fault::failed(ec)) << "from(record) bad payload: fails";
    }
} // namespace
