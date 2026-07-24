/**
 * @file ShadowsocksDatagramDeep.cpp
 * @brief SS2022 UDP 数据报深度覆盖测试
 * @details 通过 #include 源文件直接测试匿名命名空间的 parse_body_after_timestamp
 *          以及完整的 AES-GCM / ChaCha20 解密成功路径。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/block.hpp>


#include <gtest/gtest.h>

#include "../../src/prism/protocol/shadowsocks/util/datagram.cpp"

namespace
{
    using namespace psm;
    using namespace psm::protocol::shadowsocks;

    using ss_config = psm::protocol::shadowsocks::config;

    auto b64_encode(std::span<const std::uint8_t> data) -> std::string
    {
        static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(4 * ((data.size() + 2) / 3));
        for (std::size_t i = 0; i < data.size(); i += 3)
        {
            std::uint32_t n = static_cast<std::uint32_t>(data[i]) << 16;
            if (i + 1 < data.size())
                n |= static_cast<std::uint32_t>(data[i + 1]) << 8;
            if (i + 2 < data.size())
                n |= static_cast<std::uint32_t>(data[i + 2]);
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
            out.push_back((i + 1 < data.size()) ? table[(n >> 6) & 0x3F] : '=');
            out.push_back((i + 2 < data.size()) ? table[n & 0x3F] : '=');
        }
        return out;
    }

    auto make_aes128_config() -> ss_config
    {
        ss_config cfg;
        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < 16; ++i)
            key[i] = static_cast<std::uint8_t>(i + 1);
        cfg.psk = b64_encode(key);
        cfg.method = "";
        cfg.enable_udp = true;
        return cfg;
    }

    auto make_chacha_config() -> ss_config
    {
        ss_config cfg;
        std::array<std::uint8_t, 32> key{};
        for (std::size_t i = 0; i < 32; ++i)
            key[i] = static_cast<std::uint8_t>(i + 1);
        cfg.psk = b64_encode(key);
        cfg.method = "2022-blake3-chacha20-poly1305";
        cfg.enable_udp = true;
        return cfg;
    }

    // 构造包含当前时间戳 + IPv4 地址的 AES-GCM 入站包
    auto build_aes_ipv4_packet(
        const memory::vector<std::uint8_t> &psk,
        const std::array<std::uint8_t, 8> &session_id,
        const std::array<std::uint8_t, 8> &packet_id)
        -> memory::vector<std::byte>
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // request_type(1) + timestamp(8) + ATYP(1) + IPv4(4) + port(2) + padding_len(2) + payload
        const std::uint8_t payload_byte = 0xAB;
        const auto plain_len = 1 + 8 + 1 + 4 + 2 + 2 + 1;
        memory::vector<std::uint8_t> plain(plain_len, memory::current_resource());
        plain[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        // SOCKS5 IPv4: ATYP=0x01
        plain[9] = atyp_ipv4;
        plain[10] = 127; plain[11] = 0; plain[12] = 0; plain[13] = 1;
        plain[14] = 0; plain[15] = 80; // port 80
        plain[16] = 0; plain[17] = 0;  // padding_len = 0
        plain[18] = payload_byte;

        // 派生会话子密钥
        std::array<std::uint8_t, 64> material{};
        const auto total = psk.size() + session_id.size();
        std::memcpy(material.data(), psk.data(), psk.size());
        std::memcpy(material.data() + psk.size(), session_id.data(), session_id.size());
        const auto derived_key = crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(material.data(), total), 16);
        crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, derived_key);

        // nonce: sessionID[4..8] + packetID[0..8]
        std::array<std::uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), session_id.data() + 4, 4);
        std::memcpy(nonce.data() + 4, packet_id.data(), 8);

        const auto body_enc_len = crypto::aead_context::seal_size(plain_len);
        memory::vector<std::uint8_t> body_enc(body_enc_len, memory::current_resource());
        ctx.seal(body_enc, plain, std::span<const std::uint8_t>(nonce.data(), nonce.size()));

        // AES-ECB 加密 SeparateHeader
        std::array<std::uint8_t, 16> separate_plain{};
        std::memcpy(separate_plain.data(), session_id.data(), 8);
        std::memcpy(separate_plain.data() + 8, packet_id.data(), 8);
        const auto header_enc = crypto::ecb_encrypt(
            std::span<const std::uint8_t, 16>{separate_plain.data(), 16},
            std::span<const std::uint8_t>(psk.data(), psk.size()));

        memory::vector<std::byte> result(16 + body_enc_len, memory::current_resource());
        std::memcpy(result.data(), header_enc.data(), 16);
        std::memcpy(result.data() + 16, body_enc.data(), body_enc_len);
        return result;
    }

    // 构造包含当前时间戳 + 域名地址的 AES-GCM 入站包
    auto build_aes_domain_packet(
        const memory::vector<std::uint8_t> &psk,
        const std::array<std::uint8_t, 8> &session_id,
        const std::array<std::uint8_t, 8> &packet_id)
        -> memory::vector<std::byte>
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        const char domain[] = "example.com";
        const auto domain_len = static_cast<std::uint8_t>(sizeof(domain) - 1);
        // request_type(1) + ts(8) + ATYP(1) + len(1) + domain(11) + port(2) + padding_len(2) + payload(1)
        const auto plain_len = 1 + 8 + 1 + 1 + domain_len + 2 + 2 + 1;
        memory::vector<std::uint8_t> plain(plain_len, memory::current_resource());
        plain[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        plain[9] = atyp_domain;
        plain[10] = domain_len;
        std::memcpy(plain.data() + 11, domain, domain_len);
        plain[11 + domain_len] = 0x01;
        plain[12 + domain_len] = 0xBB; // port 443
        plain[13 + domain_len] = 0;
        plain[14 + domain_len] = 0; // padding_len = 0
        plain[15 + domain_len] = 0xCC;

        std::array<std::uint8_t, 64> material{};
        const auto total = psk.size() + session_id.size();
        std::memcpy(material.data(), psk.data(), psk.size());
        std::memcpy(material.data() + psk.size(), session_id.data(), session_id.size());
        const auto derived_key = crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(material.data(), total), 16);
        crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, derived_key);

        std::array<std::uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), session_id.data() + 4, 4);
        std::memcpy(nonce.data() + 4, packet_id.data(), 8);

        const auto body_enc_len = crypto::aead_context::seal_size(plain_len);
        memory::vector<std::uint8_t> body_enc(body_enc_len, memory::current_resource());
        ctx.seal(body_enc, plain, std::span<const std::uint8_t>(nonce.data(), nonce.size()));

        std::array<std::uint8_t, 16> separate_plain{};
        std::memcpy(separate_plain.data(), session_id.data(), 8);
        std::memcpy(separate_plain.data() + 8, packet_id.data(), 8);
        const auto header_enc = crypto::ecb_encrypt(
            std::span<const std::uint8_t, 16>{separate_plain.data(), 16},
            std::span<const std::uint8_t>(psk.data(), psk.size()));

        memory::vector<std::byte> result(16 + body_enc_len, memory::current_resource());
        std::memcpy(result.data(), header_enc.data(), 16);
        std::memcpy(result.data() + 16, body_enc.data(), body_enc_len);
        return result;
    }

    // 构造带 padding 的 AES-GCM 入站包
    auto build_aes_with_padding(
        const memory::vector<std::uint8_t> &psk,
        const std::array<std::uint8_t, 8> &session_id,
        const std::array<std::uint8_t, 8> &packet_id)
        -> memory::vector<std::byte>
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // request_type(1) + ts(8) + ATYP(1) + IPv4(4) + port(2) + padding_len(2) + padding(4) + payload(2)
        const auto plain_len = 1 + 8 + 1 + 4 + 2 + 2 + 4 + 2;
        memory::vector<std::uint8_t> plain(plain_len, memory::current_resource());
        plain[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        plain[9] = atyp_ipv4;
        plain[10] = 10; plain[11] = 0; plain[12] = 0; plain[13] = 1;
        plain[14] = 0; plain[15] = 80;
        // padding_len = 4
        plain[16] = 0; plain[17] = 4;
        // padding data (zeros, already zero-initialized)
        // payload
        plain[22] = 0xDD; plain[23] = 0xEE;

        std::array<std::uint8_t, 64> material{};
        const auto total = psk.size() + session_id.size();
        std::memcpy(material.data(), psk.data(), psk.size());
        std::memcpy(material.data() + psk.size(), session_id.data(), session_id.size());
        const auto derived_key = crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(material.data(), total), 16);
        crypto::aead_context ctx(crypto::aead_cipher::aes_128_gcm, derived_key);

        std::array<std::uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), session_id.data() + 4, 4);
        std::memcpy(nonce.data() + 4, packet_id.data(), 8);

        const auto body_enc_len = crypto::aead_context::seal_size(plain_len);
        memory::vector<std::uint8_t> body_enc(body_enc_len, memory::current_resource());
        ctx.seal(body_enc, plain, std::span<const std::uint8_t>(nonce.data(), nonce.size()));

        std::array<std::uint8_t, 16> separate_plain{};
        std::memcpy(separate_plain.data(), session_id.data(), 8);
        std::memcpy(separate_plain.data() + 8, packet_id.data(), 8);
        const auto header_enc = crypto::ecb_encrypt(
            std::span<const std::uint8_t, 16>{separate_plain.data(), 16},
            std::span<const std::uint8_t>(psk.data(), psk.size()));

        memory::vector<std::byte> result(16 + body_enc_len, memory::current_resource());
        std::memcpy(result.data(), header_enc.data(), 16);
        std::memcpy(result.data() + 16, body_enc.data(), body_enc_len);
        return result;
    }

    // 构造 IPv6 地址的 ChaCha20 入站包
    auto build_chacha_ipv6_packet(
        const memory::vector<std::uint8_t> &psk,
        const std::array<std::uint8_t, 8> &session_id,
        const std::array<std::uint8_t, 8> &packet_id)
        -> memory::vector<std::byte>
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // request_type(1) + ts(8) + ATYP(1) + IPv6(16) + port(2) + padding_len(2) + payload(1)
        const auto plain_len = 1 + 8 + 1 + 16 + 2 + 2 + 1;
        memory::vector<std::uint8_t> plain(plain_len, memory::current_resource());
        plain[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        plain[9] = atyp_ipv6;
        // ::1
        plain[10] = 0; plain[11] = 0; plain[12] = 0; plain[13] = 0;
        plain[14] = 0; plain[15] = 0; plain[16] = 0; plain[17] = 0;
        plain[18] = 0; plain[19] = 0; plain[20] = 0; plain[21] = 0;
        plain[22] = 0; plain[23] = 0; plain[24] = 0; plain[25] = 1;
        plain[26] = 0; plain[27] = 80; // port 80
        plain[28] = 0; plain[29] = 0;  // padding_len = 0
        plain[30] = 0xFF;

        crypto::aead_context ctx(crypto::aead_cipher::xchacha20_poly1305,
            std::span<const std::uint8_t>(psk.data(), psk.size()));

        // 24 字节 nonce
        std::array<std::uint8_t, 24> nonce{};
        std::memcpy(nonce.data(), session_id.data(), 8);
        std::memcpy(nonce.data() + 8, packet_id.data(), 8);

        const auto body_enc_len = crypto::aead_context::seal_size(plain_len);
        memory::vector<std::uint8_t> body_enc(body_enc_len, memory::current_resource());
        ctx.seal(body_enc, plain, std::span<const std::uint8_t>(nonce.data(), nonce.size()));

        memory::vector<std::byte> result(16 + body_enc_len, memory::current_resource());
        std::memcpy(result.data(), session_id.data(), 8);
        std::memcpy(result.data() + 8, packet_id.data(), 8);
        std::memcpy(result.data() + 16, body_enc.data(), body_enc_len);
        return result;
    }

    // 构造 ChaCha20 域名地址包
    auto build_chacha_domain_packet(
        const memory::vector<std::uint8_t> &psk,
        const std::array<std::uint8_t, 8> &session_id,
        const std::array<std::uint8_t, 8> &packet_id)
        -> memory::vector<std::byte>
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        const char domain[] = "test.local";
        const auto domain_len = static_cast<std::uint8_t>(sizeof(domain) - 1);
        const auto plain_len = 1 + 8 + 1 + 1 + domain_len + 2 + 2 + 1;
        memory::vector<std::uint8_t> plain(plain_len, memory::current_resource());
        plain[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            plain[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        plain[9] = atyp_domain;
        plain[10] = domain_len;
        std::memcpy(plain.data() + 11, domain, domain_len);
        plain[11 + domain_len] = 1;
        plain[12 + domain_len] = 187; // port 443
        plain[13 + domain_len] = 0;
        plain[14 + domain_len] = 0;
        plain[15 + domain_len] = 0x77;

        crypto::aead_context ctx(crypto::aead_cipher::xchacha20_poly1305,
            std::span<const std::uint8_t>(psk.data(), psk.size()));

        std::array<std::uint8_t, 24> nonce{};
        std::memcpy(nonce.data(), session_id.data(), 8);
        std::memcpy(nonce.data() + 8, packet_id.data(), 8);

        const auto body_enc_len = crypto::aead_context::seal_size(plain_len);
        memory::vector<std::uint8_t> body_enc(body_enc_len, memory::current_resource());
        ctx.seal(body_enc, plain, std::span<const std::uint8_t>(nonce.data(), nonce.size()));

        memory::vector<std::byte> result(16 + body_enc_len, memory::current_resource());
        std::memcpy(result.data(), session_id.data(), 8);
        std::memcpy(result.data() + 8, packet_id.data(), 8);
        std::memcpy(result.data() + 16, body_enc.data(), body_enc_len);
        return result;
    }

    // ─── parse_body_after_timestamp 直接测试 ────────────────

    TEST(ShadowsocksDatagramDeep, ParseBodyTooShort)
    {
        memory::vector<std::uint8_t> short_body(5, memory::current_resource());
        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(short_body, result);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_body: too short -> bad_message";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyBadRequestType)
    {
        // 10 字节最小，但 request_type = 0xFF（无效）
        memory::vector<std::uint8_t> body(10, memory::current_resource());
        body[0] = 0xFF;
        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_body: bad request type -> bad_message";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyTimestampExpired)
    {
        // request_type + old timestamp + 足够数据
        memory::vector<std::uint8_t> body(20, memory::current_resource());
        body[0] = request_type;
        const std::uint64_t old_ts = 100;
        for (std::size_t i = 0; i < 8; ++i)
            body[1 + i] = static_cast<std::uint8_t>((old_ts >> (56 - 8 * i)) & 0xFF);
        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::timestamp_expired) << "parse_body: expired ts -> timestamp_expired";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyBadAddress)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // 有效时间戳，但地址类型无效（0x05）
        memory::vector<std::uint8_t> body(15, memory::current_resource());
        body[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            body[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        body[9] = 0x05; // 无效 ATYP
        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec != psm::fault::code::success) << "parse_body: bad address -> error";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyIpv4Success)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // request_type(1) + ts(8) + ATYP(1) + IPv4(4) + port(2) + padding_len(2) + payload(3)
        memory::vector<std::uint8_t> body(21, memory::current_resource());
        body[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            body[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        body[9] = atyp_ipv4;
        body[10] = 192; body[11] = 168; body[12] = 1; body[13] = 1;
        body[14] = 0x1F; body[15] = 0x90; // port 8080
        body[16] = 0; body[17] = 0;    // padding_len = 0
        body[18] = 0xAA; body[19] = 0xBB; body[20] = 0xCC;

        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_body: IPv4 success";
        EXPECT_TRUE(result.destination_port == 8080) << "parse_body: IPv4 port=8080";
        EXPECT_TRUE(result.payload.size() == 3) << "parse_body: IPv4 payload size=3";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyDomainSuccess)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        const char domain[] = "test.io";
        const auto dlen = static_cast<std::uint8_t>(sizeof(domain) - 1);
        // request_type(1) + ts(8) + ATYP(1) + len(1) + domain(7) + port(2) + padding_len(2) + payload(2)
        const auto total = 1 + 8 + 1 + 1 + dlen + 2 + 2 + 2;
        memory::vector<std::uint8_t> body(total, memory::current_resource());
        body[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            body[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        body[9] = atyp_domain;
        body[10] = dlen;
        std::memcpy(body.data() + 11, domain, dlen);
        body[11 + dlen] = 1;
        body[12 + dlen] = 187; // port 443
        body[13 + dlen] = 0;
        body[14 + dlen] = 0;
        body[15 + dlen] = 0xDE;
        body[16 + dlen] = 0xAD;

        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_body: domain success";
        EXPECT_TRUE(result.destination_port == 443) << "parse_body: domain port=443";
        EXPECT_TRUE(result.payload.size() == 2) << "parse_body: domain payload size=2";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyWithPadding)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // request_type(1) + ts(8) + ATYP(1) + IPv4(4) + port(2) + padding_len(2)=8 + padding(8) + payload(2)
        const auto total = 1 + 8 + 1 + 4 + 2 + 2 + 8 + 2;
        memory::vector<std::uint8_t> body(total, memory::current_resource());
        body[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            body[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        body[9] = atyp_ipv4;
        body[10] = 10; body[11] = 0; body[12] = 0; body[13] = 1;
        body[14] = 0; body[15] = 80;
        body[16] = 0; body[17] = 8; // padding_len = 8
        // padding data is zeros (already)
        body[26] = 0x11; body[27] = 0x22;

        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_body: padding success";
        EXPECT_TRUE(result.payload.size() == 2) << "parse_body: padding payload size=2";
        EXPECT_TRUE(result.payload[0] == 0x11) << "parse_body: padding payload[0]";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyNoPayload)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // request_type(1) + ts(8) + ATYP(1) + IPv4(4) + port(2) + padding_len(2) = 18 字节
        memory::vector<std::uint8_t> body(18, memory::current_resource());
        body[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            body[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        body[9] = atyp_ipv4;
        body[10] = 127; body[11] = 0; body[12] = 0; body[13] = 1;
        body[14] = 0; body[15] = 80;
        body[16] = 0; body[17] = 0; // padding = 0, no payload

        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_body: no payload success";
        EXPECT_TRUE(result.payload.empty()) << "parse_body: no payload -> empty span";
    }

    TEST(ShadowsocksDatagramDeep, ParseBodyNoPaddingField)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto ts = static_cast<std::uint64_t>(now);

        // request_type(1) + ts(8) + ATYP(1) + IPv4(4) + port(2) = 16 字节（不够 padding_len）
        memory::vector<std::uint8_t> body(16, memory::current_resource());
        body[0] = request_type;
        for (std::size_t i = 0; i < 8; ++i)
            body[1 + i] = static_cast<std::uint8_t>((ts >> (56 - 8 * i)) & 0xFF);
        body[9] = atyp_ipv4;
        body[10] = 127; body[11] = 0; body[12] = 0; body[13] = 1;
        body[14] = 0; body[15] = 80;

        udp_dec_pkt result;
        auto ec = parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::success) << "parse_body: no padding field success";
        EXPECT_TRUE(result.payload.empty()) << "parse_body: no padding field -> empty payload";
    }

    // ─── 完整 AES-GCM 解密路径 ────────────────────────

    TEST(ShadowsocksDatagramDeep, AesDecryptIpv4Success)
    {
        auto cfg = make_aes128_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "aes ipv4: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[0] = 0xAA;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 1;

        auto packet = build_aes_ipv4_packet(psk_bytes, session_id, packet_id);
        net::ip::udp::endpoint sender(net::ip::make_address("127.0.0.1"), 9999);

        auto [ec, result] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec == psm::fault::code::success) << "aes ipv4 decrypt: success";
        EXPECT_TRUE(result.destination_port == 80) << "aes ipv4 decrypt: port=80";
        EXPECT_TRUE(result.payload.size() == 1) << "aes ipv4 decrypt: payload size=1";
        EXPECT_TRUE(result.payload[0] == 0xAB) << "aes ipv4 decrypt: payload[0]=0xAB";
        EXPECT_TRUE(result.relay_id == session_id) << "aes ipv4 decrypt: session_id";
    }

    TEST(ShadowsocksDatagramDeep, AesDecryptDomainSuccess)
    {
        auto cfg = make_aes128_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "aes domain: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[1] = 0xBB;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 2;

        auto packet = build_aes_domain_packet(psk_bytes, session_id, packet_id);
        net::ip::udp::endpoint sender(net::ip::make_address("127.0.0.1"), 9999);

        auto [ec, result] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec == psm::fault::code::success) << "aes domain decrypt: success";
        EXPECT_TRUE(result.destination_port == 443) << "aes domain decrypt: port=443";
        EXPECT_TRUE(result.payload.size() == 1) << "aes domain decrypt: payload size=1";
    }

    TEST(ShadowsocksDatagramDeep, AesDecryptWithPadding)
    {
        auto cfg = make_aes128_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "aes padding: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[2] = 0xCC;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 3;

        auto packet = build_aes_with_padding(psk_bytes, session_id, packet_id);
        net::ip::udp::endpoint sender(net::ip::make_address("127.0.0.1"), 9999);

        auto [ec, result] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec == psm::fault::code::success) << "aes padding decrypt: success";
        EXPECT_TRUE(result.payload.size() == 2) << "aes padding decrypt: payload size=2";
        EXPECT_TRUE(result.payload[0] == 0xDD) << "aes padding decrypt: payload[0]=0xDD";
        EXPECT_TRUE(result.payload[1] == 0xEE) << "aes padding decrypt: payload[1]=0xEE";
    }

    TEST(ShadowsocksDatagramDeep, AesDecryptReplay)
    {
        auto cfg = make_aes128_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "aes replay: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[3] = 0xDD;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 42;

        auto packet = build_aes_ipv4_packet(psk_bytes, session_id, packet_id);
        net::ip::udp::endpoint sender(net::ip::make_address("127.0.0.1"), 9999);

        // 首次解密成功
        auto [ec1, res1] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec1 == psm::fault::code::success) << "aes replay: first decrypt success";

        // 重放同一包 -> AEAD nonce 自增导致解密失败（crypto_error，replay 检查在解密之后）
        auto [ec2, res2] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec2 == psm::fault::code::crypto_error) << "aes replay: crypto_error (nonce mismatch)";
    }

    // ─── 完整 ChaCha20 解密路径 ────────────────────────

    TEST(ShadowsocksDatagramDeep, ChachaDecryptIpv6Success)
    {
        auto cfg = make_chacha_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "chacha ipv6: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[0] = 0xEE;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 1;

        auto packet = build_chacha_ipv6_packet(psk_bytes, session_id, packet_id);
        net::ip::udp::endpoint sender(net::ip::make_address("::1"), 9999);

        auto [ec, result] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec == psm::fault::code::success) << "chacha ipv6 decrypt: success";
        EXPECT_TRUE(result.destination_port == 80) << "chacha ipv6 decrypt: port=80";
        EXPECT_TRUE(result.payload.size() == 1) << "chacha ipv6 decrypt: payload size=1";
        EXPECT_TRUE(result.payload[0] == 0xFF) << "chacha ipv6 decrypt: payload[0]=0xFF";
        EXPECT_TRUE(result.relay_id == session_id) << "chacha ipv6 decrypt: session_id";
    }

    TEST(ShadowsocksDatagramDeep, ChachaDecryptDomainSuccess)
    {
        auto cfg = make_chacha_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "chacha domain: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[1] = 0xFF;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 2;

        auto packet = build_chacha_domain_packet(psk_bytes, session_id, packet_id);
        net::ip::udp::endpoint sender(net::ip::make_address("::1"), 9999);

        auto [ec, result] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec == psm::fault::code::success) << "chacha domain decrypt: success";
        EXPECT_TRUE(result.destination_port == 443) << "chacha domain decrypt: port=443";
        EXPECT_TRUE(result.payload.size() == 1) << "chacha domain decrypt: payload size=1";
        EXPECT_TRUE(result.payload[0] == 0x77) << "chacha domain decrypt: payload[0]=0x77";
    }

    TEST(ShadowsocksDatagramDeep, ChachaDecryptReplay)
    {
        auto cfg = make_chacha_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "chacha replay: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[2] = 0x11;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 99;

        auto packet = build_chacha_ipv6_packet(psk_bytes, session_id, packet_id);
        net::ip::udp::endpoint sender(net::ip::make_address("::1"), 9999);

        auto [ec1, res1] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec1 == psm::fault::code::success) << "chacha replay: first success";

        auto [ec2, res2] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec2 == psm::fault::code::crypto_error) << "chacha replay: crypto_error (nonce mismatch)";
    }

    // ─── encrypt_out / send_chacha null entry ─────────────

    TEST(ShadowsocksDatagramDeep, ChachaEncryptNullEntry)
    {
        auto cfg = make_chacha_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        std::array<std::uint8_t, 8> sid{};
        auto [ec, enc] = relay->encrypt_out({}, sid, nullptr);
        EXPECT_TRUE(ec == psm::fault::code::crypto_error) << "chacha encrypt null: crypto_error";
    }

    TEST(ShadowsocksDatagramDeep, AesEncryptNoAeadCtx)
    {
        auto cfg = make_aes128_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        std::array<std::uint8_t, 8> sid{};
        // 手动创建一个没有 aead_ctx 的 entry
        auto entry = std::make_shared<udp_session>();
        // entry->aead_ctx 默认为 nullptr

        const std::byte payload[] = {std::byte{0x01}};
        auto [ec, enc] = relay->encrypt_out(payload, sid, entry);
        EXPECT_TRUE(ec == psm::fault::code::crypto_error) << "aes encrypt no ctx: crypto_error";
    }

    // ─── decrypt_inbound 密文篡改 ─────────────────────

    TEST(ShadowsocksDatagramDeep, AesDecryptCorruptedBody)
    {
        auto cfg = make_aes128_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "aes corrupt: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 10;

        auto packet = build_aes_ipv4_packet(psk_bytes, session_id, packet_id);
        // 篡改 body 密文
        if (packet.size() > 20)
            packet[20] = static_cast<std::byte>(~static_cast<unsigned char>(packet[20]));

        net::ip::udp::endpoint sender(net::ip::make_address("127.0.0.1"), 9999);
        auto [ec, result] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec == psm::fault::code::crypto_error) << "aes corrupt body: crypto_error";
    }

    TEST(ShadowsocksDatagramDeep, ChachaDecryptCorruptedBody)
    {
        auto cfg = make_chacha_config();
        auto tracker = std::make_shared<session_tracker>();
        auto relay = make_udp_relay(cfg, tracker);

        auto [dec_ec, psk_bytes] = format::decode_psk(cfg.psk);
        EXPECT_TRUE(dec_ec == psm::fault::code::success) << "chacha corrupt: decode psk";

        std::array<std::uint8_t, 8> session_id{};
        session_id[4] = 0x22;
        std::array<std::uint8_t, 8> packet_id{};
        packet_id[7] = 10;

        auto packet = build_chacha_ipv6_packet(psk_bytes, session_id, packet_id);
        if (packet.size() > 20)
            packet[20] = static_cast<std::byte>(~static_cast<unsigned char>(packet[20]));

        net::ip::udp::endpoint sender(net::ip::make_address("::1"), 9999);
        auto [ec, result] = relay->decrypt_inbound(packet, sender);
        EXPECT_TRUE(ec == psm::fault::code::crypto_error) << "chacha corrupt body: crypto_error";
    }

} // namespace
