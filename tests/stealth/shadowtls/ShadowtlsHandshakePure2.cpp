/**
 * @file ShadowtlsHandshakePure2.cpp
 * @brief ShadowTLS 握手纯函数深度测试
 * @details 测试 extract_random、is_tls13_hello 纯函数逻辑。
 *          通过 #include 源文件覆盖编译行，调用匿名命名空间中的真实函数。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>
#include <prism/stealth/facade/shadowtls/handshake.hpp>
#include <prism/stealth/common.hpp>

#include "../../src/prism/stealth/facade/shadowtls/handshake.cpp"

namespace
{
    using namespace psm::stealth::shadowtls;

    // ─── 辅助：构造 TLS ServerHello 帧 ──────────────

    auto build_server_hello(bool with_tls13_ext, std::uint8_t session_id_len = 0)
        -> std::vector<std::byte>
    {
        std::size_t ext_size = with_tls13_ext ? 6 : 0;
        std::size_t body_size = 2 + tls_rndsize + 1 + session_id_len + 2 + 1 + 2 + ext_size;
        std::size_t total = tls_hdrsize + 1 + 3 + body_size;

        std::vector<std::byte> buf(total, std::byte{0});
        auto *raw = reinterpret_cast<std::uint8_t *>(buf.data());

        // TLS record header
        raw[0] = content_handshake;
        raw[1] = 0x03; raw[2] = 0x01;
        raw[3] = static_cast<std::uint8_t>(((body_size + 4) >> 8) & 0xFF);
        raw[4] = static_cast<std::uint8_t>((body_size + 4) & 0xFF);

        // Handshake header
        raw[5] = hs_type_serverhello;
        raw[6] = static_cast<std::uint8_t>((body_size >> 16) & 0xFF);
        raw[7] = static_cast<std::uint8_t>((body_size >> 8) & 0xFF);
        raw[8] = static_cast<std::uint8_t>(body_size & 0xFF);

        // Server version (legacy TLS 1.2)
        raw[9] = 0x03; raw[10] = 0x03;

        // Random (32 bytes)
        for (int i = 0; i < 32; ++i)
            raw[11 + i] = static_cast<std::uint8_t>(i + 0x40);

        // Session ID length + session ID
        std::size_t offset = 43;
        raw[offset] = session_id_len;
        for (int i = 0; i < session_id_len; ++i)
            raw[offset + 1 + i] = static_cast<std::uint8_t>(i + 0xA0);
        offset += 1 + session_id_len;

        // Cipher suite
        raw[offset] = 0x13; raw[offset + 1] = 0x01;
        offset += 2;

        // Compression
        raw[offset] = 0x00;
        offset += 1;

        // Extensions length
        raw[offset] = static_cast<std::uint8_t>((ext_size >> 8) & 0xFF);
        raw[offset + 1] = static_cast<std::uint8_t>(ext_size & 0xFF);
        offset += 2;

        if (with_tls13_ext)
        {
            raw[offset] = 0x00; raw[offset + 1] = 43;
            raw[offset + 2] = 0x00; raw[offset + 3] = 0x02;
            raw[offset + 4] = 0x03; raw[offset + 5] = 0x04;
        }

        return buf;
    }

    // ─── extract_random ───────────────────────────

    TEST(ShadowtlsHandshakePure2, ExtractRandomValid)
    {
        auto hello = build_server_hello(false);
        auto result = extract_random(hello);
        EXPECT_TRUE(result.has_value()) << "extract_random: valid";
        EXPECT_TRUE((*result)[0] == std::byte{0x40}) << "extract_random: first byte=0x40";
        EXPECT_TRUE((*result)[31] == std::byte{0x5F}) << "extract_random: last byte=0x5F";
    }

    TEST(ShadowtlsHandshakePure2, ExtractRandomTooShort)
    {
        std::vector<std::byte> short_hello(20, std::byte{0});
        auto result = extract_random(short_hello);
        EXPECT_TRUE(!result.has_value()) << "extract_random: too short -> nullopt";
    }

    TEST(ShadowtlsHandshakePure2, ExtractRandomBadContentType)
    {
        auto hello = build_server_hello(false);
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        raw[0] = 0x17;
        auto result = extract_random(hello);
        EXPECT_TRUE(!result.has_value()) << "extract_random: bad content type -> nullopt";
    }

    TEST(ShadowtlsHandshakePure2, ExtractRandomBadHandshakeType)
    {
        auto hello = build_server_hello(false);
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        raw[5] = 0x01;
        auto result = extract_random(hello);
        EXPECT_TRUE(!result.has_value()) << "extract_random: bad hs type -> nullopt";
    }

    TEST(ShadowtlsHandshakePure2, ExtractRandomAllOnes)
    {
        auto hello = build_server_hello(false);
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        // 确保正确的内容类型和握手类型
        raw[0] = content_handshake;
        raw[5] = hs_type_serverhello;
        // 把 random 区域设为 0xFF
        for (int i = 0; i < 32; ++i)
            raw[11 + i] = 0xFF;

        auto result = extract_random(hello);
        EXPECT_TRUE(result.has_value()) << "extract_random: all 0xFF valid";
        for (std::size_t i = 0; i < tls_rndsize; ++i)
        {
            EXPECT_TRUE((*result)[i] == std::byte{0xFF}) << "extract_random: all 0xFF bytes";
        }
    }

    TEST(ShadowtlsHandshakePure2, ExtractRandomExactMinSize)
    {
        // 5+1+3+2+32 = 43 刚好满足
        std::vector<std::byte> hello(43, std::byte{0});
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        raw[0] = content_handshake;
        raw[5] = hs_type_serverhello;
        raw[11] = 0x42;

        auto result = extract_random(hello);
        EXPECT_TRUE(result.has_value()) << "extract_random: exact min size";
        EXPECT_TRUE((*result)[0] == std::byte{0x42}) << "extract_random: exact first byte";
    }

    TEST(ShadowtlsHandshakePure2, ExtractRandomOneBelowMin)
    {
        std::vector<std::byte> hello(42, std::byte{0});
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        raw[0] = content_handshake;
        raw[5] = hs_type_serverhello;

        auto result = extract_random(hello);
        EXPECT_TRUE(!result.has_value()) << "extract_random: 42 bytes -> nullopt";
    }

    // ─── is_tls13_hello ───────────────────────────

    TEST(ShadowtlsHandshakePure2, IsTls13HelloTrue)
    {
        auto hello = build_server_hello(true);
        auto result = is_tls13_hello(hello);
        EXPECT_TRUE(result) << "is_tls13: with ext43 -> true";
    }

    TEST(ShadowtlsHandshakePure2, IsTls13HelloFalse)
    {
        auto hello = build_server_hello(false);
        auto result = is_tls13_hello(hello);
        EXPECT_TRUE(!result) << "is_tls13: no ext43 -> false";
    }

    TEST(ShadowtlsHandshakePure2, IsTls13HelloTooShort)
    {
        std::vector<std::byte> short_hello(20, std::byte{0});
        auto result = is_tls13_hello(short_hello);
        EXPECT_TRUE(!result) << "is_tls13: too short -> false";
    }

    TEST(ShadowtlsHandshakePure2, IsTls13HelloWithSessionId)
    {
        auto hello = build_server_hello(true, 32);
        auto result = is_tls13_hello(hello);
        EXPECT_TRUE(result) << "is_tls13: with 32-byte session_id -> true";
    }

    TEST(ShadowtlsHandshakePure2, IsTls13HelloWrongVersionValue)
    {
        auto hello = build_server_hello(true);
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        // 将 supported_versions 的值改为 TLS 1.2 (0x0303)
        raw[hello.size() - 1] = 0x03;
        auto result = is_tls13_hello(hello);
        EXPECT_TRUE(!result) << "is_tls13: ext43 with TLS 1.2 value -> false";
    }

    TEST(ShadowtlsHandshakePure2, IsTls13HelloTruncatedBeforeSessionId)
    {
        auto hello = build_server_hello(true);
        std::vector<std::byte> truncated(hello.begin(), hello.begin() + 43);
        auto result = is_tls13_hello(truncated);
        EXPECT_TRUE(!result) << "is_tls13: truncated before session_id -> false";
    }

    TEST(ShadowtlsHandshakePure2, IsTls13HelloTruncatedInExtensions)
    {
        auto hello = build_server_hello(true);
        std::vector<std::byte> truncated(hello.begin(), hello.begin() + hello.size() - 2);
        auto result = is_tls13_hello(truncated);
        EXPECT_TRUE(!result) << "is_tls13: truncated in extensions -> false";
    }

    TEST(ShadowtlsHandshakePure2, IsTls13HelloWithShortSessionId)
    {
        auto hello = build_server_hello(true, 4);
        auto result = is_tls13_hello(hello);
        EXPECT_TRUE(result) << "is_tls13: with 4-byte session_id -> true";
    }

} // namespace
