/**
 * @file ShadowsocksConnPure.cpp
 * @brief SS2022 Relay 密钥派生纯函数单元测试
 * @details 测试 derive_aead_context 的核心逻辑：PSK+salt 拼接后通过 BLAKE3 KDF
 *          派生密钥，再构造 aead_context。覆盖 AES-128/256-GCM 和 ChaCha20-Poly1305
 *          三种加密方法，以及 format 命名空间的 decode_psk/resolve_method/keysalt_len。
 */

#include <prism/proto/protocol/shadowsocks/constants.hpp>
#include <prism/proto/protocol/shadowsocks/framing.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>


#include <gtest/gtest.h>

namespace
{
    using psm::protocol::shadowsocks::cipher_method;
    using psm::protocol::shadowsocks::kdf_context;
    namespace ss_fmt = psm::protocol::shadowsocks::format;

    TEST(ShadowsocksConnPure, DeriveKeyAes128)
    {
        const std::array<std::uint8_t, 16> psk = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        const std::array<std::uint8_t, 16> salt = {16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};

        std::array<std::uint8_t, 32> material{};
        std::memcpy(material.data(), psk.data(), 16);
        std::memcpy(material.data() + 16, salt.data(), 16);

        auto key = psm::crypto::derive_key(
            kdf_context,
            std::span<const std::uint8_t>(material.data(), 32),
            16);

        EXPECT_TRUE(key.size() == 16) << "derive aes-128: key length=16";

        // 用两个独立的 aead_context 分别 seal 和 open（每个 nonce 从 0 开始）
        psm::crypto::aead_context seal_ctx(psm::crypto::aead_cipher::aes_128_gcm, key);
        psm::crypto::aead_context open_ctx(psm::crypto::aead_cipher::aes_128_gcm, key);

        const std::uint8_t pt[] = {0x01, 0x02, 0x03, 0x04};
        std::vector<std::uint8_t> sealed(seal_ctx.seal_size(4));
        auto seal_ec = seal_ctx.seal(sealed, pt);
        EXPECT_TRUE(seal_ec == psm::fault::code::success) << "derive aes-128: seal success";
        EXPECT_TRUE(sealed.size() == 20) << "derive aes-128: sealed size=20";

        std::vector<std::uint8_t> opened(open_ctx.open_size(sealed.size()));
        auto open_ec = open_ctx.open(opened, sealed);
        EXPECT_TRUE(open_ec == psm::fault::code::success) << "derive aes-128: open success";
        EXPECT_TRUE(opened.size() == 4) << "derive aes-128: opened size=4";
        EXPECT_TRUE(std::memcmp(opened.data(), pt, 4) == 0)
                     << "derive aes-128: round-trip matches";
    }

    TEST(ShadowsocksConnPure, DeriveKeyAes256)
    {
        std::array<std::uint8_t, 32> psk{};
        std::array<std::uint8_t, 32> salt{};
        for (int i = 0; i < 32; ++i)
        {
            psk[i] = static_cast<std::uint8_t>(i);
            salt[i] = static_cast<std::uint8_t>(32 + i);
        }

        std::array<std::uint8_t, 64> material{};
        std::memcpy(material.data(), psk.data(), 32);
        std::memcpy(material.data() + 32, salt.data(), 32);

        auto key = psm::crypto::derive_key(
            kdf_context,
            std::span<const std::uint8_t>(material.data(), 64),
            32);

        EXPECT_TRUE(key.size() == 32) << "derive aes-256: key length=32";

        psm::crypto::aead_context seal_ctx(psm::crypto::aead_cipher::aes_256_gcm, key);
        psm::crypto::aead_context open_ctx(psm::crypto::aead_cipher::aes_256_gcm, key);
        const std::uint8_t pt[] = {0xAA, 0xBB, 0xCC};
        std::vector<std::uint8_t> sealed(seal_ctx.seal_size(3));
        seal_ctx.seal(sealed, pt);
        std::vector<std::uint8_t> opened(open_ctx.open_size(sealed.size()));
        auto ec = open_ctx.open(opened, sealed);
        EXPECT_TRUE(ec == psm::fault::code::success) << "derive aes-256: open success";
        EXPECT_TRUE(std::memcmp(opened.data(), pt, 3) == 0)
                     << "derive aes-256: round-trip matches";
    }

    TEST(ShadowsocksConnPure, DeriveKeyChaCha20)
    {
        std::array<std::uint8_t, 32> psk{};
        std::array<std::uint8_t, 32> salt{};
        for (int i = 0; i < 32; ++i)
        {
            psk[i] = static_cast<std::uint8_t>(i ^ 0x55);
            salt[i] = static_cast<std::uint8_t>(i ^ 0xAA);
        }

        std::array<std::uint8_t, 64> material{};
        std::memcpy(material.data(), psk.data(), 32);
        std::memcpy(material.data() + 32, salt.data(), 32);

        auto key = psm::crypto::derive_key(
            kdf_context,
            std::span<const std::uint8_t>(material.data(), 64),
            32);

        EXPECT_TRUE(key.size() == 32) << "derive chacha20: key length=32";

        psm::crypto::aead_context seal_ctx(psm::crypto::aead_cipher::chacha20_poly1305, key);
        psm::crypto::aead_context open_ctx(psm::crypto::aead_cipher::chacha20_poly1305, key);
        const std::uint8_t pt[] = {0xDE, 0xAD, 0xBE, 0xEF};
        std::vector<std::uint8_t> sealed(seal_ctx.seal_size(4));
        seal_ctx.seal(sealed, pt);
        std::vector<std::uint8_t> opened(open_ctx.open_size(sealed.size()));
        auto ec = open_ctx.open(opened, sealed);
        EXPECT_TRUE(ec == psm::fault::code::success) << "derive chacha20: open success";
        EXPECT_TRUE(std::memcmp(opened.data(), pt, 4) == 0)
                     << "derive chacha20: round-trip matches";
    }

    TEST(ShadowsocksConnPure, DeriveKeyDeterministic)
    {
        std::array<std::uint8_t, 32> material{};
        for (int i = 0; i < 32; ++i) material[i] = static_cast<std::uint8_t>(i);

        auto key1 = psm::crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(material.data(), 32), 16);
        auto key2 = psm::crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(material.data(), 32), 16);

        EXPECT_TRUE(key1.size() == key2.size()) << "derive: same size";
        EXPECT_TRUE(std::memcmp(key1.data(), key2.data(), key1.size()) == 0)
                     << "derive: deterministic output";
    }

    TEST(ShadowsocksConnPure, DeriveKeyDifferentSalt)
    {
        std::array<std::uint8_t, 16> psk{};
        std::array<std::uint8_t, 16> salt_a{};
        std::array<std::uint8_t, 16> salt_b{};
        salt_a[0] = 0x01;
        salt_b[0] = 0x02;

        std::array<std::uint8_t, 32> mat_a{};
        std::array<std::uint8_t, 32> mat_b{};
        std::memcpy(mat_a.data(), psk.data(), 16);
        std::memcpy(mat_a.data() + 16, salt_a.data(), 16);
        std::memcpy(mat_b.data(), psk.data(), 16);
        std::memcpy(mat_b.data() + 16, salt_b.data(), 16);

        auto key_a = psm::crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(mat_a.data(), 32), 16);
        auto key_b = psm::crypto::derive_key(
            kdf_context, std::span<const std::uint8_t>(mat_b.data(), 32), 16);

        EXPECT_TRUE(std::memcmp(key_a.data(), key_b.data(), 16) != 0)
                     << "derive: different salt produces different key";
    }

    TEST(ShadowsocksConnPure, FormatDecodePsk)
    {
        // Base64 编码 32 个 0x00 字节
        auto [ec, bytes] = ss_fmt::decode_psk("//////////////////////////////////////////8=");
        EXPECT_TRUE(ec == psm::fault::code::success) << "decode_psk: valid base64 success";
        EXPECT_TRUE(bytes.size() == 32) << "decode_psk: 32-byte key";
    }

    TEST(ShadowsocksConnPure, FormatDecodePskEmpty)
    {
        auto [ec, bytes] = ss_fmt::decode_psk("");
        EXPECT_TRUE(ec != psm::fault::code::success || bytes.empty())
                     << "decode_psk: empty string handled";
    }

    TEST(ShadowsocksConnPure, FormatResolveMethod)
    {
        auto m1 = ss_fmt::resolve_method("2022-blake3-aes-128-gcm", 16);
        EXPECT_TRUE(m1 == cipher_method::aes_128_gcm) << "resolve: aes-128";

        auto m2 = ss_fmt::resolve_method("2022-blake3-aes-256-gcm", 32);
        EXPECT_TRUE(m2 == cipher_method::aes_256_gcm) << "resolve: aes-256";

        auto m3 = ss_fmt::resolve_method("2022-blake3-chacha20-poly1305", 32);
        EXPECT_TRUE(m3 == cipher_method::chacha20_poly1305) << "resolve: chacha20";

        auto m4 = ss_fmt::resolve_method("", 16);
        EXPECT_TRUE(m4 == cipher_method::aes_128_gcm) << "resolve: default for 16-byte PSK";
    }

    TEST(ShadowsocksConnPure, FormatKeysaltLen)
    {
        EXPECT_TRUE(ss_fmt::keysalt_len(cipher_method::aes_128_gcm) == 16)
                     << "keysalt_len: aes-128 = 16";
        EXPECT_TRUE(ss_fmt::keysalt_len(cipher_method::aes_256_gcm) == 32)
                     << "keysalt_len: aes-256 = 32";
        EXPECT_TRUE(ss_fmt::keysalt_len(cipher_method::chacha20_poly1305) == 32)
                     << "keysalt_len: chacha20 = 32";
    }

} // namespace
