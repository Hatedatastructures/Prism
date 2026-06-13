/**
 * @file CryptoPure.cpp
 * @brief 纯密码学函数单元测试
 * @details 测试 BLAKE3 (hash, keyed_hash, derive_key)、AES-ECB (ecb_encrypt/ecb_decrypt)、
 *          X25519 (generate_keypair, derive_pubkey, x25519 round-trip)。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/block.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/core/core.hpp>

#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    // --- BLAKE3 ---

    TEST(CryptoPure, Blake3Hash)
    {
        const std::uint8_t data[] = {0x01, 0x02, 0x03};
        auto h = psm::crypto::hash(data);
        EXPECT_EQ(h.size(), 32u) << "blake3 hash: 32 bytes";
        // Deterministic: same input -> same output
        auto h2 = psm::crypto::hash(data);
        EXPECT_EQ(std::memcmp(h.data(), h2.data(), 32), 0) << "blake3 hash: deterministic";
    }

    TEST(CryptoPure, Blake3HashEmpty)
    {
        auto h = psm::crypto::hash(std::span<const std::uint8_t>{});
        EXPECT_EQ(h.size(), 32u) << "blake3 hash empty: 32 bytes";
        // Not all zeros (BLAKE3 of empty is a known value)
        bool all_zero = true;
        for (auto b : h)
            if (b != 0)
                all_zero = false;
        EXPECT_FALSE(all_zero) << "blake3 hash empty: not all zero";
    }

    TEST(CryptoPure, Blake3KeyedHash)
    {
        std::array<std::uint8_t, 32> key{};
        for (std::size_t i = 0; i < 32; ++i)
            key[i] = static_cast<std::uint8_t>(i);

        const std::uint8_t data[] = "hello world";
        auto h = psm::crypto::keyed_hash(key, data);
        EXPECT_EQ(h.size(), 32u) << "blake3 keyed_hash: 32 bytes";

        // Different key -> different hash
        std::array<std::uint8_t, 32> key2{};
        auto h2 = psm::crypto::keyed_hash(key2, data);
        EXPECT_NE(std::memcmp(h.data(), h2.data(), 32), 0) << "blake3 keyed_hash: different keys differ";
    }

    TEST(CryptoPure, Blake3DeriveKey)
    {
        const std::uint8_t material[] = {0xAA, 0xBB, 0xCC};
        std::array<std::uint8_t, 32> out{};
        psm::crypto::derive_key("test context", material, out);
        EXPECT_EQ(out.size(), 32u) << "blake3 derive_key: 32 bytes";

        // Not all zeros
        bool all_zero = true;
        for (auto b : out)
            if (b != 0)
                all_zero = false;
        EXPECT_FALSE(all_zero) << "blake3 derive_key: not all zero";

        // Deterministic
        std::array<std::uint8_t, 32> out2{};
        psm::crypto::derive_key("test context", material, out2);
        EXPECT_EQ(std::memcmp(out.data(), out2.data(), 32), 0) << "blake3 derive_key: deterministic";
    }

    TEST(CryptoPure, Blake3DeriveKeyVector)
    {
        const std::uint8_t material[] = {0x01};
        auto out = psm::crypto::derive_key("context", material, 16);
        EXPECT_EQ(out.size(), 16u) << "blake3 derive_key vector: 16 bytes";
    }

    // --- AES-ECB ---

    TEST(CryptoPure, EcbRoundTrip)
    {
        std::array<std::uint8_t, 16> plaintext{};
        for (std::size_t i = 0; i < 16; ++i)
            plaintext[i] = static_cast<std::uint8_t>(i);

        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < 16; ++i)
            key[i] = static_cast<std::uint8_t>(i * 2);

        auto encrypted = psm::crypto::ecb_encrypt(plaintext, key);
        EXPECT_EQ(encrypted.size(), 16u) << "ecb encrypt: 16 bytes";
        EXPECT_NE(std::memcmp(plaintext.data(), encrypted.data(), 16), 0)
            << "ecb encrypt: ciphertext differs from plaintext";

        auto decrypted = psm::crypto::ecb_decrypt(encrypted, key);
        EXPECT_EQ(std::memcmp(plaintext.data(), decrypted.data(), 16), 0)
            << "ecb round-trip: decrypt(encrypt(x)) == x";
    }

    TEST(CryptoPure, EcbRoundTrip256)
    {
        std::array<std::uint8_t, 16> plaintext{};
        plaintext[0] = 0xFF;

        std::array<std::uint8_t, 32> key256{};
        for (std::size_t i = 0; i < 32; ++i)
            key256[i] = static_cast<std::uint8_t>(i);

        auto encrypted = psm::crypto::ecb_encrypt(plaintext, key256);
        auto decrypted = psm::crypto::ecb_decrypt(encrypted, key256);
        EXPECT_EQ(std::memcmp(plaintext.data(), decrypted.data(), 16), 0)
            << "ecb round-trip aes-256: decrypt(encrypt(x)) == x";
    }

    TEST(CryptoPure, EcbDeterministic)
    {
        std::array<std::uint8_t, 16> plaintext{};
        plaintext[15] = 0x42;
        std::array<std::uint8_t, 16> key{};
        key[0] = 0x01;

        auto e1 = psm::crypto::ecb_encrypt(plaintext, key);
        auto e2 = psm::crypto::ecb_encrypt(plaintext, key);
        EXPECT_EQ(std::memcmp(e1.data(), e2.data(), 16), 0) << "ecb encrypt: deterministic";
    }

    // --- X25519 ---

    TEST(CryptoPure, X25519Keypair)
    {
        auto kp = psm::crypto::generate_keypair();
        EXPECT_EQ(kp.private_key.size(), 32u) << "x25519 keypair: private_key 32 bytes";
        EXPECT_EQ(kp.public_key.size(), 32u) << "x25519 keypair: public_key 32 bytes";

        // Not all zeros
        bool priv_zero = true, pub_zero = true;
        for (std::size_t i = 0; i < 32; ++i)
        {
            if (kp.private_key[i] != 0)
                priv_zero = false;
            if (kp.public_key[i] != 0)
                pub_zero = false;
        }
        EXPECT_FALSE(priv_zero) << "x25519 keypair: private_key not all zero";
        EXPECT_FALSE(pub_zero) << "x25519 keypair: public_key not all zero";
    }

    TEST(CryptoPure, X25519DerivePubkey)
    {
        auto kp = psm::crypto::generate_keypair();
        auto derived_pub = psm::crypto::derive_pubkey(kp.private_key);
        EXPECT_EQ(std::memcmp(kp.public_key.data(), derived_pub.data(), 32), 0)
            << "x25519 derive_pubkey: matches keypair public_key";
    }

    TEST(CryptoPure, X25519KeyExchange)
    {
        auto alice = psm::crypto::generate_keypair();
        auto bob = psm::crypto::generate_keypair();

        auto [ec1, shared_ab] = psm::crypto::x25519(alice.private_key, bob.public_key);
        EXPECT_EQ(ec1, psm::fault::code::success) << "x25519 alice->bob: success";

        auto [ec2, shared_ba] = psm::crypto::x25519(bob.private_key, alice.public_key);
        EXPECT_EQ(ec2, psm::fault::code::success) << "x25519 bob->alice: success";

        EXPECT_EQ(std::memcmp(shared_ab.data(), shared_ba.data(), 32), 0)
            << "x25519 key exchange: shared secrets match";
    }

    TEST(CryptoPure, X25519SharedNotZero)
    {
        auto alice = psm::crypto::generate_keypair();
        auto bob = psm::crypto::generate_keypair();
        auto [ec, shared] = psm::crypto::x25519(alice.private_key, bob.public_key);
        EXPECT_EQ(ec, psm::fault::code::success) << "x25519 shared: success";

        bool all_zero = true;
        for (auto b : shared)
            if (b != 0)
                all_zero = false;
        EXPECT_FALSE(all_zero) << "x25519 shared: not all zero";
    }

} // namespace
