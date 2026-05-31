/**
 * @file CryptoPure.cpp
 * @brief 纯密码学函数单元测试
 * @details 测试 BLAKE3 (hash, keyed_hash, derive_key)、AES-ECB (ecb_encrypt/ecb_decrypt)、
 *          X25519 (generate_keypair, derive_pubkey, x25519 round-trip)。
 */

#include <prism/memory.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/block.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#include <array>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    // --- BLAKE3 ---

    void TestBlake3Hash(TestRunner &runner)
    {
        const std::uint8_t data[] = {0x01, 0x02, 0x03};
        auto h = psm::crypto::hash(data);
        runner.Check(h.size() == 32, "blake3 hash: 32 bytes");
        // Deterministic: same input → same output
        auto h2 = psm::crypto::hash(data);
        runner.Check(std::memcmp(h.data(), h2.data(), 32) == 0, "blake3 hash: deterministic");
    }

    void TestBlake3HashEmpty(TestRunner &runner)
    {
        auto h = psm::crypto::hash(std::span<const std::uint8_t>{});
        runner.Check(h.size() == 32, "blake3 hash empty: 32 bytes");
        // Not all zeros (BLAKE3 of empty is a known value)
        bool all_zero = true;
        for (auto b : h)
            if (b != 0)
                all_zero = false;
        runner.Check(!all_zero, "blake3 hash empty: not all zero");
    }

    void TestBlake3KeyedHash(TestRunner &runner)
    {
        std::array<std::uint8_t, 32> key{};
        for (std::size_t i = 0; i < 32; ++i)
            key[i] = static_cast<std::uint8_t>(i);

        const std::uint8_t data[] = "hello world";
        auto h = psm::crypto::keyed_hash(key, data);
        runner.Check(h.size() == 32, "blake3 keyed_hash: 32 bytes");

        // Different key → different hash
        std::array<std::uint8_t, 32> key2{};
        auto h2 = psm::crypto::keyed_hash(key2, data);
        runner.Check(std::memcmp(h.data(), h2.data(), 32) != 0, "blake3 keyed_hash: different keys differ");
    }

    void TestBlake3DeriveKey(TestRunner &runner)
    {
        const std::uint8_t material[] = {0xAA, 0xBB, 0xCC};
        std::array<std::uint8_t, 32> out{};
        psm::crypto::derive_key("test context", material, out);
        runner.Check(out.size() == 32, "blake3 derive_key: 32 bytes");

        // Not all zeros
        bool all_zero = true;
        for (auto b : out)
            if (b != 0)
                all_zero = false;
        runner.Check(!all_zero, "blake3 derive_key: not all zero");

        // Deterministic
        std::array<std::uint8_t, 32> out2{};
        psm::crypto::derive_key("test context", material, out2);
        runner.Check(std::memcmp(out.data(), out2.data(), 32) == 0, "blake3 derive_key: deterministic");
    }

    void TestBlake3DeriveKeyVector(TestRunner &runner)
    {
        const std::uint8_t material[] = {0x01};
        auto out = psm::crypto::derive_key("context", material, 16);
        runner.Check(out.size() == 16, "blake3 derive_key vector: 16 bytes");
    }

    // --- AES-ECB ---

    void TestEcbRoundTrip(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> plaintext{};
        for (std::size_t i = 0; i < 16; ++i)
            plaintext[i] = static_cast<std::uint8_t>(i);

        std::array<std::uint8_t, 16> key{};
        for (std::size_t i = 0; i < 16; ++i)
            key[i] = static_cast<std::uint8_t>(i * 2);

        auto encrypted = psm::crypto::ecb_encrypt(plaintext, key);
        runner.Check(encrypted.size() == 16, "ecb encrypt: 16 bytes");
        runner.Check(std::memcmp(plaintext.data(), encrypted.data(), 16) != 0,
                     "ecb encrypt: ciphertext differs from plaintext");

        auto decrypted = psm::crypto::ecb_decrypt(encrypted, key);
        runner.Check(std::memcmp(plaintext.data(), decrypted.data(), 16) == 0,
                     "ecb round-trip: decrypt(encrypt(x)) == x");
    }

    void TestEcbRoundTrip256(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> plaintext{};
        plaintext[0] = 0xFF;

        std::array<std::uint8_t, 32> key256{};
        for (std::size_t i = 0; i < 32; ++i)
            key256[i] = static_cast<std::uint8_t>(i);

        auto encrypted = psm::crypto::ecb_encrypt(plaintext, key256);
        auto decrypted = psm::crypto::ecb_decrypt(encrypted, key256);
        runner.Check(std::memcmp(plaintext.data(), decrypted.data(), 16) == 0,
                     "ecb round-trip aes-256: decrypt(encrypt(x)) == x");
    }

    void TestEcbDeterministic(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> plaintext{};
        plaintext[15] = 0x42;
        std::array<std::uint8_t, 16> key{};
        key[0] = 0x01;

        auto e1 = psm::crypto::ecb_encrypt(plaintext, key);
        auto e2 = psm::crypto::ecb_encrypt(plaintext, key);
        runner.Check(std::memcmp(e1.data(), e2.data(), 16) == 0, "ecb encrypt: deterministic");
    }

    // --- X25519 ---

    void TestX25519Keypair(TestRunner &runner)
    {
        auto kp = psm::crypto::generate_keypair();
        runner.Check(kp.private_key.size() == 32, "x25519 keypair: private_key 32 bytes");
        runner.Check(kp.public_key.size() == 32, "x25519 keypair: public_key 32 bytes");

        // Not all zeros
        bool priv_zero = true, pub_zero = true;
        for (std::size_t i = 0; i < 32; ++i)
        {
            if (kp.private_key[i] != 0)
                priv_zero = false;
            if (kp.public_key[i] != 0)
                pub_zero = false;
        }
        runner.Check(!priv_zero, "x25519 keypair: private_key not all zero");
        runner.Check(!pub_zero, "x25519 keypair: public_key not all zero");
    }

    void TestX25519DerivePubkey(TestRunner &runner)
    {
        auto kp = psm::crypto::generate_keypair();
        auto derived_pub = psm::crypto::derive_pubkey(kp.private_key);
        runner.Check(std::memcmp(kp.public_key.data(), derived_pub.data(), 32) == 0,
                     "x25519 derive_pubkey: matches keypair public_key");
    }

    void TestX25519KeyExchange(TestRunner &runner)
    {
        auto alice = psm::crypto::generate_keypair();
        auto bob = psm::crypto::generate_keypair();

        auto [ec1, shared_ab] = psm::crypto::x25519(alice.private_key, bob.public_key);
        runner.Check(ec1 == psm::fault::code::success, "x25519 alice→bob: success");

        auto [ec2, shared_ba] = psm::crypto::x25519(bob.private_key, alice.public_key);
        runner.Check(ec2 == psm::fault::code::success, "x25519 bob→alice: success");

        runner.Check(std::memcmp(shared_ab.data(), shared_ba.data(), 32) == 0,
                     "x25519 key exchange: shared secrets match");
    }

    void TestX25519SharedNotZero(TestRunner &runner)
    {
        auto alice = psm::crypto::generate_keypair();
        auto bob = psm::crypto::generate_keypair();
        auto [ec, shared] = psm::crypto::x25519(alice.private_key, bob.public_key);
        runner.Check(ec == psm::fault::code::success, "x25519 shared: success");

        bool all_zero = true;
        for (auto b : shared)
            if (b != 0)
                all_zero = false;
        runner.Check(!all_zero, "x25519 shared: not all zero");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("CryptoPure");

    TestBlake3Hash(runner);
    TestBlake3HashEmpty(runner);
    TestBlake3KeyedHash(runner);
    TestBlake3DeriveKey(runner);
    TestBlake3DeriveKeyVector(runner);
    TestEcbRoundTrip(runner);
    TestEcbRoundTrip256(runner);
    TestEcbDeterministic(runner);
    TestX25519Keypair(runner);
    TestX25519DerivePubkey(runner);
    TestX25519KeyExchange(runner);
    TestX25519SharedNotZero(runner);

    return runner.Summary();
}
