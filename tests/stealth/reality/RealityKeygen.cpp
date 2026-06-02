/**
 * @file RealityKeygen.cpp
 * @brief Reality TLS 1.3 密钥调度单元测试
 * @details 测试 derive_hs_keys、derive_app_keys、compute_verify。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/util/keygen.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/fault.hpp>

#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    TEST(RealityKeygen, DeriveHsKeys)
    {
        // Generate X25519 keypair to produce a realistic shared secret
        auto alice = psm::crypto::generate_keypair();
        auto bob = psm::crypto::generate_keypair();
        auto [ec_ss, shared_secret] = psm::crypto::x25519(alice.private_key, bob.public_key);
        ASSERT_EQ(ec_ss, psm::fault::code::success) << "x25519 for test: success";

        // Dummy handshake messages
        std::array<std::uint8_t, 64> chello_msg{};
        for (std::size_t i = 0; i < 64; ++i)
            chello_msg[i] = static_cast<std::uint8_t>(i);
        std::array<std::uint8_t, 64> shello_msg{};
        for (std::size_t i = 0; i < 64; ++i)
            shello_msg[i] = static_cast<std::uint8_t>(i + 100);

        auto [ec, keys] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        EXPECT_EQ(ec, psm::fault::code::success) << "derive_hs_keys: success";

        // Verify all key fields are non-zero (with high probability)
        bool server_hskey_zero = true;
        for (auto b : keys.server_hskey)
            if (b != 0)
                server_hskey_zero = false;
        EXPECT_TRUE(!server_hskey_zero) << "derive_hs_keys: server_hskey not all zero";

        bool client_hskey_zero = true;
        for (auto b : keys.client_hskey)
            if (b != 0)
                client_hskey_zero = false;
        EXPECT_TRUE(!client_hskey_zero) << "derive_hs_keys: client_hskey not all zero";

        bool master_secret_zero = true;
        for (auto b : keys.master_secret)
            if (b != 0)
                master_secret_zero = false;
        EXPECT_TRUE(!master_secret_zero) << "derive_hs_keys: master_secret not all zero";

        EXPECT_TRUE(keys.server_finkey.size() == 32) << "derive_hs_keys: finkey 32 bytes";
    }

    TEST(RealityKeygen, DeriveHsKeysDeterministic)
    {
        std::array<std::uint8_t, 32> shared_secret{};
        shared_secret[0] = 0x42;
        std::array<std::uint8_t, 32> chello_msg{};
        std::array<std::uint8_t, 32> shello_msg{};

        auto [ec1, keys1] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        auto [ec2, keys2] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        EXPECT_TRUE(ec1 == psm::fault::code::success) << "derive_hs_keys det: success";
        EXPECT_TRUE(std::memcmp(keys1.server_hskey.data(), keys2.server_hskey.data(), 16) == 0)
            << "derive_hs_keys: deterministic";
    }

    TEST(RealityKeygen, DeriveAppKeys)
    {
        // First derive handshake keys to get a valid master_secret
        std::array<std::uint8_t, 32> shared_secret{};
        shared_secret[0] = 0x42;
        std::array<std::uint8_t, 32> chello_msg{};
        std::array<std::uint8_t, 32> shello_msg{};

        auto [ec_hs, keys] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        ASSERT_TRUE(ec_hs == psm::fault::code::success) << "derive_app setup: success";

        // Derive app keys using the master_secret
        std::array<std::uint8_t, 32> server_finhash{};
        psm::stealth::reality::key_material app_keys = keys;
        auto ec = psm::stealth::reality::derive_app_keys(keys.master_secret, server_finhash, app_keys);
        EXPECT_TRUE(ec == psm::fault::code::success) << "derive_app_keys: success";

        bool server_appkey_zero = true;
        for (auto b : app_keys.server_appkey)
            if (b != 0)
                server_appkey_zero = false;
        EXPECT_TRUE(!server_appkey_zero) << "derive_app_keys: server_appkey not all zero";

        bool client_appkey_zero = true;
        for (auto b : app_keys.client_appkey)
            if (b != 0)
                client_appkey_zero = false;
        EXPECT_TRUE(!client_appkey_zero) << "derive_app_keys: client_appkey not all zero";
    }

    TEST(RealityKeygen, ComputeVerify)
    {
        std::array<std::uint8_t, 32> finished_key{};
        finished_key[0] = 0xAA;
        std::array<std::uint8_t, 32> transcript_hash{};
        transcript_hash[0] = 0xBB;

        auto verify = psm::stealth::reality::compute_verify(finished_key, transcript_hash);
        EXPECT_TRUE(verify.size() == 32) << "compute_verify: 32 bytes";

        // Deterministic
        auto verify2 = psm::stealth::reality::compute_verify(finished_key, transcript_hash);
        EXPECT_TRUE(std::memcmp(verify.data(), verify2.data(), 32) == 0) << "compute_verify: deterministic";

        // Different inputs -> different outputs
        finished_key[0] = 0xCC;
        auto verify3 = psm::stealth::reality::compute_verify(finished_key, transcript_hash);
        EXPECT_TRUE(std::memcmp(verify.data(), verify3.data(), 32) != 0)
            << "compute_verify: different inputs -> different outputs";
    }

    TEST(RealityKeygen, ComputeVerifyIsHmac)
    {
        // compute_verify(finished_key, transcript_hash) = HMAC-SHA256(finished_key, transcript_hash)
        std::array<std::uint8_t, 32> key{};
        key[0] = 0x01;
        std::array<std::uint8_t, 32> hash{};
        hash[0] = 0x02;

        auto verify = psm::stealth::reality::compute_verify(key, hash);
        auto hmac = psm::crypto::hmac_sha256(key, hash);
        EXPECT_TRUE(std::memcmp(verify.data(), hmac.data(), 32) == 0)
            << "compute_verify == hmac_sha256";
    }

} // namespace
