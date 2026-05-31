/**
 * @file RealityKeygen.cpp
 * @brief Reality TLS 1.3 密钥调度单元测试
 * @details 测试 derive_hs_keys、derive_app_keys、compute_verify。
 */

#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/util/keygen.hpp>
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
    void TestDeriveHsKeys(TestRunner &runner)
    {
        // Generate X25519 keypair to produce a realistic shared secret
        auto alice = psm::crypto::generate_keypair();
        auto bob = psm::crypto::generate_keypair();
        auto [ec_ss, shared_secret] = psm::crypto::x25519(alice.private_key, bob.public_key);
        runner.Check(ec_ss == psm::fault::code::success, "x25519 for test: success");

        // Dummy handshake messages
        std::array<std::uint8_t, 64> chello_msg{};
        for (std::size_t i = 0; i < 64; ++i)
            chello_msg[i] = static_cast<std::uint8_t>(i);
        std::array<std::uint8_t, 64> shello_msg{};
        for (std::size_t i = 0; i < 64; ++i)
            shello_msg[i] = static_cast<std::uint8_t>(i + 100);

        auto [ec, keys] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        runner.Check(ec == psm::fault::code::success, "derive_hs_keys: success");

        // Verify all key fields are non-zero (with high probability)
        bool server_hskey_zero = true;
        for (auto b : keys.server_hskey)
            if (b != 0)
                server_hskey_zero = false;
        runner.Check(!server_hskey_zero, "derive_hs_keys: server_hskey not all zero");

        bool client_hskey_zero = true;
        for (auto b : keys.client_hskey)
            if (b != 0)
                client_hskey_zero = false;
        runner.Check(!client_hskey_zero, "derive_hs_keys: client_hskey not all zero");

        bool master_secret_zero = true;
        for (auto b : keys.master_secret)
            if (b != 0)
                master_secret_zero = false;
        runner.Check(!master_secret_zero, "derive_hs_keys: master_secret not all zero");

        runner.Check(keys.server_finkey.size() == 32, "derive_hs_keys: finkey 32 bytes");
    }

    void TestDeriveHsKeysDeterministic(TestRunner &runner)
    {
        std::array<std::uint8_t, 32> shared_secret{};
        shared_secret[0] = 0x42;
        std::array<std::uint8_t, 32> chello_msg{};
        std::array<std::uint8_t, 32> shello_msg{};

        auto [ec1, keys1] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        auto [ec2, keys2] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        runner.Check(ec1 == psm::fault::code::success, "derive_hs_keys det: success");
        runner.Check(std::memcmp(keys1.server_hskey.data(), keys2.server_hskey.data(), 16) == 0,
                     "derive_hs_keys: deterministic");
    }

    void TestDeriveAppKeys(TestRunner &runner)
    {
        // First derive handshake keys to get a valid master_secret
        std::array<std::uint8_t, 32> shared_secret{};
        shared_secret[0] = 0x42;
        std::array<std::uint8_t, 32> chello_msg{};
        std::array<std::uint8_t, 32> shello_msg{};

        auto [ec_hs, keys] = psm::stealth::reality::derive_hs_keys(shared_secret, chello_msg, shello_msg);
        runner.Check(ec_hs == psm::fault::code::success, "derive_app setup: success");

        // Derive app keys using the master_secret
        std::array<std::uint8_t, 32> server_finhash{};
        psm::stealth::reality::key_material app_keys = keys;
        auto ec = psm::stealth::reality::derive_app_keys(keys.master_secret, server_finhash, app_keys);
        runner.Check(ec == psm::fault::code::success, "derive_app_keys: success");

        bool server_appkey_zero = true;
        for (auto b : app_keys.server_appkey)
            if (b != 0)
                server_appkey_zero = false;
        runner.Check(!server_appkey_zero, "derive_app_keys: server_appkey not all zero");

        bool client_appkey_zero = true;
        for (auto b : app_keys.client_appkey)
            if (b != 0)
                client_appkey_zero = false;
        runner.Check(!client_appkey_zero, "derive_app_keys: client_appkey not all zero");
    }

    void TestComputeVerify(TestRunner &runner)
    {
        std::array<std::uint8_t, 32> finished_key{};
        finished_key[0] = 0xAA;
        std::array<std::uint8_t, 32> transcript_hash{};
        transcript_hash[0] = 0xBB;

        auto verify = psm::stealth::reality::compute_verify(finished_key, transcript_hash);
        runner.Check(verify.size() == 32, "compute_verify: 32 bytes");

        // Deterministic
        auto verify2 = psm::stealth::reality::compute_verify(finished_key, transcript_hash);
        runner.Check(std::memcmp(verify.data(), verify2.data(), 32) == 0, "compute_verify: deterministic");

        // Different inputs → different outputs
        finished_key[0] = 0xCC;
        auto verify3 = psm::stealth::reality::compute_verify(finished_key, transcript_hash);
        runner.Check(std::memcmp(verify.data(), verify3.data(), 32) != 0,
                     "compute_verify: different inputs → different outputs");
    }

    void TestComputeVerifyIsHmac(TestRunner &runner)
    {
        // compute_verify(finished_key, transcript_hash) = HMAC-SHA256(finished_key, transcript_hash)
        std::array<std::uint8_t, 32> key{};
        key[0] = 0x01;
        std::array<std::uint8_t, 32> hash{};
        hash[0] = 0x02;

        auto verify = psm::stealth::reality::compute_verify(key, hash);
        auto hmac = psm::crypto::hmac_sha256(key, hash);
        runner.Check(std::memcmp(verify.data(), hmac.data(), 32) == 0,
                     "compute_verify == hmac_sha256");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RealityKeygen");

    TestDeriveHsKeys(runner);
    TestDeriveHsKeysDeterministic(runner);
    TestDeriveAppKeys(runner);
    TestComputeVerify(runner);
    TestComputeVerifyIsHmac(runner);

    return runner.Summary();
}
