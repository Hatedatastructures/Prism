/**
 * @file RealityKeygenDeep.cpp
 * @brief Reality keygen 深度测试
 * @details 测试 derive_hs_keys、derive_app_keys、compute_verify 的完整逻辑。
 *          通过 #include 源文件覆盖编译行。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>

// #include 源文件增加覆盖率计数
#include "../../src/prism/stealth/facade/reality/util/keygen.cpp"

namespace
{
    using namespace psm::stealth::reality;

    // ─── derive_hs_keys ─────────────────────────────

    TEST(RealityKeygenDeep, DeriveHsKeysBasic)
    {
        // 使用全零 shared_secret 和空消息
        std::array<std::uint8_t, 32> shared_secret{};
        psm::memory::vector<std::uint8_t> chello(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> shello(psm::memory::current_resource());

        auto [ec, keys] = derive_hs_keys(shared_secret, chello, shello);
        EXPECT_TRUE(ec == psm::fault::code::success) << "derive_hs: basic success";
        EXPECT_TRUE(!keys.master_secret.empty()) << "derive_hs: master_secret not empty";
    }

    TEST(RealityKeygenDeep, DeriveHsKeysWithMessages)
    {
        std::array<std::uint8_t, 32> shared_secret{};
        // 填充非空 ClientHello 和 ServerHello
        psm::memory::vector<std::uint8_t> chello(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> shello(psm::memory::current_resource());
        for (std::size_t i = 0; i < 64; ++i) chello.push_back(static_cast<std::uint8_t>(i));
        for (std::size_t i = 0; i < 64; ++i) shello.push_back(static_cast<std::uint8_t>(i + 64));

        auto [ec, keys] = derive_hs_keys(shared_secret, chello, shello);
        EXPECT_TRUE(ec == psm::fault::code::success) << "derive_hs: with messages success";
    }

    TEST(RealityKeygenDeep, DeriveHsKeysDeterministic)
    {
        std::array<std::uint8_t, 32> shared_secret{};
        shared_secret[0] = 42;
        psm::memory::vector<std::uint8_t> chello(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> shello(psm::memory::current_resource());
        chello.push_back(0x01);
        shello.push_back(0x02);

        auto [ec1, keys1] = derive_hs_keys(shared_secret, chello, shello);
        auto [ec2, keys2] = derive_hs_keys(shared_secret, chello, shello);
        EXPECT_TRUE(ec1 == psm::fault::code::success) << "derive_hs: deterministic success";
        EXPECT_TRUE(keys1.master_secret == keys2.master_secret) << "derive_hs: master_secret deterministic";
        EXPECT_TRUE(keys1.server_hskey == keys2.server_hskey) << "derive_hs: server_hskey deterministic";
        EXPECT_TRUE(keys1.client_hskey == keys2.client_hskey) << "derive_hs: client_hskey deterministic";
    }

    TEST(RealityKeygenDeep, DeriveHsKeysDifferentSecret)
    {
        std::array<std::uint8_t, 32> secret1{};
        std::array<std::uint8_t, 32> secret2{};
        secret2[0] = 1;

        psm::memory::vector<std::uint8_t> chello(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> shello(psm::memory::current_resource());
        chello.push_back(0x01);
        shello.push_back(0x02);

        auto [ec1, keys1] = derive_hs_keys(secret1, chello, shello);
        auto [ec2, keys2] = derive_hs_keys(secret2, chello, shello);
        EXPECT_TRUE(ec1 == psm::fault::code::success) << "derive_hs: diff secret success";
        EXPECT_TRUE(keys1.master_secret != keys2.master_secret) << "derive_hs: diff secret -> diff master";
    }

    // ─── derive_app_keys ────────────────────────────

    TEST(RealityKeygenDeep, DeriveAppKeysBasic)
    {
        // 先 derive_hs_keys 获取 master_secret
        std::array<std::uint8_t, 32> shared_secret{};
        psm::memory::vector<std::uint8_t> chello(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> shello(psm::memory::current_resource());
        auto [hs_ec, keys] = derive_hs_keys(shared_secret, chello, shello);
        ASSERT_TRUE(hs_ec == psm::fault::code::success) << "derive_app: prerequisite hs success";

        // 模拟 server_finhash
        std::array<std::uint8_t, 32> server_finhash{};
        auto app_ec = derive_app_keys(keys.master_secret, server_finhash, keys);
        EXPECT_TRUE(app_ec == psm::fault::code::success) << "derive_app: basic success";
    }

    TEST(RealityKeygenDeep, DeriveAppKeysWithFinhash)
    {
        std::array<std::uint8_t, 32> shared_secret{};
        shared_secret[0] = 0xAB;
        psm::memory::vector<std::uint8_t> chello(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> shello(psm::memory::current_resource());
        chello.push_back(0x01);
        shello.push_back(0x02);

        auto [hs_ec, keys] = derive_hs_keys(shared_secret, chello, shello);

        std::array<std::uint8_t, 32> finhash{};
        finhash[0] = 0xCD;
        auto app_ec = derive_app_keys(keys.master_secret, finhash, keys);
        EXPECT_TRUE(app_ec == psm::fault::code::success) << "derive_app: with finhash success";
    }

    TEST(RealityKeygenDeep, DeriveAppKeysDeterministic)
    {
        std::array<std::uint8_t, 32> shared_secret{};
        psm::memory::vector<std::uint8_t> chello(psm::memory::current_resource());
        psm::memory::vector<std::uint8_t> shello(psm::memory::current_resource());
        auto [hs_ec, keys1] = derive_hs_keys(shared_secret, chello, shello);
        auto [_, keys2] = derive_hs_keys(shared_secret, chello, shello);

        std::array<std::uint8_t, 32> finhash{};
        auto ec1 = derive_app_keys(keys1.master_secret, finhash, keys1);
        auto ec2 = derive_app_keys(keys2.master_secret, finhash, keys2);

        EXPECT_TRUE(ec1 == psm::fault::code::success) << "derive_app: deterministic success";
        EXPECT_TRUE(keys1.server_appkey == keys2.server_appkey) << "derive_app: server_appkey deterministic";
        EXPECT_TRUE(keys1.client_appkey == keys2.client_appkey) << "derive_app: client_appkey deterministic";
    }

    // ─── compute_verify ─────────────────────────────

    TEST(RealityKeygenDeep, ComputeVerifyBasic)
    {
        std::array<std::uint8_t, 32> finished_key{};
        std::array<std::uint8_t, 32> transcript_hash{};

        auto verify = compute_verify(finished_key, transcript_hash);
        EXPECT_TRUE(verify.size() == 32) << "compute_verify: output size=32";
    }

    TEST(RealityKeygenDeep, ComputeVerifyNonZero)
    {
        std::array<std::uint8_t, 32> finished_key{};
        std::array<std::uint8_t, 32> transcript_hash{};
        for (std::size_t i = 0; i < 32; ++i)
        {
            finished_key[i] = static_cast<std::uint8_t>(i);
            transcript_hash[i] = static_cast<std::uint8_t>(i + 32);
        }

        auto verify = compute_verify(finished_key, transcript_hash);
        // 不全为零
        bool any_nonzero = false;
        for (auto b : verify)
        {
            if (b != 0) any_nonzero = true;
        }
        EXPECT_TRUE(any_nonzero) << "compute_verify: non-zero output for non-zero input";
    }

    TEST(RealityKeygenDeep, ComputeVerifyDeterministic)
    {
        std::array<std::uint8_t, 32> finished_key{};
        std::array<std::uint8_t, 32> transcript_hash{};
        finished_key[0] = 0xAA;
        transcript_hash[0] = 0xBB;

        auto v1 = compute_verify(finished_key, transcript_hash);
        auto v2 = compute_verify(finished_key, transcript_hash);
        EXPECT_TRUE(v1 == v2) << "compute_verify: deterministic";
    }

    TEST(RealityKeygenDeep, ComputeVerifyDifferentKeys)
    {
        std::array<std::uint8_t, 32> key1{};
        std::array<std::uint8_t, 32> key2{};
        key2[0] = 1;

        std::array<std::uint8_t, 32> transcript_hash{};

        auto v1 = compute_verify(key1, transcript_hash);
        auto v2 = compute_verify(key2, transcript_hash);
        EXPECT_TRUE(v1 != v2) << "compute_verify: different keys -> different verify";
    }

} // namespace
