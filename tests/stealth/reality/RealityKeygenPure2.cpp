/**
 * @file RealityKeygenPure2.cpp
 * @brief Reality 密钥派生纯函数测试
 * @details 测试 derive_hs_keys 和 derive_app_keys 的正确性：
 *          使用已知的 X25519 共享密钥构造输入，验证输出密钥长度正确。
 *          测试 compute_verify 的 HMAC-SHA256 计算。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/util/keygen.hpp>
#include <prism/crypto/hkdf.hpp>

namespace
{
    namespace reality = psm::stealth::reality;
    namespace crypto = psm::crypto;

    /**
     * @brief derive_hs_keys 正常路径返回 success
     */
    TEST(RealityKeygenPure2, DeriveHsKeysSuccess)
    {
        // 任意非零 shared_secret + 非 empty chello/shello
        std::array<std::uint8_t, 32> shared{};
        shared[0] = 0x42;
        std::array<std::uint8_t, 64> chello{};
        chello[0] = 0x01;
        std::array<std::uint8_t, 64> shello{};
        shello[0] = 0x02;

        auto [ec, keys] = reality::derive_hs_keys(shared, chello, shello);
        EXPECT_TRUE(ec == psm::fault::code::success) << "derive_hs_keys: success";
        EXPECT_TRUE(!keys.server_hskey.empty()) << "derive_hs_keys: server_hskey non-empty";
        EXPECT_TRUE(!keys.server_hsiv.empty()) << "derive_hs_keys: server_hsiv non-empty";
        EXPECT_TRUE(!keys.client_hskey.empty()) << "derive_hs_keys: client_hskey non-empty";
        EXPECT_TRUE(!keys.client_hsiv.empty()) << "derive_hs_keys: client_hsiv non-empty";
        EXPECT_TRUE(!keys.server_finkey.empty()) << "derive_hs_keys: server_finkey non-empty";
        EXPECT_TRUE(!keys.master_secret.empty()) << "derive_hs_keys: master_secret non-empty";
    }

    /**
     * @brief derive_hs_keys 相同输入产生相同输出
     */
    TEST(RealityKeygenPure2, DeriveHsKeysDeterministic)
    {
        std::array<std::uint8_t, 32> shared{};
        shared[31] = 0xFF;
        std::array<std::uint8_t, 32> chello{};
        chello[0] = 0x03;
        std::array<std::uint8_t, 32> shello{};
        shello[0] = 0x04;

        auto [ec1, keys1] = reality::derive_hs_keys(shared, chello, shello);
        auto [ec2, keys2] = reality::derive_hs_keys(shared, chello, shello);

        EXPECT_TRUE(ec1 == psm::fault::code::success) << "derive_hs_keys: deterministic ec1=success";
        EXPECT_TRUE(ec2 == psm::fault::code::success) << "derive_hs_keys: deterministic ec2=success";
        EXPECT_TRUE(keys1.server_hskey == keys2.server_hskey) << "derive_hs_keys: deterministic server_hskey";
        EXPECT_TRUE(keys1.client_hsiv == keys2.client_hsiv) << "derive_hs_keys: deterministic client_hsiv";
        EXPECT_TRUE(keys1.master_secret == keys2.master_secret) << "derive_hs_keys: deterministic master_secret";
    }

    /**
     * @brief derive_hs_keys 不同输入产生不同输出
     */
    TEST(RealityKeygenPure2, DeriveHsKeysDifferentInputs)
    {
        std::array<std::uint8_t, 32> shared_a{};
        shared_a[0] = 0xAA;
        std::array<std::uint8_t, 32> shared_b{};
        shared_b[0] = 0xBB;
        std::array<std::uint8_t, 16> chello{};
        std::array<std::uint8_t, 16> shello{};

        auto [ec1, keys1] = reality::derive_hs_keys(shared_a, chello, shello);
        auto [ec2, keys2] = reality::derive_hs_keys(shared_b, chello, shello);

        EXPECT_TRUE(keys1.server_hskey != keys2.server_hskey)
            << "derive_hs_keys: different shared -> different keys";
    }

    /**
     * @brief derive_app_keys 正常路径返回 success
     */
    TEST(RealityKeygenPure2, DeriveAppKeysSuccess)
    {
        // 先获取一个有效的 master_secret
        std::array<std::uint8_t, 32> shared{};
        shared[0] = 0x42;
        std::array<std::uint8_t, 32> chello{};
        std::array<std::uint8_t, 32> shello{};

        auto [hs_ec, keys] = reality::derive_hs_keys(shared, chello, shello);
        ASSERT_TRUE(hs_ec == psm::fault::code::success) << "derive_app_keys: setup success";

        // derive_app_keys 需要 server_finhash
        auto finhash = crypto::sha256(std::span<const std::uint8_t>{});
        auto app_ec = reality::derive_app_keys(keys.master_secret, finhash, keys);
        EXPECT_TRUE(app_ec == psm::fault::code::success) << "derive_app_keys: success";
        EXPECT_TRUE(!keys.server_appkey.empty()) << "derive_app_keys: server_appkey set";
        EXPECT_TRUE(!keys.server_appiv.empty()) << "derive_app_keys: server_appiv set";
        EXPECT_TRUE(!keys.client_appkey.empty()) << "derive_app_keys: client_appkey set";
        EXPECT_TRUE(!keys.client_appiv.empty()) << "derive_app_keys: client_appiv set";
    }

    /**
     * @brief compute_verify 返回 32 字节 HMAC
     */
    TEST(RealityKeygenPure2, ComputeVerify)
    {
        std::array<std::uint8_t, 32> fin_key{};
        fin_key[0] = 0xAA;
        std::array<std::uint8_t, 32> transcript{};
        transcript[0] = 0xBB;

        auto verify = reality::compute_verify(fin_key, transcript);
        EXPECT_TRUE(verify.size() == 32) << "compute_verify: 32 bytes output";
        // 非零输入应产生非全零输出
        bool all_zero = true;
        for (auto b : verify)
        {
            if (b != 0)
            {
                all_zero = false;
                break;
            }
        }
        EXPECT_TRUE(!all_zero) << "compute_verify: non-zero output";
    }

    /**
     * @brief compute_verify 确定性：相同输入产生相同输出
     */
    TEST(RealityKeygenPure2, ComputeVerifyDeterministic)
    {
        std::array<std::uint8_t, 32> fin_key{};
        fin_key[0] = 0xCC;
        std::array<std::uint8_t, 32> transcript{};
        transcript[0] = 0xDD;

        auto v1 = reality::compute_verify(fin_key, transcript);
        auto v2 = reality::compute_verify(fin_key, transcript);
        EXPECT_TRUE(v1 == v2) << "compute_verify: deterministic";
    }

} // namespace
