/**
 * @file RealityKeygenTest.cpp
 * @brief Reality X25519 共享密钥 + HKDF + AEAD 快速验证
 */

#include <array>
#include <cstdint>
#include <cstring>

#include <preview/Protocols/Reality/Reality.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    TEST(RealityKeygen, X25519Shared)
    {
        std::array<std::uint8_t, 32> srv_priv{};
        std::array<std::uint8_t, 32> srv_pub{};
        std::array<std::uint8_t, 32> cli_priv{};
        std::array<std::uint8_t, 32> cli_pub{};
        ASSERT_FALSE(Reality::GenerateKeypair(srv_priv, srv_pub));
        ASSERT_FALSE(Reality::GenerateKeypair(cli_priv, cli_pub));

        std::array<std::uint8_t, 32> s1{};
        std::array<std::uint8_t, 32> s2{};
        ASSERT_FALSE(Reality::X25519Shared(cli_priv, srv_pub, s1));
        ASSERT_FALSE(Reality::X25519Shared(srv_priv, cli_pub, s2));
        EXPECT_EQ(s1, s2) << "X25519 共享密钥应一致";
    }

    TEST(RealityKeygen, AuthKeyDerive)
    {
        std::array<std::uint8_t, 32> srv_priv{};
        std::array<std::uint8_t, 32> srv_pub{};
        std::array<std::uint8_t, 32> cli_priv{};
        std::array<std::uint8_t, 32> cli_pub{};
        ASSERT_FALSE(Reality::GenerateKeypair(srv_priv, srv_pub));
        ASSERT_FALSE(Reality::GenerateKeypair(cli_priv, cli_pub));
        std::array<std::uint8_t, 40> random{};
        for (std::size_t i = 0; i < 40; ++i)
        {
            random[i] = static_cast<std::uint8_t>(i * 5 + 2);
        }

        std::array<std::uint8_t, 32> shared{};
        ASSERT_FALSE(Reality::X25519Shared(cli_priv, srv_pub, shared));
        std::array<std::uint8_t, 32> AuthKey{};
        ASSERT_FALSE(Reality::DeriveAuthKey(shared, random, AuthKey));
    }

    TEST(RealityKeygen, SessionIdSealOpen)
    {
        std::array<std::uint8_t, 32> srv_priv{};
        std::array<std::uint8_t, 32> srv_pub{};
        std::array<std::uint8_t, 32> cli_priv{};
        std::array<std::uint8_t, 32> cli_pub{};
        ASSERT_FALSE(Reality::GenerateKeypair(srv_priv, srv_pub));
        ASSERT_FALSE(Reality::GenerateKeypair(cli_priv, cli_pub));
        std::array<std::uint8_t, 40> random{};
        for (std::size_t i = 0; i < 40; ++i)
        {
            random[i] = static_cast<std::uint8_t>(i * 5 + 2);
        }
        std::array<std::uint8_t, 128> hello{};
        for (std::size_t i = 0; i < 128; ++i)
        {
            hello[i] = static_cast<std::uint8_t>(i);
        }

        // 客户端侧
        std::array<std::uint8_t, 32> shared{};
        ASSERT_FALSE(Reality::X25519Shared(cli_priv, srv_pub, shared));
        std::array<std::uint8_t, 32> AuthKey{};
        ASSERT_FALSE(Reality::DeriveAuthKey(shared, random, AuthKey));
        std::array<std::uint8_t, 16> plain{};
        plain[0] = 0x01;
        plain[8] = 0x42;
        std::array<std::uint8_t, 32> sealed{};
        ASSERT_FALSE(
            Reality::SealSessionId(Reality::SessionIdSealInput{AuthKey, random, plain, hello}, sealed));

        // 服务端侧
        std::array<std::uint8_t, 32> shared2{};
        ASSERT_FALSE(Reality::X25519Shared(srv_priv, cli_pub, shared2));
        std::array<std::uint8_t, 32> auth_key2{};
        ASSERT_FALSE(Reality::DeriveAuthKey(shared2, random, auth_key2));
        std::array<std::uint8_t, 16> opened{};
        ASSERT_FALSE(Reality::OpenSessionId(
            Reality::SessionIdOpenInput{auth_key2, random, sealed, hello}, opened));
        EXPECT_EQ(opened[0], 0x01);
        EXPECT_EQ(opened[8], 0x42);
    }

} // namespace
