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
    namespace Reality = Preview::Reality;

    TEST(RealityKeygen, X25519Shared)
    {
        std::array<std::uint8_t, 32> ServerPrivate{};
        std::array<std::uint8_t, 32> ServerPublic{};
        std::array<std::uint8_t, 32> ClientPrivate{};
        std::array<std::uint8_t, 32> ClientPublic{};
        ASSERT_FALSE(Reality::GenerateKeypair(ServerPrivate, ServerPublic));
        ASSERT_FALSE(Reality::GenerateKeypair(ClientPrivate, ClientPublic));

        std::array<std::uint8_t, 32> SharedOne{};
        std::array<std::uint8_t, 32> SharedTwo{};
        ASSERT_FALSE(Reality::X25519Shared(ClientPrivate, ServerPublic, SharedOne));
        ASSERT_FALSE(Reality::X25519Shared(ServerPrivate, ClientPublic, SharedTwo));
        EXPECT_EQ(SharedOne, SharedTwo) << "X25519 共享密钥应一致";
    }

    TEST(RealityKeygen, AuthKeyDerive)
    {
        std::array<std::uint8_t, 32> ServerPrivate{};
        std::array<std::uint8_t, 32> ServerPublic{};
        std::array<std::uint8_t, 32> ClientPrivate{};
        std::array<std::uint8_t, 32> ClientPublic{};
        ASSERT_FALSE(Reality::GenerateKeypair(ServerPrivate, ServerPublic));
        ASSERT_FALSE(Reality::GenerateKeypair(ClientPrivate, ClientPublic));
        std::array<std::uint8_t, 40> ClientRandom{};
        for (std::size_t Index = 0; Index < ClientRandom.size(); ++Index)
        {
            ClientRandom[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
        }

        std::array<std::uint8_t, 32> Shared{};
        ASSERT_FALSE(Reality::X25519Shared(ClientPrivate, ServerPublic, Shared));
        std::array<std::uint8_t, 32> AuthKey{};
        ASSERT_FALSE(Reality::DeriveAuthKey(Shared, ClientRandom, AuthKey));
    }

    TEST(RealityKeygen, SessionIdSealOpen)
    {
        std::array<std::uint8_t, 32> ServerPrivate{};
        std::array<std::uint8_t, 32> ServerPublic{};
        std::array<std::uint8_t, 32> ClientPrivate{};
        std::array<std::uint8_t, 32> ClientPublic{};
        ASSERT_FALSE(Reality::GenerateKeypair(ServerPrivate, ServerPublic));
        ASSERT_FALSE(Reality::GenerateKeypair(ClientPrivate, ClientPublic));
        std::array<std::uint8_t, 40> ClientRandom{};
        for (std::size_t Index = 0; Index < ClientRandom.size(); ++Index)
        {
            ClientRandom[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
        }
        std::array<std::uint8_t, 128> Hello{};
        for (std::size_t Index = 0; Index < Hello.size(); ++Index)
        {
            Hello[Index] = static_cast<std::uint8_t>(Index);
        }

        // 客户端侧
        std::array<std::uint8_t, 32> Shared{};
        ASSERT_FALSE(Reality::X25519Shared(ClientPrivate, ServerPublic, Shared));
        std::array<std::uint8_t, 32> AuthKey{};
        ASSERT_FALSE(Reality::DeriveAuthKey(Shared, ClientRandom, AuthKey));
        std::array<std::uint8_t, 16> Plain{};
        Plain[0] = 0x01;
        Plain[8] = 0x42;
        std::array<std::uint8_t, 32> Sealed{};
        ASSERT_FALSE(
            Reality::SealSessionId(Reality::SessionIdSealInput{AuthKey, ClientRandom, Plain, Hello}, Sealed));

        // 服务端侧
        std::array<std::uint8_t, 32> SharedTwo{};
        ASSERT_FALSE(Reality::X25519Shared(ServerPrivate, ClientPublic, SharedTwo));
        std::array<std::uint8_t, 32> ServerAuthKey{};
        ASSERT_FALSE(Reality::DeriveAuthKey(SharedTwo, ClientRandom, ServerAuthKey));
        std::array<std::uint8_t, 16> Opened{};
        ASSERT_FALSE(Reality::OpenSessionId(
            Reality::SessionIdOpenInput{ServerAuthKey, ClientRandom, Sealed, Hello}, Opened));
        EXPECT_EQ(Opened[0], 0x01);
        EXPECT_EQ(Opened[8], 0x42);
    }

    TEST(RealityKeygen, SessionIdSealRejectsInvalidKeyLength)
    {
        const std::array<std::uint8_t, 31> ShortAuthKey{};
        const std::array<std::uint8_t, 40> ClientRandom{};
        const std::array<std::uint8_t, 16> Plain{};
        const std::array<std::uint8_t, 64> Hello{};
        std::array<std::uint8_t, Reality::SessionIdAuthLen> Sealed{};

        EXPECT_TRUE(Reality::SealSessionId(
            Reality::SessionIdSealInput{ShortAuthKey, ClientRandom, Plain, Hello}, Sealed));
    }

} // namespace
