/**
 * @file KeygenTest.cpp
 * @brief Reality 密钥派生、SessionId 密封与编解码 owner 契约测试。
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <Prism/Protocols/Reality/Detail/SessionId.hpp>
#include <Prism/Protocols/Reality/Detail/KeyMaterial.hpp>
#include <Prism/Protocols/Reality/Detail/Tls13.hpp>

namespace
{
    namespace Reality = Prism::Reality;

    TEST(RealityKeygen, X25519Shared)
    {
        std::array<std::uint8_t, 32> ServerPrivate{};
        std::array<std::uint8_t, 32> ServerPublic{};
        std::array<std::uint8_t, 32> ClientPrivate{};
        std::array<std::uint8_t, 32> ClientPublic{};
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(ServerPrivate, ServerPublic));
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(ClientPrivate, ClientPublic));

        std::array<std::uint8_t, 32> SharedOne{};
        std::array<std::uint8_t, 32> SharedTwo{};
        ASSERT_FALSE(Reality::Detail::X25519Shared(ClientPrivate, ServerPublic, SharedOne));
        ASSERT_FALSE(Reality::Detail::X25519Shared(ServerPrivate, ClientPublic, SharedTwo));
        EXPECT_EQ(SharedOne, SharedTwo) << "X25519 共享密钥应一致";
    }

    TEST(RealityKeygen, AuthKeyDerive)
    {
        std::array<std::uint8_t, 32> ServerPrivate{};
        std::array<std::uint8_t, 32> ServerPublic{};
        std::array<std::uint8_t, 32> ClientPrivate{};
        std::array<std::uint8_t, 32> ClientPublic{};
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(ServerPrivate, ServerPublic));
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(ClientPrivate, ClientPublic));
        std::array<std::uint8_t, 32> ClientRandom{};
        for (std::size_t Index = 0; Index < ClientRandom.size(); ++Index)
        {
            ClientRandom[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
        }

        std::array<std::uint8_t, 32> Shared{};
        ASSERT_FALSE(Reality::Detail::X25519Shared(ClientPrivate, ServerPublic, Shared));
        std::array<std::uint8_t, 32> AuthKey{};
        ASSERT_FALSE(Reality::Detail::DeriveAuthKey(Shared, ClientRandom, AuthKey));
    }

    TEST(RealityKeygen, SessionIdSealOpen)
    {
        std::array<std::uint8_t, 32> ServerPrivate{};
        std::array<std::uint8_t, 32> ServerPublic{};
        std::array<std::uint8_t, 32> ClientPrivate{};
        std::array<std::uint8_t, 32> ClientPublic{};
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(ServerPrivate, ServerPublic));
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(ClientPrivate, ClientPublic));
        std::array<std::uint8_t, 32> ClientRandom{};
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
        ASSERT_FALSE(Reality::Detail::X25519Shared(ClientPrivate, ServerPublic, Shared));
        std::array<std::uint8_t, 32> AuthKey{};
        ASSERT_FALSE(Reality::Detail::DeriveAuthKey(Shared, ClientRandom, AuthKey));
        std::array<std::uint8_t, 16> Plain{};
        Plain[0] = 0x01;
        Plain[8] = 0x42;
        std::array<std::uint8_t, 32> Sealed{};
        ASSERT_FALSE(
            Reality::Detail::SealSessionId(Reality::Detail::SessionIdSealInput{AuthKey, ClientRandom, Plain, Hello}, Sealed));

        // 服务端侧
        std::array<std::uint8_t, 32> SharedTwo{};
        ASSERT_FALSE(Reality::Detail::X25519Shared(ServerPrivate, ClientPublic, SharedTwo));
        std::array<std::uint8_t, 32> ServerAuthKey{};
        ASSERT_FALSE(Reality::Detail::DeriveAuthKey(SharedTwo, ClientRandom, ServerAuthKey));
        std::array<std::uint8_t, 16> Opened{};
        ASSERT_FALSE(Reality::Detail::OpenSessionId(
            Reality::Detail::SessionIdOpenInput{ServerAuthKey, ClientRandom, Sealed, Hello}, Opened));
        EXPECT_EQ(Opened[0], 0x01);
        EXPECT_EQ(Opened[8], 0x42);
    }

    TEST(RealityKeygen, RejectsOversizedClientRandom)
    {
        std::array<std::uint8_t, Reality::KeyLen> Shared{};
        std::array<std::uint8_t, Reality::KeyLen> AuthKey{};
        std::array<std::uint8_t, 40> ClientRandom{};
        std::array<std::uint8_t, 16> Plain{};
        std::array<std::uint8_t, 80> Hello{};
        for (std::size_t Index = 0; Index < AuthKey.size(); ++Index)
        {
            AuthKey[Index] = static_cast<std::uint8_t>(Index);
        }
        for (std::size_t Index = 0; Index < ClientRandom.size(); ++Index)
        {
            ClientRandom[Index] = static_cast<std::uint8_t>(0x20 + Index);
        }
        for (std::size_t Index = 0; Index < Plain.size(); ++Index)
        {
            Plain[Index] = static_cast<std::uint8_t>(0xa0 + Index);
        }
        for (std::size_t Index = 0; Index < Hello.size(); ++Index)
        {
            Hello[Index] = static_cast<std::uint8_t>(0x50 + Index);
        }

        std::array<std::uint8_t, Reality::KeyLen> Derived{};
        EXPECT_TRUE(Reality::Detail::DeriveAuthKey(Shared, ClientRandom, Derived));

        std::array<std::uint8_t, Reality::SessionIdAuthLen> Sealed{};
        EXPECT_TRUE(Reality::Detail::SealSessionId(
            Reality::Detail::SessionIdSealInput{AuthKey, ClientRandom, Plain, Hello}, Sealed));

        const std::array<std::uint8_t, Reality::SessionIdAuthLen> Cipher{
            0x14, 0xde, 0x74, 0x05, 0xfa, 0x40, 0x73, 0x57,
            0xf5, 0xa5, 0x9d, 0xa1, 0x73, 0x24, 0xb0, 0x98,
            0x10, 0x05, 0x6b, 0x62, 0x9d, 0xce, 0x06, 0x05,
            0xd6, 0x6f, 0x95, 0x62, 0x25, 0x9a, 0xfe, 0x76};
        std::array<std::uint8_t, 16> Opened{};
        EXPECT_TRUE(Reality::Detail::OpenSessionId(
            Reality::Detail::SessionIdOpenInput{AuthKey, ClientRandom, Cipher, Hello}, Opened));
    }

    TEST(RealityKeygen, RejectsUndersizedClientRandom)
    {
        const std::array<std::uint8_t, Reality::KeyLen> Shared{};
        const std::array<std::uint8_t, Reality::KeyLen> AuthKey{};
        const std::array<std::uint8_t, 31> ClientRandom{};
        const std::array<std::uint8_t, 16> Plain{};
        const std::array<std::uint8_t, 80> Hello{};

        std::array<std::uint8_t, Reality::KeyLen> Derived{};
        EXPECT_TRUE(Reality::Detail::DeriveAuthKey(Shared, ClientRandom, Derived));

        std::array<std::uint8_t, Reality::SessionIdAuthLen> Sealed{};
        EXPECT_TRUE(Reality::Detail::SealSessionId(
            Reality::Detail::SessionIdSealInput{AuthKey, ClientRandom, Plain, Hello}, Sealed));

        const std::array<std::uint8_t, Reality::SessionIdAuthLen> Cipher{};
        std::array<std::uint8_t, 16> Opened{};
        EXPECT_TRUE(Reality::Detail::OpenSessionId(
            Reality::Detail::SessionIdOpenInput{AuthKey, ClientRandom, Cipher, Hello}, Opened));
    }

    TEST(RealityKeygen, SessionIdSealRejectsInvalidKeyLength)
    {
        const std::array<std::uint8_t, 31> ShortAuthKey{};
        const std::array<std::uint8_t, 32> ClientRandom{};
        const std::array<std::uint8_t, 16> Plain{};
        const std::array<std::uint8_t, 64> Hello{};
        std::array<std::uint8_t, Reality::SessionIdAuthLen> Sealed{};

        EXPECT_TRUE(Reality::Detail::SealSessionId(
            Reality::Detail::SessionIdSealInput{ShortAuthKey, ClientRandom, Plain, Hello}, Sealed));
    }

    TEST(RealityCodecOwners, EachOwnerHeaderExposesItsStandaloneContract)
    {
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};
        EXPECT_FALSE(Reality::Detail::ParseShortId("0102", ShortId));
        EXPECT_EQ(ShortId[0], 0x01);
        EXPECT_EQ(ShortId[1], 0x02);

        const std::array<std::uint8_t, 3> Bytes{0x01, 0x02, 0x03};
        EXPECT_EQ(Reality::Detail::Base64urlEncode(Bytes), "AQID");
        EXPECT_EQ(Reality::Detail::Base64urlDecode("AQID"),
                  std::vector<std::uint8_t>(Bytes.begin(), Bytes.end()));

        Reality::Detail::Tls13Keys Keys;
        EXPECT_EQ(Keys.ClientHandshakeKey.size(), 16U);
        EXPECT_EQ(Keys.ClientHandshakeIv.size(), 12U);
    }

} // namespace
