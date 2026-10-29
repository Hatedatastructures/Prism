/**
 * @file KeyMaterialTest.cpp
 * @brief Reality 密钥材料与会话标识的纯函数测试。
 */

#include <array>
#include <cstdint>
#include <string>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Reality/Detail/KeyMaterial.hpp>
#include <Prism/Protocols/Reality/Detail/SessionId.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Reality = Prism::Reality;
    using Prism::Error;

    template <typename ByteRange>
    auto Hex(const ByteRange &Bytes) -> std::string
    {
        static constexpr char Digits[] = "0123456789abcdef";
        std::string Output;
        Output.reserve(Bytes.size() * 2);
        for (const auto Byte : Bytes)
        {
            const auto Value = static_cast<std::uint8_t>(Byte);
            Output.push_back(Digits[Value >> 4]);
            Output.push_back(Digits[Value & 0x0f]);
        }
        return Output;
    }

TEST(RealityBeast, KeypairAndBase64)
    {
        std::array<std::uint8_t, 32> priv{};
        std::array<std::uint8_t, 32> pub{};
        EXPECT_FALSE(Reality::Detail::GenerateKeypair(priv, pub));
        std::array<std::uint8_t, 32> derived{};
        EXPECT_FALSE(Reality::Detail::DerivePublicKey(priv, derived));
        EXPECT_EQ(derived, pub);

        const std::string enc = Reality::Detail::Base64urlEncode(priv);
        std::array<std::uint8_t, 32> Parsed{};
        EXPECT_FALSE(Reality::Detail::ParsePrivateKey(enc, Parsed));
        EXPECT_EQ(Parsed, priv);

        std::array<std::uint8_t, 8> sid{};
        EXPECT_FALSE(Reality::Detail::ParseShortId("45587ac66ce007e4", sid));
        EXPECT_EQ(sid[0], 0x45);
        EXPECT_EQ(sid[7], 0xE4);
        EXPECT_TRUE(Reality::Detail::ParseShortId("xyz", sid));
    }

TEST(CarrierWireVector, RealitySessionIdSealIsExactAndReversible)
    {
        std::array<std::uint8_t, Prism::Reality::KeyLen> AuthKey{};
        std::array<std::uint8_t, 32> ClientRandom{};
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

        std::array<std::uint8_t, Prism::Reality::SessionIdAuthLen> Cipher{};
        EXPECT_FALSE(Prism::Reality::Detail::SealSessionId(
            Prism::Reality::Detail::SessionIdSealInput{AuthKey, ClientRandom, Plain, Hello}, Cipher));
        EXPECT_EQ(Hex(Cipher),
                  "14de7405fa407357f5a59da17324b09810056b629dce0605d66f9562259afe76");

        std::array<std::uint8_t, 16> Opened{};
        EXPECT_FALSE(Prism::Reality::Detail::OpenSessionId(
            Prism::Reality::Detail::SessionIdOpenInput{AuthKey, ClientRandom, Cipher, Hello}, Opened));
        EXPECT_EQ(Opened, Plain);
    }

} // namespace
