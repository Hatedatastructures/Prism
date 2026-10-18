/**
 * @file CarrierWireVectorTest.cpp
 * @brief Reality、ShadowTLS、Restls 的确定性 wire/编解码向量。
 * @details 这些测试只证明已有纯编解码的精确字节行为；真实 Reality TLS wire
 *          握手由 RealityCarrierTest 覆盖。
 */

#include <Prism/Protocols/Reality/Detail/Key.hpp>
#include <Prism/Protocols/Restls/Detail/Record.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Record.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace
{

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

    TEST(CarrierWireVector, ShadowtlsSessionIdAndRecordLayoutAreExact)
    {
        std::vector<std::uint8_t> Body(80);
        Body[0] = Prism::Shadowtls::HsTypeClienthello;
        Body[1] = 0;
        Body[2] = 0;
        Body[3] = 76;
        Body[4] = 3;
        Body[5] = 3;
        for (std::size_t Index = 0; Index < Prism::Shadowtls::TlsRndSize; ++Index)
        {
            Body[6 + Index] = static_cast<std::uint8_t>(0x40 + Index);
        }
        Body[38] = static_cast<std::uint8_t>(Prism::Shadowtls::TlsSessionIdSz);
        for (std::size_t Index = 0; Index < Prism::Shadowtls::TlsSessionIdSz; ++Index)
        {
            Body[39 + Index] = static_cast<std::uint8_t>(0x80 + Index);
        }
        for (std::size_t Index = 71; Index < Body.size(); ++Index)
        {
            Body[Index] = static_cast<std::uint8_t>(Index ^ 0x5a);
        }

        auto SessionId = std::span<std::uint8_t, Prism::Shadowtls::TlsSessionIdSz>(
            Body.data() + Prism::Shadowtls::SessionIdStart,
            Prism::Shadowtls::TlsSessionIdSz);
        EXPECT_EQ(Prism::Shadowtls::Detail::GenerateSessionId(
                      Prism::Shadowtls::Detail::SessionIdInput{"wire-vector-password", Body, SessionId}),
                  Prism::Error::None);
        EXPECT_EQ(Hex(SessionId),
                  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b04358e92");

        std::vector<std::uint8_t> Record(Prism::Shadowtls::TlsHdrsize + Body.size());
        Record[0] = 0x16;
        Record[1] = Prism::Shadowtls::TlsRecordVersionMajor;
        Record[2] = Prism::Shadowtls::TlsRecordVersionMinor;
        Record[3] = static_cast<std::uint8_t>(Body.size() >> 8);
        Record[4] = static_cast<std::uint8_t>(Body.size());
        std::copy(Body.begin(), Body.end(), Record.begin() + Prism::Shadowtls::TlsHdrsize);
        Prism::Shadowtls::Detail::ClientHelloRecord Parsed;
        EXPECT_EQ(Prism::Shadowtls::Detail::ParseClientHelloRecord(Record, Parsed), Prism::Error::None);
        EXPECT_EQ(Parsed.SessionIdOffset, Prism::Shadowtls::TlsHdrsize + Prism::Shadowtls::SessionIdStart);
        EXPECT_EQ(Parsed.SessionId.size(), Prism::Shadowtls::TlsSessionIdSz);
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

    TEST(CarrierWireVector, RestlsTrafficKeyAndMaskAreExact)
    {
        const auto Secret = Prism::Restls::Detail::DeriveSecret("wire-vector-password");
        std::array<std::uint8_t, 32> ServerRandom{};
        for (std::size_t Index = 0; Index < ServerRandom.size(); ++Index)
        {
            ServerRandom[Index] = static_cast<std::uint8_t>(0x60 + Index);
        }
        const auto ServerMask = Prism::Restls::Detail::ComputeServerMask(Secret, ServerRandom);
        EXPECT_EQ(Hex(Secret),
                  "84b52d81e495d59d4f18c5d7c18d64b88a59f223b7378df641c0e7db6f7fc994");
        EXPECT_EQ(Hex(ServerMask),
                  "3efa1598c3da5630ef149568566750e5");
    }

} // namespace
