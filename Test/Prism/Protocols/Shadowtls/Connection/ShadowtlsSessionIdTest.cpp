/**
 * @file ShadowtlsSessionIdTest.cpp
 * @brief ShadowTLS 会话标识生成与 ClientHello wire 布局测试。
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Protocols/Shadowtls/Detail/ClientHello.hpp>
#include <Prism/Protocols/Shadowtls/Detail/RecordProtector.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Shadowtls = Prism::Shadowtls;
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

TEST(ShadowTlsBeast, SessionIdRoundtrip)
    {
        const std::string password = "shadowtls_password";
        // 构造固定 ClientHello（含 TLS 头）：记录头 + 握手头 + version + random + sidLen + sid
        std::vector<std::uint8_t> hello(5 + Shadowtls::SessionIdStart + 32 + 16, 0);
        hello[0] = 0x16;
        hello[5] = Shadowtls::HsTypeClienthello;
        hello[5 + Shadowtls::SessionIdStart - 1] = Shadowtls::TlsSessionIdSz;
        for (std::size_t i = 0; i < Shadowtls::TlsRndSize; ++i)
        {
            hello[5 + 1 + 3 + 2 + i] = static_cast<std::uint8_t>(i);
        }

        std::array<std::uint8_t, Shadowtls::TlsSessionIdSz> SessionId{};
        for (std::size_t i = 0; i < Shadowtls::TlsSessionIdSz - Shadowtls::HmacSize; ++i)
        {
            SessionId[i] = static_cast<std::uint8_t>(i * 7 + 3);
        }
        const auto handshake = std::span<const std::uint8_t>(hello).subspan(Shadowtls::TlsHdrsize);
        EXPECT_EQ(
            Shadowtls::Detail::GenerateSessionId(Shadowtls::Detail::SessionIdInput{password, handshake, SessionId}),
            Error::None);
        std::memcpy(hello.data() + 5 + Shadowtls::SessionIdStart, SessionId.data(),
                    Shadowtls::TlsSessionIdSz);

        // 校验通过
        EXPECT_TRUE(Shadowtls::Detail::VerifyClientHello(
            password,
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(hello.data()), hello.size())));

        // 错误密码校验失败
        EXPECT_FALSE(Shadowtls::Detail::VerifyClientHello(
            "wrong_password",
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(hello.data()), hello.size())));
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

} // namespace
