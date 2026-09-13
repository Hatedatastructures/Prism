/**
 * @file ShadowtlsCodecDeep.cpp
 * @brief shadowtls Codec 字节级深测（纯函数）
 * @details 覆盖：SessionId 派生、ClientHello 验证、帧 HMAC、
 *          KDF 派生的确定性/差异性与错误路径。
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <gtest/gtest.h>
#include <preview/Protocols/Shadowtls/Codec.hpp>

namespace
{
    namespace Shadowtls = Preview::Shadowtls;
    using Preview::Error;

    auto MakeStandardClientHello() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(75, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t I = 0; I < Shadowtls::TlsRndSize; ++I)
        {
            Hello[2 + I] = static_cast<std::uint8_t>(0x30 + I);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0;
        Hello[68] = 2;
        Hello[69] = 0x13;
        Hello[70] = 0x01;
        Hello[71] = 1;
        Hello[72] = 0;
        Hello[73] = 0;
        Hello[74] = 0;

        constexpr std::size_t HandshakeHeaderSize = 4;
        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + HandshakeHeaderSize + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(HandshakeHeaderSize + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = Shadowtls::HsTypeClienthello;
        Record[6] = 0;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + Shadowtls::TlsHdrsize + HandshakeHeaderSize);
        std::span<std::uint8_t, Shadowtls::TlsSessionIdSz> SessionId(
            Record.data() + Shadowtls::TlsHdrsize + Shadowtls::SessionIdStart, Shadowtls::TlsSessionIdSz);
        const std::span<const std::uint8_t> RecordView{Record};
        const auto ClientHello = RecordView.subspan(Shadowtls::TlsHdrsize);
        const Shadowtls::SessionIdInput Input{"pw", ClientHello, SessionId};
        const auto ErrorCode = Shadowtls::GenerateSessionId(Input);
        EXPECT_EQ(ErrorCode, Error::None);
        if (ErrorCode != Error::None)
        {
            return {};
        }
        return Record;
    }

    auto MakeStandardServerHello() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(78, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t I = 0; I < Shadowtls::TlsRndSize; ++I)
        {
            Hello[2 + I] = static_cast<std::uint8_t>(0x70 + I);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0x13;
        Hello[68] = 0x01;
        Hello[69] = 0;
        Hello[70] = 0;
        Hello[71] = 6;
        Hello[72] = 0;
        Hello[73] = 43;
        Hello[74] = 0;
        Hello[75] = 2;
        Hello[76] = 3;
        Hello[77] = 4;

        constexpr std::size_t HandshakeHeaderSize = 4;
        constexpr std::uint8_t ServerHelloType = 2;
        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + HandshakeHeaderSize + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(HandshakeHeaderSize + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = ServerHelloType;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + Shadowtls::TlsHdrsize + HandshakeHeaderSize);
        return Record;
    }

    TEST(ShadowtlsCodecDeep, SessionIdDerivation)
    {
        // 构造最小合法 ClientHello（SessionId 占位 32 字节，偏移 39）
        std::array<std::uint8_t, 96> ClientHello{};
        ClientHello[0] = 0x03;
        ClientHello[1] = 0x03; // TLS 1.2 版本
        std::array<std::uint8_t, 32> SessionId{};
        std::array<std::uint8_t, 32> SecondSessionId{};

        const Shadowtls::SessionIdInput Input{"pw", ClientHello, SessionId};
        EXPECT_EQ(Shadowtls::GenerateSessionId(Input), Error::None);
        EXPECT_NE(SessionId.back(), 0u); // 后 4 字节 HMAC 已写入

        // 同输入确定性（SessionId 前 28 随机 → 仅后 4 字节 HMAC 稳定）
        const Shadowtls::SessionIdInput SecondInput{"pw", ClientHello, SecondSessionId};
        EXPECT_EQ(Shadowtls::GenerateSessionId(SecondInput), Error::None);
        EXPECT_EQ(SessionId.back(), SecondSessionId.back());

        // 超短 ClientHello → BadLength
        const std::array<std::uint8_t, 4> TinyClientHello{};
        const Shadowtls::SessionIdInput InvalidInput{"pw", TinyClientHello, SessionId};
        EXPECT_EQ(Shadowtls::GenerateSessionId(InvalidInput), Error::BadLength);
    }

    TEST(ShadowtlsCodecDeep, VerifyClientHelloShort)
    {
        // 短输入 → false（不崩溃）
        const std::span<const std::byte> EmptyClientHello;
        EXPECT_FALSE(Shadowtls::VerifyClientHello("pw", EmptyClientHello));
        const std::array<std::byte, 16> ShortHello{};
        EXPECT_FALSE(Shadowtls::VerifyClientHello("pw", ShortHello));
    }

    TEST(ShadowtlsCodecDeep, FrameHmacInput)
    {
        const std::array<std::uint8_t, 32> ServerRandom{0x44};
        const std::array<std::uint8_t, 8> Payload{0x55};

        Shadowtls::FrameHmacInput Input{"pw", ServerRandom, Shadowtls::TagClient, Payload};
        const auto Hmac = Shadowtls::FrameHmac(Input);
        EXPECT_EQ(Hmac.size(), Shadowtls::HmacSize);
        // 同输入确定性
        EXPECT_EQ(Shadowtls::FrameHmac(Input), Hmac);
        // 方向标签变化 → 输出变化
        Input.tag = Shadowtls::TagServer;
        EXPECT_NE(Shadowtls::FrameHmac(Input), Hmac);
    }

    TEST(ShadowtlsCodecDeep, KdfDerivation)
    {
        const std::array<std::uint8_t, 32> ServerRandom{0x66};
        const auto Key = Shadowtls::Kdf("pw", ServerRandom);
        EXPECT_EQ(Key.size(), 32u);
        EXPECT_EQ(Shadowtls::Kdf("pw", ServerRandom), Key); // 确定性
        // 密码不同 → 密钥不同
        EXPECT_NE(Shadowtls::Kdf("other", ServerRandom), Key);
        // ServerRandom 不同 → 密钥不同
        const std::array<std::uint8_t, 32> SecondServerRandom{0x67};
        EXPECT_NE(Shadowtls::Kdf("pw", SecondServerRandom), Key);
    }

    TEST(ShadowtlsCodecDeep, StatefulApplicationRecordRoundTrip)
    {
        const auto ServerRandom = []() -> std::array<std::uint8_t, Shadowtls::TlsRndSize>
        {
            std::array<std::uint8_t, Shadowtls::TlsRndSize> Value{};
            Value.fill(0x41);
            return Value;
        }();
        Shadowtls::RecordProtector Encoder{"pw", ServerRandom, Shadowtls::TagClient};
        Shadowtls::RecordProtector Decoder{"pw", ServerRandom, Shadowtls::TagClient};
        const std::array<std::uint8_t, 7> First{1, 2, 3, 4, 5, 6, 7};
        const std::array<std::uint8_t, 3> Second{8, 9, 10};
        const std::vector<std::uint8_t> ExpectedFirstPayload(First.begin(), First.end());
        const std::vector<std::uint8_t> ExpectedSecondPayload(Second.begin(), Second.end());
        const std::array<std::uint8_t, Shadowtls::HmacSize> ExpectedFirstHmac{0x98, 0x0E, 0xF6, 0xB3};
        const std::vector<std::uint8_t> ExpectedFirstWire{0x17, 0x03, 0x03, 0x00, 0x0B, 0x98, 0x0E, 0xF6,
                                                          0xB3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        const std::vector<std::uint8_t> ExpectedSecondWire{0x17, 0x03, 0x03, 0x00, 0x07, 0xEA,
                                                           0x8A, 0xF6, 0x4F, 0x08, 0x09, 0x0A};
        std::vector<std::uint8_t> Wire;
        std::vector<std::uint8_t> Payload;
        const Shadowtls::FrameHmacInput FirstHmac{"pw", ServerRandom, Shadowtls::TagClient, First};
        EXPECT_EQ(Shadowtls::FrameHmac(FirstHmac), ExpectedFirstHmac);

        ASSERT_EQ(Encoder.Encode(First, Wire), Error::None);
        EXPECT_EQ(Wire, ExpectedFirstWire);
        EXPECT_EQ(Decoder.Decode(Wire, Payload), Error::None);
        EXPECT_EQ(Payload, ExpectedFirstPayload);

        ASSERT_EQ(Encoder.Encode(Second, Wire), Error::None);
        EXPECT_EQ(Wire, ExpectedSecondWire);
        EXPECT_EQ(Decoder.Decode(Wire, Payload), Error::None);
        EXPECT_EQ(Payload, ExpectedSecondPayload);
    }

    TEST(ShadowtlsCodecDeep, ApplicationRecordRejectsWrongDirectionAndTampering)
    {
        const std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom{0x52};
        Shadowtls::RecordProtector Encoder{"pw", ServerRandom, Shadowtls::TagServer};
        Shadowtls::RecordProtector WrongDirection{"pw", ServerRandom, Shadowtls::TagClient};
        const std::array<std::uint8_t, 4> Payload{0xA0, 0xA1, 0xA2, 0xA3};
        std::vector<std::uint8_t> Wire;
        std::vector<std::uint8_t> Decoded;

        ASSERT_EQ(Encoder.Encode(Payload, Wire), Error::None);
        EXPECT_EQ(WrongDirection.Decode(Wire, Decoded), Error::BadAuth);
        Wire.back() ^= 0x01;
        EXPECT_EQ(Encoder.Decode(Wire, Decoded), Error::BadAuth);
    }

    TEST(ShadowtlsCodecDeep, ApplicationRecordBoundsAndDirection)
    {
        const std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom{0x63};
        Shadowtls::RecordProtector InvalidDirection{"pw", ServerRandom, 'X'};
        EXPECT_FALSE(InvalidDirection.IsValid());

        Shadowtls::RecordProtector Protector{"pw", ServerRandom, Shadowtls::TagClient};
        std::vector<std::uint8_t> Wire;
        std::vector<std::uint8_t> Payload;
        const std::span<const std::uint8_t> EmptyRecord;
        const std::array<std::uint8_t, Shadowtls::TlsHdrsize> ShortRecord{0x17, 3, 3, 0, 3};
        EXPECT_EQ(Protector.Decode(EmptyRecord, Payload), Error::NeedMore);
        EXPECT_EQ(Protector.Decode(ShortRecord, Payload), Error::BadLength);

        std::vector<std::uint8_t> MaxPayload(Shadowtls::MaxTlsPlaintext, 0xA5);
        EXPECT_EQ(Protector.Encode(MaxPayload, Wire), Error::None);
        EXPECT_EQ(Wire.size(), Shadowtls::TlsHdrsize + Shadowtls::HmacSize + MaxPayload.size());

        MaxPayload.push_back(0x5A);
        EXPECT_EQ(Protector.Encode(MaxPayload, Wire), Error::BadLength);
    }

    TEST(ShadowtlsCodecDeep, ServerFlightUsesUnchainedHmacAndXor)
    {
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom{};
        for (std::size_t I = 0; I < ServerRandom.size(); ++I)
        {
            ServerRandom[I] = static_cast<std::uint8_t>(0x80 + I);
        }
        Shadowtls::RecordProtector Encoder{"relay-password",
                                           ServerRandom,
                                           Shadowtls::TagServer,
                                           Shadowtls::RecordSeed::ServerRandomOnly,
                                           true,
                                           false};
        Shadowtls::RecordProtector Decoder{"relay-password",
                                           ServerRandom,
                                           Shadowtls::TagServer,
                                           Shadowtls::RecordSeed::ServerRandomOnly,
                                           true,
                                           false};
        const std::array<std::uint8_t, 3> First{0xD1, 0xD2, 0xD3};
        const std::array<std::uint8_t, 2> Second{0xE1, 0xE2};
        const std::vector<std::uint8_t> ExpectedFirstPayload(First.begin(), First.end());
        const std::vector<std::uint8_t> ExpectedSecondPayload(Second.begin(), Second.end());
        const std::vector<std::uint8_t> ExpectedFirstWire{0x17, 0x03, 0x03, 0x00, 0x07, 0x46,
                                                          0x0E, 0xD6, 0xE8, 0x23, 0xC5, 0x69};
        const std::vector<std::uint8_t> ExpectedSecondWire{0x17, 0x03, 0x03, 0x00, 0x06, 0x3E,
                                                           0x63, 0xE6, 0x23, 0x13, 0xF5};
        std::vector<std::uint8_t> Wire;
        std::vector<std::uint8_t> Payload;

        ASSERT_EQ(Encoder.Encode(First, Wire), Error::None);
        EXPECT_EQ(Wire, ExpectedFirstWire);
        EXPECT_EQ(Decoder.Decode(Wire, Payload), Error::None);
        EXPECT_EQ(Payload, ExpectedFirstPayload);

        ASSERT_EQ(Encoder.Encode(Second, Wire), Error::None);
        EXPECT_EQ(Wire, ExpectedSecondWire);
        EXPECT_EQ(Decoder.Decode(Wire, Payload), Error::None);
        EXPECT_EQ(Payload, ExpectedSecondPayload);
    }

    TEST(ShadowtlsCodecDeep, ParsesCompleteClientHelloRecord)
    {
        const auto Record = MakeStandardClientHello();
        Shadowtls::ClientHelloRecord Parsed;
        EXPECT_EQ(Shadowtls::ParseClientHelloRecord(Record, Parsed), Error::None);
        EXPECT_EQ(Parsed.SessionId.size(), Shadowtls::TlsSessionIdSz);
        EXPECT_EQ(Parsed.Hello.size(), 79u);
        const std::span<const std::uint8_t> RecordView{Record};
        const auto ClientHelloBytes = std::as_bytes(RecordView);
        EXPECT_TRUE(Shadowtls::VerifyClientHello("pw", ClientHelloBytes));

        auto Truncated = Record;
        Truncated.pop_back();
        EXPECT_EQ(Shadowtls::ParseClientHelloRecord(Truncated, Parsed), Error::NeedMore);

        auto BadType = Record;
        BadType[0] = 0x17;
        EXPECT_EQ(Shadowtls::ParseClientHelloRecord(BadType, Parsed), Error::BadMagic);

        auto BadSessionLength = Record;
        BadSessionLength[43] = 31;
        EXPECT_EQ(Shadowtls::ParseClientHelloRecord(BadSessionLength, Parsed), Error::BadMessage);
    }

    TEST(ShadowtlsCodecDeep, ParsesServerHelloRandomAndTlsVersion)
    {
        const auto Record = MakeStandardServerHello();
        Shadowtls::ServerHelloRecord Parsed;
        EXPECT_EQ(Shadowtls::ParseServerHelloRecord(Record, Parsed), Error::None);
        EXPECT_EQ(Parsed.Random.size(), Shadowtls::TlsRndSize);
        EXPECT_EQ(Parsed.Random.front(), 0x70);
        EXPECT_EQ(Parsed.SessionId.size(), Shadowtls::TlsSessionIdSz);
        EXPECT_TRUE(Parsed.Tls13);

        auto Truncated = Record;
        Truncated.pop_back();
        EXPECT_EQ(Shadowtls::ParseServerHelloRecord(Truncated, Parsed), Error::NeedMore);

        auto BadType = Record;
        BadType[5] = Shadowtls::HsTypeClienthello;
        EXPECT_EQ(Shadowtls::ParseServerHelloRecord(BadType, Parsed), Error::BadMagic);

        auto BadSessionLength = Record;
        BadSessionLength[43] = static_cast<std::uint8_t>(Shadowtls::TlsSessionIdSz + 1);
        EXPECT_EQ(Shadowtls::ParseServerHelloRecord(BadSessionLength, Parsed), Error::BadLength);
    }

} // namespace
