/**
 * @file Deep.cpp
 * @brief VMess Codec 剩余分支深度测试
 * @details 覆盖 BuildRequestHeader 的 ipv4 非法输入 / ipv6 分支、
 *          ParseRequestHeader 的地址截断与 FNV1a 校验失败、
 *          ChunkDecryptor 的错误路径（头部不足 / 坏密文 / 超长）、
 *          Parser 的 need_more / 认证失败 / 头解析失败传播、
 *          ChunkStream::Decrypt 错误路径，以及 AesGcmOpen 的
 *          密文过短分支。
 */

#include <boost/asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <chrono>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/Crypto/Aead.hpp>
#include <Prism/Protocols/Vmess/AuthCrypto.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Vmess/AuthKdf.hpp>
#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/ResponseCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Protocols/Vmess/ChunkMask.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Vmess = Prism::Vmess;
    using Prism::Error;
    using Prism::make_error_code;

    TEST(VmessCodecDeep, ShakeStreamMatchesShake128EmptyVector)
    {
        constexpr std::array<std::uint8_t, 32> Expected{
            0x7F, 0x9C, 0x2B, 0xA4, 0xE8, 0x8F, 0x82, 0x7D,
            0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3E,
            0xD7, 0x3B, 0x80, 0x93, 0xF6, 0xEF, 0xBC, 0x88,
            0xEB, 0x1A, 0x6E, 0xAC, 0xFA, 0x66, 0xEF, 0x26};
        Vmess::ShakeStream Stream(std::span<const std::uint8_t>{});
        std::array<std::uint8_t, Expected.size()> Actual{};
        for (std::size_t Offset = 0; Offset < Actual.size(); Offset += 2)
        {
            Stream.Take(std::span<std::uint8_t>(Actual).subspan(Offset, 2));
        }
        EXPECT_EQ(Actual, Expected);
    }

    TEST(VmessCodecDeep, ChunkMaskStreamMatchesFourChunkVector)
    {
        std::array<std::uint8_t, 16> Seed{};
        Seed.fill(0x72);
        constexpr std::array<std::uint8_t, 8> Expected{
            0xFD, 0x02, 0x82, 0x06, 0x32, 0x55, 0x4E, 0xAF};
        Vmess::ShakeStream Stream(Seed);
        std::array<std::uint8_t, Expected.size()> Actual{};
        for (std::size_t Chunk = 0; Chunk < Actual.size() / 2; ++Chunk)
        {
            Stream.Take(std::span<std::uint8_t>(Actual).subspan(Chunk * 2, 2));
        }
        EXPECT_EQ(Actual, Expected);
    }

    /**
     * @brief 构造 16 字节 UUID
     */
    auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        Uuid.fill(0x33);
        return Uuid;
    }

    TEST(VmessCodecDeep, AesGcmOpenShortCipher)
    {
        std::array<std::uint8_t, 16> Key{};
        std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 8> Cipher{};
        const auto Plain = Vmess::detail::AesGcmOpen(
            Vmess::detail::OpenInput{std::span<const std::uint8_t, 16>(Key), std::span<const std::uint8_t, 12>(Nonce), Cipher, std::span<const std::uint8_t>{}});
        EXPECT_TRUE(Plain.empty());
    }

    TEST(VmessCodecDeep, AesGcmSealRejectsInvalidParameters)
    {
        const std::array<std::uint8_t, 15> ShortKey{};
        const std::array<std::uint8_t, 12> Nonce{};
        const std::array<std::uint8_t, 11> ShortNonce{};
        const std::array<std::uint8_t, 1> Plain{0x42};

        EXPECT_TRUE(Vmess::detail::AesGcmSeal(
                        Vmess::detail::SealInput{ShortKey, Nonce, Plain, {}})
                        .empty());
        EXPECT_TRUE(Vmess::detail::AesGcmSeal(
                        Vmess::detail::SealInput{std::span<const std::uint8_t>{}, Nonce, Plain, {}})
                        .empty());
        EXPECT_TRUE(Vmess::detail::AesGcmSeal(
                        Vmess::detail::SealInput{std::array<std::uint8_t, 16>{}, ShortNonce, Plain, {}})
                        .empty());
    }

    TEST(VmessCodecDeep, BuildHeaderAddressBranches)
    {
        Vmess::RequestHeader Header{};
        std::array<std::uint8_t, 16> Iv{};
        std::array<std::uint8_t, 16> Key{};
        Vmess::RequestMeta Meta{std::span<const std::uint8_t, 16>(Iv), std::span<const std::uint8_t, 16>(Key)};
        Meta.v = 0x42;
        Meta.p = 3;

        // ipv4 正常
        Header.Target.Type = Vmess::AddressType::Ipv4;
        Header.Target.Host = "10.0.0.1";
        Header.Target.Port = 443;
        const auto Ok = Vmess::BuildRequestHeader(Header, Meta);
        EXPECT_GT(Ok.size(), 40u);

        // ipv4 段过多
        Header.Target.Host = "1.2.3.4.5";
        EXPECT_TRUE(Vmess::BuildRequestHeader(Header, Meta).empty());

        // ipv4 段超 255
        Header.Target.Host = "300.1.1.1";
        EXPECT_TRUE(Vmess::BuildRequestHeader(Header, Meta).empty());

        // ipv4 段数不足
        Header.Target.Host = "1.2.3";
        EXPECT_TRUE(Vmess::BuildRequestHeader(Header, Meta).empty());

        // ipv6 编码
        Header.Target.Type = Vmess::AddressType::Ipv6;
        Header.Target.Host.assign(16, 'w');
        const auto V6 = Vmess::BuildRequestHeader(Header, Meta);
        EXPECT_EQ(V6.size(), 41u + 16u + Meta.p + 4u);

        Header.Target.Type = static_cast<Vmess::AddressType>(0xFF);
        EXPECT_TRUE(Vmess::BuildRequestHeader(Header, Meta).empty());

        Header.Target.Type = Vmess::AddressType::Domain;
        Header.Target.Host.assign(256, 'd');
        EXPECT_TRUE(Vmess::BuildRequestHeader(Header, Meta).empty());

        Header.Target.Type = Vmess::AddressType::Ipv6;
        Header.Target.Host = "not-an-ipv6";
        EXPECT_TRUE(Vmess::BuildRequestHeader(Header, Meta).empty());
    }

    TEST(VmessCodecDeep, ParseHeaderBranches)
    {
        Vmess::RequestHeader Header{};
        Vmess::RequestMetaOut MetaOut{};
        std::array<std::uint8_t, 16> Iv{};
        std::array<std::uint8_t, 16> Key{};

        // ipv4 截断
        std::vector<std::uint8_t> v4(41, 0);
        v4[0] = 0x01;
        v4[40] = 0x01; // ipv4
        EXPECT_EQ(Vmess::ParseRequestHeader(v4, Header, MetaOut), Error::NeedMore);

        // ipv6 截断
        std::vector<std::uint8_t> v6(41, 0);
        v6[0] = 0x01;
        v6[40] = static_cast<std::uint8_t>(Vmess::AddressType::Ipv6); // ipv6
        EXPECT_EQ(Vmess::ParseRequestHeader(v6, Header, MetaOut), Error::NeedMore);

        // ipv6 成功（Build 后回解析）
        Vmess::RequestHeader Source{};
        Source.Cmd = static_cast<std::uint8_t>(Vmess::Command::Udp);
        Source.Target.Type = Vmess::AddressType::Ipv6;
        Source.Target.Host.assign(16, 'z');
        Source.Target.Port = 53;
        Vmess::RequestMeta Meta{std::span<const std::uint8_t, 16>(Iv), std::span<const std::uint8_t, 16>(Key)};
        const auto Wire = Vmess::BuildRequestHeader(Source, Meta);
        EXPECT_EQ(Vmess::ParseRequestHeader(Wire, Header, MetaOut), Error::None);
        EXPECT_EQ(Header.Target.Type, Vmess::AddressType::Ipv6);
        EXPECT_EQ(Header.Target.Host, std::string(16, 'z'));
        EXPECT_EQ(Header.Target.Port, 53u);

        // FNV1a 校验失败
        auto Tampered = Wire;
        Tampered.back() ^= 0x01;
        EXPECT_EQ(Vmess::ParseRequestHeader(Tampered, Header, MetaOut), Error::BadAuth);

        std::vector<std::uint8_t> UnknownAddress(46, 0);
        UnknownAddress[0] = Vmess::ProtocolVersion;
        UnknownAddress[40] = 0xFF;
        const auto UnknownHash = Vmess::detail::Fnv1a32(
            std::span<const std::uint8_t>(UnknownAddress).first(42));
        UnknownAddress[42] = static_cast<std::uint8_t>(UnknownHash >> 24);
        UnknownAddress[43] = static_cast<std::uint8_t>(UnknownHash >> 16);
        UnknownAddress[44] = static_cast<std::uint8_t>(UnknownHash >> 8);
        UnknownAddress[45] = static_cast<std::uint8_t>(UnknownHash);
        EXPECT_EQ(Vmess::ParseRequestHeader(UnknownAddress, Header, MetaOut), Error::BadMessage);
    }

    TEST(VmessCodecDeep, ChunkDecryptorErrors)
    {
        std::array<std::uint8_t, 16> Key{};
        std::array<std::uint8_t, 12> Nonce{};
        Vmess::ChunkDecryptor Decoder{std::span<const std::uint8_t, 16>(Key), std::span<const std::uint8_t, 12>(Nonce)};

        // 头部不足
        std::array<std::uint8_t, 10> ShortHead{};
        const auto Result1 = Decoder.OpenLen(std::span<const std::uint8_t>(ShortHead));
        EXPECT_FALSE(Result1);
        EXPECT_EQ(Result1.error(), Error::NeedMore);

        // 坏密文（tag 篡改）
        std::array<std::uint8_t, 18> BadHead{};
        BadHead[17] = 0xFF;
        const auto Result2 = Decoder.OpenLen(std::span<const std::uint8_t>(BadHead));
        EXPECT_FALSE(Result2);
        EXPECT_EQ(Result2.error(), Error::BadAuth);

        // 超长（> max_chunk_len）
        Vmess::ChunkEncryptor Encoder{std::span<const std::uint8_t, 16>(Key), std::span<const std::uint8_t, 12>(Nonce)};
        std::array<std::uint8_t, 34> LengthEncoded{};
        const auto BytesWritten = Encoder.Seal({}, LengthEncoded); // 空块：长度 0
        (void)BytesWritten;
        const auto Result3 = Decoder.OpenLen(std::span<const std::uint8_t>(LengthEncoded).first(18));
        ASSERT_TRUE(Result3);
        EXPECT_EQ(*Result3, 0u);

        Vmess::ChunkDecryptor EmptyChunkDecoder{
            std::span<const std::uint8_t, 16>(Key),
            std::span<const std::uint8_t, 12>(Nonce)};
        std::size_t EmptyChunkConsumed = 0U;
        EXPECT_EQ(EmptyChunkDecoder.Open(
                      std::span<const std::uint8_t>(LengthEncoded).first(BytesWritten),
                      std::span<std::uint8_t>{}, EmptyChunkConsumed),
                  Error::None);
        EXPECT_EQ(EmptyChunkConsumed, BytesWritten);

        // 16 KiB 是唯一有效边界；边界成功，超过一字节和 20,000 字节都拒绝。
        Vmess::ChunkEncryptor Encoder2{
            std::span<const std::uint8_t, 16>(Key),
            std::span<const std::uint8_t, 12>(Nonce)};
        std::vector<std::uint8_t> MaxPayload(Vmess::MaxChunkLen, 0xAB);
        std::vector<std::uint8_t> MaxWire(MaxPayload.size() + Vmess::ChunkEncryptor::Overhead);
        EXPECT_EQ(Encoder2.Seal(MaxPayload, MaxWire), MaxWire.size());

        std::vector<std::uint8_t> OverLimitPayload(Vmess::MaxChunkLen + 1U, 0xAB);
        std::vector<std::uint8_t> OverLimitWire(
            OverLimitPayload.size() + Vmess::ChunkEncryptor::Overhead);
        EXPECT_EQ(Encoder2.Seal(OverLimitPayload, OverLimitWire), 0U);

        std::array<std::uint8_t, 16> LegacyNonce{};
        constexpr auto LegacyOptions = static_cast<std::uint8_t>(Vmess::Option::ChunkStream) |
                                       static_cast<std::uint8_t>(Vmess::Option::ChunkMasking);
        Vmess::ChunkEncryptor LegacyEncoder{
            std::span<const std::uint8_t, 16>(Key),
            std::span<const std::uint8_t, 16>(LegacyNonce), LegacyOptions};
        EXPECT_EQ(LegacyEncoder.Seal(OverLimitPayload, OverLimitWire), 0U);

        std::vector<std::uint8_t> BigPayload(20000, 0xAB);
        std::vector<std::uint8_t> BigWire(
            BigPayload.size() + Vmess::ChunkEncryptor::Overhead);
        const auto BigBytesWritten = Encoder2.Seal(BigPayload, BigWire);
        EXPECT_EQ(BigBytesWritten, 0U);
    }

    TEST(VmessCodecDeep, ChunkDecryptorRejectsOverLimitAuthenticatedAndLegacyLengths)
    {
        constexpr std::size_t OverLimitPayloadLength = 20000U;
        std::array<std::uint8_t, 16> Key{};
        std::array<std::uint8_t, 12> AuthenticatedNonce{};
        // 直接用初始 nonce 认证大端 20,000 长度，绕过编码器的超限输入拒绝。
        const std::array<std::uint8_t, 2> AuthenticatedLength{
            static_cast<std::uint8_t>(OverLimitPayloadLength >> 8U),
            static_cast<std::uint8_t>(OverLimitPayloadLength & 0xFFU)};
        std::array<std::uint8_t, 18> AuthenticatedHeader{};
        Prism::Crypto::AeadContext LengthSealer(
            Prism::Crypto::AeadCipher::Aes128Gcm, std::span<const std::uint8_t>(Key));
        ASSERT_EQ(LengthSealer.Seal(Prism::Crypto::SealInput{
                      std::span<std::uint8_t>(AuthenticatedHeader),
                      std::span<const std::uint8_t>(AuthenticatedLength),
                      std::span<const std::uint8_t>(AuthenticatedNonce), {}}),
                  Prism::Fault::Code::Success);

        Vmess::ChunkDecryptor AuthenticatedDecoder{
            std::span<const std::uint8_t, 16>(Key),
            std::span<const std::uint8_t, 12>(AuthenticatedNonce)};
        const auto AuthenticatedResult = AuthenticatedDecoder.OpenLen(AuthenticatedHeader);
        ASSERT_FALSE(AuthenticatedResult);
        EXPECT_EQ(AuthenticatedResult.error(), Error::BadLength);

        std::array<std::uint8_t, 16> LegacyNonce{};
        constexpr auto LegacyOptions = static_cast<std::uint8_t>(Vmess::Option::ChunkStream);
        // Legacy 长度字段记录密文长度，包含 16 字节 AEAD tag；无长度认证及 mask。
        constexpr auto LegacyEncodedLength = OverLimitPayloadLength + 16U;
        const std::array<std::uint8_t, 2> LegacyHeader{
            static_cast<std::uint8_t>(LegacyEncodedLength >> 8U),
            static_cast<std::uint8_t>(LegacyEncodedLength & 0xFFU)};
        Vmess::ChunkDecryptor LegacyDecoder{
            std::span<const std::uint8_t, 16>(Key),
            std::span<const std::uint8_t, 16>(LegacyNonce), LegacyOptions};
        const auto LegacyResult = LegacyDecoder.OpenLen(LegacyHeader);
        ASSERT_FALSE(LegacyResult);
        EXPECT_EQ(LegacyResult.error(), Error::BadLength);
    }

    TEST(VmessCodecDeep, AuthenticatedLengthSealRejectsEofMarkerSizedOverLimitPayload)
    {
        std::array<std::uint8_t, 16> Key{};
        std::array<std::uint8_t, 12> Nonce{};
        std::vector<std::uint8_t> Payload(Vmess::AuthenticatedLengthEofMarker, 0x5A);
        std::vector<std::uint8_t> Wire(Payload.size() + Vmess::ChunkEncryptor::Overhead);
        Vmess::ChunkEncryptor Encoder{
            std::span<const std::uint8_t, 16>(Key),
            std::span<const std::uint8_t, 12>(Nonce)};

        // 此输入同时达到 EOF marker 长度并超过普通 chunk 上限，不能单独区分拒绝原因。
        EXPECT_EQ(Encoder.Seal(Payload, Wire), 0U);
    }

    TEST(VmessCodecDeep, StandardChunkMaskingRoundtrip)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 16> nonce{};
        key.fill(0x31);
        nonce.fill(0x72);
        constexpr auto Options = static_cast<std::uint8_t>(Vmess::Option::ChunkStream) |
                                  static_cast<std::uint8_t>(Vmess::Option::ChunkMasking);
        const std::string Payload = "standard vmess chunk masking";

        Vmess::ChunkEncryptor Encoder{std::span<const std::uint8_t, 16>(key),
                                      std::span<const std::uint8_t, 16>(nonce), Options};
        std::array<std::uint8_t, 256> Wire{};
        const auto Written = Encoder.Seal(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Payload.data()),
                                           Payload.size()),
            Wire);
        EXPECT_EQ(Written, Payload.size() + 18u);
        const auto MaskedLength = static_cast<std::uint16_t>(Wire[0]) << 8 | Wire[1];
        EXPECT_EQ(MaskedLength,
                  (static_cast<std::uint16_t>(Payload.size() + 16u) ^ std::uint16_t{0xFD02}));

        Vmess::ChunkDecryptor Decoder{std::span<const std::uint8_t, 16>(key),
                                      std::span<const std::uint8_t, 16>(nonce), Options};
        const auto Length = Decoder.OpenLen(std::span<const std::uint8_t>(Wire).first(2));
        ASSERT_TRUE(Length);
        EXPECT_EQ(*Length, Payload.size() + 16u);
        std::vector<std::uint8_t> Plain(Payload.size());
        EXPECT_EQ(Decoder.OpenPayload(std::span<const std::uint8_t>(Wire).subspan(2, Written - 2), Plain),
                  Error::None);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Plain.data()), Plain.size()), Payload);

        std::array<std::uint8_t, 256> Finish{};
        ASSERT_EQ(Encoder.Finish(Finish), 2u);
        std::size_t FinishConsumed = 0U;
        EXPECT_EQ(Decoder.Open(std::span<const std::uint8_t>(Finish).first(2), Plain, FinishConsumed),
                  Error::None);
        EXPECT_EQ(FinishConsumed, 2U);
        const auto LengthAfterFinish = Decoder.OpenLen(
            std::span<const std::uint8_t>(Finish).first(2));
        ASSERT_FALSE(LengthAfterFinish);
        EXPECT_EQ(LengthAfterFinish.error(), Error::ProtocolError);
        EXPECT_EQ(Decoder.OpenPayload({}, Plain), Error::ProtocolError);
        std::size_t RepeatedFinishConsumed = 7U;
        EXPECT_EQ(Decoder.Open(std::span<const std::uint8_t>(Finish).first(2), Plain,
                      RepeatedFinishConsumed),
                  Error::ProtocolError);
        EXPECT_EQ(RepeatedFinishConsumed, 0U);
    }

    TEST(VmessCodecDeep, ChunkOpenEndAndErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 12> Nonce{};

        // 认证长度模式结束 marker 加上 tag 后按 uint16 回绕为零。
        Vmess::ChunkEncryptor enc{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};
        std::array<std::uint8_t, 34> fin{};
        std::array<std::uint8_t, 17> shortFin{};
        EXPECT_EQ(enc.Finish(shortFin), 0U);
        const auto nf = enc.Finish(fin);
        ASSERT_EQ(nf, 18u);

        Vmess::ChunkDecryptor lengthDecoder{
            std::span<const std::uint8_t, 16>(key),
            std::span<const std::uint8_t, 12>(Nonce)};
        const auto EndLength = lengthDecoder.OpenLen(
            std::span<const std::uint8_t>(fin).first(nf));
        ASSERT_TRUE(EndLength);
        EXPECT_EQ(*EndLength, Vmess::AuthenticatedLengthEofMarker);
        const auto LengthAfterMarker = lengthDecoder.OpenLen(
            std::span<const std::uint8_t>(fin).first(nf));
        ASSERT_FALSE(LengthAfterMarker);
        EXPECT_EQ(LengthAfterMarker.error(), Error::ProtocolError);

        Vmess::ChunkDecryptor dec{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};
        std::array<std::uint8_t, 64> out{};
        EXPECT_EQ(lengthDecoder.OpenPayload({}, out), Error::ProtocolError);
        std::size_t consumed = 0;
        EXPECT_EQ(dec.Open(std::span<const std::uint8_t>(fin), out, consumed), Error::None);
        EXPECT_EQ(consumed, nf);

        const std::array<std::uint8_t, 3> Payload{0x31, 0x32, 0x33};
        auto PostMarkerNonce = Nonce;
        for (std::size_t I = PostMarkerNonce.size(); I > 0; --I)
        {
            if (++PostMarkerNonce[I - 1] != 0U)
            {
                break;
            }
        }
        Vmess::ChunkEncryptor PostMarkerEncoder{
            std::span<const std::uint8_t, 16>(key),
            std::span<const std::uint8_t, 12>(PostMarkerNonce)};
        std::array<std::uint8_t, 3 + Vmess::ChunkEncryptor::Overhead> PostMarkerWire{};
        const auto PostMarkerSize = PostMarkerEncoder.Seal(Payload, PostMarkerWire);
        ASSERT_EQ(PostMarkerSize, PostMarkerWire.size());
        std::size_t PostMarkerConsumed = 0U;
        EXPECT_EQ(dec.Open(
                      std::span<const std::uint8_t>(PostMarkerWire).first(PostMarkerSize),
                      out, PostMarkerConsumed),
                  Error::ProtocolError);
        EXPECT_EQ(PostMarkerConsumed, 0U);

        Vmess::ChunkEncryptor FinishedEncoder{
            std::span<const std::uint8_t, 16>(key),
            std::span<const std::uint8_t, 12>(Nonce)};
        std::array<std::uint8_t, 34> FinishedMarker{};
        ASSERT_EQ(FinishedEncoder.Finish(FinishedMarker), 18U);
        std::array<std::uint8_t, 3 + Vmess::ChunkEncryptor::Overhead> PostFinishWire{};
        EXPECT_EQ(FinishedEncoder.Seal(Payload, PostFinishWire), 0U);
        EXPECT_EQ(FinishedEncoder.Finish(FinishedMarker), 0U);

        // 错误传播（OpenLen 失败 → Open 返回错误）
        std::array<std::uint8_t, 18> bad{};
        bad[17] = 0x01;
        Vmess::ChunkDecryptor ErrorDecoder{
            std::span<const std::uint8_t, 16>(key),
            std::span<const std::uint8_t, 12>(Nonce)};
        std::size_t ErrorConsumed = nf;
        const auto ec = ErrorDecoder.Open(
            std::span<const std::uint8_t>(bad), out, ErrorConsumed);
        EXPECT_EQ(ec, Error::BadAuth);
        EXPECT_EQ(ErrorConsumed, 0U);
    }

    TEST(VmessCodecDeep, ParserErrorPropagation)
    {
        const auto Uuid = MakeUuid();
        const auto CommandKey = Vmess::CmdKeyFromUuid(Uuid);
        std::array<std::uint8_t, 4> random{0x11, 0x22, 0x33, 0x44};

        // 合法 body（ipv4）
        Vmess::RequestHeader hdr{};
        hdr.Cmd = Vmess::CmdTcp;
        hdr.Target.Type = Vmess::AddressType::Ipv4;
        hdr.Target.Host = "8.8.8.8";
        hdr.Target.Port = 53;
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        Vmess::RequestMeta m{std::span<const std::uint8_t, 16>(iv), std::span<const std::uint8_t, 16>(key)};
        const auto body = Vmess::BuildRequestHeader(hdr, m);
        const auto time_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count();
        const auto wire =
            Vmess::SealAuthHeader(CommandKey, Vmess::AuthHeaderInput{body, time_sec, random});

        Vmess::Parser Parser(Uuid);
        std::error_code ec;

        // 数据不足
        EXPECT_EQ(Parser.Put(boost::asio::buffer(std::array<std::uint8_t, 30>{}), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));
        Parser.Reset();

        // 总长不足（截断 wire 尾部）
        const auto truncated = std::vector<std::uint8_t>(wire.begin(), wire.end() - 20);
        EXPECT_EQ(Parser.Put(boost::asio::buffer(truncated), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));
        Parser.Reset();

        // 认证头解密失败（篡改 hdr_enc 区）
        auto tampered = wire;
        tampered.back() ^= 0x01;
        EXPECT_EQ(Parser.Put(boost::asio::buffer(tampered), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::BadAuth));
        Parser.Reset();

        // 头解析失败（版本错误 body）
        Vmess::RequestHeader bad_hdr{};
        bad_hdr.Version = 0x02;
        bad_hdr.Target.Type = Vmess::AddressType::Domain;
        bad_hdr.Target.Host = "x.com";
        const auto bad_body = Vmess::BuildRequestHeader(bad_hdr, m);
        const auto bad_wire =
            Vmess::SealAuthHeader(CommandKey, Vmess::AuthHeaderInput{bad_body, time_sec, random});
        EXPECT_EQ(Parser.Put(boost::asio::buffer(bad_wire), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::BadMagic));
        Parser.Reset();

        // 增量成功解析：先收齐固定 AuthID/长度/nonce，再补齐认证头正文。
        constexpr std::size_t PrefixLength = 16 + 18 + 8 + 18;
        ASSERT_GT(wire.size(), PrefixLength);
        EXPECT_EQ(Parser.Put(boost::asio::buffer(wire.data(), PrefixLength), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));
        EXPECT_EQ(Parser.Put(boost::asio::buffer(wire.data() + PrefixLength, wire.size() - PrefixLength), ec),
            wire.size());
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().dst.Host, "8.8.8.8");
        EXPECT_EQ(Parser.Get().Cmd, 0x01u);
        EXPECT_TRUE(std::equal(Parser.Get().AuthId.begin(), Parser.Get().AuthId.end(), wire.begin()));

        const auto FirstAuthId = Parser.Get().AuthId;
        Parser.Reset();
        EXPECT_EQ(Parser.Put(boost::asio::buffer(wire), ec), wire.size());
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().AuthId, FirstAuthId);
        // Done 后再 Put → 返回累积字节数
        std::error_code ec2;
        EXPECT_EQ(Parser.Put(boost::asio::buffer(std::array<std::uint8_t, 4>{}), ec2), wire.size());
        EXPECT_FALSE(ec2);
    }

    TEST(VmessCodecDeep, ChunkStreamDecryptErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 16> iv{};
        Vmess::ChunkStream cs;
        cs.Init(std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 16>(iv));

        // wire 不足 18 字节
        std::string plain;
        std::array<std::uint8_t, 10> short_wire{};
        auto r1 = cs.Decrypt(std::span<const std::uint8_t>(short_wire), plain);
        EXPECT_TRUE(r1.Ec);
        EXPECT_EQ(r1.Ec, make_error_code(Error::NeedMore));

        // 坏密文
        std::array<std::uint8_t, 18> bad{};
        bad[17] = 0x01;
        auto r2 = cs.Decrypt(std::span<const std::uint8_t>(bad), plain);
        EXPECT_TRUE(r2.Ec);
        EXPECT_EQ(r2.Ec, make_error_code(Error::BadAuth));
    }

} // namespace
