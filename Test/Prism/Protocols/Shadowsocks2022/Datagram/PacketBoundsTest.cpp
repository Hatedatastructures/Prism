/**
 * @file PacketBoundsTest.cpp
 * @brief SS2022 UDP packet 长度、字段上限与认证后载荷限制。
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Protocols/Shadowsocks2022/ResponseCodec.hpp>

namespace
{
    namespace SS = Prism::Shadowsocks2022;

    constexpr std::array<std::uint8_t, SS::AeadKeyLen> TestKey{
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};
    constexpr std::array<std::uint8_t, SS::SessionIdLen> TestSessionId{
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78};
    constexpr std::array<std::uint8_t, SS::SessionIdLen> TestRemoteSessionId{
        0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0};
    constexpr std::uint64_t TestPacketId{0x0102030405060708ULL};
    constexpr std::size_t MaximumPaddingLength =
        (std::numeric_limits<std::uint16_t>::max)();
    constexpr std::size_t MaximumDomainWireLength = 1U + 1U + 0xFFU + 2U;
    constexpr std::size_t MinimumDomainWireLength = 1U + 1U + 1U + 2U;
    constexpr std::size_t MaximumServerPlaintextLength =
        1U + SS::UdpTsLen + SS::SessionIdLen + 2U + MaximumPaddingLength +
        MaximumDomainWireLength + SS::MaxUdpPayload;
    constexpr std::size_t MaximumPacketLength =
        SS::SeparateHdrLen + SS::AeadTagLen + MaximumServerPlaintextLength;
    constexpr std::size_t MinimumClientPacketLength =
        SS::SeparateHdrLen + SS::AeadTagLen + 1U + SS::UdpTsLen + 2U +
        MinimumDomainWireLength;
    static_assert(MaximumPacketLength == 131380U);
    static_assert(MinimumClientPacketLength == 48U);

    struct PlaintextRecipe final
    {
        std::uint8_t HeaderType;
        std::uint64_t Timestamp;
        std::array<std::uint8_t, SS::SessionIdLen> RemoteSessionId;
        std::uint16_t PaddingLength;
        std::string_view Domain;
        std::uint16_t Port;
        std::span<const std::uint8_t> Payload;
    };

    /** @brief 追加 64 位大端序整数。 */
    auto AppendUint64(std::vector<std::uint8_t> &Output, const std::uint64_t Value)
        -> void
    {
        for (std::size_t Index = 0; Index < 8U; ++Index)
        {
            const auto Shift =
                static_cast<unsigned int>((7U - Index) * 8U);
            Output.push_back(static_cast<std::uint8_t>((Value >> Shift) & 0xFFU));
        }
    }

    /** @brief 追加 16 位大端序整数。 */
    auto AppendUint16(std::vector<std::uint8_t> &Output, const std::uint16_t Value)
        -> void
    {
        Output.push_back(static_cast<std::uint8_t>((Value >> 8U) & 0xFFU));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    /** @brief 构造指定类型的明文 body，支持协议允许的最大 padding。 */
    [[nodiscard]] auto MakePlaintext(const PlaintextRecipe &Recipe)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Plaintext;
        Plaintext.reserve(
            1U + SS::UdpTsLen + SS::SessionIdLen + 2U +
            Recipe.PaddingLength + MaximumDomainWireLength + Recipe.Payload.size());
        Plaintext.push_back(Recipe.HeaderType);
        AppendUint64(Plaintext, Recipe.Timestamp);
        if (Recipe.HeaderType == SS::HeaderTypeServer)
        {
            Plaintext.insert(
                Plaintext.end(),
                Recipe.RemoteSessionId.begin(),
                Recipe.RemoteSessionId.end());
        }
        AppendUint16(Plaintext, Recipe.PaddingLength);
        Plaintext.insert(Plaintext.end(), Recipe.PaddingLength, 0xA5U);
        Plaintext.push_back(static_cast<std::uint8_t>(SS::AddressType::Domain));
        Plaintext.push_back(static_cast<std::uint8_t>(Recipe.Domain.size()));
        Plaintext.insert(
            Plaintext.end(), Recipe.Domain.begin(), Recipe.Domain.end());
        AppendUint16(Plaintext, Recipe.Port);
        Plaintext.insert(
            Plaintext.end(), Recipe.Payload.begin(), Recipe.Payload.end());
        return Plaintext;
    }

    /** @brief 封装手工构造的 body，按 SIP022 派生 Separate、subkey 与 nonce。 */
    [[nodiscard]] auto SealPacket(std::span<const std::uint8_t> Plaintext)
        -> std::vector<std::uint8_t>
    {
        std::array<std::uint8_t, SS::SeparateHdrLen> SeparatePlain{};
        std::memcpy(
            SeparatePlain.data(), TestSessionId.data(), SS::SessionIdLen);
        for (std::size_t Index = 0; Index < SS::PacketIdLen; ++Index)
        {
            const auto Shift = static_cast<unsigned int>(
                56U - static_cast<unsigned int>(Index * 8U));
            SeparatePlain[SS::SessionIdLen + Index] =
                static_cast<std::uint8_t>((TestPacketId >> Shift) & 0xFFU);
        }

        const auto Separate = SS::detail::CryptSeparate(
            std::span<const std::uint8_t>(TestKey),
            std::span<const std::uint8_t, SS::SeparateHdrLen>(SeparatePlain),
            true);
        if (!Separate)
        {
            return {};
        }

        const auto Subkey = SS::SessionKey(
            std::span<const std::uint8_t>(TestKey),
            std::span<const std::uint8_t>(TestSessionId),
            SS::AeadKeyLen);
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(
            Nonce.data(),
            SeparatePlain.data() + SS::SessionIdLen / 2U,
            SS::SessionIdLen / 2U);
        std::memcpy(
            Nonce.data() + SS::SessionIdLen / 2U,
            SeparatePlain.data() + SS::SessionIdLen,
            SS::PacketIdLen);

        const auto EncryptedBody = SS::detail::UdpSeal(
            SS::detail::UdpSealInput{
                std::span<const std::uint8_t>(Subkey),
                std::span<const std::uint8_t>(Nonce),
                Plaintext,
                {}});
        if (EncryptedBody.empty())
        {
            return {};
        }

        std::vector<std::uint8_t> Packet(
            Separate->begin(), Separate->end());
        Packet.insert(
            Packet.end(), EncryptedBody.begin(), EncryptedBody.end());
        return Packet;
    }

    [[nodiscard]] auto MakePayload(const std::size_t Size)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Payload(Size);
        for (std::size_t Index = 0; Index < Payload.size(); ++Index)
        {
            Payload[Index] = static_cast<std::uint8_t>(Index * 37U + 11U);
        }
        return Payload;
    }

    [[nodiscard]] auto CurrentTimestamp() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    TEST(Ss2022UdpPacketBounds, AcceptsMinimumLegalClientPacket)
    {
        const auto Timestamp = CurrentTimestamp();
        const auto Plaintext = MakePlaintext(PlaintextRecipe{
            SS::HeaderTypeClient,
            Timestamp,
            {},
            0U,
            "a",
            443U,
            {}});
        const auto Packet = SealPacket(Plaintext);
        ASSERT_EQ(Packet.size(), MinimumClientPacketLength);

        SS::Address Target{};
        std::vector<std::uint8_t> Payload;
        const auto Error = SS::ParseUdpPacket(SS::UdpParseInput{
            .SessionKey = std::span<const std::uint8_t>(TestKey),
            .packet = std::span<const std::uint8_t>(Packet),
            .Target = &Target,
            .payload = &Payload,
            .Now = Timestamp,
            .TimeWindow = 0U});

        ASSERT_EQ(Error, Prism::Error::None);
        EXPECT_EQ(Target.Type, SS::AddressType::Domain);
        EXPECT_EQ(Target.Host, "a");
        EXPECT_EQ(Target.Port, 443U);
        EXPECT_TRUE(Payload.empty());
    }

    TEST(Ss2022UdpPacketBounds, AcceptsMaximumServerPacketAtLimit)
    {
        const auto Timestamp = CurrentTimestamp();
        const std::string Domain(0xFFU, 'd');
        const auto Payload = MakePayload(SS::MaxUdpPayload);
        const auto Plaintext = MakePlaintext(PlaintextRecipe{
            SS::HeaderTypeServer,
            Timestamp,
            TestRemoteSessionId,
            static_cast<std::uint16_t>(MaximumPaddingLength),
            Domain,
            443U,
            std::span<const std::uint8_t>(Payload)});
        const auto Packet = SealPacket(Plaintext);
        ASSERT_EQ(Packet.size(), MaximumPacketLength);

        SS::Address Target{};
        std::vector<std::uint8_t> ParsedPayload;
        std::array<std::uint8_t, SS::SessionIdLen> ParsedSessionId{};
        std::array<std::uint8_t, SS::SessionIdLen> ParsedRemoteSessionId{};
        std::uint64_t ParsedPacketId = 0;
        std::uint64_t ParsedTimestamp = 0;
        std::uint8_t ParsedHeaderType = 0;
        const auto Error = SS::ParseUdpPacket(SS::UdpParseInput{
            .SessionKey = std::span<const std::uint8_t>(TestKey),
            .packet = std::span<const std::uint8_t>(Packet),
            .Target = &Target,
            .payload = &ParsedPayload,
            .SessionId = &ParsedSessionId,
            .PacketId = &ParsedPacketId,
            .Timestamp = &ParsedTimestamp,
            .HeaderType = &ParsedHeaderType,
            .RemoteSessionId = &ParsedRemoteSessionId,
            .Now = Timestamp,
            .TimeWindow = 0U});

        ASSERT_EQ(Error, Prism::Error::None);
        EXPECT_EQ(Packet.size(), MaximumPacketLength);
        EXPECT_EQ(ParsedSessionId, TestSessionId);
        EXPECT_EQ(ParsedPacketId, TestPacketId);
        EXPECT_EQ(ParsedTimestamp, Timestamp);
        EXPECT_EQ(ParsedHeaderType, SS::HeaderTypeServer);
        EXPECT_EQ(ParsedRemoteSessionId, TestRemoteSessionId);
        EXPECT_EQ(Target.Type, SS::AddressType::Domain);
        EXPECT_EQ(Target.Host, Domain);
        EXPECT_EQ(Target.Port, 443U);
        EXPECT_EQ(ParsedPayload, Payload);
    }

    TEST(Ss2022UdpPacketBounds, RejectsOneByteAboveMaximumBeforeAuthentication)
    {
        const auto OversizedPacket =
            std::vector<std::uint8_t>(MaximumPacketLength + 1U, 0U);
        ASSERT_EQ(OversizedPacket.size(), MaximumPacketLength + 1U);

        SS::Address Target{};
        std::vector<std::uint8_t> Payload;
        const auto Error = SS::ParseUdpPacket(SS::UdpParseInput{
            .SessionKey = std::span<const std::uint8_t>(TestKey),
            .packet = std::span<const std::uint8_t>(OversizedPacket),
            .Target = &Target,
            .payload = &Payload});

        EXPECT_EQ(Error, Prism::Error::BadLength);
    }

    TEST(Ss2022UdpPacketBounds, RejectsAuthenticatedPayloadAboveMaximum)
    {
        const auto Timestamp = CurrentTimestamp();
        const auto Payload = MakePayload(SS::MaxUdpPayload + 1U);
        const auto Plaintext = MakePlaintext(PlaintextRecipe{
            SS::HeaderTypeClient,
            Timestamp,
            {},
            0U,
            "a",
            443U,
            std::span<const std::uint8_t>(Payload)});
        const auto Packet = SealPacket(Plaintext);
        ASSERT_FALSE(Packet.empty());
        ASSERT_LT(Packet.size(), MaximumPacketLength);

        SS::Address Target{};
        std::vector<std::uint8_t> ParsedPayload;
        const auto Error = SS::ParseUdpPacket(SS::UdpParseInput{
            .SessionKey = std::span<const std::uint8_t>(TestKey),
            .packet = std::span<const std::uint8_t>(Packet),
            .Target = &Target,
            .payload = &ParsedPayload,
            .Now = Timestamp,
            .TimeWindow = 0U});

        EXPECT_EQ(Error, Prism::Error::BadLength);
    }
} // namespace
