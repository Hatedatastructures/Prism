/** @file FragmentTest.cpp @brief Hysteria2 QUIC UDP fragment 编码、乱序重组和边界。 */
#include <gtest/gtest.h>
#include <Prism/Protocols/Hysteria2/Datagram/Fragments.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    namespace Hysteria = Prism::Hysteria2;
    using Error = Prism::Error;
    using FragmentView = Hysteria::Detail::ReferenceUdpFragmentView;
    using BuildInput = Hysteria::Detail::ReferenceUdpBuildInput;
    constexpr std::string_view Address{"127.0.0.1:28053"};

    auto MakePayload(const std::size_t Size) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result(Size);
        for (std::size_t Index = 0; Index < Size; ++Index)
            Result[Index] = static_cast<std::uint8_t>((Index * 31U + Size) & 0xFFU);
        return Result;
    }

    auto BuildFrames(const std::string_view Target, const std::span<const std::uint8_t> Payload)
        -> std::vector<std::vector<std::uint8_t>>
    {
        const auto Maximum = Hysteria::Detail::MaxReferenceUdpFragmentPayload(Target.size());
        if (!Maximum || Payload.empty()) return {};
        const auto Count = (Payload.size() + *Maximum - 1U) / *Maximum;
        if (Count == 0U || Count > 255U) return {};
        std::vector<std::vector<std::uint8_t>> Result(Count);
        for (std::size_t Index = 0; Index < Count; ++Index)
        {
            const auto Offset = Index * *Maximum;
            const auto PartSize = (std::min)(*Maximum, Payload.size() - Offset);
            const BuildInput Input{.SessionId = 0x12345678U,
                .PacketId = 0xBEEFU,
                .FragmentId = static_cast<std::uint8_t>(Index),
                .FragmentCount = static_cast<std::uint8_t>(Count),
                .Address = Target,
                .Payload = Payload.subspan(Offset, PartSize)};
            if (!Hysteria::Detail::BuildReferenceUdpFragment(Input, Result[Index])) return {};
        }
        return Result;
    }

    auto ParseFragment(const std::vector<std::uint8_t> &Frame)
        -> std::expected<FragmentView, Error>
    {
        return Hysteria::Detail::ParseReferenceUdpFragment(Frame);
    }
}

TEST(Hysteria2DatagramFragments, Payload1200BytesFitsAndReassemblesOutOfOrder)
{
    const auto Payload = MakePayload(1200U);
    const auto Frames = BuildFrames(Address, Payload);
    ASSERT_EQ(Frames.size(), 2U);
    const auto Maximum = Hysteria::Detail::MaxReferenceUdpFragmentPayload(Address.size());
    ASSERT_TRUE(Maximum);
    EXPECT_EQ(*Maximum, 1176U);
    for (const auto &Frame : Frames) EXPECT_LE(Frame.size(), 1200U);

    Hysteria::Detail::ReferenceUdpFragmentReassembler Reassembler;
    const auto Last = ParseFragment(Frames[1]);
    ASSERT_TRUE(Last);
    EXPECT_EQ(Last->FragmentId, 1U);
    EXPECT_EQ(Last->FragmentCount, 2U);
    auto Partial = Reassembler.Accept(*Last);
    ASSERT_TRUE(Partial);
    EXPECT_FALSE(Partial->has_value());

    const auto First = ParseFragment(Frames[0]);
    ASSERT_TRUE(First);
    auto Complete = Reassembler.Accept(*First);
    ASSERT_TRUE(Complete);
    ASSERT_TRUE(Complete->has_value());
    EXPECT_EQ((*Complete)->SessionId, 0x12345678U);
    EXPECT_EQ((*Complete)->PacketId, 0xBEEFU);
    EXPECT_EQ((*Complete)->Address, Address);
    EXPECT_EQ((*Complete)->Payload, Payload);
}

TEST(Hysteria2DatagramFragments, SmallPayloadUsesOneCompleteDatagram)
{
    const auto Payload = MakePayload(512U);
    const auto Frames = BuildFrames(Address, Payload);
    ASSERT_EQ(Frames.size(), 1U);
    EXPECT_LE(Frames.front().size(), 1200U);
    const auto Parsed = ParseFragment(Frames.front());
    ASSERT_TRUE(Parsed);
    EXPECT_EQ(Parsed->FragmentId, 0U);
    EXPECT_EQ(Parsed->FragmentCount, 1U);

    Hysteria::Detail::ReferenceUdpFragmentReassembler Reassembler;
    const auto Complete = Reassembler.Accept(*Parsed);
    ASSERT_TRUE(Complete);
    ASSERT_TRUE(Complete->has_value());
    EXPECT_EQ((*Complete)->Payload, Payload);
}

TEST(Hysteria2DatagramFragments, EmptyPayloadRemainsAValidUdpDatagram)
{
    std::vector<std::uint8_t> Frame;
    const BuildInput Input{.SessionId = 7U, .PacketId = 9U,
        .FragmentId = 0U, .FragmentCount = 1U,
        .Address = Address, .Payload = std::span<const std::uint8_t>{}};
    ASSERT_TRUE(Hysteria::Detail::BuildReferenceUdpFragment(Input, Frame));

    const auto Fragment = ParseFragment(Frame);
    ASSERT_TRUE(Fragment);
    EXPECT_TRUE(Fragment->Payload.empty());

    Hysteria::Detail::ReferenceUdpFragmentReassembler Reassembler;
    const auto Complete = Reassembler.Accept(*Fragment);
    ASSERT_TRUE(Complete);
    ASSERT_TRUE(Complete->has_value());
    EXPECT_TRUE((*Complete)->Payload.empty());
    EXPECT_EQ((*Complete)->SessionId, 7U);
    EXPECT_EQ((*Complete)->PacketId, 9U);
}

TEST(Hysteria2DatagramFragments, Payload4096BytesReassemblesAcrossFourOutOfOrderFrames)
{
    const auto Payload = MakePayload(4096U);
    const auto Frames = BuildFrames(Address, Payload);
    ASSERT_EQ(Frames.size(), 4U);
    Hysteria::Detail::ReferenceUdpFragmentReassembler Reassembler;
    std::optional<Hysteria::Detail::ReferenceUdpPacket> Complete;
    for (auto Index = Frames.size(); Index > 0U; --Index)
    {
        const auto Fragment = ParseFragment(Frames[Index - 1U]);
        ASSERT_TRUE(Fragment);
        auto Result = Reassembler.Accept(*Fragment);
        ASSERT_TRUE(Result);
        if (Result->has_value()) Complete = std::move(**Result);
    }
    ASSERT_TRUE(Complete);
    EXPECT_EQ(Complete->Address, Address);
    EXPECT_EQ(Complete->Payload, Payload);
}

TEST(Hysteria2DatagramFragments, AddressVarintBoundaryPreservesDatagramBudget)
{
    for (const auto &[HostSize, ExpectedBudget] :
        {std::pair{60U, 1128U}, std::pair{61U, 1126U}})
    {
        std::string Target(HostSize, 'a');
        Target += ":53";
        const auto Maximum = Hysteria::Detail::MaxReferenceUdpFragmentPayload(Target.size());
        ASSERT_TRUE(Maximum);
        EXPECT_EQ(*Maximum, ExpectedBudget);
        const auto Frames = BuildFrames(Target, MakePayload(1200U));
        ASSERT_EQ(Frames.size(), 2U);
        for (const auto &Frame : Frames) EXPECT_LE(Frame.size(), 1200U);
        const auto Parsed = ParseFragment(Frames[0]);
        ASSERT_TRUE(Parsed);
        EXPECT_EQ(Parsed->Address, Target);
    }
}

TEST(Hysteria2DatagramFragments, RejectsInvalidFragmentIdsAndOversizedFrames)
{
    const auto Frames = BuildFrames(Address, MakePayload(64U));
    ASSERT_EQ(Frames.size(), 1U);

    auto InvalidId = Frames.front();
    InvalidId[6] = 1U;
    EXPECT_FALSE(ParseFragment(InvalidId));

    auto InvalidCount = Frames.front();
    InvalidCount[7] = 0U;
    EXPECT_FALSE(ParseFragment(InvalidCount));

    std::vector<std::uint8_t> Oversized(Hysteria::Detail::MaxDatagramFrameSize + 1U);
    EXPECT_FALSE(ParseFragment(Oversized));
}

TEST(Hysteria2DatagramFragments, FragmentsFromDifferentSessionsRemainIsolated)
{
    const auto Payload = MakePayload(1200U);
    const auto Frames = BuildFrames(Address, Payload);
    ASSERT_EQ(Frames.size(), 2U);
    auto FirstSessionLast = ParseFragment(Frames[1]);
    auto SecondSessionFirst = ParseFragment(Frames[0]);
    auto FirstSessionFirst = ParseFragment(Frames[0]);
    auto SecondSessionLast = ParseFragment(Frames[1]);
    ASSERT_TRUE(FirstSessionLast);
    ASSERT_TRUE(SecondSessionFirst);
    ASSERT_TRUE(FirstSessionFirst);
    ASSERT_TRUE(SecondSessionLast);
    FirstSessionLast->SessionId = 10U;
    FirstSessionFirst->SessionId = 10U;
    SecondSessionFirst->SessionId = 11U;
    SecondSessionLast->SessionId = 11U;

    Hysteria::Detail::ReferenceUdpFragmentReassembler Reassembler;
    auto FirstPartial = Reassembler.Accept(*FirstSessionLast);
    ASSERT_TRUE(FirstPartial);
    EXPECT_FALSE(FirstPartial->has_value());
    auto SecondPartial = Reassembler.Accept(*SecondSessionFirst);
    ASSERT_TRUE(SecondPartial);
    EXPECT_FALSE(SecondPartial->has_value());
    auto First = Reassembler.Accept(*FirstSessionFirst);
    ASSERT_TRUE(First);
    ASSERT_TRUE(First->has_value());
    EXPECT_EQ((*First)->SessionId, 10U);
    EXPECT_EQ((*First)->Payload, Payload);
    auto Second = Reassembler.Accept(*SecondSessionLast);
    ASSERT_TRUE(Second);
    ASSERT_TRUE(Second->has_value());
    EXPECT_EQ((*Second)->SessionId, 11U);
    EXPECT_EQ((*Second)->Payload, Payload);
}

TEST(Hysteria2DatagramFragments, InconsistentAddressDropsPendingPacket)
{
    const auto Payload = MakePayload(1200U);
    const auto Frames = BuildFrames(Address, Payload);
    ASSERT_EQ(Frames.size(), 2U);
    const auto First = ParseFragment(Frames[0]);
    const auto Last = ParseFragment(Frames[1]);
    ASSERT_TRUE(First);
    ASSERT_TRUE(Last);

    Hysteria::Detail::ReferenceUdpFragmentReassembler Reassembler;
    const auto Partial = Reassembler.Accept(*First);
    ASSERT_TRUE(Partial);
    EXPECT_FALSE(Partial->has_value());
    auto Conflicting = *Last;
    Conflicting.Address = "127.0.0.2:28053";
    const auto Rejected = Reassembler.Accept(Conflicting);
    ASSERT_FALSE(Rejected);
    EXPECT_EQ(Rejected.error(), Error::BadMessage);
}
