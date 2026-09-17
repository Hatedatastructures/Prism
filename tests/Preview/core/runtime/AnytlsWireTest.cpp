/**
 * @file AnytlsWireTest.cpp
 * @brief AnyTLS sing-mux bootstrap and StreamRequest wire contracts.
 */

#include <gtest/gtest.h>

#include <Preview/Composition/AnytlsWire.hpp>
#include <Preview/Protocols/Mux/Smux/Codec.hpp>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

namespace
{

    auto Bytes(std::initializer_list<std::uint8_t> Values) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        Result.reserve(Values.size());
        for (const auto Value : Values)
        {
            Result.push_back(static_cast<std::byte>(Value));
        }
        return Result;
    }

} // namespace

TEST(AnytlsWire, ParsesSingMuxBootstrapVariants)
{
    const auto V0 = Preview::Composition::AnytlsWire::ParseBootstrap(Bytes({0x00, 0x00}));
    ASSERT_TRUE(V0.has_value());
    EXPECT_EQ(V0->Version, 0U);
    EXPECT_EQ(V0->Protocol, 0U);
    EXPECT_EQ(V0->Consumed, 2U);

    const auto V1 = Preview::Composition::AnytlsWire::ParseBootstrap(Bytes({0x01, 0x00, 0x00}));
    ASSERT_TRUE(V1.has_value());
    EXPECT_EQ(V1->Version, 1U);
    EXPECT_EQ(V1->Protocol, 0U);
    EXPECT_EQ(V1->Consumed, 3U);

    const auto Padded = Preview::Composition::AnytlsWire::ParseBootstrap(
        Bytes({0x01, 0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB}));
    ASSERT_TRUE(Padded.has_value());
    EXPECT_EQ(Padded->Consumed, 7U);

    EXPECT_EQ(Preview::Composition::AnytlsWire::ParseBootstrap(Bytes({0x01, 0x00, 0x01})),
              Preview::Error::NeedMore);
}
TEST(AnytlsWire, ParsesStreamRequestAndPreservesTrailingPayload)
{
    auto Data = Bytes({0x00, 0x00, 0x01, 127, 0, 0, 1, 0x46, 0x50});
    Data.push_back(static_cast<std::byte>('G'));
    Data.push_back(static_cast<std::byte>('E'));
    Data.push_back(static_cast<std::byte>('T'));

    const auto Request = Preview::Composition::AnytlsWire::ParseStreamRequest(Data);
    ASSERT_TRUE(Request.has_value());
    EXPECT_FALSE(Request->Udp);
    EXPECT_FALSE(Request->PacketAddress);
    EXPECT_EQ(Request->Target.Host, "127.0.0.1");
    EXPECT_EQ(Request->Target.Port, "18000");
    EXPECT_EQ(Request->Consumed, 9U);
}

TEST(AnytlsWire, SmuxCodecMatchesBootstrapStreamContract)
{
    const auto Syn = Preview::Mux::Smux::BuildSyn(3U);
    Preview::Mux::Smux::FrameHeader SynHeader{};
    EXPECT_EQ(Preview::Mux::Smux::ParseHeader(Syn, SynHeader), Preview::Error::None);
    EXPECT_EQ(SynHeader.cmd, Preview::Mux::Smux::Command::Syn);
    EXPECT_EQ(SynHeader.StreamId, 3U);

    const auto StreamRequest = Bytes({0x00, 0x00, 0x01, 127, 0, 0, 1, 0x46, 0x50});
    const std::vector<std::uint8_t> Payload(
        reinterpret_cast<const std::uint8_t *>(StreamRequest.data()),
        reinterpret_cast<const std::uint8_t *>(StreamRequest.data()) + StreamRequest.size());
    const auto Push = Preview::Mux::Smux::BuildPush(3U, Payload);
    Preview::Mux::Smux::FrameHeader PushHeader{};
    EXPECT_EQ(Preview::Mux::Smux::ParseHeader(
                  std::span<const std::uint8_t>(Push.data(), Preview::Mux::Smux::FrameHdrsize),
                  PushHeader),
              Preview::Error::None);
    EXPECT_EQ(PushHeader.cmd, Preview::Mux::Smux::Command::Push);
    EXPECT_EQ(PushHeader.length, StreamRequest.size());
    EXPECT_EQ(PushHeader.StreamId, 3U);
}
