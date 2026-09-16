/**
 * @file Task9ContractTest.cpp
 * @brief Task 9 typed data-plane and wire contract tests.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <Preview/Composition/Adapters/DataPlane.hpp>
#include <Preview/Composition/Adapters/TypedResult.hpp>
#include <Preview/Protocols/Hysteria2/Codec.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Transport/Unreliable.hpp>

#include <boost/asio/io_context.hpp>

TEST(Task9Contract, Hysteria2UdpGoldenVectorRemainsStable)
{
    const Preview::Hysteria2::Address Target{
        Preview::Hysteria2::AddressType::Domain, "example.com", 443};
    const std::array<std::uint8_t, 2> Payload{0xAA, 0x55};
    const auto Wire = Preview::Hysteria2::BuildUdp(
        Preview::Hysteria2::UdpFrameInput{0x01020304, 0x05060708, &Target, Payload});

    const std::vector<std::uint8_t> Expected{
        0x02, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05,
        0x02, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x01, 0xBB, 0xAA, 0x55};
    EXPECT_EQ(Wire, Expected);
}

TEST(Task9Contract, TuicPacketGoldenVectorRemainsStable)
{
    const Preview::Tuic::Message Packet{
        Preview::Tuic::CmdPacket, 7, 9, 1, 0, 2,
        Preview::Tuic::Address{Preview::Tuic::AddressType::Domain, "example.com", 443}, "ok"};

    const std::vector<std::uint8_t> Expected{
        0x05, 0x02, 0x00, 0x07, 0x00, 0x09, 0x01, 0x00, 0x00, 0x02,
        0x00, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x01, 0xBB, 'o', 'k'};
    EXPECT_EQ(Preview::Tuic::Build(Packet), Expected);
}

TEST(Task9Contract, DataPlaneVariantCannotBeMistakenForAnotherTransport)
{
    const auto Empty = Preview::Composition::Adapters::DataPlaneResult::Datagram(nullptr);
    EXPECT_TRUE(Empty.IsDatagram());
    EXPECT_FALSE(Empty.IsStream());
    EXPECT_EQ(Empty.Status, Preview::Error::None);
}

TEST(Task9Contract, LegacyHandlerFieldsAreConvertedToTypedDataPlane)
{
    boost::asio::io_context Io;
    Preview::Runtime::Handler::AcceptResult Legacy;
    Legacy.IsDgram = true;
    Legacy.Transmission = std::make_shared<Preview::Transport::Unreliable>(Io.get_executor());

    const auto Typed = Preview::Composition::Adapters::ToTypedResult(std::move(Legacy));

    EXPECT_EQ(Typed.Status, Preview::Error::None);
    EXPECT_TRUE(Typed.Data.IsDatagram());
    EXPECT_FALSE(Typed.Data.IsStream());
}

TEST(Task9Contract, CompositionMaterializesRuntimeTypedRootWithoutRtti)
{
    boost::asio::io_context Io;
    Preview::Runtime::Handler::AcceptResult Legacy;
    Legacy.IsDgram = true;
    Legacy.Transmission = std::make_shared<Preview::Transport::Unreliable>(Io.get_executor());

    Preview::Composition::Adapters::MaterializeTypedDataPlane(Legacy, true);

    EXPECT_TRUE(Legacy.DataPlane.IsDatagram());
    EXPECT_TRUE(Legacy.DataPlane.HasTransport());
    EXPECT_EQ(Legacy.DataPlane.Transport().get(), Legacy.Transmission.get());
}
