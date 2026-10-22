/**
 * @file SurfaceContractTest.cpp
 * @brief Task 9 typed data-plane and wire contract tests.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <type_traits>
#include <Prism/Protocols/Hysteria2/Codec.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Transport/Unreliable.hpp>

#include <boost/asio/io_context.hpp>

TEST(Task9Contract, Hysteria2UdpGoldenVectorRemainsStable)
{
    const Prism::Hysteria2::Address Target{
        Prism::Hysteria2::AddressType::Domain, "example.com", 443};
    const std::array<std::uint8_t, 2> Payload{0xAA, 0x55};
    const auto Wire = Prism::Hysteria2::BuildUdp(
        Prism::Hysteria2::UdpFrameInput{0x01020304, 0x05060708, &Target, Payload});

    const std::vector<std::uint8_t> Expected{
        0x02, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05,
        0x02, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x01, 0xBB, 0xAA, 0x55};
    EXPECT_EQ(Wire, Expected);
}

TEST(Task9Contract, TuicPacketGoldenVectorRemainsStable)
{
    const Prism::Tuic::Message Packet{
        Prism::Tuic::CmdPacket, 7, 9, 1, 0, 2,
        Prism::Tuic::Address{Prism::Tuic::AddressType::Domain, "example.com", 443}, "ok"};

    const std::vector<std::uint8_t> Expected{
        0x05, 0x02, 0x00, 0x07, 0x00, 0x09, 0x01, 0x00, 0x00, 0x02,
        0x00, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x01, 0xBB, 'o', 'k'};
    EXPECT_EQ(Prism::Tuic::Build(Packet), Expected);
}

TEST(Task9Contract, CanonicalOutcomeMovesTheOnlyTransportOwner)
{
    boost::asio::io_context Io;
    Prism::Contract::ProtocolDataPlane Plane;
    auto Transport = std::make_shared<Prism::Transport::Unreliable>(Io.get_executor());
    Plane.Root = Prism::Contract::StreamDataPlane{Transport};
    Plane.Target.Host = *Prism::Network::ParseHost("127.0.0.1");
    Plane.Target.Port = 443;
    Prism::Contract::AcceptOutcome Accepted(std::move(Plane));
    ASSERT_TRUE(Accepted);
    auto Handoff = std::move(*Accepted);
    EXPECT_EQ(Handoff.Transport(), Transport);
    EXPECT_EQ(Handoff.Target.Host, *Prism::Network::ParseHost("127.0.0.1"));
    EXPECT_FALSE(Accepted->HasTransport());
    EXPECT_FALSE(std::is_copy_constructible_v<Prism::Contract::ProtocolDataPlane>);
}

TEST(Task9Contract, RejectedOutcomeHasNoForwardablePayload)
{
    Prism::Contract::AcceptOutcome Rejected(std::unexpected(
        Prism::Contract::FailureFromProtocolError(Prism::Error::BadAuth)));
    EXPECT_FALSE(Rejected);
    EXPECT_EQ(Rejected.error().Code, Prism::Fault::Code::AuthFailed);
    EXPECT_FALSE(Rejected.error().Native);
}
