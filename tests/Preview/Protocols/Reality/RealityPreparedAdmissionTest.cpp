/**
 * @file RealityPreparedAdmissionTest.cpp
 * @brief Reality Prepared 配置与认证拒绝行为。
 */

#include "RealityCarrierTestSupport.hpp"

#include <Preview/Protocols/Reality/Prepared.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <openssl/curve25519.h>

#include <array>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Test = Preview::Tests::Protocols::Reality;
    using Test::BuildClientHello;
    using Test::ClientHelloKeyMaterial;

    struct PreparedFailureResult final
    {
        std::expected<Preview::SharedTransmission, Preview::Fault::Failure> Accepted{
            std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable})};
        bool InboundRetired{false};
        bool PeerDrained{false};
    };

    struct PreparedFailureRequest final
    {
        Preview::Reality::PreparedConfig Config;
        Test::ClientHelloWire Hello;
        Preview::SharedTransmission Inbound;
        Preview::SharedTransmission Peer;
    };

    auto RunRejectedPreparedHandshake(PreparedFailureRequest Request)
        -> Net::awaitable<PreparedFailureResult>
    {
        PreparedFailureResult Result;
        Result.Accepted = co_await Preview::Reality::AcceptPrepared(
            Preview::Reality::PreparedRequest{
                Request.Inbound, std::move(Request.Config), Request.Hello.Random,
                Request.Hello.SessionId, Request.Hello.PublicKey,
                Request.Hello.Message, "example.com"});
        Result.InboundRetired = Request.Inbound->Activity()->IsRetired();
        const auto PeerClose = Request.Peer->Close();
        const auto PeerDrain = co_await Request.Peer->Activity()->Drain();
        Result.PeerDrained = PeerClose.has_value() && PeerDrain.has_value();
        co_return Result;
    }
}

TEST(RealityCarrier, PreparedProfileRetainsShortIdsAndServerNames)
{
    Preview::Reality::PreparedConfig Config;
    Config.PrivateKey.fill(0x11);
    const std::array<std::uint8_t, Preview::Reality::MaxShortIdLen> ShortId{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    Config.ShortIds.push_back(ShortId);
    Config.ServerNames.emplace_back("example.com");

    EXPECT_EQ(Config.PrivateKey.front(), 0x11);
    ASSERT_EQ(Config.ShortIds.size(), 1U);
    EXPECT_EQ(Config.ShortIds.front(), ShortId);
    ASSERT_EQ(Config.ServerNames.size(), 1U);
    EXPECT_EQ(Config.ServerNames.front(), "example.com");
}

TEST(RealityCarrier, RejectsUnconfiguredShortIdAndReturnsRetiredInbound)
{
    Net::io_context Context;
    auto [InboundStream, PeerStream] = Preview::MakeMemoryPair(Context.get_executor());
    auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(InboundStream));
    auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerStream));

    std::array<std::uint8_t, Preview::Reality::KeyLen> ServerPrivate{};
    std::array<std::uint8_t, Preview::Reality::KeyLen> ServerPublic{};
    std::array<std::uint8_t, Preview::Reality::KeyLen> ClientPrivate{};
    ServerPrivate.fill(0x11);
    ClientPrivate.fill(0x22);
    X25519_public_from_private(ServerPublic.data(), ServerPrivate.data());
    const std::array<std::uint8_t, Preview::Reality::MaxShortIdLen> ClientShortId{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const std::array<std::uint8_t, Preview::Reality::MaxShortIdLen> AllowedShortId{
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    std::array<std::uint8_t, 32> Random{};
    Random.fill(0x42);
    auto Hello = BuildClientHello(
        ClientHelloKeyMaterial{ServerPublic, ClientPrivate, Random},
        ClientShortId, "example.com");
    std::optional<PreparedFailureResult> Result;
    std::exception_ptr Failure;
    Net::co_spawn(Context,
        RunRejectedPreparedHandshake(PreparedFailureRequest{
            Preview::Reality::PreparedConfig{ServerPrivate, {AllowedShortId}, {"example.com"}},
            std::move(Hello), Inbound, Peer}),
        [&Result, &Failure](std::exception_ptr Error, PreparedFailureResult Value)
        {
            Failure = std::move(Error);
            Result = std::move(Value);
        });
    Context.run();

    EXPECT_FALSE(Failure);
    ASSERT_TRUE(Result);
    ASSERT_FALSE(Result->Accepted);
    EXPECT_EQ(Result->Accepted.error().Code, Preview::Fault::Code::Unauth);
    EXPECT_TRUE(Result->InboundRetired);
    EXPECT_TRUE(Result->PeerDrained);
}
